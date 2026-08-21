#![forbid(unsafe_code)]

//! Complete offline Sitecore-to-Proof candidate pipeline.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use proof_migrate_evaluate::{EvaluationReportV1, EvaluationVerdict, evaluate};
use proof_migrate_evidence::{EvidenceBundleV1, SitecoreExportV1, canonical_json, domain_digest};
use proof_migrate_improve::{ImprovementReportV1, improve};
use proof_migrate_normalize::normalize;
use proof_migrate_preflight::{
    EstateManifestV1, EstateObservationV1, EvidenceBasis, PreflightStatus,
    RecommendedAcquisitionPath, assess, assess_with_basis,
};
use proof_migrate_projector::{ProofCandidateBundleV1, ProofTargetContractV1};
use proof_migrate_source_inspect::{
    SourceInspectionConfig, SourceInspectionReportV1, SourceKind, inspect_source,
};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OBSERVATION_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunConfig {
    pub source: PathBuf,
    pub target_contract: PathBuf,
    pub output: PathBuf,
    pub source_locale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummaryV1 {
    pub api_version: String,
    pub output: String,
    pub source_snapshot_id: String,
    pub evaluation_verdict: EvaluationVerdict,
    pub promoted_candidate_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightConfig {
    pub observation: PathBuf,
    pub output: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightSummaryV1 {
    pub api_version: String,
    pub output: String,
    pub estate_id: String,
    pub semantic_snapshot_id: String,
    pub status: PreflightStatus,
    pub ready_for_extractor_design: bool,
    pub recommended_acquisition_path: RecommendedAcquisitionPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectConfig {
    pub source: PathBuf,
    pub output: PathBuf,
    pub estate_id: Option<String>,
    pub observed_at: Option<String>,
    pub authorization_reference: Option<String>,
    pub approved_for_read_only_preflight: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectSummaryV1 {
    pub api_version: String,
    pub output: String,
    pub estate_id: String,
    pub source_kind: SourceKind,
    pub preflight_status: PreflightStatus,
    pub ready_for_extractor_design: bool,
    pub files_seen: u64,
    pub safe_manifests_read: u64,
    pub sensitive_marked_files_opened: u64,
    pub source_writes_performed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunManifestV1 {
    api_version: String,
    source_snapshot_id: String,
    artifacts: Vec<ArtifactManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifestEntryV1 {
    path: String,
    byte_length: u64,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PreflightRunManifestV1 {
    api_version: String,
    estate_id: String,
    semantic_snapshot_id: String,
    artifacts: Vec<ArtifactManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InspectRunManifestV1 {
    api_version: String,
    estate_id: String,
    semantic_snapshot_id: String,
    artifacts: Vec<ArtifactManifestEntryV1>,
}

/// Runs the complete offline pipeline and atomically publishes its artifact bundle.
///
/// # Errors
///
/// Returns an error when inputs violate their contracts, projection or evaluation cannot finish,
/// the output already exists, or the complete bundle cannot be staged and published.
pub fn run_pipeline(config: &RunConfig) -> Result<RunSummaryV1> {
    if config.output.exists() {
        bail!(
            "output path already exists; choose a new directory to preserve prior evidence: {}",
            config.output.display()
        );
    }
    let source_bytes = read_bounded(&config.source, MAX_SOURCE_BYTES)
        .with_context(|| format!("failed to read source export {}", config.source.display()))?;
    let source = serde_json::from_slice::<SitecoreExportV1>(&source_bytes)
        .context("source export did not satisfy the versioned Sitecore export contract")?;
    let contract_bytes = read_bounded(&config.target_contract, 1024 * 1024).with_context(|| {
        format!(
            "failed to read Proof target contract {}",
            config.target_contract.display()
        )
    })?;
    let contract = serde_json::from_slice::<ProofTargetContractV1>(&contract_bytes)
        .context("Proof target contract is invalid")?;

    let evidence =
        normalize(source, &source_bytes).context("source evidence normalization failed")?;
    let improved = improve(&evidence, &contract, &config.source_locale)
        .context("automatic improvement loop failed")?;
    let evaluation = evaluate(&evidence, &improved.projection, &improved.report);

    let parent = config.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output parent {}", parent.display()))?;
    let stage = Builder::new()
        .prefix(".proof-migrate-stage-")
        .tempdir_in(parent)
        .context("failed to create an isolated output staging directory")?;
    write_artifacts(
        stage.path(),
        &evidence,
        &improved.projection,
        &evaluation,
        &improved.report,
    )?;
    let stage_path = stage.keep();
    fs::rename(&stage_path, &config.output).with_context(|| {
        format!(
            "failed to publish the complete output bundle to {}",
            config.output.display()
        )
    })?;

    Ok(RunSummaryV1 {
        api_version: "proof-migrate.dev/run-summary/v1".to_owned(),
        output: config.output.display().to_string(),
        source_snapshot_id: evidence.snapshot_id,
        evaluation_verdict: evaluation.verdict,
        promoted_candidate_count: improved
            .report
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.status == proof_migrate_improve::CandidateStatus::PromotedNonProduction
            })
            .count() as u64,
    })
}

/// Validates a local, content-free estate observation and atomically publishes its assessment.
///
/// This command performs no network access, estate access, Sitecore write, or Proof write. The
/// resulting readiness decision is based on declared input facts rather than independently
/// verified estate state.
///
/// # Errors
///
/// Returns an error when the input violates the preflight contract, the output already exists,
/// or the complete output bundle cannot be staged and published.
pub fn run_preflight(config: &PreflightConfig) -> Result<PreflightSummaryV1> {
    if config.output.exists() {
        bail!(
            "output path already exists; choose a new directory to preserve prior evidence: {}",
            config.output.display()
        );
    }
    let observation_bytes =
        read_bounded(&config.observation, MAX_OBSERVATION_BYTES).with_context(|| {
            format!(
                "failed to read estate observation {}",
                config.observation.display()
            )
        })?;
    let observation = serde_json::from_slice::<EstateObservationV1>(&observation_bytes)
        .context("input did not satisfy the versioned, content-free estate observation contract")?;
    let manifest = assess(observation, &observation_bytes)
        .context("estate observation failed read-only preflight validation")?;

    let parent = config.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output parent {}", parent.display()))?;
    let stage = Builder::new()
        .prefix(".proof-migrate-preflight-stage-")
        .tempdir_in(parent)
        .context("failed to create an isolated preflight staging directory")?;
    write_preflight_artifacts(stage.path(), &manifest)?;
    let stage_path = stage.keep();
    fs::rename(&stage_path, &config.output).with_context(|| {
        format!(
            "failed to publish the complete preflight bundle to {}",
            config.output.display()
        )
    })?;

    Ok(PreflightSummaryV1 {
        api_version: "proof-migrate.dev/preflight-summary/v1".to_owned(),
        output: config.output.display().to_string(),
        estate_id: manifest.estate_id,
        semantic_snapshot_id: manifest.semantic_snapshot_id,
        status: manifest.assessment.status,
        ready_for_extractor_design: manifest.assessment.ready_for_extractor_design,
        recommended_acquisition_path: manifest.assessment.recommended_acquisition_path,
    })
}

/// Inspects a local Sitecore solution using a content-free, read-only scanner and publishes both
/// the generated observation and its preflight assessment.
///
/// A completed inspection succeeds even when preflight is blocked; blockers are the expected
/// discovery output. The source directory is never an allowed output location.
///
/// # Errors
///
/// Returns an error when the source cannot be inspected safely, the output is inside the source,
/// the output already exists, or the complete bundle cannot be staged and published.
pub fn run_inspection(config: &InspectConfig) -> Result<InspectSummaryV1> {
    if config.output.exists() {
        bail!(
            "output path already exists; choose a new directory to preserve prior evidence: {}",
            config.output.display()
        );
    }
    ensure_output_outside_source(&config.source, &config.output)?;
    let inspection = inspect_source(&SourceInspectionConfig {
        source: config.source.clone(),
        estate_id: config.estate_id.clone(),
        observed_at: config.observed_at.clone(),
        authorization_reference: config.authorization_reference.clone(),
        approved_for_read_only_preflight: config.approved_for_read_only_preflight,
    })
    .context("source directory failed read-only inspection")?;
    let observation_bytes = canonical_json(&inspection.observation)
        .map_err(anyhow::Error::msg)?
        .into_bytes();
    let estate_manifest = assess_with_basis(
        inspection.observation.clone(),
        &observation_bytes,
        EvidenceBasis::GeneratedSourceInspection,
    )
    .context("generated estate observation failed preflight validation")?;

    let parent = config.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output parent {}", parent.display()))?;
    let stage = Builder::new()
        .prefix(".proof-migrate-inspect-stage-")
        .tempdir_in(parent)
        .context("failed to create an isolated inspection staging directory")?;
    write_inspection_artifacts(
        stage.path(),
        &inspection.report,
        &inspection.observation,
        &estate_manifest,
    )?;
    let stage_path = stage.keep();
    fs::rename(&stage_path, &config.output).with_context(|| {
        format!(
            "failed to publish the complete inspection bundle to {}",
            config.output.display()
        )
    })?;

    Ok(InspectSummaryV1 {
        api_version: "proof-migrate.dev/inspect-summary/v1".to_owned(),
        output: config.output.display().to_string(),
        estate_id: estate_manifest.estate_id,
        source_kind: inspection.report.source_kind,
        preflight_status: estate_manifest.assessment.status,
        ready_for_extractor_design: estate_manifest.assessment.ready_for_extractor_design,
        files_seen: inspection.report.statistics.files_seen,
        safe_manifests_read: inspection.report.statistics.safe_manifests_read,
        sensitive_marked_files_opened: inspection.report.safety.sensitive_marked_files_opened,
        source_writes_performed: inspection.report.safety.source_writes_performed,
    })
}

fn write_artifacts(
    output: &Path,
    evidence: &EvidenceBundleV1,
    projection: &ProofCandidateBundleV1,
    evaluation: &EvaluationReportV1,
    improvement: &ImprovementReportV1,
) -> Result<()> {
    let mut manifest_entries = Vec::new();
    write_one(output, "evidence.json", evidence, &mut manifest_entries)?;
    write_one(
        output,
        "proof-candidate.json",
        projection,
        &mut manifest_entries,
    )?;
    write_one(output, "evaluation.json", evaluation, &mut manifest_entries)?;
    write_one(
        output,
        "improvement.json",
        improvement,
        &mut manifest_entries,
    )?;
    let manifest = RunManifestV1 {
        api_version: "proof-migrate.dev/run-manifest/v1".to_owned(),
        source_snapshot_id: evidence.snapshot_id.clone(),
        artifacts: manifest_entries,
    };
    write_canonical(&output.join("run-manifest.json"), &manifest)?;
    Ok(())
}

fn write_preflight_artifacts(output: &Path, manifest: &EstateManifestV1) -> Result<()> {
    let artifact_path = output.join("estate-manifest.json");
    let bytes = write_canonical(&artifact_path, manifest)?;
    let run_manifest = PreflightRunManifestV1 {
        api_version: "proof-migrate.dev/preflight-run-manifest/v1".to_owned(),
        estate_id: manifest.estate_id.clone(),
        semantic_snapshot_id: manifest.semantic_snapshot_id.clone(),
        artifacts: vec![ArtifactManifestEntryV1 {
            path: "estate-manifest.json".to_owned(),
            byte_length: bytes.len() as u64,
            digest: domain_digest("proof-migrate:preflight-artifact:v1", &bytes),
        }],
    };
    write_canonical(&output.join("preflight-run-manifest.json"), &run_manifest)?;
    Ok(())
}

fn write_inspection_artifacts(
    output: &Path,
    report: &SourceInspectionReportV1,
    observation: &EstateObservationV1,
    estate_manifest: &EstateManifestV1,
) -> Result<()> {
    let mut artifacts = Vec::new();
    write_inspection_artifact(output, "source-inspection.json", report, &mut artifacts)?;
    write_inspection_artifact(
        output,
        "estate-observation.json",
        observation,
        &mut artifacts,
    )?;
    write_inspection_artifact(
        output,
        "estate-manifest.json",
        estate_manifest,
        &mut artifacts,
    )?;
    let manifest = InspectRunManifestV1 {
        api_version: "proof-migrate.dev/inspect-run-manifest/v1".to_owned(),
        estate_id: estate_manifest.estate_id.clone(),
        semantic_snapshot_id: estate_manifest.semantic_snapshot_id.clone(),
        artifacts,
    };
    write_canonical(&output.join("inspect-run-manifest.json"), &manifest)?;
    Ok(())
}

fn write_inspection_artifact<T: Serialize>(
    output: &Path,
    name: &str,
    value: &T,
    artifacts: &mut Vec<ArtifactManifestEntryV1>,
) -> Result<()> {
    let bytes = write_canonical(&output.join(name), value)?;
    artifacts.push(ArtifactManifestEntryV1 {
        path: name.to_owned(),
        byte_length: bytes.len() as u64,
        digest: domain_digest("proof-migrate:inspect-artifact:v1", &bytes),
    });
    Ok(())
}

fn write_one<T: Serialize>(
    output: &Path,
    name: &str,
    value: &T,
    manifest: &mut Vec<ArtifactManifestEntryV1>,
) -> Result<()> {
    let path = output.join(name);
    let bytes = write_canonical(&path, value)?;
    manifest.push(ArtifactManifestEntryV1 {
        path: name.to_owned(),
        byte_length: bytes.len() as u64,
        digest: domain_digest("proof-migrate:run-artifact:v1", &bytes),
    });
    Ok(())
}

fn write_canonical<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json(value).map_err(anyhow::Error::msg)?;
    let bytes = canonical.into_bytes();
    fs::write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(bytes)
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "file exceeds the {} byte safety limit: {}",
            max_bytes,
            path.display()
        );
    }
    fs::read(path).map_err(Into::into)
}

fn ensure_output_outside_source(source: &Path, output: &Path) -> Result<()> {
    let source = fs::canonicalize(source)
        .with_context(|| format!("failed to resolve source directory {}", source.display()))?;
    if !source.is_dir() {
        bail!(
            "inspection source must be a directory: {}",
            source.display()
        );
    }
    let output = resolve_without_creating(output)?;
    if output == source || output.starts_with(&source) {
        bail!("inspection output must be outside the source directory");
    }
    Ok(())
}

fn resolve_without_creating(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut cursor = absolute.as_path();
    let mut missing = Vec::<OsString>::new();
    while !cursor.exists() {
        let name = cursor
            .file_name()
            .context("output path has no resolvable parent")?;
        missing.push(name.to_os_string());
        cursor = cursor
            .parent()
            .context("output path has no resolvable parent")?;
    }
    let mut resolved = fs::canonicalize(cursor)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use proof_migrate_evaluate::EvaluationVerdict;
    use proof_migrate_improve::{CandidateStatus, ImprovementReportV1};
    use tempfile::tempdir;

    use proof_migrate_preflight::{EstateManifestV1, EvidenceBasis, PreflightStatus};

    use super::{
        InspectConfig, PreflightConfig, RunConfig, run_inspection, run_pipeline, run_preflight,
    };

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn complete_pipeline_is_byte_reproducible() {
        let temp = tempdir().unwrap();
        let config = |name: &str| RunConfig {
            source: root().join("evaluations/fixtures/sitecore-export.synthetic.json"),
            target_contract: root().join("contracts/proof/contract.v1.json"),
            output: temp.path().join(name),
            source_locale: "en-US".to_owned(),
        };
        let first = run_pipeline(&config("first")).unwrap();
        let second = run_pipeline(&config("second")).unwrap();
        assert_eq!(first.evaluation_verdict, EvaluationVerdict::Pass);
        assert_eq!(second.evaluation_verdict, EvaluationVerdict::Pass);
        for name in [
            "evidence.json",
            "proof-candidate.json",
            "evaluation.json",
            "improvement.json",
            "run-manifest.json",
        ] {
            assert_eq!(
                fs::read(temp.path().join("first").join(name)).unwrap(),
                fs::read(temp.path().join("second").join(name)).unwrap(),
                "{name} differed across identical runs"
            );
        }
        let improvement: ImprovementReportV1 =
            serde_json::from_slice(&fs::read(temp.path().join("first/improvement.json")).unwrap())
                .unwrap();
        assert_eq!(improvement.model_calls_on_known_path, 0);
        assert!(
            improvement
                .candidates
                .iter()
                .any(|candidate| { candidate.status == CandidateStatus::PromotedNonProduction })
        );
    }

    #[test]
    fn existing_output_is_never_overwritten() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("existing");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("keep.txt"), "user data").unwrap();
        let result = run_pipeline(&RunConfig {
            source: root().join("evaluations/fixtures/sitecore-export.synthetic.json"),
            target_contract: root().join("contracts/proof/contract.v1.json"),
            output: output.clone(),
            source_locale: "en-US".to_owned(),
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(output.join("keep.txt")).unwrap(),
            "user data"
        );
    }

    #[test]
    fn preflight_is_byte_reproducible() {
        let temp = tempdir().unwrap();
        let config = |name: &str| PreflightConfig {
            observation: root().join("evaluations/fixtures/estate-observation.synthetic.json"),
            output: temp.path().join(name),
        };
        let first = run_preflight(&config("first")).unwrap();
        let second = run_preflight(&config("second")).unwrap();
        assert_eq!(first.status, PreflightStatus::Ready);
        assert_eq!(second.status, PreflightStatus::Ready);
        for name in ["estate-manifest.json", "preflight-run-manifest.json"] {
            assert_eq!(
                fs::read(temp.path().join("first").join(name)).unwrap(),
                fs::read(temp.path().join("second").join(name)).unwrap(),
                "{name} differed across identical preflight runs"
            );
        }
    }

    #[test]
    fn preflight_existing_output_is_never_overwritten() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("existing");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("keep.txt"), "user data").unwrap();
        let result = run_preflight(&PreflightConfig {
            observation: root().join("evaluations/fixtures/estate-observation.synthetic.json"),
            output: output.clone(),
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(output.join("keep.txt")).unwrap(),
            "user data"
        );
    }

    #[test]
    fn inspection_is_reproducible_and_never_mutates_source() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir_all(source.join("project")).unwrap();
        fs::write(source.join("Sitecore.config"), "unchanged").unwrap();
        fs::write(
            source.join("project/packages.config"),
            r#"<packages><package id="Sitecore.Logging" version="10.3.123456" /></packages>"#,
        )
        .unwrap();
        let source_before = fs::read(source.join("Sitecore.config")).unwrap();
        let config = |name: &str| InspectConfig {
            source: source.clone(),
            output: temp.path().join(name),
            estate_id: Some("SYNTH-INSPECT-001".to_owned()),
            observed_at: Some("2026-08-21T12:00:00Z".to_owned()),
            authorization_reference: None,
            approved_for_read_only_preflight: false,
        };
        let first = run_inspection(&config("first")).unwrap();
        let second = run_inspection(&config("second")).unwrap();
        assert_eq!(first.preflight_status, PreflightStatus::Blocked);
        assert_eq!(second.preflight_status, PreflightStatus::Blocked);
        for name in [
            "source-inspection.json",
            "estate-observation.json",
            "estate-manifest.json",
            "inspect-run-manifest.json",
        ] {
            assert_eq!(
                fs::read(temp.path().join("first").join(name)).unwrap(),
                fs::read(temp.path().join("second").join(name)).unwrap(),
                "{name} differed across identical inspections"
            );
        }
        assert_eq!(
            fs::read(source.join("Sitecore.config")).unwrap(),
            source_before
        );
        let manifest: EstateManifestV1 = serde_json::from_slice(
            &fs::read(temp.path().join("first/estate-manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest.assessment.evidence_basis,
            EvidenceBasis::GeneratedSourceInspection
        );
        assert!(!source.join("first").exists());
    }

    #[test]
    fn inspection_output_inside_source_is_rejected() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        let result = run_inspection(&InspectConfig {
            source: source.clone(),
            output: source.join("generated-output"),
            estate_id: Some("SYNTH-INSPECT-002".to_owned()),
            observed_at: Some("2026-08-21T12:00:00Z".to_owned()),
            authorization_reference: None,
            approved_for_read_only_preflight: false,
        });
        assert!(result.is_err());
        assert!(!source.join("generated-output").exists());
    }
}
