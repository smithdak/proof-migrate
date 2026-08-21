#![forbid(unsafe_code)]

//! Evidence-backed evaluation of an offline migration candidate.

use std::collections::{BTreeMap, BTreeSet};

use proof_migrate_evidence::{
    EvidenceBundleV1, FindingSeverity, SitecoreItemV1, template_evidence_key,
};
use proof_migrate_improve::ImprovementReportV1;
use proof_migrate_projector::{
    ProjectionDisposition, ProofCandidateBundleV1, ProofObjectCandidateV1,
    ProofRenditionCandidateV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EVALUATION_REPORT_API_V1: &str = "proof-migrate.dev/evaluation-report/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationVerdict {
    Pass,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReportV1 {
    pub api_version: String,
    pub source_snapshot_id: String,
    pub verdict: EvaluationVerdict,
    pub counts: EvaluationCountsV1,
    pub checks: Vec<EvaluationCheckV1>,
    pub gaps: Vec<EvaluationGapV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCountsV1 {
    pub source_entities: u64,
    pub classified_entities: u64,
    pub mapped_or_transformed: u64,
    pub preserved: u64,
    pub unsupported: u64,
    pub failed_or_unknown: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationCheckV1 {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationGapV1 {
    pub code: String,
    pub source_key: String,
    pub disposition: ProjectionDisposition,
    pub reason: String,
}

#[must_use]
#[allow(clippy::too_many_lines)] // Keeps the verdict and its complete check set in one audit path.
pub fn evaluate(
    evidence: &EvidenceBundleV1,
    projection: &ProofCandidateBundleV1,
    improvement: &ImprovementReportV1,
) -> EvaluationReportV1 {
    let expected_keys = expected_source_keys(evidence);
    let actual_keys = projection
        .classifications
        .iter()
        .map(|classification| classification.source_key.clone())
        .collect::<Vec<_>>();
    let actual_unique = actual_keys.iter().cloned().collect::<BTreeSet<_>>();
    let duplicate_classifications = actual_keys.len() != actual_unique.len();
    let complete_accounting = !duplicate_classifications && actual_unique == expected_keys;
    let raw_values_preserved = mapped_raw_values_are_preserved(evidence, projection);
    let no_source_errors = evidence.source_errors.is_empty()
        && !evidence
            .normalization_findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::Error);
    let offline_only = projection.target.write_mode == "offline-candidate-only";
    let deterministic_improvement = improvement.deterministic_replay_passed();
    let no_failed_or_unknown = projection.classifications.iter().all(|classification| {
        !matches!(
            classification.disposition,
            ProjectionDisposition::Failed | ProjectionDisposition::Unknown
        )
    });

    let checks = vec![
        check(
            "complete-source-accounting",
            complete_accounting,
            if complete_accounting {
                "every captured template, item version, and media record has exactly one disposition"
            } else {
                "classification keys did not exactly match captured source keys"
            },
        ),
        check(
            "raw-value-preservation",
            raw_values_preserved,
            if raw_values_preserved {
                "every mapped item retains its exact raw Sitecore field values"
            } else {
                "at least one mapped item lost or changed a raw field value"
            },
        ),
        check(
            "source-integrity",
            no_source_errors,
            if no_source_errors {
                "the source bundle contains no extraction or structural errors"
            } else {
                "source extraction or structural errors require adjudication"
            },
        ),
        check(
            "offline-only",
            offline_only,
            if offline_only {
                "the target contract permits candidate files only and performs no Proof writes"
            } else {
                "the projection target is not constrained to offline candidates"
            },
        ),
        check(
            "improvement-replay",
            deterministic_improvement,
            if deterministic_improvement {
                "every promoted non-production candidate reproduced byte-identical shadow output"
            } else {
                "an automatically promoted candidate lacked deterministic replay evidence"
            },
        ),
        check(
            "no-failed-or-unknown-dispositions",
            no_failed_or_unknown,
            if no_failed_or_unknown {
                "unsupported work is explicit and preserved; no entity failed or remained unknown"
            } else {
                "at least one entity failed projection or has an unknown disposition"
            },
        ),
    ];
    let verdict = if checks.iter().all(|check| check.passed) {
        EvaluationVerdict::Pass
    } else {
        EvaluationVerdict::Fail
    };
    let mut gaps = projection
        .classifications
        .iter()
        .filter(|classification| {
            !matches!(
                classification.disposition,
                ProjectionDisposition::Mapped | ProjectionDisposition::Transformed
            )
        })
        .map(|classification| EvaluationGapV1 {
            code: "entity-disposition".to_owned(),
            source_key: classification.source_key.clone(),
            disposition: classification.disposition,
            reason: classification.reason.clone(),
        })
        .collect::<Vec<_>>();
    gaps.extend(projection.surface_gaps.iter().map(|gap| EvaluationGapV1 {
        code: gap.code.clone(),
        source_key: gap.source_key.clone(),
        disposition: gap.disposition,
        reason: gap.reason.clone(),
    }));
    gaps.extend(evidence.source_unknowns.iter().map(|unknown| {
        EvaluationGapV1 {
            code: unknown.code.clone(),
            source_key: unknown
                .subject
                .clone()
                .unwrap_or_else(|| "source-capture".to_owned()),
            disposition: ProjectionDisposition::Unknown,
            reason: unknown.message.clone(),
        }
    }));
    gaps.sort_by(|left, right| {
        (&left.source_key, &left.code, &left.reason).cmp(&(
            &right.source_key,
            &right.code,
            &right.reason,
        ))
    });
    let mapped_or_transformed = projection
        .classifications
        .iter()
        .filter(|classification| {
            matches!(
                classification.disposition,
                ProjectionDisposition::Mapped | ProjectionDisposition::Transformed
            )
        })
        .count() as u64;
    let preserved = projection
        .classifications
        .iter()
        .filter(|classification| classification.disposition == ProjectionDisposition::Preserved)
        .count() as u64;
    let unsupported = projection
        .classifications
        .iter()
        .filter(|classification| classification.disposition == ProjectionDisposition::Unsupported)
        .count() as u64;
    let failed_or_unknown = projection
        .classifications
        .iter()
        .filter(|classification| {
            matches!(
                classification.disposition,
                ProjectionDisposition::Failed | ProjectionDisposition::Unknown
            )
        })
        .count() as u64;

    EvaluationReportV1 {
        api_version: EVALUATION_REPORT_API_V1.to_owned(),
        source_snapshot_id: evidence.snapshot_id.clone(),
        verdict,
        counts: EvaluationCountsV1 {
            source_entities: expected_keys.len() as u64,
            classified_entities: projection.classifications.len() as u64,
            mapped_or_transformed,
            preserved,
            unsupported,
            failed_or_unknown,
        },
        checks,
        gaps,
    }
}

fn expected_source_keys(evidence: &EvidenceBundleV1) -> BTreeSet<String> {
    evidence
        .templates
        .iter()
        .map(|template| template_evidence_key(&template.id))
        .chain(evidence.items.iter().map(SitecoreItemV1::evidence_key))
        .chain(
            evidence
                .media
                .iter()
                .map(proof_migrate_evidence::SitecoreMediaV1::evidence_key),
        )
        .collect()
}

fn mapped_raw_values_are_preserved(
    evidence: &EvidenceBundleV1,
    projection: &ProofCandidateBundleV1,
) -> bool {
    let item_map = evidence
        .items
        .iter()
        .map(|item| (item.evidence_key(), item))
        .collect::<BTreeMap<_, _>>();
    projection
        .objects
        .iter()
        .all(|object| raw_values_match_object(&item_map, &object.source_key, object))
        && projection.renditions.iter().all(|rendition| {
            raw_values_match_rendition(&item_map, &rendition.source_key, rendition)
        })
}

fn raw_values_match_object(
    item_map: &BTreeMap<String, &SitecoreItemV1>,
    source_key: &str,
    object: &ProofObjectCandidateV1,
) -> bool {
    item_map
        .get(source_key)
        .is_some_and(|item| raw_values_match_content(item, &object.canonical_content))
}

fn raw_values_match_rendition(
    item_map: &BTreeMap<String, &SitecoreItemV1>,
    source_key: &str,
    rendition: &ProofRenditionCandidateV1,
) -> bool {
    item_map
        .get(source_key)
        .is_some_and(|item| raw_values_match_content(item, &rendition.canonical_content))
}

fn raw_values_match_content(item: &SitecoreItemV1, canonical_content: &str) -> bool {
    let Ok(content) = serde_json::from_str::<Value>(canonical_content) else {
        return false;
    };
    let Some(raw_fields) = content
        .get("_sitecore")
        .and_then(|source| source.get("raw_fields"))
        .and_then(Value::as_object)
    else {
        return false;
    };
    if raw_fields.len() != item.fields.len() {
        return false;
    }
    item.fields.iter().all(|field| {
        let expected = field.raw.clone().map_or(Value::Null, Value::String);
        raw_fields.get(&field.field_id) == Some(&expected)
    })
}

fn check(name: &str, passed: bool, detail: &str) -> EvaluationCheckV1 {
    EvaluationCheckV1 {
        name: name.to_owned(),
        passed,
        detail: detail.to_owned(),
    }
}
