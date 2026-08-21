#![forbid(unsafe_code)]

//! Read-only, content-free inspection of a local Sitecore solution directory.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use proof_migrate_evidence::domain_digest;
use proof_migrate_preflight::{
    AuthorizationDeclarationV1, DataPresenceDeclarationV1, DataSafetyDeclarationV1,
    DeploymentModel, ESTATE_OBSERVATION_API_V1, EnvironmentClass, EstateCountsV1,
    EstateObservationV1, EstateRole, ExportMechanismKind, ExportMechanismV1, ProductFamily,
    ProductObservationV1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const SOURCE_INSPECTION_API_V1: &str = "proof-migrate.dev/source-inspection/v1";
const MAX_ENTRIES: u64 = 1_000_000;
const MAX_SAFE_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceInspectionConfig {
    pub source: PathBuf,
    pub estate_id: Option<String>,
    pub observed_at: Option<String>,
    pub authorization_reference: Option<String>,
    pub approved_for_read_only_preflight: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceInspectionResultV1 {
    pub observation: EstateObservationV1,
    pub report: SourceInspectionReportV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInspectionReportV1 {
    pub api_version: String,
    pub scanner_version: String,
    pub estate_id: String,
    pub source_kind: SourceKind,
    pub statistics: InspectionStatisticsV1,
    pub signals: InspectionSignalsV1,
    pub safety: InspectionSafetyV1,
    pub finding_codes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    SitecoreSolution,
    UnknownDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionStatisticsV1 {
    pub entries_seen: u64,
    pub files_seen: u64,
    pub directories_seen: u64,
    pub symlinks_skipped: u64,
    pub excluded_directories: u64,
    pub unreadable_entries: u64,
    pub safe_manifests_read: u64,
    pub safe_manifest_bytes_read: u64,
    pub sensitive_file_markers_skipped: u64,
    pub serialization_markers: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionSignalsV1 {
    pub sitecore_marker_count: u64,
    pub sitecore_packages_observed: u64,
    pub product_version_candidate_count: u64,
    pub inferred_roles: Vec<EstateRole>,
    pub inferred_export_mechanisms: Vec<ExportMechanismKind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionSafetyV1 {
    pub source_access: SourceAccess,
    pub file_content_policy: FileContentPolicy,
    pub network_access: NetworkAccess,
    pub sensitive_marked_files_opened: u64,
    pub source_writes_performed: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAccess {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileContentPolicy {
    AllowlistedPackageManifestsOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    None,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SourceInspectionError {
    #[error("source path is not an existing directory")]
    SourceNotDirectory,
    #[error("source directory could not be resolved")]
    SourceResolution,
    #[error("source tree exceeds the {MAX_ENTRIES} entry safety limit")]
    EntryLimit,
    #[error("current UTC observation time could not be formatted")]
    TimeFormatting,
}

#[derive(Default)]
struct ScanState {
    statistics: MutableStatistics,
    sitecore_marker_count: u64,
    sitecore_packages_observed: u64,
    version_counts: BTreeMap<String, u64>,
    roles: BTreeSet<EstateRole>,
    flags: BTreeSet<ScanFlag>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ScanFlag {
    XpSignal,
    ExistingExport,
    Serialization,
    Incomplete,
}

#[derive(Default)]
struct MutableStatistics {
    entries_seen: u64,
    files_seen: u64,
    directories_seen: u64,
    symlinks_skipped: u64,
    excluded_directories: u64,
    unreadable_entries: u64,
    safe_manifests_read: u64,
    safe_manifest_bytes_read: u64,
    sensitive_file_markers_skipped: u64,
    serialization_markers: u64,
}

/// Inspects a local source directory without following links, opening content-bearing files, or
/// writing to the source tree.
///
/// Only files named `packages.config` are opened, with a one MiB per-file bound. From those files,
/// only strictly numeric versions of `Sitecore.*` packages influence output. No paths, package
/// names, source content, credentials, or license data are emitted.
///
/// # Errors
///
/// Returns an error when the source is unavailable or exceeds the bounded traversal envelope.
pub fn inspect_source(
    config: &SourceInspectionConfig,
) -> Result<SourceInspectionResultV1, SourceInspectionError> {
    let root =
        fs::canonicalize(&config.source).map_err(|_| SourceInspectionError::SourceResolution)?;
    if !root.is_dir() {
        return Err(SourceInspectionError::SourceNotDirectory);
    }

    let estate_id = config
        .estate_id
        .clone()
        .unwrap_or_else(|| derived_estate_id(&root));
    let observed_at = match &config.observed_at {
        Some(value) => value.clone(),
        None => OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|_| SourceInspectionError::TimeFormatting)?,
    };

    let mut state = ScanState::default();
    state.statistics.directories_seen = 1;
    let mut pending = vec![root];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            state.statistics.unreadable_entries += 1;
            state.flags.insert(ScanFlag::Incomplete);
            continue;
        };
        for entry_result in entries {
            let Ok(entry) = entry_result else {
                state.statistics.unreadable_entries += 1;
                state.flags.insert(ScanFlag::Incomplete);
                continue;
            };
            state.statistics.entries_seen += 1;
            if state.statistics.entries_seen > MAX_ENTRIES {
                return Err(SourceInspectionError::EntryLimit);
            }
            let Ok(file_type) = entry.file_type() else {
                state.statistics.unreadable_entries += 1;
                state.flags.insert(ScanFlag::Incomplete);
                continue;
            };
            let name = entry.file_name();
            observe_name(&name, file_type.is_dir(), &mut state);
            if file_type.is_symlink() {
                state.statistics.symlinks_skipped += 1;
            } else if file_type.is_dir() {
                state.statistics.directories_seen += 1;
                if excluded_directory(&name) {
                    state.statistics.excluded_directories += 1;
                } else {
                    pending.push(entry.path());
                }
            } else if file_type.is_file() {
                state.statistics.files_seen += 1;
                inspect_file(&entry.path(), &name, &mut state);
            }
        }
    }

    Ok(build_result(config, estate_id, observed_at, &state))
}

fn inspect_file(path: &Path, name: &OsStr, state: &mut ScanState) {
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if sensitive_file_marker(&lower) {
        state.statistics.sensitive_file_markers_skipped += 1;
    }
    if lower != "packages.config" {
        return;
    }
    let metadata = match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_SAFE_MANIFEST_BYTES => metadata,
        _ => {
            state.flags.insert(ScanFlag::Incomplete);
            return;
        }
    };
    let Ok(bytes) = fs::read(path) else {
        state.flags.insert(ScanFlag::Incomplete);
        return;
    };
    state.statistics.safe_manifests_read += 1;
    state.statistics.safe_manifest_bytes_read += metadata.len();
    let content = String::from_utf8_lossy(&bytes);
    for package in package_entries(&content) {
        if !package.id.to_ascii_lowercase().starts_with("sitecore.") {
            continue;
        }
        state.sitecore_packages_observed += 1;
        state.sitecore_marker_count += 1;
        let package_id = package.id.to_ascii_lowercase();
        if package_id.contains("analytics")
            || package_id.contains("xconnect")
            || package_id.contains("xdb")
        {
            state.flags.insert(ScanFlag::XpSignal);
        }
        if numeric_sitecore_version(package.version) {
            *state
                .version_counts
                .entry(package.version.to_owned())
                .or_default() += 1;
        }
    }
}

fn observe_name(name: &OsStr, is_directory: bool, state: &mut ScanState) {
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if is_sitecore_marker(&lower) {
        state.sitecore_marker_count += 1;
    }
    if lower == "source-export.json"
        || (lower.starts_with("sitecore-export") && has_extension(&lower, "json"))
    {
        state.flags.insert(ScanFlag::ExistingExport);
    }
    if has_extension(&lower, "item")
        || lower == "sitecore.json"
        || (has_extension(&lower, "json")
            && Path::new(&lower)
                .file_stem()
                .is_some_and(|stem| stem.to_string_lossy().ends_with(".module")))
        || lower.contains("unicorn")
    {
        state.flags.insert(ScanFlag::Serialization);
        state.statistics.serialization_markers += 1;
    }
    if is_directory {
        if matches!(
            lower.as_str(),
            "cm" | "contentmanagement" | "content-management"
        ) {
            state.roles.insert(EstateRole::ContentManagement);
        }
        if matches!(
            lower.as_str(),
            "cd" | "contentdelivery" | "content-delivery"
        ) {
            state.roles.insert(EstateRole::ContentDelivery);
        }
        if lower == "xconnect"
            || lower.ends_with(".xconnect")
            || lower.starts_with("xconnect.")
            || lower.starts_with("xc-")
            || lower.starts_with("xc_")
        {
            state.roles.insert(EstateRole::Xconnect);
            state.flags.insert(ScanFlag::XpSignal);
        }
        if matches!(lower.as_str(), "processing" | "processingengine" | "prc") {
            state.roles.insert(EstateRole::Processing);
        }
        if matches!(lower.as_str(), "reporting" | "rep") {
            state.roles.insert(EstateRole::Reporting);
        }
        if matches!(lower.as_str(), "identity" | "identityserver") {
            state.roles.insert(EstateRole::Identity);
        }
    }
}

fn build_result(
    config: &SourceInspectionConfig,
    estate_id: String,
    observed_at: String,
    state: &ScanState,
) -> SourceInspectionResultV1 {
    let source_kind = if state.sitecore_marker_count > 0 {
        SourceKind::SitecoreSolution
    } else {
        SourceKind::UnknownDirectory
    };
    let selected_build = selected_build(&state.version_counts);
    let product_version = selected_build.as_deref().and_then(product_version);
    let roles = state.roles.iter().copied().collect::<Vec<_>>();
    let product_family = if state.flags.contains(&ScanFlag::XpSignal) {
        ProductFamily::SitecoreXp
    } else {
        ProductFamily::Unknown
    };
    let deployment_model = if roles.len() > 1 {
        DeploymentModel::Scaled
    } else {
        DeploymentModel::Unknown
    };
    let mechanisms = observed_mechanisms(&state.flags);
    let finding_codes = finding_codes(
        state,
        source_kind,
        product_family,
        deployment_model,
        &roles,
        &mechanisms,
        selected_build.is_some(),
    );
    let mechanism_kinds = mechanisms
        .iter()
        .map(|mechanism| mechanism.kind)
        .collect::<Vec<_>>();

    let observation = EstateObservationV1 {
        api_version: ESTATE_OBSERVATION_API_V1.to_owned(),
        estate_id: estate_id.clone(),
        observed_at,
        product: ProductObservationV1 {
            family: product_family,
            version: product_version,
            build: selected_build,
        },
        environment_class: EnvironmentClass::Unknown,
        deployment_model,
        roles: roles.clone(),
        databases: vec![],
        modules: vec![],
        languages: vec![],
        counts: EstateCountsV1 {
            templates: None,
            items: None,
            media_items: None,
        },
        export_mechanisms: mechanisms,
        custom_field_types: vec![],
        unknown_fact_codes: finding_codes.clone(),
        authorization: AuthorizationDeclarationV1 {
            reference: config.authorization_reference.clone(),
            approved_for_read_only_preflight: config.approved_for_read_only_preflight,
        },
        data_safety: DataSafetyDeclarationV1 {
            read_only: true,
            contains: DataPresenceDeclarationV1 {
                content: false,
                credentials: false,
                personal_data: false,
            },
        },
    };
    let report = SourceInspectionReportV1 {
        api_version: SOURCE_INSPECTION_API_V1.to_owned(),
        scanner_version: env!("CARGO_PKG_VERSION").to_owned(),
        estate_id,
        source_kind,
        statistics: inspection_statistics(&state.statistics),
        signals: InspectionSignalsV1 {
            sitecore_marker_count: state.sitecore_marker_count,
            sitecore_packages_observed: state.sitecore_packages_observed,
            product_version_candidate_count: state.version_counts.len() as u64,
            inferred_roles: roles,
            inferred_export_mechanisms: mechanism_kinds,
        },
        safety: inspection_safety(),
        finding_codes,
    };
    SourceInspectionResultV1 {
        observation,
        report,
    }
}

const fn inspection_statistics(statistics: &MutableStatistics) -> InspectionStatisticsV1 {
    InspectionStatisticsV1 {
        entries_seen: statistics.entries_seen,
        files_seen: statistics.files_seen,
        directories_seen: statistics.directories_seen,
        symlinks_skipped: statistics.symlinks_skipped,
        excluded_directories: statistics.excluded_directories,
        unreadable_entries: statistics.unreadable_entries,
        safe_manifests_read: statistics.safe_manifests_read,
        safe_manifest_bytes_read: statistics.safe_manifest_bytes_read,
        sensitive_file_markers_skipped: statistics.sensitive_file_markers_skipped,
        serialization_markers: statistics.serialization_markers,
    }
}

const fn inspection_safety() -> InspectionSafetyV1 {
    InspectionSafetyV1 {
        source_access: SourceAccess::ReadOnly,
        file_content_policy: FileContentPolicy::AllowlistedPackageManifestsOnly,
        network_access: NetworkAccess::None,
        sensitive_marked_files_opened: 0,
        source_writes_performed: 0,
    }
}

fn selected_build(version_counts: &BTreeMap<String, u64>) -> Option<String> {
    version_counts
        .iter()
        .max_by(|(left_version, left_count), (right_version, right_count)| {
            left_count
                .cmp(right_count)
                .then_with(|| left_version.cmp(right_version))
        })
        .map(|(version, _)| version.clone())
}

fn observed_mechanisms(flags: &BTreeSet<ScanFlag>) -> Vec<ExportMechanismV1> {
    let mut mechanisms = Vec::new();
    if flags.contains(&ScanFlag::ExistingExport) {
        mechanisms.push(ExportMechanismV1 {
            kind: ExportMechanismKind::ExistingOfflineExport,
            available: true,
            read_only: true,
        });
    }
    if flags.contains(&ScanFlag::Serialization) {
        mechanisms.push(ExportMechanismV1 {
            kind: ExportMechanismKind::Serialization,
            available: true,
            read_only: true,
        });
    }
    mechanisms
}

#[allow(clippy::too_many_arguments)]
fn finding_codes(
    state: &ScanState,
    source_kind: SourceKind,
    product_family: ProductFamily,
    deployment_model: DeploymentModel,
    roles: &[EstateRole],
    mechanisms: &[ExportMechanismV1],
    build_observed: bool,
) -> Vec<String> {
    let mut findings = BTreeSet::from([
        "acquisition-environment-not-selected".to_owned(),
        "content-counts-not-observed".to_owned(),
        "database-roles-not-observed".to_owned(),
        "languages-not-observed".to_owned(),
        "module-inventory-incomplete".to_owned(),
    ]);
    if source_kind == SourceKind::UnknownDirectory {
        findings.insert("sitecore-solution-not-confirmed".to_owned());
    }
    if product_family == ProductFamily::Unknown {
        findings.insert("product-family-not-observed".to_owned());
    } else {
        findings.insert("product-family-inferred-from-source-signals".to_owned());
    }
    if build_observed {
        findings.insert("product-version-inferred-from-package-manifests".to_owned());
    } else {
        findings.insert("product-version-not-observed".to_owned());
    }
    if state.version_counts.len() > 1 {
        findings.insert("sitecore-package-versions-conflict".to_owned());
    }
    if deployment_model == DeploymentModel::Unknown {
        findings.insert("deployment-model-not-observed".to_owned());
    } else {
        findings.insert("deployment-model-inferred-from-source-layout".to_owned());
    }
    if roles.is_empty() {
        findings.insert("estate-roles-not-observed".to_owned());
    } else {
        findings.insert("topology-inferred-from-source-layout".to_owned());
    }
    if mechanisms.is_empty() {
        findings.insert("read-only-export-mechanism-not-observed".to_owned());
    } else {
        findings.insert("export-mechanism-inferred-from-source-layout".to_owned());
    }
    if state.flags.contains(&ScanFlag::Incomplete) {
        findings.insert("source-scan-incomplete".to_owned());
    }
    findings.into_iter().collect()
}

fn derived_estate_id(root: &Path) -> String {
    let normalized = root.to_string_lossy().to_ascii_lowercase();
    let digest = domain_digest("proof-migrate:local-source-root:v1", normalized.as_bytes());
    let hex = digest.strip_prefix("blake3:").unwrap_or(&digest);
    format!("LOCAL-{}", &hex[..16])
}

fn excluded_directory(name: &OsStr) -> bool {
    let lower = name.to_string_lossy().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        ".git"
            | ".hg"
            | ".svn"
            | ".vs"
            | "app_data"
            | "artifacts"
            | "bin"
            | "data"
            | "indexes"
            | "logs"
            | "node_modules"
            | "obj"
            | "packages"
            | "target"
            | "temp"
            | "tmp"
            | "upload"
            | "uploads"
    ) || matches!(
        lower.as_str(),
        "certificates" | "credentials" | "keys" | "private-keys" | "secrets" | "tokens"
    )
}

fn sensitive_file_marker(lower: &str) -> bool {
    lower == "connectionstrings.config"
        || lower == "connectionstrings.json"
        || lower == "license.xml"
        || lower == "nuget.config"
        || lower == "secrets.json"
        || lower.starts_with(".env")
        || has_extension(lower, "pfx")
        || has_extension(lower, "key")
        || has_extension(lower, "pem")
        || has_extension(lower, "cer")
        || has_extension(lower, "crt")
        || has_extension(lower, "p12")
        || has_extension(lower, "publishsettings")
        || lower.contains("certificate")
        || lower.contains("connection-string")
        || lower.contains("connectionstring")
        || lower.contains("credential")
        || lower.contains("license")
        || lower.contains("password")
        || lower.contains("private_key")
        || lower.contains("privatekey")
        || lower.contains("secret")
        || lower.contains("token")
}

fn has_extension(name: &str, expected: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn is_sitecore_marker(lower: &str) -> bool {
    lower == "app_config"
        || lower == "sitecore.config"
        || lower == "sitecore.json"
        || lower == "sitecore.kernel.dll"
        || lower.starts_with("sitecore.")
        || lower.ends_with(".sitecore")
}

#[derive(Clone, Copy)]
struct PackageEntry<'a> {
    id: &'a str,
    version: &'a str,
}

fn package_entries(content: &str) -> Vec<PackageEntry<'_>> {
    let lower = content.to_ascii_lowercase();
    let mut entries = Vec::new();
    let mut offset = 0;
    while let Some(relative_start) = lower[offset..].find("<package") {
        let start = offset + relative_start;
        let Some(relative_end) = lower[start..].find('>') else {
            break;
        };
        let end = start + relative_end + 1;
        let tag = &content[start..end];
        if let (Some(id), Some(version)) =
            (attribute_value(tag, "id"), attribute_value(tag, "version"))
        {
            entries.push(PackageEntry { id, version });
        }
        offset = end;
    }
    entries
}

fn attribute_value<'a>(tag: &'a str, target: &str) -> Option<&'a str> {
    let bytes = tag.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        while index < bytes.len() && !is_attribute_character(bytes[index]) {
            index += 1;
        }
        let start = index;
        while index < bytes.len() && is_attribute_character(bytes[index]) {
            index += 1;
        }
        if start == index || !tag[start..index].eq_ignore_ascii_case(target) {
            continue;
        }
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) != Some(&b'=') {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let quote = *bytes.get(index)?;
        if quote != b'\'' && quote != b'"' {
            continue;
        }
        index += 1;
        let value_start = index;
        while index < bytes.len() && bytes[index] != quote {
            index += 1;
        }
        return (index < bytes.len()).then_some(&tag[value_start..index]);
    }
    None
}

const fn is_attribute_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':')
}

fn numeric_sitecore_version(value: &str) -> bool {
    let segments = value.split('.').collect::<Vec<_>>();
    (2..=4).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= 8
                && segment.chars().all(|character| character.is_ascii_digit())
        })
}

fn product_version(build: &str) -> Option<String> {
    let mut segments = build.split('.');
    let major = segments.next()?;
    let minor = segments.next()?;
    Some(format!("{major}.{minor}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use proof_migrate_preflight::{EstateRole, EvidenceBasis, PreflightStatus, assess_with_basis};
    use tempfile::tempdir;

    use super::{
        FileContentPolicy, NetworkAccess, SourceInspectionConfig, SourceKind, inspect_source,
    };

    #[test]
    fn solution_inspection_is_content_free_and_deterministic() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("private-source-name");
        fs::create_dir_all(source.join("roles/xconnect/App_Data")).unwrap();
        fs::create_dir_all(source.join("roles/cm")).unwrap();
        fs::create_dir_all(source.join("project")).unwrap();
        fs::write(source.join("roles/cm/Sitecore.config"), "not opened").unwrap();
        fs::write(
            source.join("roles/xconnect/App_Data/ConnectionStrings.config"),
            "SENTINEL-SHOULD-NEVER-BE-READ",
        )
        .unwrap();
        fs::write(
            source.join("project/packages.config"),
            r#"<packages><package version="10.3.123456" id="Sitecore.Logging" /></packages>"#,
        )
        .unwrap();
        let config = SourceInspectionConfig {
            source: source.clone(),
            estate_id: Some("SYNTH-SOLUTION-001".to_owned()),
            observed_at: Some("2026-08-21T12:00:00Z".to_owned()),
            authorization_reference: None,
            approved_for_read_only_preflight: false,
        };

        let first = inspect_source(&config).unwrap();
        let second = inspect_source(&config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.report.source_kind, SourceKind::SitecoreSolution);
        assert_eq!(first.observation.product.version.as_deref(), Some("10.3"));
        assert_eq!(
            first.observation.product.build.as_deref(),
            Some("10.3.123456")
        );
        assert!(first.observation.roles.contains(&EstateRole::Xconnect));
        assert_eq!(first.report.statistics.safe_manifests_read, 1);
        assert_eq!(first.report.safety.sensitive_marked_files_opened, 0);
        assert_eq!(
            first.report.safety.file_content_policy,
            FileContentPolicy::AllowlistedPackageManifestsOnly
        );
        assert_eq!(first.report.safety.network_access, NetworkAccess::None);
        let serialized = serde_json::to_string(&first.report).unwrap();
        assert!(!serialized.contains("private-source-name"));
        assert!(!serialized.contains("SENTINEL-SHOULD-NEVER-BE-READ"));

        let observation_bytes = serde_json::to_vec(&first.observation).unwrap();
        let manifest = assess_with_basis(
            first.observation,
            &observation_bytes,
            EvidenceBasis::GeneratedSourceInspection,
        )
        .unwrap();
        assert_eq!(manifest.assessment.status, PreflightStatus::Blocked);
        assert_eq!(
            manifest.assessment.evidence_basis,
            EvidenceBasis::GeneratedSourceInspection
        );
    }

    #[test]
    fn sensitive_files_are_never_opened() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("secrets")).unwrap();
        fs::write(temp.path().join("license.xml"), "SENSITIVE-LICENSE").unwrap();
        fs::write(
            temp.path().join("ConnectionStrings.config"),
            "SENSITIVE-CONNECTION",
        )
        .unwrap();
        fs::write(
            temp.path().join("secrets/packages.config"),
            r#"<packages><package id="Sitecore.Hidden" version="99.9.999999" /></packages>"#,
        )
        .unwrap();
        let result = inspect_source(&SourceInspectionConfig {
            source: temp.path().to_path_buf(),
            estate_id: Some("SYNTH-SENSITIVE-001".to_owned()),
            observed_at: Some("2026-08-21T12:00:00Z".to_owned()),
            authorization_reference: None,
            approved_for_read_only_preflight: false,
        })
        .unwrap();
        assert_eq!(result.report.statistics.sensitive_file_markers_skipped, 2);
        assert_eq!(result.report.statistics.safe_manifests_read, 0);
        assert_eq!(result.observation.product.version, None);
        assert_eq!(result.report.safety.sensitive_marked_files_opened, 0);
        let serialized = format!(
            "{}{}",
            serde_json::to_string(&result.report).unwrap(),
            serde_json::to_string(&result.observation).unwrap()
        );
        assert!(!serialized.contains("SENSITIVE-LICENSE"));
        assert!(!serialized.contains("SENSITIVE-CONNECTION"));
    }
}
