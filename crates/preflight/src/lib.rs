#![forbid(unsafe_code)]

//! Content-free validation and assessment of a declared Sitecore estate observation.

use std::collections::BTreeSet;

use proof_migrate_evidence::{canonical_json, domain_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const ESTATE_OBSERVATION_API_V1: &str = "proof-migrate.dev/estate-observation/v1";
pub const ESTATE_MANIFEST_API_V1: &str = "proof-migrate.dev/estate-manifest/v1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstateObservationV1 {
    pub api_version: String,
    pub estate_id: String,
    pub observed_at: String,
    pub product: ProductObservationV1,
    pub environment_class: EnvironmentClass,
    pub deployment_model: DeploymentModel,
    #[serde(default)]
    pub roles: Vec<EstateRole>,
    #[serde(default)]
    pub databases: Vec<DatabaseRole>,
    #[serde(default)]
    pub modules: Vec<ModuleObservationV1>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub counts: EstateCountsV1,
    #[serde(default)]
    pub export_mechanisms: Vec<ExportMechanismV1>,
    #[serde(default)]
    pub custom_field_types: Vec<String>,
    #[serde(default)]
    pub unknown_fact_codes: Vec<String>,
    pub authorization: AuthorizationDeclarationV1,
    pub data_safety: DataSafetyDeclarationV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductObservationV1 {
    pub family: ProductFamily,
    pub version: Option<String>,
    pub build: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductFamily {
    SitecoreXm,
    SitecoreXp,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentClass {
    ProductionReadOnly,
    NonProduction,
    NonProductionClone,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentModel {
    SingleInstance,
    Scaled,
    Containerized,
    ManagedCloud,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EstateRole {
    ContentManagement,
    ContentDelivery,
    Xconnect,
    Processing,
    Reporting,
    Identity,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseRole {
    Core,
    Master,
    Web,
    ExperienceForms,
    Reporting,
    Analytics,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleObservationV1 {
    pub id: String,
    pub version: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstateCountsV1 {
    pub templates: Option<u64>,
    pub items: Option<u64>,
    pub media_items: Option<u64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportMechanismV1 {
    pub kind: ExportMechanismKind,
    pub available: bool,
    pub read_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMechanismKind {
    ExistingOfflineExport,
    Serialization,
    Package,
    NativeApi,
    OfflineDatabaseBackup,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDeclarationV1 {
    pub reference: Option<String>,
    pub approved_for_read_only_preflight: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataSafetyDeclarationV1 {
    pub read_only: bool,
    pub contains: DataPresenceDeclarationV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataPresenceDeclarationV1 {
    pub content: bool,
    pub credentials: bool,
    pub personal_data: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstateManifestV1 {
    pub api_version: String,
    pub estate_id: String,
    pub observed_at: String,
    pub observation_commitment: String,
    pub semantic_snapshot_id: String,
    pub product: ProductObservationV1,
    pub environment_class: EnvironmentClass,
    pub deployment_model: DeploymentModel,
    pub roles: Vec<EstateRole>,
    pub databases: Vec<DatabaseRole>,
    pub modules: Vec<ModuleObservationV1>,
    pub languages: Vec<String>,
    pub counts: EstateCountsV1,
    pub export_mechanisms: Vec<ExportMechanismV1>,
    pub custom_field_types: Vec<String>,
    pub unknown_fact_codes: Vec<String>,
    pub authorization: AuthorizationDeclarationV1,
    pub data_safety: DataSafetyDeclarationV1,
    pub assessment: PreflightAssessmentV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightAssessmentV1 {
    pub evidence_basis: EvidenceBasis,
    pub status: PreflightStatus,
    pub ready_for_extractor_design: bool,
    pub recommended_acquisition_path: RecommendedAcquisitionPath,
    pub native_extractor_required: bool,
    pub blocker_codes: Vec<String>,
    pub unresolved_fact_codes: Vec<String>,
    pub tool_activity: ToolActivityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolActivityV1 {
    pub estate_access_performed_by_tool: bool,
    pub estate_writes_performed_by_tool: bool,
    pub proof_writes_performed_by_tool: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBasis {
    DeclaredObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Ready,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAcquisitionPath {
    ExistingOfflineExport,
    Serialization,
    Package,
    NativeApi,
    OfflineDatabaseBackup,
    Blocked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PreflightError {
    #[error("unsupported estate observation API version")]
    UnsupportedApi,
    #[error("{0} must be a non-empty safe identifier of at most 128 characters")]
    InvalidSafeIdentifier(&'static str),
    #[error("observed_at must be canonical RFC 3339 UTC using `Z`")]
    InvalidObservedAt,
    #[error("estate observation must declare read-only collection")]
    ObservationNotReadOnly,
    #[error("estate observation must not contain content")]
    ContainsContent,
    #[error("estate observation must not contain credentials")]
    ContainsCredentials,
    #[error("estate observation must not contain personal data")]
    ContainsPersonalData,
    #[error("duplicate {0} entry")]
    Duplicate(&'static str),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Validates, normalizes, and assesses a content-free estate observation.
///
/// The assessment is based only on declarations in the input. This function performs no network
/// access and cannot independently verify the estate, authorization, or safety declarations.
///
/// # Errors
///
/// Returns an error when the observation violates the versioned contract or safety boundary.
pub fn assess(
    mut observation: EstateObservationV1,
    raw_observation_bytes: &[u8],
) -> Result<EstateManifestV1, PreflightError> {
    validate_envelope(&observation)?;
    validate_and_sort(&mut observation)?;

    let semantic_json = canonical_json(&observation).map_err(PreflightError::Canonicalization)?;
    let semantic_snapshot_id = domain_digest(
        "proof-migrate:estate-observation-semantic:v1",
        semantic_json.as_bytes(),
    );
    let observation_commitment = domain_digest(
        "proof-migrate:estate-observation-source:v1",
        raw_observation_bytes,
    );
    let assessment = make_assessment(&observation);

    Ok(EstateManifestV1 {
        api_version: ESTATE_MANIFEST_API_V1.to_owned(),
        estate_id: observation.estate_id,
        observed_at: observation.observed_at,
        observation_commitment,
        semantic_snapshot_id,
        product: observation.product,
        environment_class: observation.environment_class,
        deployment_model: observation.deployment_model,
        roles: observation.roles,
        databases: observation.databases,
        modules: observation.modules,
        languages: observation.languages,
        counts: observation.counts,
        export_mechanisms: observation.export_mechanisms,
        custom_field_types: observation.custom_field_types,
        unknown_fact_codes: observation.unknown_fact_codes,
        authorization: observation.authorization,
        data_safety: observation.data_safety,
        assessment,
    })
}

fn validate_envelope(observation: &EstateObservationV1) -> Result<(), PreflightError> {
    if observation.api_version != ESTATE_OBSERVATION_API_V1 {
        return Err(PreflightError::UnsupportedApi);
    }
    validate_safe_identifier("estate_id", &observation.estate_id)?;
    if !observation.observed_at.ends_with('Z')
        || OffsetDateTime::parse(&observation.observed_at, &Rfc3339).is_err()
    {
        return Err(PreflightError::InvalidObservedAt);
    }
    if !observation.data_safety.read_only {
        return Err(PreflightError::ObservationNotReadOnly);
    }
    if observation.data_safety.contains.content {
        return Err(PreflightError::ContainsContent);
    }
    if observation.data_safety.contains.credentials {
        return Err(PreflightError::ContainsCredentials);
    }
    if observation.data_safety.contains.personal_data {
        return Err(PreflightError::ContainsPersonalData);
    }
    if let Some(value) = &observation.product.version {
        validate_safe_identifier("product.version", value)?;
    }
    if let Some(value) = &observation.product.build {
        validate_safe_identifier("product.build", value)?;
    }
    if let Some(value) = &observation.authorization.reference {
        validate_safe_identifier("authorization.reference", value)?;
    }
    Ok(())
}

fn validate_and_sort(observation: &mut EstateObservationV1) -> Result<(), PreflightError> {
    sort_unique(&mut observation.roles, "role")?;
    sort_unique(&mut observation.databases, "database role")?;

    for module in &observation.modules {
        validate_safe_identifier("modules[].id", &module.id)?;
        if let Some(version) = &module.version {
            validate_safe_identifier("modules[].version", version)?;
        }
    }
    observation.modules.sort();
    reject_adjacent_duplicate_by(&observation.modules, "module", |left, right| {
        left.id == right.id
    })?;

    for language in &observation.languages {
        validate_language(language)?;
    }
    observation.languages.sort();
    reject_adjacent_duplicates(&observation.languages, "language")?;

    observation.export_mechanisms.sort();
    reject_adjacent_duplicate_by(
        &observation.export_mechanisms,
        "export mechanism",
        |left, right| left.kind == right.kind,
    )?;

    for field_type in &observation.custom_field_types {
        validate_safe_identifier("custom_field_types[]", field_type)?;
    }
    observation.custom_field_types.sort();
    reject_adjacent_duplicates(&observation.custom_field_types, "custom field type")?;

    for code in &observation.unknown_fact_codes {
        validate_safe_identifier("unknown_fact_codes[]", code)?;
    }
    observation.unknown_fact_codes.sort();
    reject_adjacent_duplicates(&observation.unknown_fact_codes, "unknown fact code")?;
    Ok(())
}

fn make_assessment(observation: &EstateObservationV1) -> PreflightAssessmentV1 {
    let recommended = recommended_acquisition_path(&observation.export_mechanisms);
    let mut blockers = BTreeSet::new();
    if !observation.authorization.approved_for_read_only_preflight {
        blockers.insert("authorization-not-declared".to_owned());
    }
    if observation.product.family == ProductFamily::Unknown {
        blockers.insert("product-family-unknown".to_owned());
    }
    if observation.product.version.is_none() {
        blockers.insert("product-version-unknown".to_owned());
    }
    if observation.product.build.is_none() {
        blockers.insert("product-build-unknown".to_owned());
    }
    if observation.environment_class == EnvironmentClass::Unknown {
        blockers.insert("acquisition-environment-unknown".to_owned());
    }
    if observation.deployment_model == DeploymentModel::Unknown {
        blockers.insert("deployment-model-unknown".to_owned());
    }
    if observation.roles.is_empty() {
        blockers.insert("estate-roles-unknown".to_owned());
    }
    if observation.databases.is_empty() {
        blockers.insert("database-roles-unknown".to_owned());
    }
    if recommended == RecommendedAcquisitionPath::Blocked {
        blockers.insert("no-read-only-export-mechanism".to_owned());
    }
    if !observation.unknown_fact_codes.is_empty() {
        blockers.insert("unresolved-estate-facts".to_owned());
    }
    let blocker_codes = blockers.into_iter().collect::<Vec<_>>();
    let ready = blocker_codes.is_empty();

    PreflightAssessmentV1 {
        evidence_basis: EvidenceBasis::DeclaredObservation,
        status: if ready {
            PreflightStatus::Ready
        } else {
            PreflightStatus::Blocked
        },
        ready_for_extractor_design: ready,
        recommended_acquisition_path: recommended,
        native_extractor_required: recommended == RecommendedAcquisitionPath::NativeApi,
        blocker_codes,
        unresolved_fact_codes: observation.unknown_fact_codes.clone(),
        tool_activity: ToolActivityV1 {
            estate_access_performed_by_tool: false,
            estate_writes_performed_by_tool: false,
            proof_writes_performed_by_tool: false,
        },
    }
}

fn recommended_acquisition_path(mechanisms: &[ExportMechanismV1]) -> RecommendedAcquisitionPath {
    const PRIORITY: [(ExportMechanismKind, RecommendedAcquisitionPath); 5] = [
        (
            ExportMechanismKind::ExistingOfflineExport,
            RecommendedAcquisitionPath::ExistingOfflineExport,
        ),
        (
            ExportMechanismKind::Serialization,
            RecommendedAcquisitionPath::Serialization,
        ),
        (
            ExportMechanismKind::Package,
            RecommendedAcquisitionPath::Package,
        ),
        (
            ExportMechanismKind::NativeApi,
            RecommendedAcquisitionPath::NativeApi,
        ),
        (
            ExportMechanismKind::OfflineDatabaseBackup,
            RecommendedAcquisitionPath::OfflineDatabaseBackup,
        ),
    ];
    PRIORITY
        .iter()
        .find_map(|(kind, recommendation)| {
            mechanisms
                .iter()
                .any(|mechanism| {
                    mechanism.kind == *kind && mechanism.available && mechanism.read_only
                })
                .then_some(*recommendation)
        })
        .unwrap_or(RecommendedAcquisitionPath::Blocked)
}

fn validate_safe_identifier(field: &'static str, value: &str) -> Result<(), PreflightError> {
    if value.is_empty()
        || value.chars().count() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:+-".contains(character))
    {
        return Err(PreflightError::InvalidSafeIdentifier(field));
    }
    Ok(())
}

fn validate_language(value: &str) -> Result<(), PreflightError> {
    if value.is_empty()
        || value.chars().count() > 35
        || !value.split('-').all(|segment| {
            !segment.is_empty()
                && segment.len() <= 8
                && segment
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
    {
        return Err(PreflightError::InvalidSafeIdentifier("languages[]"));
    }
    Ok(())
}

fn sort_unique<T: Ord>(values: &mut [T], kind: &'static str) -> Result<(), PreflightError> {
    values.sort();
    reject_adjacent_duplicates(values, kind)
}

fn reject_adjacent_duplicates<T: PartialEq>(
    values: &[T],
    kind: &'static str,
) -> Result<(), PreflightError> {
    reject_adjacent_duplicate_by(values, kind, PartialEq::eq)
}

fn reject_adjacent_duplicate_by<T>(
    values: &[T],
    kind: &'static str,
    duplicate: impl Fn(&T, &T) -> bool,
) -> Result<(), PreflightError> {
    if values.windows(2).any(|pair| duplicate(&pair[0], &pair[1])) {
        return Err(PreflightError::Duplicate(kind));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationDeclarationV1, DataPresenceDeclarationV1, DataSafetyDeclarationV1,
        DatabaseRole, DeploymentModel, EnvironmentClass, EstateCountsV1, EstateObservationV1,
        EstateRole, ExportMechanismKind, ExportMechanismV1, PreflightError, PreflightStatus,
        ProductFamily, ProductObservationV1, RecommendedAcquisitionPath, assess,
    };

    fn observation() -> EstateObservationV1 {
        EstateObservationV1 {
            api_version: "proof-migrate.dev/estate-observation/v1".to_owned(),
            estate_id: "SYNTH-ESTATE-001".to_owned(),
            observed_at: "2026-08-21T12:00:00Z".to_owned(),
            product: ProductObservationV1 {
                family: ProductFamily::SitecoreXm,
                version: Some("10.3".to_owned()),
                build: Some("10.3.1-rev.010203".to_owned()),
            },
            environment_class: EnvironmentClass::NonProductionClone,
            deployment_model: DeploymentModel::Scaled,
            roles: vec![EstateRole::ContentManagement, EstateRole::ContentDelivery],
            databases: vec![DatabaseRole::Master, DatabaseRole::Core, DatabaseRole::Web],
            modules: vec![],
            languages: vec!["fr-CA".to_owned(), "en-US".to_owned()],
            counts: EstateCountsV1 {
                templates: Some(25),
                items: Some(1_000),
                media_items: Some(80),
            },
            export_mechanisms: vec![ExportMechanismV1 {
                kind: ExportMechanismKind::ExistingOfflineExport,
                available: true,
                read_only: true,
            }],
            custom_field_types: vec![],
            unknown_fact_codes: vec![],
            authorization: AuthorizationDeclarationV1 {
                reference: Some("SYNTH-AUTH-001".to_owned()),
                approved_for_read_only_preflight: true,
            },
            data_safety: DataSafetyDeclarationV1 {
                read_only: true,
                contains: DataPresenceDeclarationV1 {
                    content: false,
                    credentials: false,
                    personal_data: false,
                },
            },
        }
    }

    #[test]
    fn complete_declared_observation_is_ready_and_deterministic() {
        let source = observation();
        let bytes = serde_json::to_vec(&source).unwrap();
        let first = assess(source.clone(), &bytes).unwrap();
        let second = assess(source, &bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.assessment.status, PreflightStatus::Ready);
        assert_eq!(
            first.assessment.recommended_acquisition_path,
            RecommendedAcquisitionPath::ExistingOfflineExport
        );
        assert!(!first.assessment.native_extractor_required);
        assert!(
            !first
                .assessment
                .tool_activity
                .estate_access_performed_by_tool
        );
    }

    #[test]
    fn exact_source_commitment_distinguishes_byte_representations() {
        let source = observation();
        let compact = serde_json::to_vec(&source).unwrap();
        let pretty = serde_json::to_vec_pretty(&source).unwrap();
        let first = assess(source.clone(), &compact).unwrap();
        let second = assess(source, &pretty).unwrap();
        assert_eq!(first.semantic_snapshot_id, second.semantic_snapshot_id);
        assert_ne!(first.observation_commitment, second.observation_commitment);
    }

    #[test]
    fn unsafe_data_declarations_fail_closed() {
        let mut source = observation();
        source.data_safety.contains.credentials = true;
        let bytes = serde_json::to_vec(&source).unwrap();
        assert_eq!(
            assess(source, &bytes),
            Err(PreflightError::ContainsCredentials)
        );
    }

    #[test]
    fn incomplete_observation_is_blocked_with_explicit_reasons() {
        let mut source = observation();
        source.product.build = None;
        source.export_mechanisms.clear();
        source.unknown_fact_codes = vec!["module-inventory-incomplete".to_owned()];
        let bytes = serde_json::to_vec(&source).unwrap();
        let manifest = assess(source, &bytes).unwrap();
        assert_eq!(manifest.assessment.status, PreflightStatus::Blocked);
        assert_eq!(
            manifest.assessment.recommended_acquisition_path,
            RecommendedAcquisitionPath::Blocked
        );
        assert_eq!(
            manifest.assessment.blocker_codes,
            vec![
                "no-read-only-export-mechanism",
                "product-build-unknown",
                "unresolved-estate-facts",
            ]
        );
    }

    #[test]
    fn writable_export_mechanism_cannot_satisfy_the_gate() {
        let mut source = observation();
        source.export_mechanisms[0].read_only = false;
        let bytes = serde_json::to_vec(&source).unwrap();
        let manifest = assess(source, &bytes).unwrap();
        assert_eq!(manifest.assessment.status, PreflightStatus::Blocked);
        assert_eq!(
            manifest.assessment.recommended_acquisition_path,
            RecommendedAcquisitionPath::Blocked
        );
        assert!(
            manifest
                .assessment
                .blocker_codes
                .contains(&"no-read-only-export-mechanism".to_owned())
        );
    }

    #[test]
    fn native_api_path_requires_a_native_extractor() {
        let mut source = observation();
        source.export_mechanisms[0].kind = ExportMechanismKind::NativeApi;
        let bytes = serde_json::to_vec(&source).unwrap();
        let manifest = assess(source, &bytes).unwrap();
        assert_eq!(manifest.assessment.status, PreflightStatus::Ready);
        assert_eq!(
            manifest.assessment.recommended_acquisition_path,
            RecommendedAcquisitionPath::NativeApi
        );
        assert!(manifest.assessment.native_extractor_required);
    }

    #[test]
    fn duplicate_semantic_entries_fail_closed() {
        let mut source = observation();
        source.languages.push("en-US".to_owned());
        let bytes = serde_json::to_vec(&source).unwrap();
        assert_eq!(
            assess(source, &bytes),
            Err(PreflightError::Duplicate("language"))
        );
    }

    #[test]
    fn malformed_language_identifier_fails_closed() {
        let mut source = observation();
        source.languages[0] = "en--US".to_owned();
        let bytes = serde_json::to_vec(&source).unwrap();
        assert_eq!(
            assess(source, &bytes),
            Err(PreflightError::InvalidSafeIdentifier("languages[]"))
        );
    }
}
