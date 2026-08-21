#![forbid(unsafe_code)]

//! Versioned, target-neutral Sitecore source evidence.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SITECORE_EXPORT_API_V1: &str = "proof-migrate.dev/sitecore-export/v1";
pub const EVIDENCE_BUNDLE_API_V1: &str = "proof-migrate.dev/evidence-bundle/v1";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreExportV1 {
    pub api_version: String,
    pub corpus_id: String,
    pub captured_at: String,
    pub source: SitecoreSourceV1,
    #[serde(default)]
    pub templates: Vec<SitecoreTemplateV1>,
    #[serde(default)]
    pub items: Vec<SitecoreItemV1>,
    #[serde(default)]
    pub media: Vec<SitecoreMediaV1>,
    #[serde(default)]
    pub unknowns: Vec<SourceIssueV1>,
    #[serde(default)]
    pub errors: Vec<SourceIssueV1>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreSourceV1 {
    pub product: String,
    pub version: Option<String>,
    #[serde(default)]
    pub databases: Vec<String>,
    #[serde(default)]
    pub topology: Vec<String>,
    pub extraction: ExtractionProfileV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionProfileV1 {
    pub mode: String,
    pub tool_version: String,
    pub native_sitecore_api: bool,
    pub read_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreTemplateV1 {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub base_template_ids: Vec<String>,
    #[serde(default)]
    pub fields: Vec<SitecoreFieldDefinitionV1>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreFieldDefinitionV1 {
    pub id: String,
    pub name: String,
    pub field_type: String,
    pub sharing: FieldSharing,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSharing {
    Shared,
    Unversioned,
    Versioned,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreItemV1 {
    pub id: String,
    pub parent_id: Option<String>,
    pub path: String,
    pub template_id: String,
    pub language: String,
    pub version: u32,
    pub revision: String,
    #[serde(default)]
    pub fields: Vec<SitecoreFieldValueV1>,
    pub layout: Option<String>,
    pub workflow: Option<String>,
    pub security: Option<String>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

impl SitecoreItemV1 {
    #[must_use]
    pub fn evidence_key(&self) -> String {
        format!("item:{}:{}:{}", self.id, self.language, self.version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreFieldValueV1 {
    pub field_id: String,
    pub raw: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SitecoreMediaV1 {
    pub item_id: String,
    pub blob_path: String,
    pub sha256: String,
    pub byte_length: u64,
    pub mime_type: Option<String>,
}

impl SitecoreMediaV1 {
    #[must_use]
    pub fn evidence_key(&self) -> String {
        format!("media:{}:{}", self.item_id, self.blob_path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIssueV1 {
    pub code: String,
    pub subject: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundleV1 {
    pub api_version: String,
    pub corpus_id: String,
    pub snapshot_id: String,
    pub captured_at: String,
    pub source_commitment: String,
    pub source: SitecoreSourceV1,
    pub templates: Vec<SitecoreTemplateV1>,
    pub items: Vec<SitecoreItemV1>,
    pub media: Vec<SitecoreMediaV1>,
    pub source_unknowns: Vec<SourceIssueV1>,
    pub source_errors: Vec<SourceIssueV1>,
    pub normalization_findings: Vec<EvidenceFindingV1>,
    pub counts: EvidenceCountsV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFindingV1 {
    pub severity: FindingSeverity,
    pub code: String,
    pub subject: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCountsV1 {
    pub templates: u64,
    pub items: u64,
    pub media: u64,
    pub source_unknowns: u64,
    pub source_errors: u64,
}

#[must_use]
pub fn template_evidence_key(id: &str) -> String {
    format!("template:{id}")
}

/// Serializes a value as RFC 8785 canonical JSON.
///
/// # Errors
///
/// Returns an error when the value cannot be represented as JSON or canonicalized.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    serde_json_canonicalizer::to_string(&value).map_err(|error| error.to_string())
}

#[must_use]
pub fn domain_digest(context: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    format!("blake3:{}", hasher.finalize().to_hex())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{canonical_json, domain_digest};

    #[test]
    fn canonical_output_and_domain_digests_are_stable() {
        let canonical = canonical_json(&json!({"z": 1, "a": 2})).unwrap();
        assert_eq!(canonical, r#"{"a":2,"z":1}"#);
        assert_eq!(
            domain_digest("proof-migrate:test:v1", canonical.as_bytes()),
            domain_digest("proof-migrate:test:v1", canonical.as_bytes())
        );
        assert_ne!(
            domain_digest("proof-migrate:test:v1", canonical.as_bytes()),
            domain_digest("proof-migrate:other:v1", canonical.as_bytes())
        );
    }
}
