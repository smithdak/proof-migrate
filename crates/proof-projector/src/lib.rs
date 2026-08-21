#![forbid(unsafe_code)]

//! Replaceable, write-free projection of source evidence into Proof candidates.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use proof_migrate_evidence::{
    EvidenceBundleV1, FieldSharing, SitecoreFieldDefinitionV1, SitecoreItemV1, SitecoreTemplateV1,
    canonical_json, domain_digest, template_evidence_key,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use uuid::Uuid;

pub const PROOF_CANDIDATE_API_V1: &str = "proof-migrate.dev/proof-candidate/v1";
const IDENTITY_NAMESPACE_EPOCH_MILLIS: u64 = 1_787_256_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofTargetContractV1 {
    pub api_version: String,
    pub repository: String,
    pub revision: String,
    pub verified_at: String,
    pub write_mode: String,
    pub schema_create: ProofOperationContractV1,
    pub object_create: ProofOperationContractV1,
    pub locale_rendition: ProofOperationContractV1,
    pub canonical_json: String,
    pub digest_algorithm: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofOperationContractV1 {
    pub api_version: String,
    pub availability: String,
    pub digest_context: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectionRules {
    raw_string_field_types: HashSet<String>,
}

impl ProjectionRules {
    #[must_use]
    pub fn from_raw_string_types(types: impl IntoIterator<Item = String>) -> Self {
        Self {
            raw_string_field_types: types
                .into_iter()
                .map(|value| normalize_field_type(&value))
                .collect(),
        }
    }

    #[must_use]
    pub fn contains_raw_string_type(&self, field_type: &str) -> bool {
        self.raw_string_field_types
            .contains(&normalize_field_type(field_type))
    }

    #[must_use]
    pub fn applied_rule_names(&self) -> Vec<String> {
        let mut values = self
            .raw_string_field_types
            .iter()
            .map(|value| format!("preserve-raw-string:{value}"))
            .collect::<Vec<_>>();
        values.sort();
        values
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofCandidateBundleV1 {
    pub api_version: String,
    pub corpus_id: String,
    pub source_snapshot_id: String,
    pub source_locale: String,
    pub target: ProofTargetContractV1,
    pub applied_rules: Vec<String>,
    pub schemas: Vec<ProofSchemaCandidateV1>,
    pub objects: Vec<ProofObjectCandidateV1>,
    pub renditions: Vec<ProofRenditionCandidateV1>,
    pub relationships: Vec<ProofRelationshipCandidateV1>,
    pub surface_gaps: Vec<ProjectionGapV1>,
    pub classifications: Vec<EntityClassificationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSchemaCandidateV1 {
    pub source_template_id: String,
    pub schema_id: String,
    pub schema_version: u32,
    pub canonical_document: String,
    pub document_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofObjectCandidateV1 {
    pub source_key: String,
    pub source_item_id: String,
    pub object_id: String,
    pub logical_key: String,
    pub schema_id: String,
    pub schema_version: u32,
    pub canonical_content: String,
    pub object_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRenditionCandidateV1 {
    pub source_key: String,
    pub source_item_id: String,
    pub object_id: String,
    pub locale: String,
    pub source_version: u32,
    pub canonical_content: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRelationshipCandidateV1 {
    pub source_item_id: String,
    pub source_field_id: String,
    pub target_source_item_ids: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionGapV1 {
    pub code: String,
    pub source_key: String,
    pub disposition: ProjectionDisposition,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityClassificationV1 {
    pub source_key: String,
    pub disposition: ProjectionDisposition,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionDisposition {
    Mapped,
    Transformed,
    Preserved,
    IntentionallyExcluded,
    Unsupported,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Each independent gate is retained as replay evidence.
pub struct ProjectionTraceV1 {
    pub signature: String,
    pub occurrence: String,
    pub task_class: String,
    pub rule_value: String,
    pub deterministic: bool,
    pub read_only: bool,
    pub non_lossy: bool,
    pub stable_io: bool,
    pub requires_judgment: bool,
    pub multi_tool: bool,
    pub measurable_outcome: bool,
    pub authority_sensitive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionOutcome {
    pub bundle: ProofCandidateBundleV1,
    pub traces: Vec<ProjectionTraceV1>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProjectionError {
    #[error("target contract must use offline-candidate-only write mode")]
    WritableTarget,
    #[error("source locale must be non-empty")]
    InvalidSourceLocale,
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Produces an offline Proof candidate and typed opportunity traces.
///
/// # Errors
///
/// Returns an error when the target is writable, the source locale is invalid, or an artifact
/// cannot be canonicalized.
#[allow(clippy::too_many_lines)] // Keeps one auditable, ordered projection transaction.
pub fn project(
    evidence: &EvidenceBundleV1,
    target: &ProofTargetContractV1,
    source_locale: &str,
    rules: &ProjectionRules,
) -> Result<ProjectionOutcome, ProjectionError> {
    if target.write_mode != "offline-candidate-only" {
        return Err(ProjectionError::WritableTarget);
    }
    if source_locale.trim().is_empty() {
        return Err(ProjectionError::InvalidSourceLocale);
    }
    let template_map = evidence
        .templates
        .iter()
        .map(|template| (template.id.as_str(), template))
        .collect::<BTreeMap<_, _>>();
    let mut traces = Vec::new();
    let mut surface_gaps = Vec::new();
    let mut classifications = Vec::new();
    let mut schemas = Vec::new();
    let mut schema_ids = BTreeMap::new();

    for template in &evidence.templates {
        let fields = flattened_fields(template, &template_map);
        let schema_id = proof_schema_id(template);
        let document = schema_document(template, &schema_id, &fields, rules, &mut traces);
        let canonical_document =
            canonical_json(&document).map_err(ProjectionError::Canonicalization)?;
        let document_digest = proof_digest(
            &target.schema_create.digest_context,
            canonical_document.as_bytes(),
        );
        let has_unhandled = fields
            .values()
            .any(|field| !field_type_is_handled(&field.field_type, rules));
        for field in fields
            .values()
            .filter(|field| !field_type_is_builtin(&field.field_type))
        {
            surface_gaps.push(ProjectionGapV1 {
                code: "field-type-semantics-unmodeled".to_owned(),
                source_key: format!("template:{}:field:{}", template.id, field.id),
                disposition: ProjectionDisposition::Preserved,
                reason: format!(
                    "Sitecore field type `{}` remains an exact raw string; its behavior is not reproduced",
                    field.field_type
                ),
            });
        }
        classifications.push(EntityClassificationV1 {
            source_key: template_evidence_key(&template.id),
            disposition: if has_unhandled {
                ProjectionDisposition::Transformed
            } else {
                ProjectionDisposition::Mapped
            },
            reason: if has_unhandled {
                "unknown field types are preserved as raw strings pending a qualified rule"
                    .to_owned()
            } else {
                "template projected to an immutable Proof JSON Schema candidate".to_owned()
            },
        });
        schema_ids.insert(template.id.as_str(), schema_id.clone());
        schemas.push(ProofSchemaCandidateV1 {
            source_template_id: template.id.clone(),
            schema_id,
            schema_version: 1,
            canonical_document,
            document_digest,
        });
    }

    let grouped_items = latest_items_by_identity_and_locale(&evidence.items, &mut classifications);
    let mut objects = Vec::new();
    let mut renditions = Vec::new();
    let mut relationships = Vec::new();

    for (item_id, by_locale) in grouped_items {
        let Some(source_item) = by_locale.get(source_locale) else {
            for item in by_locale.values() {
                classifications.push(EntityClassificationV1 {
                    source_key: item.evidence_key(),
                    disposition: ProjectionDisposition::Unsupported,
                    reason: format!("required source locale {source_locale} was not captured"),
                });
            }
            continue;
        };
        let Some(schema_id) = schema_ids.get(source_item.template_id.as_str()) else {
            for item in by_locale.values() {
                classifications.push(EntityClassificationV1 {
                    source_key: item.evidence_key(),
                    disposition: ProjectionDisposition::Unsupported,
                    reason: "governing Sitecore template was not captured".to_owned(),
                });
            }
            continue;
        };
        let Some(template) = template_map.get(source_item.template_id.as_str()) else {
            continue;
        };
        let fields = flattened_fields(template, &template_map);
        let object_id = deterministic_uuid_v7(&format!("{}:{item_id}", evidence.corpus_id));
        let content = item_content(source_item, &fields);
        let canonical_content =
            canonical_json(&content).map_err(ProjectionError::Canonicalization)?;
        let object_digest = object_revision_digest(target, &object_id, schema_id, &content)?;
        objects.push(ProofObjectCandidateV1 {
            source_key: source_item.evidence_key(),
            source_item_id: source_item.id.clone(),
            object_id: object_id.clone(),
            logical_key: format!("sitecore:{}", source_item.id),
            schema_id: schema_id.clone(),
            schema_version: 1,
            canonical_content,
            object_digest,
        });
        classifications.push(EntityClassificationV1 {
            source_key: source_item.evidence_key(),
            disposition: ProjectionDisposition::Mapped,
            reason: "latest source-locale version projected as a Proof Object candidate".to_owned(),
        });
        surface_gaps.extend(item_surface_gaps(source_item));
        let item_relationships = relationship_candidates(source_item, &fields);
        surface_gaps.extend(item_relationships.iter().map(|relationship| ProjectionGapV1 {
            code: "relationship-contract-unavailable".to_owned(),
            source_key: format!(
                "item:{}:field:{}",
                relationship.source_item_id, relationship.source_field_id
            ),
            disposition: ProjectionDisposition::Preserved,
            reason: "relationship targets are parsed into an offline candidate but not written to Proof"
                .to_owned(),
        }));
        relationships.extend(item_relationships);

        for (locale, item) in by_locale {
            if locale == source_locale {
                continue;
            }
            if !proof_locale_is_valid(&locale) {
                classifications.push(EntityClassificationV1 {
                    source_key: item.evidence_key(),
                    disposition: ProjectionDisposition::Unsupported,
                    reason: format!("locale `{locale}` is outside the pinned Proof profile"),
                });
                surface_gaps.push(ProjectionGapV1 {
                    code: "proof-locale-profile-mismatch".to_owned(),
                    source_key: item.evidence_key(),
                    disposition: ProjectionDisposition::Unsupported,
                    reason: "raw locale content remains in evidence and requires explicit mapping"
                        .to_owned(),
                });
                continue;
            }
            let content = item_content(item, &fields);
            renditions.push(ProofRenditionCandidateV1 {
                source_key: item.evidence_key(),
                source_item_id: item.id.clone(),
                object_id: object_id.clone(),
                locale: locale.clone(),
                source_version: item.version,
                canonical_content: canonical_json(&content)
                    .map_err(ProjectionError::Canonicalization)?,
                status: "requires-governed-proof-changeset".to_owned(),
            });
            classifications.push(EntityClassificationV1 {
                source_key: item.evidence_key(),
                disposition: ProjectionDisposition::Mapped,
                reason: "latest non-source locale preserved as an offline rendition candidate"
                    .to_owned(),
            });
            surface_gaps.extend(item_surface_gaps(item));
        }
    }

    for media in &evidence.media {
        classifications.push(EntityClassificationV1 {
            source_key: media.evidence_key(),
            disposition: ProjectionDisposition::Preserved,
            reason: "media metadata and commitment are preserved; Proof media ingestion is not authorized"
                .to_owned(),
        });
    }

    schemas.sort_by(|left, right| left.schema_id.cmp(&right.schema_id));
    objects.sort_by(|left, right| left.object_id.cmp(&right.object_id));
    renditions.sort_by(|left, right| {
        (&left.object_id, &left.locale).cmp(&(&right.object_id, &right.locale))
    });
    relationships.sort_by(|left, right| {
        (&left.source_item_id, &left.source_field_id)
            .cmp(&(&right.source_item_id, &right.source_field_id))
    });
    classifications.sort_by(|left, right| left.source_key.cmp(&right.source_key));
    surface_gaps.sort_by(|left, right| {
        (&left.source_key, &left.code, &left.reason).cmp(&(
            &right.source_key,
            &right.code,
            &right.reason,
        ))
    });
    traces.sort_by(|left, right| {
        (&left.signature, &left.occurrence).cmp(&(&right.signature, &right.occurrence))
    });

    Ok(ProjectionOutcome {
        bundle: ProofCandidateBundleV1 {
            api_version: PROOF_CANDIDATE_API_V1.to_owned(),
            corpus_id: evidence.corpus_id.clone(),
            source_snapshot_id: evidence.snapshot_id.clone(),
            source_locale: source_locale.to_owned(),
            target: target.clone(),
            applied_rules: rules.applied_rule_names(),
            schemas,
            objects,
            renditions,
            relationships,
            surface_gaps,
            classifications,
        },
        traces,
    })
}

/// Commits only the candidate payload whose semantics an automatic rule is forbidden to change.
///
/// # Errors
///
/// Returns an error when the selected candidate payload cannot be canonicalized.
pub fn projection_payload_commitment(bundle: &ProofCandidateBundleV1) -> Result<String, String> {
    let payload = json!({
        "objects": bundle.objects,
        "relationships": bundle.relationships,
        "renditions": bundle.renditions,
        "schemas": bundle.schemas,
        "source_snapshot_id": bundle.source_snapshot_id,
        "target_revision": bundle.target.revision,
    });
    canonical_json(&payload)
        .map(|canonical| domain_digest("proof-migrate:projection-payload:v1", canonical.as_bytes()))
}

fn latest_items_by_identity_and_locale<'a>(
    items: &'a [SitecoreItemV1],
    classifications: &mut Vec<EntityClassificationV1>,
) -> BTreeMap<String, BTreeMap<String, &'a SitecoreItemV1>> {
    let mut grouped = BTreeMap::<String, BTreeMap<String, &SitecoreItemV1>>::new();
    for item in items {
        let locale_items = grouped.entry(item.id.clone()).or_default();
        if let Some(previous) = locale_items.get(&item.language) {
            if previous.version < item.version {
                classifications.push(EntityClassificationV1 {
                    source_key: previous.evidence_key(),
                    disposition: ProjectionDisposition::Preserved,
                    reason: "historical version retained in source evidence".to_owned(),
                });
                locale_items.insert(item.language.clone(), item);
            } else {
                classifications.push(EntityClassificationV1 {
                    source_key: item.evidence_key(),
                    disposition: ProjectionDisposition::Preserved,
                    reason: "historical version retained in source evidence".to_owned(),
                });
            }
        } else {
            locale_items.insert(item.language.clone(), item);
        }
    }
    grouped
}

fn flattened_fields<'a>(
    template: &'a SitecoreTemplateV1,
    templates: &BTreeMap<&'a str, &'a SitecoreTemplateV1>,
) -> BTreeMap<String, &'a SitecoreFieldDefinitionV1> {
    fn visit<'a>(
        template: &'a SitecoreTemplateV1,
        templates: &BTreeMap<&'a str, &'a SitecoreTemplateV1>,
        visited: &mut BTreeSet<&'a str>,
        output: &mut BTreeMap<String, &'a SitecoreFieldDefinitionV1>,
    ) {
        if !visited.insert(&template.id) {
            return;
        }
        for base_id in &template.base_template_ids {
            if let Some(base) = templates.get(base_id.as_str()) {
                visit(base, templates, visited, output);
            }
        }
        for field in &template.fields {
            output.insert(field.id.clone(), field);
        }
    }

    let mut output = BTreeMap::new();
    visit(template, templates, &mut BTreeSet::new(), &mut output);
    output
}

fn schema_document(
    template: &SitecoreTemplateV1,
    schema_id: &str,
    fields: &BTreeMap<String, &SitecoreFieldDefinitionV1>,
    rules: &ProjectionRules,
    traces: &mut Vec<ProjectionTraceV1>,
) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "_sitecore".to_owned(),
        json!({
            "additionalProperties": false,
            "properties": {
                "item_id": {"type": "string"},
                "language": {"type": "string"},
                "path": {"type": "string"},
                "raw_fields": {"additionalProperties": {"type": ["string", "null"]}, "type": "object"},
                "revision": {"type": "string"},
                "version": {"minimum": 1, "type": "integer"}
            },
            "required": ["item_id", "language", "path", "raw_fields", "revision", "version"],
            "type": "object"
        }),
    );
    for field in fields.values() {
        let property_name = field_property_name(&field.id);
        properties.insert(
            property_name,
            json!({
                "title": field.name,
                "type": ["string", "null"],
                "x-proof-localizable": field.sharing == FieldSharing::Versioned,
                "x-proof-sitecore-field-id": field.id,
                "x-proof-sitecore-field-type": field.field_type
            }),
        );
        if !field_type_is_handled(&field.field_type, rules) {
            traces.push(ProjectionTraceV1 {
                signature: format!(
                    "unsupported-field-type:{}",
                    normalize_field_type(&field.field_type)
                ),
                occurrence: format!("template:{}:field:{}", template.id, field.id),
                task_class: "field-type-mapping".to_owned(),
                rule_value: normalize_field_type(&field.field_type),
                deterministic: true,
                read_only: true,
                non_lossy: true,
                stable_io: true,
                requires_judgment: false,
                multi_tool: false,
                measurable_outcome: true,
                authority_sensitive: false,
            });
        }
    }
    json!({
        "$id": format!("proof.dev/schema/{schema_id}/v1"),
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": properties,
        "required": ["_sitecore"],
        "title": template.name,
        "type": "object",
        "x-proof-sitecore-template-id": template.id,
        "x-proof-sitecore-template-path": template.path
    })
}

fn item_content(
    item: &SitecoreItemV1,
    fields: &BTreeMap<String, &SitecoreFieldDefinitionV1>,
) -> Value {
    let raw_fields = item
        .fields
        .iter()
        .map(|field| {
            (
                field.field_id.clone(),
                field.raw.clone().map_or(Value::Null, Value::String),
            )
        })
        .collect::<Map<_, _>>();
    let mut content = Map::new();
    content.insert(
        "_sitecore".to_owned(),
        json!({
            "item_id": item.id,
            "language": item.language,
            "path": item.path,
            "raw_fields": raw_fields,
            "revision": item.revision,
            "version": item.version
        }),
    );
    for field in &item.fields {
        if fields.contains_key(&field.field_id) {
            content.insert(
                field_property_name(&field.field_id),
                field.raw.clone().map_or(Value::Null, Value::String),
            );
        }
    }
    Value::Object(content)
}

fn relationship_candidates(
    item: &SitecoreItemV1,
    fields: &BTreeMap<String, &SitecoreFieldDefinitionV1>,
) -> Vec<ProofRelationshipCandidateV1> {
    item.fields
        .iter()
        .filter_map(|value| {
            let definition = fields.get(&value.field_id)?;
            if !is_relationship_field(&definition.field_type) {
                return None;
            }
            let targets = value.raw.as_deref().map(extract_uuids).unwrap_or_default();
            Some(ProofRelationshipCandidateV1 {
                source_item_id: item.id.clone(),
                source_field_id: value.field_id.clone(),
                target_source_item_ids: targets,
                status: "preserved-pending-proof-relationship-contract".to_owned(),
            })
        })
        .collect()
}

fn item_surface_gaps(item: &SitecoreItemV1) -> Vec<ProjectionGapV1> {
    let mut gaps = Vec::new();
    for (code, present, reason) in [
        (
            "presentation-layout-source-only",
            item.layout.is_some(),
            "raw Sitecore layout is preserved in evidence but not reproduced by Proof",
        ),
        (
            "workflow-source-only",
            item.workflow.is_some(),
            "workflow assignment is preserved in evidence but its semantics are not reproduced",
        ),
        (
            "security-source-only",
            item.security.is_some(),
            "security values are preserved in evidence but authorization meaning is not reproduced",
        ),
    ] {
        if present {
            gaps.push(ProjectionGapV1 {
                code: code.to_owned(),
                source_key: item.evidence_key(),
                disposition: ProjectionDisposition::Preserved,
                reason: reason.to_owned(),
            });
        }
    }
    gaps
}

fn object_revision_digest(
    target: &ProofTargetContractV1,
    object_id: &str,
    schema_id: &str,
    content: &Value,
) -> Result<String, ProjectionError> {
    let artifact = json!({
        "api_version": target.object_create.api_version,
        "content": content,
        "lifecycle_state": "active",
        "object_id": object_id,
        "relationships": [],
        "revision": 1,
        "schema_id": schema_id,
        "schema_version": 1
    });
    canonical_json(&artifact)
        .map(|canonical| proof_digest(&target.object_create.digest_context, canonical.as_bytes()))
        .map_err(ProjectionError::Canonicalization)
}

fn proof_digest(context: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn deterministic_uuid_v7(source_identity: &str) -> String {
    let timestamp = IDENTITY_NAMESPACE_EPOCH_MILLIS.to_be_bytes();
    let hash = blake3::derive_key(
        "proof-migrate:proof-object-id:v1",
        source_identity.as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&timestamp[2..]);
    bytes[6] = 0x70 | (hash[0] & 0x0f);
    bytes[7] = hash[1];
    bytes[8] = 0x80 | (hash[2] & 0x3f);
    bytes[9..].copy_from_slice(&hash[3..10]);
    Uuid::from_bytes(bytes).hyphenated().to_string()
}

fn proof_schema_id(template: &SitecoreTemplateV1) -> String {
    let mut slug = template
        .name
        .chars()
        .flat_map(char::to_lowercase)
        .map(|character| {
            if character.is_ascii_lowercase() || character.is_ascii_digit() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug = slug.trim_matches('-').to_owned();
    if slug.is_empty() || !slug.starts_with(char::is_alphabetic) {
        slug = format!("template-{slug}");
    }
    slug.truncate(110);
    slug = slug.trim_end_matches('-').to_owned();
    format!("sitecore.{slug}.{}", &template.id[..8])
}

fn field_property_name(field_id: &str) -> String {
    format!("f_{}", field_id.replace('-', ""))
}

fn normalize_field_type(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn field_type_is_handled(field_type: &str, rules: &ProjectionRules) -> bool {
    field_type_is_builtin(field_type) || rules.contains_raw_string_type(field_type)
}

fn field_type_is_builtin(field_type: &str) -> bool {
    const KNOWN: &[&str] = &[
        "checkbox",
        "date",
        "datetime",
        "droplink",
        "droptree",
        "general link",
        "image",
        "integer",
        "multiline text",
        "multilist",
        "number",
        "rich text",
        "single-line text",
        "single line text",
        "treelist",
        "treelistex",
    ];
    let normalized = normalize_field_type(field_type);
    KNOWN.contains(&normalized.as_str())
}

fn is_relationship_field(field_type: &str) -> bool {
    matches!(
        normalize_field_type(field_type).as_str(),
        "droplink" | "droptree" | "general link" | "multilist" | "treelist" | "treelistex"
    )
}

fn proof_locale_is_valid(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let subtags = value.split('-').collect::<Vec<_>>();
    let Some(language) = subtags.first() else {
        return false;
    };
    if !(2..=8).contains(&language.len()) || !language.bytes().all(|byte| byte.is_ascii_lowercase())
    {
        return false;
    }
    let mut index = 1;
    if subtags.get(index).is_some_and(|script| {
        script.len() == 4
            && script
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase())
            && script.bytes().skip(1).all(|byte| byte.is_ascii_lowercase())
    }) {
        index += 1;
    }
    if subtags.get(index).is_some_and(|region| {
        (region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase()))
            || (region.len() == 3 && region.bytes().all(|byte| byte.is_ascii_digit()))
    }) {
        index += 1;
    }
    !subtags[index..].iter().any(|variant| {
        !((variant.len() >= 5
            && variant.len() <= 8
            && variant
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
            || (variant.len() == 4
                && variant
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_digit())
                && variant
                    .bytes()
                    .skip(1)
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())))
    })
}

fn extract_uuids(value: &str) -> Vec<String> {
    let mut output = value
        .split(|character: char| !(character.is_ascii_hexdigit() || character == '-'))
        .filter(|candidate| candidate.len() >= 32)
        .filter_map(|candidate| Uuid::parse_str(candidate).ok())
        .map(|id| id.hyphenated().to_string())
        .collect::<Vec<_>>();
    output.sort();
    output.dedup();
    output
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{deterministic_uuid_v7, extract_uuids, proof_locale_is_valid};

    #[test]
    fn source_identity_maps_to_a_stable_uuid_v7() {
        let first = deterministic_uuid_v7("SYNTH-001:source-item");
        let second = deterministic_uuid_v7("SYNTH-001:source-item");
        assert_eq!(first, second);
        assert_eq!(Uuid::parse_str(&first).unwrap().get_version_num(), 7);
    }

    #[test]
    fn relationship_values_yield_sorted_unique_source_ids() {
        let ids = extract_uuids(
            "{019c0000-0000-7000-8000-000000000002}|019c0000-0000-7000-8000-000000000001|019c0000-0000-7000-8000-000000000002",
        );
        assert_eq!(ids.len(), 2);
        assert!(ids[0] < ids[1]);
    }

    #[test]
    fn proof_locale_profile_is_pinned_exactly() {
        assert!(proof_locale_is_valid("en-US"));
        assert!(proof_locale_is_valid("zh-Hant-TW"));
        assert!(!proof_locale_is_valid("en-us"));
        assert!(!proof_locale_is_valid("EN-US"));
    }
}
