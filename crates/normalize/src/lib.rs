#![forbid(unsafe_code)]

//! Deterministic normalization and structural validation of Sitecore evidence.

use std::collections::{BTreeMap, BTreeSet};

use proof_migrate_evidence::{
    EVIDENCE_BUNDLE_API_V1, EvidenceBundleV1, EvidenceCountsV1, EvidenceFindingV1, FindingSeverity,
    SITECORE_EXPORT_API_V1, SitecoreExportV1, SitecoreTemplateV1, canonical_json, domain_digest,
};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NormalizeError {
    #[error("unsupported source API version `{0}`")]
    UnsupportedApi(String),
    #[error("corpus_id must be non-empty and contain at most 128 characters")]
    InvalidCorpusId,
    #[error("captured_at must be canonical RFC 3339 UTC using `Z`")]
    InvalidCapturedAt,
    #[error("source extraction must be declared read-only")]
    SourceNotReadOnly,
    #[error("{kind} identifier `{value}` is not a canonical lowercase UUID")]
    InvalidIdentifier { kind: &'static str, value: String },
    #[error("duplicate {kind} key `{key}`")]
    Duplicate { kind: &'static str, key: String },
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Validates and deterministically normalizes one source export.
///
/// # Errors
///
/// Returns an error when the envelope, identifiers, uniqueness, timestamp, or read-only
/// acquisition declaration violates the source contract.
pub fn normalize(
    mut source: SitecoreExportV1,
    raw_source_bytes: &[u8],
) -> Result<EvidenceBundleV1, NormalizeError> {
    validate_envelope(&source)?;
    validate_and_sort(&mut source)?;

    let source_canonical = canonical_json(&source).map_err(NormalizeError::Canonicalization)?;
    let source_commitment =
        domain_digest("proof-migrate:sitecore-source-export:v1", raw_source_bytes);
    let snapshot_id = domain_digest(
        "proof-migrate:sitecore-snapshot:v1",
        source_canonical.as_bytes(),
    );
    let findings = structural_findings(&source);

    Ok(EvidenceBundleV1 {
        api_version: EVIDENCE_BUNDLE_API_V1.to_owned(),
        corpus_id: source.corpus_id,
        snapshot_id,
        captured_at: source.captured_at,
        source_commitment,
        source: source.source,
        counts: EvidenceCountsV1 {
            templates: source.templates.len() as u64,
            items: source.items.len() as u64,
            media: source.media.len() as u64,
            source_unknowns: source.unknowns.len() as u64,
            source_errors: source.errors.len() as u64,
        },
        templates: source.templates,
        items: source.items,
        media: source.media,
        source_unknowns: source.unknowns,
        source_errors: source.errors,
        normalization_findings: findings,
    })
}

fn validate_envelope(source: &SitecoreExportV1) -> Result<(), NormalizeError> {
    if source.api_version != SITECORE_EXPORT_API_V1 {
        return Err(NormalizeError::UnsupportedApi(source.api_version.clone()));
    }
    if source.corpus_id.trim().is_empty() || source.corpus_id.chars().count() > 128 {
        return Err(NormalizeError::InvalidCorpusId);
    }
    if !source.captured_at.ends_with('Z')
        || OffsetDateTime::parse(&source.captured_at, &Rfc3339).is_err()
    {
        return Err(NormalizeError::InvalidCapturedAt);
    }
    if !source.source.extraction.read_only {
        return Err(NormalizeError::SourceNotReadOnly);
    }
    Ok(())
}

fn validate_and_sort(source: &mut SitecoreExportV1) -> Result<(), NormalizeError> {
    let mut template_ids = BTreeSet::new();
    for template in &mut source.templates {
        validate_uuid("template", &template.id)?;
        if !template_ids.insert(template.id.clone()) {
            return Err(NormalizeError::Duplicate {
                kind: "template",
                key: template.id.clone(),
            });
        }
        template.base_template_ids.sort();
        let mut field_ids = BTreeSet::new();
        for field in &template.fields {
            validate_uuid("field", &field.id)?;
            if !field_ids.insert(field.id.clone()) {
                return Err(NormalizeError::Duplicate {
                    kind: "template field",
                    key: format!("{}:{}", template.id, field.id),
                });
            }
        }
        template
            .fields
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
    source
        .templates
        .sort_by(|left, right| left.id.cmp(&right.id));

    let mut item_keys = BTreeSet::new();
    for item in &mut source.items {
        validate_uuid("item", &item.id)?;
        validate_uuid("template", &item.template_id)?;
        validate_uuid("revision", &item.revision)?;
        if let Some(parent_id) = &item.parent_id {
            validate_uuid("parent item", parent_id)?;
        }
        if item.version == 0 {
            return Err(NormalizeError::Duplicate {
                kind: "invalid zero-version item",
                key: item.evidence_key(),
            });
        }
        if !item_keys.insert(item.evidence_key()) {
            return Err(NormalizeError::Duplicate {
                kind: "item",
                key: item.evidence_key(),
            });
        }
        let mut field_ids = BTreeSet::new();
        for field in &item.fields {
            validate_uuid("field", &field.field_id)?;
            if !field_ids.insert(field.field_id.clone()) {
                return Err(NormalizeError::Duplicate {
                    kind: "item field",
                    key: format!("{}:{}", item.evidence_key(), field.field_id),
                });
            }
        }
        item.fields
            .sort_by(|left, right| left.field_id.cmp(&right.field_id));
    }
    source.items.sort_by(|left, right| {
        (&left.id, &left.language, left.version).cmp(&(&right.id, &right.language, right.version))
    });

    let mut media_keys = BTreeSet::new();
    for media in &source.media {
        validate_uuid("media item", &media.item_id)?;
        if !media_keys.insert(media.evidence_key()) {
            return Err(NormalizeError::Duplicate {
                kind: "media",
                key: media.evidence_key(),
            });
        }
    }
    source
        .media
        .sort_by_key(proof_migrate_evidence::SitecoreMediaV1::evidence_key);
    source.unknowns.sort_by(issue_order);
    source.errors.sort_by(issue_order);
    source.source.databases.sort();
    source.source.topology.sort();
    Ok(())
}

fn issue_order(
    left: &proof_migrate_evidence::SourceIssueV1,
    right: &proof_migrate_evidence::SourceIssueV1,
) -> std::cmp::Ordering {
    (&left.code, &left.subject, &left.message).cmp(&(&right.code, &right.subject, &right.message))
}

fn validate_uuid(kind: &'static str, value: &str) -> Result<(), NormalizeError> {
    let parsed = Uuid::parse_str(value).map_err(|_| NormalizeError::InvalidIdentifier {
        kind,
        value: value.to_owned(),
    })?;
    if parsed.hyphenated().to_string() != value {
        return Err(NormalizeError::InvalidIdentifier {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn structural_findings(source: &SitecoreExportV1) -> Vec<EvidenceFindingV1> {
    let templates = source
        .templates
        .iter()
        .map(|template| (template.id.as_str(), template))
        .collect::<BTreeMap<_, _>>();
    let item_ids = source
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();

    for template in &source.templates {
        detect_template_issues(template, &templates, &mut findings);
    }

    for item in &source.items {
        let subject = item.evidence_key();
        if templates.contains_key(item.template_id.as_str()) {
            let mut field_ids = BTreeSet::new();
            collect_template_field_ids(
                &item.template_id,
                &templates,
                &mut BTreeSet::new(),
                &mut field_ids,
            );
            for value in &item.fields {
                if !field_ids.contains(value.field_id.as_str()) {
                    findings.push(finding(
                        FindingSeverity::Warning,
                        "field-definition-not-captured",
                        &subject,
                        format!("field {} remains preserved raw", value.field_id),
                    ));
                }
            }
        } else {
            findings.push(finding(
                FindingSeverity::Error,
                "missing-template",
                &subject,
                format!("template {} was not captured", item.template_id),
            ));
        }
        if let Some(parent_id) = &item.parent_id
            && !item_ids.contains(parent_id.as_str())
        {
            findings.push(finding(
                FindingSeverity::Warning,
                "parent-outside-capture",
                &subject,
                format!("parent {parent_id} was outside the capture envelope"),
            ));
        }
    }

    for media in &source.media {
        if !item_ids.contains(media.item_id.as_str()) {
            findings.push(finding(
                FindingSeverity::Warning,
                "media-item-not-captured",
                &media.evidence_key(),
                "media metadata remains preserved without its Sitecore item".to_owned(),
            ));
        }
    }

    findings.sort_by(|left, right| {
        (&left.severity, &left.code, &left.subject, &left.message).cmp(&(
            &right.severity,
            &right.code,
            &right.subject,
            &right.message,
        ))
    });
    findings
}

fn detect_template_issues(
    template: &SitecoreTemplateV1,
    templates: &BTreeMap<&str, &SitecoreTemplateV1>,
    findings: &mut Vec<EvidenceFindingV1>,
) {
    for base_id in &template.base_template_ids {
        if !templates.contains_key(base_id.as_str()) {
            findings.push(finding(
                FindingSeverity::Warning,
                "base-template-not-captured",
                &format!("template:{}", template.id),
                format!("base template {base_id} was outside the capture envelope"),
            ));
        }
    }
    if template_cycle(&template.id, templates, &mut BTreeSet::new()) {
        findings.push(finding(
            FindingSeverity::Error,
            "template-inheritance-cycle",
            &format!("template:{}", template.id),
            "template inheritance must be acyclic".to_owned(),
        ));
    }
}

fn template_cycle<'a>(
    id: &'a str,
    templates: &BTreeMap<&'a str, &'a SitecoreTemplateV1>,
    visiting: &mut BTreeSet<&'a str>,
) -> bool {
    if !visiting.insert(id) {
        return true;
    }
    let found = templates.get(id).is_some_and(|template| {
        template
            .base_template_ids
            .iter()
            .any(|base| template_cycle(base, templates, visiting))
    });
    visiting.remove(id);
    found
}

fn collect_template_field_ids<'a>(
    id: &'a str,
    templates: &BTreeMap<&'a str, &'a SitecoreTemplateV1>,
    visited: &mut BTreeSet<&'a str>,
    output: &mut BTreeSet<&'a str>,
) {
    if !visited.insert(id) {
        return;
    }
    if let Some(template) = templates.get(id) {
        for field in &template.fields {
            output.insert(&field.id);
        }
        for base in &template.base_template_ids {
            collect_template_field_ids(base, templates, visited, output);
        }
    }
}

fn finding(
    severity: FindingSeverity,
    code: &str,
    subject: &str,
    message: String,
) -> EvidenceFindingV1 {
    EvidenceFindingV1 {
        severity,
        code: code.to_owned(),
        subject: subject.to_owned(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proof_migrate_evidence::{ExtractionProfileV1, SitecoreExportV1, SitecoreSourceV1};

    use super::{NormalizeError, normalize};

    fn empty_export() -> SitecoreExportV1 {
        SitecoreExportV1 {
            api_version: "proof-migrate.dev/sitecore-export/v1".to_owned(),
            corpus_id: "SYNTH-EMPTY".to_owned(),
            captured_at: "2026-08-20T20:00:00Z".to_owned(),
            source: SitecoreSourceV1 {
                product: "Sitecore XM".to_owned(),
                version: None,
                databases: vec!["master".to_owned()],
                topology: vec!["synthetic".to_owned()],
                extraction: ExtractionProfileV1 {
                    mode: "offline_fixture".to_owned(),
                    tool_version: "0.1.0".to_owned(),
                    native_sitecore_api: false,
                    read_only: true,
                },
            },
            templates: vec![],
            items: vec![],
            media: vec![],
            unknowns: vec![],
            errors: vec![],
            extensions: BTreeMap::default(),
        }
    }

    #[test]
    fn identical_exports_produce_identical_snapshot_ids() {
        let source = empty_export();
        let bytes = serde_json::to_vec(&source).unwrap();
        let first = normalize(source.clone(), &bytes).unwrap();
        let second = normalize(source, &bytes).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn exact_source_commitment_distinguishes_byte_representations() {
        let source = empty_export();
        let compact = serde_json::to_vec(&source).unwrap();
        let pretty = serde_json::to_vec_pretty(&source).unwrap();
        let first = normalize(source.clone(), &compact).unwrap();
        let second = normalize(source, &pretty).unwrap();
        assert_eq!(first.snapshot_id, second.snapshot_id);
        assert_ne!(first.source_commitment, second.source_commitment);
    }

    #[test]
    fn writable_sources_fail_closed() {
        let mut source = empty_export();
        source.source.extraction.read_only = false;
        let bytes = serde_json::to_vec(&source).unwrap();
        assert_eq!(
            normalize(source, &bytes),
            Err(NormalizeError::SourceNotReadOnly)
        );
    }
}
