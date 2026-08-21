#![forbid(unsafe_code)]

//! Automatic opportunity classification and replay-gated non-production improvement.

use std::collections::BTreeMap;

use proof_migrate_evidence::{EvidenceBundleV1, canonical_json, domain_digest};
use proof_migrate_projector::{
    ProjectionError, ProjectionOutcome, ProjectionRules, ProjectionTraceV1, ProofCandidateBundleV1,
    ProofTargetContractV1, project, projection_payload_commitment,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const IMPROVEMENT_REPORT_API_V1: &str = "proof-migrate.dev/improvement-report/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityArtifactType {
    Function,
    Rule,
    Recipe,
    Skill,
    Fixture,
    Policy,
    NoAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Shadow,
    QualifiedDraft,
    PromotedNonProduction,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // Orthogonal routing features are evaluated independently.
pub struct OpportunityFeatures {
    pub occurrences: u64,
    pub deterministic: bool,
    pub read_only: bool,
    pub non_lossy: bool,
    pub stable_io: bool,
    pub requires_judgment: bool,
    pub multi_tool: bool,
    pub measurable_outcome: bool,
    pub authority_sensitive: bool,
}

#[must_use]
pub const fn classify_opportunity(features: &OpportunityFeatures) -> CapabilityArtifactType {
    if features.authority_sensitive {
        return CapabilityArtifactType::Policy;
    }
    if (features.requires_judgment || features.multi_tool)
        && features.measurable_outcome
        && features.occurrences >= 3
    {
        return CapabilityArtifactType::Skill;
    }
    if features.deterministic && features.stable_io && features.occurrences >= 3 {
        return CapabilityArtifactType::Function;
    }
    if features.deterministic
        && features.read_only
        && features.non_lossy
        && features.occurrences >= 2
    {
        return CapabilityArtifactType::Rule;
    }
    if features.measurable_outcome && features.occurrences >= 2 {
        return CapabilityArtifactType::Fixture;
    }
    CapabilityArtifactType::NoAction
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCandidateV1 {
    pub candidate_id: String,
    pub signature: String,
    pub artifact_type: CapabilityArtifactType,
    pub status: CandidateStatus,
    pub occurrences: u64,
    pub rule_value: String,
    pub rationale: String,
    pub promotion_evidence: PromotionEvidenceV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Persisted gates must remain individually inspectable.
pub struct PromotionEvidenceV1 {
    pub deterministic_replay: bool,
    pub read_only: bool,
    pub non_lossy: bool,
    pub within_existing_semantics: bool,
    pub projection_payload_unchanged: bool,
    pub mandatory_regressions: u64,
    pub trace_count_reduced: bool,
    pub previous_version_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementReportV1 {
    pub api_version: String,
    pub source_snapshot_id: String,
    pub router: String,
    pub model_calls_on_known_path: u64,
    pub baseline_trace_count: u64,
    pub final_trace_count: u64,
    pub baseline_projection_digest: String,
    pub final_projection_digest: String,
    pub candidates: Vec<CapabilityCandidateV1>,
    pub promoted_rules: Vec<String>,
}

impl ImprovementReportV1 {
    #[must_use]
    pub fn deterministic_replay_passed(&self) -> bool {
        self.candidates.iter().all(|candidate| {
            candidate.status != CandidateStatus::PromotedNonProduction
                || candidate.promotion_evidence.deterministic_replay
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImprovementOutcome {
    pub projection: ProofCandidateBundleV1,
    pub report: ImprovementReportV1,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ImproveError {
    #[error(transparent)]
    Projection(#[from] ProjectionError),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Discovers repeated work and promotes only replay-proven non-production rules.
///
/// # Errors
///
/// Returns an error when baseline, shadow, or final projection or canonicalization fails.
pub fn improve(
    evidence: &EvidenceBundleV1,
    target: &ProofTargetContractV1,
    source_locale: &str,
) -> Result<ImprovementOutcome, ImproveError> {
    let baseline = project(evidence, target, source_locale, &ProjectionRules::default())?;
    let opportunities = group_traces(&baseline.traces);
    let mut candidates = opportunities
        .values()
        .filter_map(candidate_from_opportunity)
        .collect::<Vec<_>>();

    let proposed_rules = ProjectionRules::from_raw_string_types(
        candidates
            .iter()
            .filter(|candidate| candidate.artifact_type == CapabilityArtifactType::Rule)
            .map(|candidate| candidate.rule_value.clone()),
    );
    let shadow_a = project(evidence, target, source_locale, &proposed_rules)?;
    let shadow_b = project(evidence, target, source_locale, &proposed_rules)?;
    let baseline_payload =
        projection_payload_commitment(&baseline.bundle).map_err(ImproveError::Canonicalization)?;
    let shadow_payload =
        projection_payload_commitment(&shadow_a.bundle).map_err(ImproveError::Canonicalization)?;
    let first_shadow_bytes =
        canonical_json(&shadow_a.bundle).map_err(ImproveError::Canonicalization)?;
    let replayed_shadow_bytes =
        canonical_json(&shadow_b.bundle).map_err(ImproveError::Canonicalization)?;
    let deterministic_replay = first_shadow_bytes == replayed_shadow_bytes;
    let payload_unchanged = baseline_payload == shadow_payload;
    let trace_count_reduced = shadow_a.traces.len() < baseline.traces.len();

    for candidate in &mut candidates {
        let safe_class = candidate.artifact_type == CapabilityArtifactType::Rule;
        let passes = safe_class && deterministic_replay && payload_unchanged && trace_count_reduced;
        candidate.status = if passes {
            CandidateStatus::PromotedNonProduction
        } else {
            CandidateStatus::Rejected
        };
        candidate.promotion_evidence = PromotionEvidenceV1 {
            deterministic_replay,
            read_only: true,
            non_lossy: payload_unchanged,
            within_existing_semantics: safe_class,
            projection_payload_unchanged: payload_unchanged,
            mandatory_regressions: u64::from(!passes),
            trace_count_reduced,
            previous_version_available: true,
        };
    }

    let promoted_rules = candidates
        .iter()
        .filter(|candidate| candidate.status == CandidateStatus::PromotedNonProduction)
        .map(|candidate| candidate.rule_value.clone())
        .collect::<Vec<_>>();
    let final_rules = ProjectionRules::from_raw_string_types(promoted_rules.clone());
    let final_projection = project(evidence, target, source_locale, &final_rules)?;
    let baseline_projection_digest = bundle_digest(&baseline)?;
    let final_projection_digest = bundle_digest(&final_projection)?;

    Ok(ImprovementOutcome {
        projection: final_projection.bundle,
        report: ImprovementReportV1 {
            api_version: IMPROVEMENT_REPORT_API_V1.to_owned(),
            source_snapshot_id: evidence.snapshot_id.clone(),
            router: "compiled-exact-signature/v1".to_owned(),
            model_calls_on_known_path: 0,
            baseline_trace_count: baseline.traces.len() as u64,
            final_trace_count: final_projection.traces.len() as u64,
            baseline_projection_digest,
            final_projection_digest,
            candidates,
            promoted_rules,
        },
    })
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // Aggregation preserves the strictest value for each gate.
struct GroupedOpportunity {
    signature: String,
    rule_value: String,
    occurrences: u64,
    deterministic: bool,
    read_only: bool,
    non_lossy: bool,
    stable_io: bool,
    requires_judgment: bool,
    multi_tool: bool,
    measurable_outcome: bool,
    authority_sensitive: bool,
}

fn group_traces(traces: &[ProjectionTraceV1]) -> BTreeMap<String, GroupedOpportunity> {
    let mut grouped = BTreeMap::new();
    for trace in traces {
        let entry = grouped
            .entry(trace.signature.clone())
            .or_insert_with(|| GroupedOpportunity {
                signature: trace.signature.clone(),
                rule_value: trace.rule_value.clone(),
                occurrences: 0,
                deterministic: true,
                read_only: true,
                non_lossy: true,
                stable_io: true,
                requires_judgment: false,
                multi_tool: false,
                measurable_outcome: true,
                authority_sensitive: false,
            });
        entry.occurrences += 1;
        entry.deterministic &= trace.deterministic;
        entry.read_only &= trace.read_only;
        entry.non_lossy &= trace.non_lossy;
        entry.stable_io &= trace.stable_io;
        entry.requires_judgment |= trace.requires_judgment;
        entry.multi_tool |= trace.multi_tool;
        entry.measurable_outcome &= trace.measurable_outcome;
        entry.authority_sensitive |= trace.authority_sensitive;
    }
    grouped
}

fn candidate_from_opportunity(opportunity: &GroupedOpportunity) -> Option<CapabilityCandidateV1> {
    let features = OpportunityFeatures {
        occurrences: opportunity.occurrences,
        deterministic: opportunity.deterministic,
        read_only: opportunity.read_only,
        non_lossy: opportunity.non_lossy,
        stable_io: opportunity.stable_io,
        requires_judgment: opportunity.requires_judgment,
        multi_tool: opportunity.multi_tool,
        measurable_outcome: opportunity.measurable_outcome,
        authority_sensitive: opportunity.authority_sensitive,
    };
    let artifact_type = classify_opportunity(&features);
    if artifact_type == CapabilityArtifactType::NoAction {
        return None;
    }
    let candidate_id = domain_digest(
        "proof-migrate:capability-candidate:v1",
        opportunity.signature.as_bytes(),
    );
    Some(CapabilityCandidateV1 {
        candidate_id,
        signature: opportunity.signature.clone(),
        artifact_type,
        status: CandidateStatus::Shadow,
        occurrences: opportunity.occurrences,
        rule_value: opportunity.rule_value.clone(),
        rationale: "repeated deterministic work is classified without a model or catalog scan"
            .to_owned(),
        promotion_evidence: PromotionEvidenceV1 {
            deterministic_replay: false,
            read_only: opportunity.read_only,
            non_lossy: opportunity.non_lossy,
            within_existing_semantics: false,
            projection_payload_unchanged: false,
            mandatory_regressions: 0,
            trace_count_reduced: false,
            previous_version_available: true,
        },
    })
}

fn bundle_digest(outcome: &ProjectionOutcome) -> Result<String, ImproveError> {
    canonical_json(&outcome.bundle)
        .map(|canonical| {
            domain_digest(
                "proof-migrate:proof-candidate-bundle:v1",
                canonical.as_bytes(),
            )
        })
        .map_err(ImproveError::Canonicalization)
}

#[cfg(test)]
mod tests {
    use super::{CapabilityArtifactType, OpportunityFeatures, classify_opportunity};

    fn baseline() -> OpportunityFeatures {
        OpportunityFeatures {
            occurrences: 3,
            deterministic: true,
            read_only: true,
            non_lossy: true,
            stable_io: true,
            requires_judgment: false,
            multi_tool: false,
            measurable_outcome: true,
            authority_sensitive: false,
        }
    }

    #[test]
    fn contextual_multi_tool_work_becomes_a_skill_candidate() {
        let mut features = baseline();
        features.requires_judgment = true;
        features.multi_tool = true;
        assert_eq!(
            classify_opportunity(&features),
            CapabilityArtifactType::Skill
        );
    }

    #[test]
    fn authority_sensitive_work_is_never_auto_classified_as_a_skill() {
        let mut features = baseline();
        features.authority_sensitive = true;
        features.requires_judgment = true;
        assert_eq!(
            classify_opportunity(&features),
            CapabilityArtifactType::Policy
        );
    }

    #[test]
    fn deterministic_stable_work_prefers_code_over_a_skill() {
        assert_eq!(
            classify_opportunity(&baseline()),
            CapabilityArtifactType::Function
        );
    }
}
