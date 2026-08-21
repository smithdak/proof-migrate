# Architecture and boundaries

## Current slice

The current implementation proves two offline paths: a content-free estate observation is assessed for extractor-design readiness, and a versioned synthetic Sitecore export is packaged, normalized into target-neutral evidence, projected against a pinned Proof contract, evaluated, and passed through an automatic but non-authorizing improvement loop.

It does not prove native Sitecore extraction, compatibility with any real client estate, current Proof compatibility beyond the pinned commit, rendered equivalence, workflow or security equivalence, production migration, or cutover readiness.

## Runtime responsibilities

| Component | Responsibility |
|---|---|
| `preflight` | Content-free estate observation validation, commitments, blockers, and acquisition recommendation |
| `.NET extractor` | Package and hash an authorized offline export; future Sitecore-native adapter boundary |
| `evidence-model` | Versioned source and canonical evidence contracts |
| `normalize` | Validation, ordering, commitments, referential findings |
| `proof-projector` | Replaceable Schema, Object, rendition, relationship candidates |
| `improve` | Exact-signature opportunity classification and replay-gated promotion |
| `evaluate` | Source accounting, raw preservation, write boundary, explicit verdict |
| `workbench` | Atomic orchestration and immutable output publication |

## Data flow

This flow answers which artifact is authoritative at each stage:

```text
content-free estate observation                 declared planning evidence
  └─ estate-manifest.json                       normalized readiness decision
       └─ ready or explicit blockers            extractor-design gate

offline Sitecore export                       source artifact
  └─ extractor manifest + copied export       acquisition evidence
       └─ evidence.json                       authoritative migration evidence
            ├─ baseline candidate + traces    replaceable derived output
            ├─ shadow candidate replays       non-production evaluation
            └─ proof-candidate.json           final derived candidate
                 ├─ improvement.json          promotion evidence
                 ├─ evaluation.json           quality verdict
                 └─ run-manifest.json         output commitments
```

## Invariants

1. The workbench never connects to or mutates Proof. The pinned target contract uses `offline-candidate-only` mode.
2. Source evidence is never rewritten to resemble Proof. Target projections are disposable derivatives.
3. Every captured template, item version, and media record receives exactly one disposition: mapped, transformed, preserved, intentionally excluded, unsupported, failed, or unknown.
4. Unsupported data remains present in source evidence with an explicit gap; no silent drop is permitted.
5. Output paths are never overwritten. A complete run is staged before its directory is published.
6. Automatic promotion is restricted to deterministic, read-only, non-lossy behavior within an existing semantic class, with byte-reproducible shadow replay and a retained prior version.
7. Judgment-heavy or multi-tool repetition becomes a skill candidate only when recurrence and measurable outcomes justify it. Authority-sensitive work is classified as policy, not a skill.
8. Client workspaces and generated runs are excluded from source control. No raw client evidence belongs in this repository.
9. Preflight accepts only structured, content-free facts. It rejects observations declared to contain content, credentials, or personal data, and never performs estate access or writes.

## Identity

Sitecore item identity is retained as the logical key. Offline Proof Object candidates receive deterministic UUIDv7 identifiers derived from the stable corpus identifier plus Sitecore item ID under a fixed project namespace epoch. This makes identifiers stable across resnapshots of the same corpus without pretending the Sitecore UUID itself satisfies Proof's UUIDv7 operational profile.

Before a real pilot, the corpus identifier and identity mapping become durable client-workspace records; changing either must be treated as an explicit migration decision.

## Proof contract pin

The projection is pinned to Proof commit `ca9de58c38530fccfe16decf862fedd2cbf8f935`, verified locally on 2026-08-20. It uses Proof's RFC 8785 canonicalization and domain-separated BLAKE3 contexts for Schema and Object candidates. Locale output remains a candidate requiring a governed Proof ChangeSet; the workbench does not fabricate committed ChangeSets, Editions, Releases, or Proofs.

The Proof repository was read only. Its unrelated dirty working tree was neither changed nor treated as part of the pinned contract.

## Automatic improvement mechanism

The execution path emits typed traces. The improvement engine groups exact signatures and classifies them with compiled branching:

- stable deterministic work prefers a function;
- bounded deterministic normalization prefers a rule;
- contextual judgment or multi-tool orchestration may become a skill candidate;
- missing evaluation evidence may become a fixture;
- authority-sensitive behavior becomes policy;
- insufficient evidence produces no action.

Candidate generation stays off known routing paths and uses zero model calls there. In the synthetic fixture, two occurrences of an unknown field type produce a raw-string preservation rule. The system applies it in shadow mode twice and promotes it only when canonical candidate payloads remain unchanged, traces decrease, and both outputs are byte identical. Promotion clears the repeated handling trace; `field-type-semantics-unmodeled` remains in the gap report until behavior is actually understood and qualified.

## Read-only preflight boundary

Preflight converts a local `estate-observation/v1` document into an immutable `estate-manifest/v1`. It records a digest of the exact bytes, a digest of the normalized meaning, and a readiness assessment. A result is ready only when the declaration includes authorization, exact product version and build, acquisition environment and deployment model, estate and database roles, at least one available read-only export mechanism, and no unresolved estate facts.

The evidence basis remains `declared_observation`: the tool does not independently prove the facts or authorization. Its activity flags are always false for estate access, estate writes, and Proof writes. A real observation and its output belong in an isolated client workspace, never in this repository.

## Next blocked boundary

The generic preflight gate now exists, but native extraction remains blocked until an authorized real observation passes it. The resulting acquisition adapter must implement the existing source-export contract rather than coupling Sitecore libraries into the Rust core.
