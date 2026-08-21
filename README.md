# Proof Migrate

An operator-run, offline-first Sitecore-to-Proof migration workbench that preserves source evidence, produces replaceable Proof candidates, and improves only inside replay-proven safety limits.

> [!IMPORTANT]
> The implemented slice runs against synthetic or already-authorized offline exports. It does not connect to any client Sitecore estate, use native Sitecore APIs, write to Proof, perform a migration, or authorize production work.

## What works now

- Validates a versioned, read-only Sitecore export contract and preserves raw values, historical versions, locales, presentation values, workflow/security strings, media commitments, errors, and unknowns.
- Normalizes source evidence deterministically with RFC 8785 canonical JSON and domain-separated BLAKE3 commitments.
- Produces offline Schema, Object, rendition, and relationship candidates pinned to Proof commit `ca9de58c38530fccfe16decf862fedd2cbf8f935`.
- Assigns every captured template, item version, and media record exactly one explicit disposition.
- Detects repeated task signatures without a model or catalog scan, distinguishes functions, rules, skills, fixtures, and policies, and replay-tests candidates.
- Automatically promotes only non-production, read-only, non-lossy rules whose candidate payload remains unchanged and whose shadow output is byte reproducible; preservation does not erase the underlying semantic gap.
- Emits a complete evidence bundle, Proof candidate, gap-aware evaluation, improvement report, and artifact manifest without overwriting prior output.
- Validates a content-free estate observation, commits its exact and normalized forms, and emits a deterministic readiness decision without contacting Sitecore or Proof.
- Runs the full quality and synthetic qualification path on both Windows and Linux in GitHub Actions.

## Quick start

Prerequisites are Rust 1.97.1, .NET 8, and PowerShell. The included fixture is synthetic and contains no client data.

```powershell
$runId = [guid]::NewGuid().ToString("N")
$preflight = Join-Path work "preflight-$runId"
$extract = Join-Path work "extract-$runId"
$result = Join-Path work "result-$runId"

cargo run --release -- preflight --observation evaluations/fixtures/estate-observation.synthetic.json --output $preflight
Get-Content (Join-Path $preflight "estate-manifest.json")

dotnet run --project apps/sitecore-extractor/ProofMigrate.SitecoreExtractor.csproj --configuration Release -- package --input evaluations/fixtures/sitecore-export.synthetic.json --output $extract
cargo run --release -- run --source (Join-Path $extract "source-export.json") --output $result --source-locale en-US
Get-Content (Join-Path $result "evaluation.json")
```

Every output directory is immutable from the tool's perspective. Use a new path for each run; existing paths fail closed.

The preflight command exits `0` only when the declared observation is ready for extractor design, `2` when it is valid but blocked, and `1` when the contract or safety boundary is invalid. A ready result qualifies the declaration; it does not independently verify the estate or authorization.

## Preflight bundle

| Artifact | Role |
|---|---|
| `estate-manifest.json` | Normalized estate facts, exact input commitment, semantic snapshot, readiness, acquisition recommendation, and blockers |
| `preflight-run-manifest.json` | Size and digest commitment for the estate manifest |

## Output bundle

| Artifact | Role |
|---|---|
| `evidence.json` | Canonical source truth and explicit findings |
| `proof-candidate.json` | Replaceable, write-free Proof projection |
| `evaluation.json` | Accounting, preservation, safety, and gap verdicts |
| `improvement.json` | Candidate classification and promotion evidence |
| `run-manifest.json` | Size and digest commitment for every other artifact |

## How it works

This flow answers how an immutable source export becomes a qualified offline candidate:

```text
authorized offline export
  → .NET package and hash boundary
  → canonical Sitecore evidence bundle
  → baseline Proof projection plus typed traces
  → compiled opportunity classification
  → shadow candidate replay
  → safe non-production promotion or rejection
  → final Proof candidate plus evaluation and manifest
```

The evidence bundle is authoritative migration evidence. The Proof projection is derived and replaceable. Automatic improvement cannot grant itself credentials, alter accepted meaning, accept loss, write to Proof, or authorize a cutover.

## Development verification

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
dotnet build apps/sitecore-extractor/ProofMigrate.SitecoreExtractor.csproj --configuration Release
```

The same gates plus the two executable synthetic paths run on `windows-latest` and `ubuntu-latest` for every pull request and every push to `main`.

## Documentation

- [Architecture and boundaries](docs/architecture.md)
- [Read-only estate preflight](docs/preflight.md)
- [Sitecore export contract](contracts/evidence/sitecore-export.v1.schema.json)
- [Estate observation contract](contracts/preflight/estate-observation.v1.schema.json)
- [Estate manifest contract](contracts/preflight/estate-manifest.v1.schema.json)
- [Pinned Proof target contract](contracts/proof/contract.v1.json)
- [Synthetic evaluation corpus](evaluations/README.md)
- [Capability lifecycle](skills/README.md)
