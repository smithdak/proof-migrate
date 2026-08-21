# Read-only estate preflight

## Decision

Preflight is the gate between general migration tooling and estate-specific extraction. It accepts a local, content-free observation and answers one question: is there enough declared information to design the acquisition adapter without guessing?

It does not connect to Sitecore, inspect content, test credentials, call Proof, or perform writes. Those activity fields are fixed to `false` in every manifest.

## Input boundary

`estate-observation/v1` permits only:

- an opaque estate identifier and UTC observation time;
- product family, exact version, and build;
- acquisition environment and deployment model;
- enumerated estate and logical database roles;
- safe module, language, and custom-field-type identifiers;
- aggregate template, item, and media counts;
- declared export mechanisms and whether each is available and read-only;
- an opaque authorization reference and approval declaration;
- a declaration that collection was read-only and contains no content, credentials, or personal data;
- bounded unknown-fact codes, never free-form notes.

The contract has no fields for hostnames, endpoints, connection strings, file paths, content, or credentials. Unknown properties, unsafe identifiers, duplicate semantic entries, non-UTC timestamps, writable collection, or declared sensitive data fail closed. The safety statement is still a declaration: the tool cannot prove that an operator did not place sensitive text inside an otherwise valid opaque identifier.

Real observations must stay in an ignored, isolated client workspace. Only the synthetic fixture belongs in this repository.

## Readiness rule

The manifest is `ready` only when all of these are declared:

1. read-only preflight authorization;
2. known product family, version, and build;
3. known acquisition environment and deployment model;
4. at least one estate role and logical database role;
5. at least one available, read-only export mechanism;
6. no unresolved estate-fact codes.

The acquisition recommendation prefers already-authorized offline material, then serialization, package export, native API, and finally an offline database backup. A native extractor is required only when the selected path is the native API. This ordering is policy in code and must be changed deliberately when evidence shows a safer or more complete estate-specific path.

## Command and outputs

```powershell
$runId = [guid]::NewGuid().ToString("N")
$output = Join-Path work "preflight-$runId"
cargo run --release -- preflight --observation evaluations/fixtures/estate-observation.synthetic.json --output $output
Get-Content (Join-Path $output "estate-manifest.json")
```

`estate-manifest.json` includes a domain-separated BLAKE3 commitment to the exact source bytes and a separate semantic snapshot identifier over canonical normalized JSON. `preflight-run-manifest.json` commits the emitted manifest. Existing output directories are never overwritten.

Exit codes are stable for automation:

| Code | Meaning |
|---:|---|
| `0` | Valid declaration and ready for extractor design |
| `1` | Invalid contract, unsafe declaration, or execution failure |
| `2` | Valid declaration with explicit readiness blockers |

Ready means the declared planning evidence is complete. It does not mean the estate facts have been independently verified, extraction is compatible, a migration is qualified, or production work is authorized.
