# Evaluation corpus

`fixtures/sitecore-export.synthetic.json` is synthetic and contains no client data. It exercises templates, fields, inheritance-ready identities, historical versions, locales, relationships, raw presentation values, workflow/security preservation, media commitments, explicit unknowns, and a repeated unknown field type.

`fixtures/estate-observation.synthetic.json` is a content-free synthetic estate profile. It exercises exact version and build facts, topology roles, logical database roles, aggregate counts, safe export mechanisms, authorization and data-safety declarations, and a ready preflight decision.

`fixtures/sitecore-solution.synthetic/` is a synthetic local-solution tree. It exercises read-only traversal, package-version discovery, topology markers, serialization detection, sensitive-file-name exclusion, generated observations, and a deliberately blocked preflight without containing client data or credentials.

Real estate observations, manifests, and client evidence must live outside this repository in an isolated client workspace. A minimized fixture may enter this directory only after it cannot reconstruct client content and its reuse is explicitly authorized.
