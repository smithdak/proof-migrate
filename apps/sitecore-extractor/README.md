# Sitecore extraction boundary

This .NET 8 executable is the only planned component allowed to depend on Sitecore-native APIs. The current slice intentionally supports only packaging an already-authorized offline JSON export. It validates the contract, rejects common secret-bearing properties, hashes the input, never overwrites output, and records that neither network access nor native Sitecore access occurred.

Native extraction is blocked until a target estate's Sitecore version, topology, available APIs, and client-approved acquisition environment are known. Adding it later must preserve the same output contract and cannot place Sitecore assemblies in the Rust workbench.
