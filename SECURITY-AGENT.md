# Agent dependency security patch

This branch is based on ChromaDB 1.5.9, upstream commit
`11f3c7435e71024aa0a2b53710a28d3289d922d1`. It is a downstream patch,
version `1.5.9+agent.2`, rather than an upstream ChromaDB release.

The patch addresses CVE-2026-45829 and CVE-2026-45833 by rejecting
`trust_remote_code` in serialized SentenceTransformer configuration, including
nested model, tokenizer, and config keyword arguments. Explicit construction
by trusted application code retains its API. Read, create, update, and schema
deserialization all use the protected constructor factory.

CVE-2026-45830 and CVE-2026-45831 are addressed by intersecting action grants
with authenticated tenant/database scope, preserving that scope in every v1
collection handler, and checking actual collection ownership in both Python
storage implementations. An explicit wildcard remains an intentional global
grant. Missing identity scope grants only the default namespace. The legacy
v1 API resolves a scoped identity's singleton namespace; v2 supports explicit
namespace selection. Collection metadata lookup is scoped as well as data
reads, queries, counts, writes, and modifications.

The upstream proposal in chroma-core/chroma#7602 informed the investigation;
this implementation also covers query/count/metadata paths and the Rust
bindings' Python API. It does not depend on that unmerged proposal.

Run the regression suite from the repository root:

```console
python -m pytest security_tests/test_collection_boundaries.py -q
```

The suite uses real configuration loaders, token authentication, RBAC,
FastAPI routing, and temporary Segment/Rust storage. Fake embedding models
record construction without downloading models or executing remote code.

## Native dependency closure

The second patch refreshes `Cargo.lock` and removes the affected native
dependency paths, rather than suppressing their advisories. PyO3 0.29.3 fixes
the iterator memory-safety issue. Its conversion API migration retains owned
metadata values and explicitly preserves the extension's GIL requirement.
`object_store` 0.14.2 selects the patched XML parser; the maintained
`serde_yaml_ng` replaces `serde_yml`/`libyml`. ZIP 9.1.0 and Swagger UI 10.0.2
replace the vulnerable extractors. The CLI preserves archive root stripping.

Kube 0.91 and the AWS SDK's modern default HTTPS client remove rustls 0.21 and
its vulnerable webpki parser. Certificate validation stays enabled. The AWS
SDK's redundant legacy `rustls` feature is omitted; its modern TLS client,
async runtime, SigV4a and HTTP/1 support remain enabled. The lock refresh also
updates OpenSSL, Quinn, Smithy JSON, and the modern rustls/webpki pair.

The fork now requires Python 3.11, matching Agent's host baseline. Security
minimums for its Python transport/locking dependencies prevent an existing
environment from satisfying the source install with vulnerable versions.

Scan the native closure with OSV-Scanner 2.3.8:

```console
osv-scanner scan source --lockfile=Cargo.lock --format=sarif --output=chroma.sarif
```

The 25 October scan has zero findings scored high or critical. Lower-severity
and unscored reports remain visible, including upstream maintenance notices,
LRU panic-safety and cryptographic timing advisories. This is not a claim that
the dependency tree has no advisories. No third-party advisory is suppressed.

The rebuilt Linux ABI3 wheel passed all 65 collection-boundary regressions,
17 existing Rust-backend metadata/array round-trip cases, and HY Memory's 19
focused store/SDK integration cases. The metadata checks exercise persistent
and ephemeral native storage with the new PyO3 conversions.
