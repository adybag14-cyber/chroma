# Agent dependency security patch

This branch is based on ChromaDB 1.5.9, upstream commit
`11f3c7435e71024aa0a2b53710a28d3289d922d1`. It is a downstream patch,
version `1.5.9+agent.1`, rather than an upstream ChromaDB release.

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
