# Worker version provider-shape fixture

This fixture preserves every result member and all 17 version / 18 deployment
rows from an authenticated, read-only provider capture. It is not a deployment
receipt. Identifiers, binding names/values, source hashes and timestamps were
replaced before publication. Secret bindings retain names/types only, matching
the response rather than fabricating secret bytes.

The version-list envelope's explicit `errors:null` and `messages:null` were
confirmed against the exact failing HTTP 200 response. The version-detail
envelope uses empty arrays; its result also exposes omitted runtime flags,
`has_preview`, an empty `author_email` and version annotations. Extra envelope
pagination metadata is deliberately not used as authority: the adapter proves
complete pagination from its fixed-size passes and short terminal page.

The test checks the complete result inventory, the selected active detail,
and the fact that the latest version is different and not deployed. Unit
negatives preserve contradictory-envelope, malformed-field, alias-conflict,
unknown-field and semantic-drift denials. The stdio tests exercise the guarded
upload/readback path with synthetic provider responses and verify one POST,
strict inheritance, no deployment, no secret output and consumed-approval
replay denial. No real provider mutation is performed by these tests.

The reader accepts the observed name/type-only secret descriptors, while the
explicit upload validator still rejects them without text. Additional negative
cases cover missing, renamed, retyped and newly exposed secret fields. Matching
redacted projections is not a claim that unknown secret bytes were compared.
