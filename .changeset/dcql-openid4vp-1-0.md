---
'@trustknots/vcknots': minor
---

Support DCQL and the OpenID4VP 1.0 response shape.

OpenID4VP 1.0 replaced Presentation Exchange with the Digital Credentials Query Language, and changed the response along with it. Both are now implemented:

- `DcqlQuery` models the query of §6 — `credentials`, `credential_sets`, `claims`, `claim_sets`, `multiple`, `trusted_authorities` and `require_cryptographic_holder_binding` — and validates the constraints the specification states in prose: ids are unique and usable as `vp_token` keys, `claim_sets` needs `claims`, claims carry an `id` when `claim_sets` is present, and every reference resolves. Unknown members are preserved, as §6 requires.
- The claims path pointer of §7 is implemented with the processing rules of §7.1.1, including the three component forms (a key, a non-negative index, `null` for every element of an array) and the rule that a component which selects nothing drops that element rather than failing the whole query.
- `verifierFlow.verifyDcqlPresentations()` verifies a `vp_token` against the query that produced it: the keys have to name Credential Queries, `multiple` is respected, the required Credential Set Queries have to be answered, and each Presentation is verified for its format and then checked to actually carry the claims that were asked for.
- `vp_token` is accepted in the object form of §8.1, keyed by Credential Query id with non-empty arrays of Presentations. `isDcqlVpToken()` tells a 1.0 response from a Presentation Exchange one.

Presentation Exchange keeps working. `verifierFlow.verifyPresentations()` is unchanged, and a request may still carry a `presentation_definition`, so wallets that have not moved to 1.0 are unaffected.

`client_id_scheme` is marked deprecated: 1.0 carries the Client Identifier Prefix inside `client_id`. It is still emitted and accepted for draft 24 wallets, but behaviour is driven by the prefix.
