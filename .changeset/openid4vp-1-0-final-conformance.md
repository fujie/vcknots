---
'@trustknots/vcknots': minor
---

Bring the Authorization Request in line with the final OpenID4VP 1.0 specification.

The request the Verifier issued carried parameters and member names from earlier drafts:

- `client_id_scheme` is no longer sent. The final specification has no such parameter; the Client Identifier Prefix travels inside `client_id`, which is what this library already drove its behaviour from (§5.9.1).
- `vp_formats` is now `vp_formats_supported` (§11.1), and the `jwt_vc_json` entry inside it uses `alg_values` rather than `alg_values_supported` (Appendix B.1.3.1.3).
- Every JWK published in `client_metadata.jwks` now carries a `kid`, which §5.1 requires to uniquely identify the key within the request, and which §8.3 has the Wallet echo in the JWE header of an encrypted response. An RFC 7638 thumbprint is used when the caller supplies no identifier.
- `client_metadata` now carries only the three members §5.1 permits — `jwks`, `encrypted_response_enc_values_supported` and `vp_formats_supported` — since a Wallet MUST ignore anything else. RFC 7591 registration members such as `client_name`, and `authorization_signed_response_alg` (which is local configuration for signing Request Objects, not a response parameter), stay in the stored Verifier metadata and off the wire.

DCQL `type_values` is now matched correctly. Appendix B.1.1 defines it as "the fully expanded types (IRIs) ... after applying the `@context` to the Verifiable Credential", but the matcher compared the terms as declared, so an expanded IRI never matched. `expandCredentialType()` expands a Credential's types before comparison, from a table of the contexts this library issues and accepts; a term no context defines is left unchanged, which is what the specification prescribes for it. Appendix B.1.1 permits this in place of a JSON-LD processor, "as long as the results are equivalent".

`VerifierMetadata.vp_formats` is renamed to `vp_formats_supported`, which is a breaking change for stored metadata and for callers that construct it.
