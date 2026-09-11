---
'@trustknots/vcknots': patch
---

Publish `client_metadata.jwks` only when the Response Mode encrypts, and only with keys a Wallet can encrypt to.

The Authorization Request carried the Verifier's Request Object signing key alongside its response encryption keys, in every Response Mode. Neither belonged there:

- OpenID4VP 1.0 Section 5.1 describes this key set as keys "used by the Wallet as an input to a key agreement that may be used for encryption of the Authorization Response", and states that public keys in it "MUST NOT be used to verify the signature of signed Authorization Requests". The signing key therefore had no purpose in the set, and a request using the `redirect_uri` Client Identifier Prefix is unsigned in any case.
- Section 8.3 has the Wallet choose an encryption key from the set "based on information about each key, such as the kty, use, alg". A signing key with no `use` and a JWS `alg` is not a candidate, so a Wallet reading the set as encryption keys had to classify a key it could not use — interoperability the specification does not ask a Wallet to provide.
- `direct_post` never encrypts the response, so the encryption keys were unused there too.

`jwks` is now present only for `direct_post.jwt` and `dc_api.jwt`, and holds only keys whose `alg` names an encryption algorithm. `encrypted_response_enc_values_supported` follows the same rule.
