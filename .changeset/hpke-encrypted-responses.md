---
'@trustknots/vcknots': minor
---

Support JOSE HPKE for encrypted Authorization Responses (OpenID4VP 1.1 §8.3 / §8.3.1).

The Verifier can now publish HPKE encryption keys, issue `direct_post.jwt` requests, and decrypt the responses that come back:

- `verifierFlow.createResponseEncryptionKeys()` generates a key pair per algorithm and publishes the public JWKs in `client_metadata.jwks`, each carrying `use: "enc"`, its `alg`, and a `kid`.
- `verifierFlow.decryptAuthorizationResponse()` decrypts the `response` parameter against a session rebuilt from the request parameters the Verifier issued. The `session_info` structure of §8.3.1 becomes the HPKE `info` parameter, so a response captured from one presentation cannot be decrypted in the context of another.
- `createAuthzRequest()` accepts `direct_post.jwt` and refuses it when no encryption key is published.
- `encrypted_response_enc_values_supported` is recognised in verifier metadata.

Implemented `alg` values are `HPKE-0`, `HPKE-1`, `HPKE-2`, `HPKE-3`, `HPKE-4` and `HPKE-7` (Integrated Encryption). `HPKE-5` and `HPKE-6` need DHKEM(X448); Node.js can perform it, but the Go wallet cannot, so the suite is left out of both sides together. `ECDH-ES` responses are decrypted as well.

The HPKE implementation is checked against the test vectors published with `draft-ietf-jose-hpke-encrypt`, and against vectors produced by the Go wallet in this repository.
