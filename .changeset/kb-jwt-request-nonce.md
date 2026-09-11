---
'@trustknots/vcknots': patch
---

Hold an SD-JWT VC Key Binding JWT to the nonce of its own Authorization Request.

Appendix B.3.6 of OpenID4VP 1.0 requires the `nonce` claim of a Key Binding JWT to be "the value of nonce from the Authorization Request". The `dc+sd-jwt` presentation verifier accepted `expectedNonce` but never read it: it checked the nonce against the nonce store, which establishes only that this Verifier issued the nonce and has not seen it used. A nonce minted for one request therefore satisfied any other request that was open at the same time.

When `expectedNonce` is given, the Key Binding JWT's nonce is now compared with it and a mismatch is rejected with `invalid_sd_jwt`. Callers that do not pass `expectedNonce` are unaffected, and the nonce store still bounds replay on its own.
