---
'@trustknots/vcknots': minor
---

Stop using `presentation_submission`, which OpenID4VP 1.0 removed.

The parameter went away with Presentation Exchange, so nothing sends, reads or defines it any more:

- `presentation_submission` is gone from the Authorization Response schema, and the `PresentationSubmission` type and its `invalid_presentation_submission` error code are removed.
- `verifierFlow.verifyPresentations()` took the Credential Format from `presentation_submission.descriptor_map[0].format`, which was the only thing the parameter was used for. It now reads the format from the Presentation itself: an SD-JWT VC is the issuer-signed JWT followed by tilde-separated disclosures, and no other format uses a tilde.

A response that still carries `presentation_submission` is not rejected — the member is simply ignored, so a Wallet that has not caught up keeps working.

This is a breaking change for anyone importing `PresentationSubmission` or reading `presentation_submission` off a parsed Authorization Response.
