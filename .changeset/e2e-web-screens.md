---
'@trustknots/server-core': minor
---

Add issuer and verifier web screens for end-to-end testing, and record the outcome of each presentation so a screen can show it.

- `GET /ui`, `GET /ui/issuer` and `GET /ui/verifier` serve dependency-free screens that drive the existing JSON endpoints. The issuer screen creates a credential offer; the verifier screen creates an authorization request in either `direct_post` or `direct_post.jwt` and displays the verified VP payload, including which JOSE HPKE algorithm the wallet chose. Both hand their payload to the wallet by link, so no copying and pasting is needed. `WALLET_UI_URL` points them at the wallet.
- `GET /presentations` and `GET /presentations/:transactionId` expose the outcome of a presentation, which otherwise arrives on the wallet's connection and is invisible to the browser that started it.
- `/request`, `/request-encrypted` and `/request-object` now return the transaction id in the `X-Presentation-Transaction-Id` header.

- `GET /ui/trace` shows every HTTP exchange the server takes part in, live. Each entry names the protocol step (`OID4VCI · Credential Request`, `OID4VP · Authorization Response (encrypted)`, …), expands to the request and response with their bodies, and calls out what is worth noticing: which requests carry a DPoP proof, and the JWE protected header of an encrypted response with its JOSE HPKE algorithm and key id. `GET /trace` serves the same data as JSON, `?since=<id>` fetches only what is new, and `DELETE /trace` clears it. Bodies are kept verbatim, so this belongs in a sample server only; `PROTOCOL_TRACE=off` turns it off.

They pair with the Go web wallet in `wallet/webwallet`, which keeps its own trace of what it sent, and the `e2e` package, which runs the whole flow unattended.
