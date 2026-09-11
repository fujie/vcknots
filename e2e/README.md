# End-to-end test

Walks a credential from issuance to verification across three components, over
real HTTP:

| Role | What runs it | Screen |
| --- | --- | --- |
| **Issuer** | the sample server (`server/single`) | `http://localhost:8080/ui/issuer` |
| **Wallet** | the Go web wallet (`wallet/webwallet`) | `http://localhost:8081/` |
| **Verifier** | the sample server (`server/single`) | `http://localhost:8080/ui/verifier` |

The wallet is a browser UI in front of the `wallet` package itself, so the run
exercises the repository's real OID4VCI and OID4VP implementation rather than a
second one written for testing. That is also what makes the encrypted response
path meaningful: a **Go** wallet encrypts and a **TypeScript** verifier decrypts.

## Prerequisites

- Node.js and pnpm, as for the rest of the repository
- Go, for building the wallet

## Automated run

```bash
pnpm -F e2e test
```

It builds the sample server and the wallet, starts both on free ports, runs the
scenarios and shuts everything down. Nothing needs to be running first, and the
wallet stores credentials in a temporary database that is discarded afterwards.

### What it covers

- **Issuance** — the issuer creates an OID4VCI credential offer, the wallet runs
  the pre-authorized code flow and stores the credential
- **Presentation, `direct_post`** — the response is returned in the clear
- **Presentation, signed Request Object** — the request is fetched over
  `request_uri` as a JAR and its certificate chain is verified
- **Presentation, `direct_post.jwt`** — the response is encrypted with JOSE HPKE
  (OpenID4VP §8.3), including that the verifier records which algorithm was used
- **Fail-closed behaviour** — a response that is not a JWE, and a genuine
  response captured from one session and offered to another, are both refused
- **The screens** — each renders and references the endpoints it drives
- **The protocol trace** — both sides recorded the expected steps, and the
  encrypted response was described with its HPKE algorithm

## Watching the protocol

Both sides record every exchange, so the flow can be watched rather than inferred
from logs.

| View | Where | Shows |
| --- | --- | --- |
| Server | `http://localhost:8080/ui/trace` | Every message that reached the issuer, authorization server or verifier |
| Wallet | the wallet screen, *Protocol trace* | Every request the wallet sent, including ones that never got an answer |

Each entry names the protocol step, and expands to the request and response with
their bodies. Things worth noticing are called out: which requests carry a DPoP
proof, and the JWE protected header of an encrypted Authorization Response with
the JOSE HPKE algorithm and key id it used.

A typical issuance reads like this, retries and all:

```
OID4VCI · Credential Offer created           POST /configurations/…/offer            200
OID4VCI · Credential Issuer Metadata         GET  /.well-known/openid-credential-issuer  200
OAuth   · Authorization Server Metadata      GET  /.well-known/oauth-authorization-server 200
OAuth   · Token Request                      POST /token                             400   ← DPoP nonce challenge
OAuth   · Token Request                      POST /token                             200
OID4VCI · Nonce                              POST /nonce                             200
OID4VCI · Credential Request                 POST /credentials                       401   ← nonce challenge
OID4VCI · Nonce                              POST /nonce                             200
OID4VCI · Credential Request                 POST /credentials                       200
```

The trace is also readable as JSON, at `GET /trace` on the server and
`GET /api/trace` on the wallet. Both accept `?since=<id>` to fetch only what is
new, and `DELETE` to clear.

Bodies are kept verbatim, access tokens and pre-authorized codes included. That
is the point of a protocol monitor and the reason it belongs in a sample server
only. Set `PROTOCOL_TRACE=off` to turn the server side off.

## Manual run

Start the two processes in separate terminals:

```bash
pnpm -F @trustknots/server start
```

```bash
make -C wallet run-webwallet
```

Then open `http://localhost:8080/ui` and follow the three steps. The issuer and
verifier screens each have an **Open in wallet** button that carries the offer or
the authorization request across, so no copying and pasting is needed.

To point the screens at a wallet elsewhere, set `WALLET_UI_URL` when starting the
server.

## The wallet's options

```
-addr                        address to listen on (default :8081)
-cert                        PEM trust roots for a verifier's certificate chain
-store                       credential database (default: temporary, discarded on exit)
-client-config, -client-key, -client-id
                             private_key_jwt client authentication (optional;
                             the sample authorization server also accepts
                             anonymous clients)
-allow-http                  allow plain HTTP endpoints, as local testing needs
-insecure-skip-x509-verify   conformance testing only
```
