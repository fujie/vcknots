# E2E テスト

発行から検証までを、3 つのコンポーネント間で実際の HTTP 通信を通して実行します。

| 役割 | 実体 | 画面 |
| --- | --- | --- |
| **Issuer** | サンプルサーバー（`server/single`） | `http://localhost:8080/ui/issuer` |
| **Wallet** | Go 製 Web Wallet（`wallet/webwallet`） | `http://localhost:8081/` |
| **Verifier** | サンプルサーバー（`server/single`） | `http://localhost:8080/ui/verifier` |

Wallet は `wallet` パッケージそのものにブラウザ UI を被せたものです。テスト用に書き直した別実装ではなく、リポジトリの実際の OID4VCI / OID4VP 実装を動かします。暗号化レスポンスの経路が意味を持つのもこのためで、**Go** の Wallet が暗号化し、**TypeScript** の Verifier が復号します。

## 前提

- Node.js と pnpm（リポジトリの他の部分と同じ）
- Go（Wallet のビルドに必要）

## 自動実行

```bash
pnpm -F e2e test
```

サンプルサーバーと Wallet をビルドし、空きポートで起動してシナリオを実行し、終了時に停止します。事前に何かを起動しておく必要はありません。Wallet は一時的なデータベースにクレデンシャルを保存し、終了時に破棄します。

### カバー範囲

- **発行** — Issuer が OID4VCI のクレデンシャルオファーを作成し、Wallet が pre-authorized code フローを実行してクレデンシャルを保存する
- **提示（`direct_post`）** — レスポンスを平文で返す
- **提示（署名付き Request Object）** — `request_uri` から JAR を取得し、証明書チェーンを検証する
- **提示（`direct_post.jwt`）** — JOSE HPKE でレスポンスを暗号化する（OpenID4VP §8.3）。Verifier がどのアルゴリズムを使ったか記録することも確認する
- **fail-closed の挙動** — JWE でないレスポンスと、あるセッションで生成された正当なレスポンスを別のセッションに提示した場合の、いずれも拒否されること
- **画面** — 各画面が表示され、対応するエンドポイントを参照していること
- **プロトコルトレース** — 両側が期待どおりのステップを記録し、暗号化レスポンスに HPKE アルゴリズムの注記が付くこと

## プロトコルのモニタリング

両側が全てのやり取りを記録するので、ログから推測せずに流れをそのまま追えます。

| ビュー | 場所 | 表示内容 |
| --- | --- | --- |
| サーバー | `http://localhost:8080/ui/trace` | Issuer / 認可サーバー / Verifier に届いた全メッセージ |
| Wallet | Wallet 画面の *Protocol trace* | Wallet が送信した全リクエスト（応答が返らなかったものを含む） |

各エントリはプロトコル上のステップ名を持ち、展開するとリクエストとレスポンスのボディが確認できます。注目すべき点は注記として表示されます。DPoP proof を伴うリクエスト、暗号化された Authorization Response の JWE ヘッダー（使用された JOSE HPKE アルゴリズムと鍵 ID）などです。

典型的な発行フローは、リトライも含めて次のように見えます。

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

JSON でも取得できます。サーバー側は `GET /trace`、Wallet 側は `GET /api/trace` です。どちらも `?since=<id>` で差分のみ取得でき、`DELETE` でクリアできます。

ボディはアクセストークンや pre-authorized code を含めてそのまま保持されます。プロトコルモニターとしてはそれが目的であり、同時にサンプルサーバー専用である理由でもあります。サーバー側は `PROTOCOL_TRACE=off` で無効化できます。

## 手動実行

2 つのターミナルでそれぞれ起動します。

```bash
pnpm -F @trustknots/server start
```

```bash
make -C wallet run-webwallet
```

`http://localhost:8080/ui` を開き、3 つのステップを順に進めます。Issuer 画面と Verifier 画面には **Open in wallet** ボタンがあり、オファーや認可リクエストをそのまま Wallet 画面に引き渡すので、コピー＆ペーストは不要です。

別の場所で動く Wallet を指す場合は、サーバー起動時に `WALLET_UI_URL` を設定してください。

## Wallet のオプション

```
-addr                        待ち受けアドレス（既定は :8081）
-cert                        Verifier の証明書チェーン検証に使う PEM 形式のトラストルート
-store                       クレデンシャルデータベース（既定は一時的なもので、終了時に破棄）
-client-config, -client-key, -client-id
                             private_key_jwt クライアント認証（任意。サンプルの
                             認可サーバーは匿名クライアントも受け付けます）
-allow-http                  ローカルテストに必要な平文 HTTP エンドポイントを許可する
-insecure-skip-x509-verify   適合性テスト専用
```
