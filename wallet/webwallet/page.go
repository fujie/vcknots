package webwallet

import "net/http"

// handlePage serves the wallet screen. It is a single dependency-free document:
// inline CSS and inline script, no bundler and no CDN, so `go run` is the only
// setup the screen needs.
//
// The issuer and verifier screens link here with the offer or the authorization
// request in the query string, which is why the page reads both on load. Linking
// rather than posting cross-origin also keeps the wallet from needing to accept
// requests from another origin.
func (s *Service) handlePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wallet</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f6f7f9; --panel: #ffffff; --border: #d8dce3;
    --text: #1a1d21; --muted: #5b6570; --accent: #2f5bd7; --ok: #12805c; --bad: #b3261e;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #16181d; --panel: #1e2127; --border: #333842;
      --text: #e7e9ec; --muted: #9aa3ae; --accent: #7ea1ff; --ok: #4cc79a; --bad: #ff8f85;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem 1.25rem; background: var(--bg); color: var(--text);
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { max-width: 60rem; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.05rem; margin: 0 0 .75rem; }
  .lede { color: var(--muted); margin: 0 0 1.5rem; }
  section {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.25rem; margin-bottom: 1.25rem;
  }
  label { display: block; font-weight: 600; margin: 0 0 .3rem; font-size: .9rem; }
  .field { margin-bottom: 1rem; }
  .hint { color: var(--muted); font-size: .85rem; margin: .3rem 0 0; }
  input[type=text], textarea {
    width: 100%; padding: .55rem .65rem; border: 1px solid var(--border); border-radius: 6px;
    background: var(--bg); color: var(--text); font: inherit;
  }
  textarea { min-height: 5rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; }
  button {
    padding: .55rem 1.1rem; border: 0; border-radius: 6px; background: var(--accent);
    color: #fff; font: inherit; font-weight: 600; cursor: pointer;
  }
  button:disabled { opacity: .5; cursor: progress; }
  .row { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
  pre {
    background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
    padding: .75rem; overflow-x: auto; font-size: .82rem; margin: .5rem 0 0;
    white-space: pre-wrap; word-break: break-all;
  }
  .ok { color: var(--ok); font-weight: 600; }
  .bad { color: var(--bad); font-weight: 600; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: 0; }
  dt { color: var(--muted); font-size: .85rem; }
  dd { margin: 0; font-size: .85rem; word-break: break-all; }
  article {
    border: 1px solid var(--border); border-radius: 8px; padding: .9rem; margin-bottom: .75rem;
  }
  article h3 { margin: 0 0 .5rem; font-size: .95rem; }
  .empty { color: var(--muted); }

  .toolbar { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; margin-bottom: .8rem; }
  .toolbar label { font-weight: 400; font-size: .85rem; display: flex; gap: .4rem; align-items: center; margin: 0; }
  button.secondary { background: transparent; color: var(--accent); border: 1px solid var(--border); }
  details.entry { border: 1px solid var(--border); border-radius: 8px; margin-bottom: .5rem; }
  details.entry > summary {
    cursor: pointer; padding: .55rem .75rem; display: flex; gap: .7rem; align-items: baseline;
    flex-wrap: wrap; font-size: .87rem;
  }
  details.entry > div { padding: 0 .75rem .75rem; }
  .step { font-weight: 600; }
  .meta { color: var(--muted); font-size: .8rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .code-2xx { color: var(--ok); font-weight: 600; }
  .code-4xx, .code-5xx { color: var(--bad); font-weight: 600; }
  .note { font-size: .82rem; color: var(--muted); margin: .1rem 0; }
  .notes { border-left: 2px solid var(--border); padding-left: .7rem; margin: .4rem 0 .8rem; }
  h4 { margin: .8rem 0 .3rem; font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; color: var(--muted); }
  .warn {
    border: 1px solid var(--border); border-left: 3px solid var(--bad); border-radius: 6px;
    padding: .6rem .8rem; margin: 0 0 .9rem; font-size: .85rem; color: var(--muted);
  }
</style>
</head>
<body>
<main>
<h1>Wallet</h1>
<p class="lede">Receives credentials from an issuer and presents them to a verifier.
   The holder key is generated per run, and credentials go into a database that is
   discarded when this process exits unless <code>-store</code> says otherwise.</p>

<section>
  <h2>This wallet</h2>
  <dl>
    <dt>Holder key</dt><dd id="keyId">–</dd>
    <dt>Algorithm</dt><dd id="keyAlg">–</dd>
    <dt>Thumbprint</dt><dd id="keyThumbprint">–</dd>
  </dl>
</section>

<section>
  <h2>Receive a credential</h2>
  <div class="field">
    <label for="offer">Credential offer</label>
    <textarea id="offer" placeholder="openid-credential-offer://?credential_offer=... or ?credential_offer_uri=..." spellcheck="false"></textarea>
    <p class="hint">Paste the offer from the issuer screen, or arrive here from its
       &ldquo;Open in wallet&rdquo; button.</p>
  </div>
  <div class="field">
    <label for="txCode">Transaction code (optional)</label>
    <input id="txCode" type="text" autocomplete="off" placeholder="only when the issuer asked for one">
  </div>
  <div class="row">
    <button id="receive">Accept offer</button>
    <span id="receiveStatus" class="hint"></span>
  </div>
</section>

<section>
  <h2>Present a credential</h2>
  <div class="field">
    <label for="request">Authorization request</label>
    <textarea id="request" placeholder="openid4vp://authorize?..." spellcheck="false"></textarea>
    <p class="hint">Paste the request from the verifier screen. The wallet picks a stored
       credential that satisfies it and posts the response.</p>
  </div>
  <div class="row">
    <button id="present">Present</button>
    <span id="presentStatus" class="hint"></span>
  </div>
</section>

<section>
  <h2>Stored credentials</h2>
  <div id="credentials"><p class="empty">None yet.</p></div>
</section>

<section>
  <h2>Protocol trace</h2>
  <p class="warn">
    Everything this wallet has sent, in order. Bodies are shown verbatim, access tokens and
    pre-authorized codes included &mdash; which is why this belongs in a test tool only.
    The server keeps its own view at <code>/ui/trace</code>.
  </p>
  <div class="toolbar">
    <label><input type="checkbox" id="live" checked> Live</label>
    <button id="clearTrace" class="secondary" type="button">Clear</button>
    <span id="traceStatus" class="hint"></span>
  </div>
  <p id="traceEmpty" class="empty">Nothing sent yet.</p>
  <div id="trace"></div>
</section>

<script>
  const $ = (id) => document.getElementById(id)

  const postJson = async (path, body) => {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    })
    const payload = await res.json().catch(() => ({}))
    if (!res.ok) {
      throw new Error(payload.error_description || payload.error || res.statusText)
    }
    return payload
  }

  const loadStatus = async () => {
    try {
      const status = await (await fetch('/api/status')).json()
      $('keyId').textContent = status.holderKeyId
      $('keyAlg').textContent = status.holderKeyAlg
      $('keyThumbprint').textContent = status.holderKeyThumbprint
    } catch {
      // The panel simply stays empty; the actions below report their own errors.
    }
  }

  // Credentials are rendered through the DOM rather than innerHTML: their
  // contents come from an issuer and are not markup.
  const renderCredentials = (credentials) => {
    const container = $('credentials')
    container.replaceChildren()

    if (!credentials.length) {
      const empty = document.createElement('p')
      empty.className = 'empty'
      empty.textContent = 'None yet.'
      container.append(empty)
      return
    }

    for (const credential of credentials) {
      const article = document.createElement('article')

      const heading = document.createElement('h3')
      heading.textContent = (credential.types && credential.types.join(', ')) || credential.mimeType
      article.append(heading)

      const list = document.createElement('dl')
      const addRow = (term, value) => {
        const dt = document.createElement('dt')
        dt.textContent = term
        const dd = document.createElement('dd')
        dd.textContent = value
        list.append(dt, dd)
      }
      addRow('Id', credential.id)
      addRow('Format', credential.mimeType)
      addRow('Received', new Date(credential.receivedAt).toLocaleString())
      article.append(list)

      if (credential.claims) {
        const claims = document.createElement('pre')
        claims.textContent = JSON.stringify(credential.claims, null, 2)
        article.append(claims)
      }

      container.append(article)
    }
  }

  const loadCredentials = async () => {
    try {
      const body = await (await fetch('/api/credentials')).json()
      renderCredentials(body.credentials ?? [])
    } catch {
      // Leave whatever was rendered last in place.
    }
  }

  $('receive').addEventListener('click', async () => {
    const button = $('receive')
    const status = $('receiveStatus')
    button.disabled = true
    status.className = 'hint'
    status.textContent = 'Requesting…'
    try {
      const body = await postJson('/api/receive', {
        offer: $('offer').value.trim(),
        tx_code: $('txCode').value.trim(),
      })
      status.className = 'ok'
      status.textContent = 'Stored ' + ((body.credential.types || []).join(', ') || body.credential.id)
      await Promise.all([loadStatus(), loadCredentials()])
    } catch (error) {
      status.className = 'bad'
      status.textContent = String(error.message ?? error)
    } finally {
      button.disabled = false
    }
  })

  $('present').addEventListener('click', async () => {
    const button = $('present')
    const status = $('presentStatus')
    button.disabled = true
    status.className = 'hint'
    status.textContent = 'Presenting…'
    try {
      const body = await postJson('/api/present', { request: $('request').value.trim() })
      status.className = 'ok'
      status.textContent = body.redirect_uri
        ? 'Presented. The verifier redirected to ' + body.redirect_uri
        : 'Presented.'
    } catch (error) {
      status.className = 'bad'
      status.textContent = String(error.message ?? error)
    } finally {
      button.disabled = false
    }
  })

  // The trace is rendered through the DOM, never innerHTML: it holds whatever
  // went over the wire and must not be treated as markup.
  let traceEntries = []
  let lastTraceId = 0
  let traceTimer = null

  const statusClass = (status) =>
    status >= 500 ? 'code-5xx' : status >= 400 ? 'code-4xx' : 'code-2xx'

  const messageSection = (title, message) => {
    const parts = []
    const heading = document.createElement('h4')
    heading.textContent = title
    parts.push(heading)

    const names = Object.keys((message && message.headers) || {})
    if (names.length) {
      const headers = document.createElement('pre')
      headers.textContent = names.map((name) => name + ': ' + message.headers[name]).join('\n')
      parts.push(headers)
    }
    if (message && message.body) {
      const body = document.createElement('pre')
      body.textContent = message.body + (message.truncated ? '\n… truncated' : '')
      parts.push(body)
    } else if (!names.length) {
      const empty = document.createElement('p')
      empty.className = 'note'
      empty.textContent = 'empty'
      parts.push(empty)
    }
    return parts
  }

  const renderTraceEntry = (entry) => {
    const details = document.createElement('details')
    details.className = 'entry'

    const summary = document.createElement('summary')
    const step = document.createElement('span')
    step.className = 'step'
    step.textContent = entry.step
    summary.append(step)

    const target = document.createElement('span')
    target.className = 'meta'
    target.textContent = entry.method + ' ' + entry.url
    summary.append(target)

    const status = document.createElement('span')
    if (entry.error) {
      status.className = 'code-5xx'
      status.textContent = 'failed'
    } else {
      status.className = statusClass(entry.status)
      status.textContent = String(entry.status)
    }
    summary.append(status)

    const timing = document.createElement('span')
    timing.className = 'meta'
    timing.textContent = new Date(entry.at).toLocaleTimeString() + ' · ' + entry.durationMs + 'ms'
    summary.append(timing)

    details.append(summary)

    const body = document.createElement('div')
    if (entry.error) {
      const failure = document.createElement('p')
      failure.className = 'note'
      failure.textContent = entry.error
      body.append(failure)
    }
    if (entry.notes && entry.notes.length) {
      const notes = document.createElement('div')
      notes.className = 'notes'
      for (const note of entry.notes) {
        const line = document.createElement('p')
        line.className = 'note'
        line.textContent = note
        notes.append(line)
      }
      body.append(notes)
    }
    body.append(...messageSection('Request', entry.request))
    if (!entry.error) body.append(...messageSection('Response', entry.response))
    details.append(body)

    return details
  }

  // Entries are appended rather than re-rendered, so an expanded one stays open
  // while the trace keeps polling.
  const appendTraceEntries = (entries) => {
    const container = $('trace')
    if (entries.length) $('traceEmpty').hidden = true
    for (const entry of entries) container.append(renderTraceEntry(entry))
  }

  const resetTrace = () => {
    $('trace').replaceChildren()
    $('traceEmpty').hidden = false
  }

  const pollTrace = async () => {
    try {
      const body = await (await fetch('/api/trace?since=' + lastTraceId)).json()
      if (body.entries && body.entries.length) {
        traceEntries = traceEntries.concat(body.entries)
        lastTraceId = body.entries[body.entries.length - 1].id
        appendTraceEntries(body.entries)
      }
      $('traceStatus').textContent = traceEntries.length + ' exchange(s)'
    } catch {
      // The next tick retries.
    }
  }

  const setTraceLive = (on) => {
    clearInterval(traceTimer)
    if (on) traceTimer = setInterval(pollTrace, 1000)
  }

  $('live').addEventListener('change', (event) => setTraceLive(event.target.checked))
  $('clearTrace').addEventListener('click', async () => {
    await fetch('/api/trace', { method: 'DELETE' })
    traceEntries = []
    lastTraceId = 0
    resetTrace()
  })

  // The issuer and verifier screens link here with their payload in the query
  // string, so a whole run needs no copying and pasting.
  const params = new URLSearchParams(location.search)
  if (params.get('offer')) $('offer').value = params.get('offer')
  if (params.get('tx_code')) $('txCode').value = params.get('tx_code')
  if (params.get('request')) $('request').value = params.get('request')

  loadStatus()
  loadCredentials()
  pollTrace()
  setTraceLive(true)
</script>
</main>
</body>
</html>`
