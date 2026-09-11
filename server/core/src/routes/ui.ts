import { Hono } from 'hono'
import type { ProtocolTrace } from '../utils/protocol-trace.js'

/**
 * Server-rendered screens for end-to-end testing by hand: an issuance screen and
 * a verification screen. They drive the same JSON endpoints the wallet and any
 * other client use, so what they exercise is the real protocol surface rather
 * than a shortcut.
 *
 * The pages are deliberately dependency-free — inline CSS and inline scripts, no
 * bundler and no CDN — so that `pnpm start` is the only setup needed.
 */

/** Where the sample web wallet is expected to run. */
const DEFAULT_WALLET_UI_URL = 'http://localhost:8081'

const escapeHtml = (value: string) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')

const styles = `
  :root {
    color-scheme: light dark;
    --bg: #f6f7f9;
    --panel: #ffffff;
    --border: #d8dce3;
    --text: #1a1d21;
    --muted: #5b6570;
    --accent: #2f5bd7;
    --ok: #12805c;
    --bad: #b3261e;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #16181d;
      --panel: #1e2127;
      --border: #333842;
      --text: #e7e9ec;
      --muted: #9aa3ae;
      --accent: #7ea1ff;
      --ok: #4cc79a;
      --bad: #ff8f85;
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
  nav { margin-bottom: 1.5rem; display: flex; gap: 1rem; }
  nav a { color: var(--accent); }
  section {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.25rem; margin-bottom: 1.25rem;
  }
  label { display: block; font-weight: 600; margin: 0 0 .3rem; font-size: .9rem; }
  .field { margin-bottom: 1rem; }
  .hint { color: var(--muted); font-size: .85rem; margin: .3rem 0 0; }
  select, input[type=text] {
    width: 100%; padding: .55rem .65rem; border: 1px solid var(--border); border-radius: 6px;
    background: var(--bg); color: var(--text); font: inherit;
  }
  fieldset { border: 1px solid var(--border); border-radius: 6px; padding: .75rem 1rem; margin: 0 0 1rem; }
  legend { font-weight: 600; font-size: .9rem; padding: 0 .35rem; }
  fieldset label { font-weight: 400; display: flex; gap: .5rem; align-items: baseline; margin: .35rem 0; }
  button {
    padding: .55rem 1.1rem; border: 0; border-radius: 6px; background: var(--accent);
    color: #fff; font: inherit; font-weight: 600; cursor: pointer;
  }
  button:disabled { opacity: .5; cursor: progress; }
  button.secondary { background: transparent; color: var(--accent); border: 1px solid var(--border); }
  .row { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
  pre {
    background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
    padding: .75rem; overflow-x: auto; font-size: .82rem; margin: 0; white-space: pre-wrap;
    word-break: break-all;
  }
  .status { font-weight: 600; }
  .status[data-state=verified] { color: var(--ok); }
  .status[data-state=failed] { color: var(--bad); }
  .status[data-state=pending] { color: var(--muted); }
  .hidden { display: none; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; margin: 0 0 1rem; }
  dt { color: var(--muted); font-size: .85rem; }
  dd { margin: 0; font-size: .85rem; word-break: break-all; }

  .warn {
    border: 1px solid var(--border); border-left: 3px solid var(--bad); border-radius: 6px;
    padding: .6rem .8rem; margin: 0 0 1.25rem; font-size: .85rem; color: var(--muted);
  }
  .toolbar { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; margin-bottom: 1rem; }
  .toolbar label { font-weight: 400; font-size: .85rem; display: flex; gap: .4rem; align-items: center; margin: 0; }
  .toolbar input[type=text] { width: 14rem; }
  details.entry {
    border: 1px solid var(--border); border-radius: 8px; margin-bottom: .5rem; background: var(--panel);
  }
  details.entry > summary {
    cursor: pointer; padding: .6rem .8rem; display: flex; gap: .7rem; align-items: baseline;
    flex-wrap: wrap; font-size: .87rem;
  }
  details.entry > div { padding: 0 .8rem .8rem; }
  .badge {
    font-size: .72rem; font-weight: 700; letter-spacing: .02em; text-transform: uppercase;
    padding: .12rem .45rem; border-radius: 4px; border: 1px solid var(--border); color: var(--muted);
  }
  .badge[data-actor=issuer] { color: #b06f00; border-color: #b06f0055; }
  .badge[data-actor=authz] { color: #7a4bcc; border-color: #7a4bcc55; }
  .badge[data-actor=verifier] { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 35%, transparent); }
  .badge[data-actor=ui] { color: var(--muted); }
  .step { font-weight: 600; }
  .meta { color: var(--muted); font-size: .8rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .code-2xx { color: var(--ok); font-weight: 600; }
  .code-4xx, .code-5xx { color: var(--bad); font-weight: 600; }
  .note { font-size: .82rem; color: var(--muted); margin: .1rem 0; }
  .notes { border-left: 2px solid var(--border); padding-left: .7rem; margin: .4rem 0 .8rem; }
  h4 { margin: .8rem 0 .3rem; font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; color: var(--muted); }
  .empty { color: var(--muted); }
`

const layout = (title: string, body: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${styles}</style>
</head>
<body>
<main>
<nav>
  <a href="/ui">Overview</a>
  <a href="/ui/issuer">Issuer</a>
  <a href="/ui/verifier">Verifier</a>
  <a href="/ui/trace">Protocol trace</a>
</nav>
${body}
</main>
</body>
</html>`

export type UiRouterOptions = {
  /** The recorded protocol exchanges the trace screen shows. */
  trace?: ProtocolTrace
  /** False when tracing was turned off, so the screen can say so. */
  traceEnabled?: boolean
  walletUiUrl?: string
}

export const createUiRouter = (baseUrl: string, options?: UiRouterOptions) => {
  const uiApp = new Hono()
  const walletUrl = (
    options?.walletUiUrl ??
    process.env.WALLET_UI_URL ??
    DEFAULT_WALLET_UI_URL
  ).replace(/\/$/, '')
  const trace = options?.trace
  const traceEnabled = options?.traceEnabled ?? Boolean(trace)

  const config = `<script>
    const SERVER_URL = ${JSON.stringify(baseUrl)}
    const WALLET_URL = ${JSON.stringify(walletUrl)}
  </script>`

  uiApp.get('/ui', (c) =>
    c.html(
      layout(
        'VCKnots end-to-end test',
        `
<h1>VCKnots end-to-end test</h1>
<p class="lede">Three screens that together walk a credential from issuance to verification.</p>

<section>
  <h2>1. Issue</h2>
  <p>The <a href="/ui/issuer">Issuer screen</a> creates an OID4VCI credential offer and hands it to the wallet.</p>
</section>

<section>
  <h2>2. Store and present</h2>
  <p>The web wallet at <a href="${escapeHtml(walletUrl)}">${escapeHtml(walletUrl)}</a> accepts the offer,
     fetches the credential and keeps it. It later presents it to the verifier.</p>
  <p class="hint">Start it with <code>make -C wallet run-webwallet</code>, or
     <code>go run ./webwallet/cmd/webwallet</code> from the <code>wallet</code> directory.</p>
</section>

<section>
  <h2>3. Verify</h2>
  <p>The <a href="/ui/verifier">Verifier screen</a> creates an OID4VP authorization request and shows what came back.
     It can ask for a plain <code>direct_post</code> response or an encrypted <code>direct_post.jwt</code> one.</p>
</section>

<section>
  <h2>Automated run</h2>
  <p>The same flow runs unattended from the repository root:</p>
  <pre>pnpm -F e2e test</pre>
</section>
`
      )
    )
  )

  uiApp.get('/ui/issuer', (c) =>
    c.html(
      layout(
        'Issuer',
        `
<h1>Issuer</h1>
<p class="lede">Create a credential offer and hand it to the wallet.</p>

<section>
  <h2>Credential offer</h2>
  <div class="field">
    <label for="configuration">Credential configuration</label>
    <select id="configuration"><option value="">Loading…</option></select>
    <p class="hint">Read from <code>/.well-known/openid-credential-issuer</code>.</p>
  </div>
  <div class="field">
    <label for="txCode">Transaction code (optional)</label>
    <input id="txCode" type="text" placeholder="leave empty for no tx_code" autocomplete="off">
    <p class="hint">When set, the wallet must send the same value to the token endpoint.</p>
  </div>
  <div class="row">
    <button id="create">Create offer</button>
    <span id="createStatus" class="hint"></span>
  </div>
</section>

<section id="offerPanel" class="hidden">
  <h2>Offer</h2>
  <pre id="offerUri"></pre>
  <div class="row">
    <a id="openWallet" class="row"><button class="secondary" type="button">Open in wallet</button></a>
    <button id="copy" class="secondary" type="button">Copy URI</button>
  </div>
  <p class="hint">The wallet screen opens with the offer filled in. Accepting it runs the OID4VCI
     pre-authorized code flow against this issuer.</p>
</section>

${config}
<script>
  const $ = (id) => document.getElementById(id)

  // Options are built through the DOM rather than innerHTML: the configuration
  // ids are issuer-controlled strings, not markup.
  const setOptions = (select, entries) => {
    select.replaceChildren(
      ...entries.map(({ value, label }) => {
        const option = document.createElement('option')
        option.value = value
        option.textContent = label
        return option
      })
    )
  }

  const loadConfigurations = async () => {
    const select = $('configuration')
    try {
      const res = await fetch(SERVER_URL + '/.well-known/openid-credential-issuer')
      const metadata = await res.json()
      const ids = Object.keys(metadata.credential_configurations_supported ?? {})
      setOptions(
        select,
        ids.length
          ? ids.map((id) => ({ value: id, label: id }))
          : [{ value: '', label: 'no configurations' }]
      )
    } catch (error) {
      setOptions(select, [{ value: '', label: 'failed to load: ' + error }])
    }
  }

  $('create').addEventListener('click', async () => {
    const button = $('create')
    const status = $('createStatus')
    const configuration = $('configuration').value
    if (!configuration) { status.textContent = 'Pick a configuration first.'; return }

    button.disabled = true
    status.textContent = 'Creating…'
    try {
      const txCode = $('txCode').value.trim()
      const res = await fetch(
        SERVER_URL + '/configurations/' + encodeURIComponent(configuration) + '/offer',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: txCode ? JSON.stringify({ tx_code: txCode }) : '',
        }
      )
      const body = await res.text()
      if (!res.ok) throw new Error(body)

      $('offerUri').textContent = body
      $('offerPanel').classList.remove('hidden')
      const params = new URLSearchParams({ offer: body })
      if (txCode) params.set('tx_code', txCode)
      $('openWallet').href = WALLET_URL + '/?' + params.toString()
      status.textContent = 'Offer created.'
    } catch (error) {
      status.textContent = 'Failed: ' + error
    } finally {
      button.disabled = false
    }
  })

  $('copy').addEventListener('click', () => navigator.clipboard.writeText($('offerUri').textContent))

  loadConfigurations()
</script>
`
      )
    )
  )

  uiApp.get('/ui/verifier', (c) =>
    c.html(
      layout(
        'Verifier',
        `
<h1>Verifier</h1>
<p class="lede">Ask the wallet for a presentation and inspect what comes back.</p>

<section>
  <h2>Authorization request</h2>
  <fieldset>
    <legend>Response mode</legend>
    <label>
      <input type="radio" name="mode" value="direct_post" checked>
      <span><code>direct_post</code> — the response is returned in the clear.</span>
    </label>
    <label>
      <input type="radio" name="mode" value="direct_post.jwt">
      <span><code>direct_post.jwt</code> — the response is encrypted to this verifier
        (OpenID4VP §8.3, JOSE HPKE).</span>
    </label>
  </fieldset>
  <fieldset>
    <legend>Credential format</legend>
    <label>
      <input type="radio" name="format" value="jwt_vc_json" checked>
      <span><code>jwt_vc_json</code> — a W3C Verifiable Credential. The Credential Query
        names its expanded types (OpenID4VP Appendix B.1.1).</span>
    </label>
    <label>
      <input type="radio" name="format" value="dc+sd-jwt">
      <span><code>dc+sd-jwt</code> — an SD-JWT VC, named by <code>vct_values</code>
        (Appendix B.3.5). Wallets that implement only this format answer
        <code>vp_formats_not_supported</code> to the other one.</span>
    </label>
  </fieldset>
  <div class="row">
    <button id="start">Start presentation</button>
    <span id="startStatus" class="hint"></span>
  </div>
</section>

<section id="requestPanel" class="hidden">
  <h2>Request</h2>
  <pre id="requestUri"></pre>
  <div class="row">
    <a id="openWallet"><button class="secondary" type="button">Open in wallet</button></a>
    <button id="copy" class="secondary" type="button">Copy URI</button>
  </div>
</section>

<section id="resultPanel" class="hidden">
  <h2>Result</h2>
  <dl>
    <dt>Status</dt><dd><span id="status" class="status">–</span></dd>
    <dt>Response mode</dt><dd id="responseMode">–</dd>
    <dt>Encryption</dt><dd id="encryption">–</dd>
  </dl>
  <pre id="payload">Waiting for the wallet…</pre>
</section>

${config}
<script>
  const $ = (id) => document.getElementById(id)
  let poller = null

  const selectedMode = () => document.querySelector('input[name=mode]:checked').value
  const selectedFormat = () => document.querySelector('input[name=format]:checked').value

  const render = (result) => {
    $('status').textContent = result.status
    $('status').dataset.state = result.status
    $('responseMode').textContent = result.responseMode
    $('encryption').textContent = result.encryption
      ? result.encryption.alg + (result.encryption.kid ? ' (kid: ' + result.encryption.kid + ')' : '')
      : result.responseMode === 'direct_post.jwt' ? '–' : 'not encrypted'

    if (result.status === 'verified') {
      $('payload').textContent = JSON.stringify(result.vpPayload, null, 2)
    } else if (result.status === 'failed') {
      $('payload').textContent = JSON.stringify(result.error, null, 2)
    }
  }

  const poll = (transactionId) => {
    clearInterval(poller)
    poller = setInterval(async () => {
      try {
        const res = await fetch(SERVER_URL + '/presentations/' + encodeURIComponent(transactionId))
        if (!res.ok) return
        const result = await res.json()
        render(result)
        if (result.status !== 'pending') clearInterval(poller)
      } catch {
        // The verifier is momentarily unreachable; the next tick retries.
      }
    }, 1000)
  }

  $('start').addEventListener('click', async () => {
    const button = $('start')
    const status = $('startStatus')
    button.disabled = true
    status.textContent = 'Creating…'
    try {
      const mode = selectedMode()
      const credentialFormat = selectedFormat()
      const endpoint = mode === 'direct_post.jwt' ? '/request-encrypted' : '/request'
      const res = await fetch(SERVER_URL + endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          credentialId: 'UniversityDegreeCredential',
          state: crypto.randomUUID().replaceAll('-', ''),
          credentialFormat,
        }),
      })
      const body = await res.text()
      if (!res.ok) throw new Error(body)

      $('requestUri').textContent = body
      $('requestPanel').classList.remove('hidden')
      $('openWallet').href = WALLET_URL + '/?' + new URLSearchParams({ request: body }).toString()

      $('resultPanel').classList.remove('hidden')
      $('payload').textContent = 'Waiting for the wallet…'
      $('status').textContent = 'pending'
      $('status').dataset.state = 'pending'
      $('responseMode').textContent = mode
      $('encryption').textContent = '–'

      const transactionId = res.headers.get('x-presentation-transaction-id')
      if (transactionId) {
        poll(transactionId)
        status.textContent = 'Request created. Waiting for the wallet…'
      } else {
        status.textContent = 'Request created, but the transaction id header is missing.'
      }
    } catch (error) {
      status.textContent = 'Failed: ' + error
    } finally {
      button.disabled = false
    }
  })

  $('copy').addEventListener('click', () => navigator.clipboard.writeText($('requestUri').textContent))
</script>
`
      )
    )
  )

  /** The recorded exchanges, for the trace screen and for anything else watching. */
  uiApp.get('/trace', (c) => {
    if (!trace) return c.json({ enabled: false, entries: [] }, 200)
    const since = Number.parseInt(c.req.query('since') ?? '', 10)
    const entries = Number.isFinite(since) ? trace.since(since) : trace.list()
    return c.json({ enabled: traceEnabled, entries }, 200)
  })

  uiApp.delete('/trace', (c) => {
    trace?.clear()
    return c.json({ cleared: true }, 200)
  })

  uiApp.get('/ui/trace', (c) =>
    c.html(
      layout(
        'Protocol trace',
        `
<h1>Protocol trace</h1>
<p class="lede">Every HTTP exchange this server takes part in, in order.</p>

<p class="warn">
  Every OID4VCI and OID4VP message passes through this server, so this is the whole conversation.
  Bodies are shown verbatim, access tokens and pre-authorized codes included &mdash; which is why this
  belongs in a sample server only. Set <code>PROTOCOL_TRACE=off</code> to disable it.
  The wallet keeps its own trace of what it sent, at <a href="${escapeHtml(walletUrl)}/">the wallet screen</a>.
</p>

<div class="toolbar">
  <label><input type="checkbox" id="live" checked> Live</label>
  <label><input type="checkbox" id="hideUi" checked> Hide the screens&rsquo; own traffic</label>
  <label>Filter <input type="text" id="filter" placeholder="path, step or body" autocomplete="off"></label>
  <button id="clear" class="secondary" type="button">Clear</button>
  <span id="status" class="hint"></span>
</div>

<p id="emptyState" class="empty">Nothing yet. Run an issuance or a presentation.</p>
<div id="entries"></div>

${config}
<script>
  const $ = (id) => document.getElementById(id)

  let entries = []
  let lastId = 0
  let timer = null

  const statusClass = (status) =>
    status >= 500 ? 'code-5xx' : status >= 400 ? 'code-4xx' : 'code-2xx'

  const matchesFilter = (entry, needle) => {
    if (!needle) return true
    const haystack = [
      entry.step, entry.method, entry.path, entry.query ?? '',
      entry.request.body ?? '', entry.response.body ?? '',
      ...entry.notes,
    ].join(' ').toLowerCase()
    return haystack.includes(needle)
  }

  // Entries are built through the DOM, never innerHTML: their bodies are
  // whatever a client sent and must not be treated as markup.
  const messageSection = (title, message) => {
    const parts = []
    const heading = document.createElement('h4')
    heading.textContent = title
    parts.push(heading)

    const headerNames = Object.keys(message.headers ?? {})
    if (headerNames.length) {
      const headers = document.createElement('pre')
      headers.textContent = headerNames.map((name) => name + ': ' + message.headers[name]).join('\\n')
      parts.push(headers)
    }

    if (message.body) {
      const body = document.createElement('pre')
      body.textContent = message.body + (message.truncated ? '\\n… truncated' : '')
      parts.push(body)
    } else if (!headerNames.length) {
      const empty = document.createElement('p')
      empty.className = 'note'
      empty.textContent = 'empty'
      parts.push(empty)
    }
    return parts
  }

  const renderEntry = (entry) => {
    const details = document.createElement('details')
    details.className = 'entry'

    const summary = document.createElement('summary')

    const badge = document.createElement('span')
    badge.className = 'badge'
    badge.dataset.actor = entry.actor
    badge.textContent = entry.actor
    summary.append(badge)

    const step = document.createElement('span')
    step.className = 'step'
    step.textContent = entry.step
    summary.append(step)

    const meta = document.createElement('span')
    meta.className = 'meta'
    meta.textContent = entry.method + ' ' + entry.path
    summary.append(meta)

    const status = document.createElement('span')
    status.className = statusClass(entry.status)
    status.textContent = String(entry.status)
    summary.append(status)

    const timing = document.createElement('span')
    timing.className = 'meta'
    timing.textContent = new Date(entry.at).toLocaleTimeString() + ' · ' + entry.durationMs + 'ms'
    summary.append(timing)

    details.append(summary)

    const body = document.createElement('div')
    if (entry.notes.length) {
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
    if (entry.query) {
      const heading = document.createElement('h4')
      heading.textContent = 'Query'
      const query = document.createElement('pre')
      query.textContent = decodeURIComponent(entry.query)
      body.append(heading, query)
    }
    body.append(...messageSection('Request', entry.request))
    body.append(...messageSection('Response', entry.response))
    details.append(body)

    return details
  }

  // Entries are appended once and then only shown or hidden. Rebuilding the list
  // on every poll would collapse whatever the reader had expanded.
  const rendered = new Map()

  const append = (newEntries) => {
    const container = $('entries')
    for (const entry of newEntries) {
      const element = renderEntry(entry)
      rendered.set(entry.id, element)
      container.append(element)
    }
  }

  const render = () => {
    const needle = $('filter').value.trim().toLowerCase()
    const hideUi = $('hideUi').checked

    let visible = 0
    for (const entry of entries) {
      const element = rendered.get(entry.id)
      if (!element) continue
      const show = (!hideUi || entry.actor !== 'ui') && matchesFilter(entry, needle)
      element.hidden = !show
      if (show) visible++
    }

    const empty = $('emptyState')
    empty.hidden = visible > 0
    empty.textContent = entries.length
      ? 'Nothing matches the current filter.'
      : 'Nothing yet. Run an issuance or a presentation.'
  }

  const poll = async () => {
    try {
      const res = await fetch(SERVER_URL + '/trace?since=' + lastId)
      const body = await res.json()
      if (body.enabled === false) {
        $('status').textContent = 'Tracing is turned off (PROTOCOL_TRACE=off).'
        clearInterval(timer)
        return
      }
      if (body.entries.length) {
        entries = entries.concat(body.entries)
        lastId = body.entries[body.entries.length - 1].id
        append(body.entries)
        render()
      }
      $('status').textContent = entries.length + ' exchange(s)'
    } catch (error) {
      $('status').textContent = 'Not reachable: ' + error
    }
  }

  const setLive = (on) => {
    clearInterval(timer)
    if (on) timer = setInterval(poll, 1000)
  }

  $('live').addEventListener('change', (event) => setLive(event.target.checked))
  $('hideUi').addEventListener('change', render)
  $('filter').addEventListener('input', render)
  $('clear').addEventListener('click', async () => {
    await fetch(SERVER_URL + '/trace', { method: 'DELETE' })
    entries = []
    lastId = 0
    rendered.clear()
    $('entries').replaceChildren()
    render()
  })

  poll()
  setLive(true)
</script>
`
      )
    )
  )

  return uiApp
}
