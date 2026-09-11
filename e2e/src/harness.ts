import { type ChildProcess, spawn } from 'node:child_process'
import { once } from 'node:events'
import { existsSync } from 'node:fs'
import { mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

/**
 * Starts the three processes an end-to-end run needs and tears them down again.
 *
 * The issuer and the verifier are the sample server; the wallet is the Go web
 * wallet. Both run as real processes over real HTTP, so what the suite exercises
 * is the wire protocol rather than an in-process shortcut — which is the only
 * way a Go wallet and a TypeScript verifier can be tested against each other.
 */

/** The repository root, from this file's location. */
export const repositoryRoot = resolve(import.meta.dirname, '..', '..')

/** Built entry point of the sample server. */
const serverEntry = join(repositoryRoot, 'server', 'single', 'lib', 'example.js')

/** Trust roots for the verifier certificate used by the signed Request Object flow. */
const verifierCertificate = join(
  repositoryRoot,
  'server',
  'samples',
  'certificate-openid-test',
  'certificate_openid.pem'
)

const READY_TIMEOUT_MS = 60_000
const READY_POLL_INTERVAL_MS = 200

export type Harness = {
  /** Base URL of the sample server, which acts as both issuer and verifier. */
  serverUrl: string
  /** Base URL of the web wallet. */
  walletUrl: string
  /** Everything the processes have written, for reporting a failure. */
  logs: () => string
  stop: () => Promise<void>
}

/** Asks the operating system for a port nothing else is using. */
const freePort = async (): Promise<number> => {
  const probe = createServer()
  probe.listen(0, '127.0.0.1')
  await once(probe, 'listening')
  const address = probe.address()
  if (address === null || typeof address === 'string') {
    throw new Error('failed to allocate a port')
  }
  const { port } = address
  await new Promise<void>((done) => probe.close(() => done()))
  return port
}

type LogSink = { append: (source: string, chunk: string) => void; text: () => string }

const createLogSink = (): LogSink => {
  const lines: string[] = []
  return {
    append(source, chunk) {
      for (const line of chunk.split('\n')) {
        if (line.trim()) lines.push(`[${source}] ${line}`)
      }
      // Keep the tail only; a failing run needs recent output, not all of it.
      if (lines.length > 400) lines.splice(0, lines.length - 400)
    },
    text: () => lines.join('\n'),
  }
}

const pipeInto = (child: ChildProcess, source: string, sink: LogSink) => {
  child.stdout?.on('data', (chunk) => sink.append(source, String(chunk)))
  child.stderr?.on('data', (chunk) => sink.append(source, String(chunk)))
}

/** Polls until the URL answers, or gives up with what the processes logged. */
const waitForReady = async (name: string, url: string, sink: LogSink) => {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError: unknown

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url)
      if (response.ok) return
      lastError = new Error(`status ${response.status}`)
    } catch (error) {
      lastError = error
    }
    await delay(READY_POLL_INTERVAL_MS)
  }

  throw new Error(
    `${name} did not become ready at ${url}: ${lastError}\n--- process output ---\n${sink.text()}`
  )
}

/** Stops a process and waits for it to actually be gone. */
const stopProcess = async (child: ChildProcess | undefined) => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  child.kill('SIGTERM')
  const exited = once(child, 'exit')
  const timedOut = delay(5_000).then(() => 'timeout' as const)
  if ((await Promise.race([exited, timedOut])) === 'timeout') {
    child.kill('SIGKILL')
    await once(child, 'exit')
  }
}

/**
 * Compiles the wallet to a binary rather than running it through `go run`.
 * `go run` starts the program as a grandchild, so signalling it does not
 * reliably stop the server it started.
 */
const buildWallet = async (outputDir: string, sink: LogSink): Promise<string> => {
  const binary = join(outputDir, 'webwallet')
  const build = spawn('go', ['build', '-o', binary, './webwallet/cmd/webwallet'], {
    cwd: join(repositoryRoot, 'wallet'),
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  pipeInto(build, 'go build', sink)

  const [code] = (await once(build, 'exit')) as [number | null]
  if (code !== 0) {
    throw new Error(`failed to build the web wallet (exit ${code})\n${sink.text()}`)
  }
  return binary
}

export const startHarness = async (): Promise<Harness> => {
  if (!existsSync(serverEntry)) {
    throw new Error(
      `The sample server is not built. Run:\n  pnpm --filter "@trustknots/server..." build\n(expected ${serverEntry})`
    )
  }

  const sink = createLogSink()
  const workDir = await mkdtemp(join(tmpdir(), 'vcknots-e2e-'))

  let server: ChildProcess | undefined
  let wallet: ChildProcess | undefined

  const stop = async () => {
    await Promise.all([stopProcess(server), stopProcess(wallet)])
    await rm(workDir, { recursive: true, force: true })
  }

  try {
    const walletBinary = await buildWallet(workDir, sink)
    const [serverPort, walletPort] = await Promise.all([freePort(), freePort()])
    const serverUrl = `http://localhost:${serverPort}`
    const walletUrl = `http://localhost:${walletPort}`

    server = spawn(process.execPath, [serverEntry], {
      cwd: repositoryRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        PORT: String(serverPort),
        BASE_URL: serverUrl,
        WALLET_UI_URL: walletUrl,
      },
    })
    pipeInto(server, 'server', sink)

    wallet = spawn(
      walletBinary,
      ['-addr', `:${walletPort}`, '-cert', verifierCertificate, '-allow-http'],
      { cwd: join(repositoryRoot, 'wallet'), stdio: ['ignore', 'pipe', 'pipe'] }
    )
    pipeInto(wallet, 'wallet', sink)

    await Promise.all([
      waitForReady('the sample server', `${serverUrl}/.well-known/openid-credential-issuer`, sink),
      waitForReady('the web wallet', `${walletUrl}/api/status`, sink),
    ])

    return { serverUrl, walletUrl, logs: sink.text, stop }
  } catch (error) {
    await stop()
    throw error
  }
}
