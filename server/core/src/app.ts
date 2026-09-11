import { VcknotsContext } from '@trustknots/vcknots'
import { showRoutes } from 'hono/dev'
import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { createAuthzRouter } from './routes/authz.js'
import { createIssueRouter } from './routes/issue.js'
import { createUiRouter } from './routes/ui.js'
import { createVerifierRouter } from './routes/verify.js'
import { createProtocolTrace, protocolTraceMiddleware } from './utils/protocol-trace.js'

export const createApp = (context: VcknotsContext, baseUrl: string) => {
  const app = new Hono()

  // Watching the protocol flow is the point of the sample server, so tracing is
  // on unless it is turned off. It keeps request and response bodies in memory,
  // which is acceptable here and nowhere else.
  const traceEnabled = process.env.PROTOCOL_TRACE !== 'off'
  const trace = createProtocolTrace()
  if (traceEnabled) {
    app.use('*', protocolTraceMiddleware(trace))
  }

  app.route('/', createIssueRouter(context, baseUrl))
  app.route('/', createAuthzRouter(context, baseUrl))
  app.route('/', createVerifierRouter(context, baseUrl))
  app.route('/', createUiRouter(baseUrl, { trace, traceEnabled }))

  app.notFound((c) => c.json({ error: 'Not Found' }, 404))
  app.onError((err, c) => {
    if (err instanceof HTTPException) return err.getResponse()
    console.error(err)
    return c.json({ error: 'internal_server_error' }, 500)
  })

  showRoutes(app, { verbose: true })

  return app
}
