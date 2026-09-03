// Feeds Electron protocol requests straight into the Express app.
//
// No socket is ever opened: we build the IncomingMessage/ServerResponse pair that
// Express expects by hand, hand it to app(), and turn what Express writes back into
// a fetch Response. That keeps every existing route, middleware and status code
// working unchanged while removing the HTTP listener entirely.
import { IncomingMessage, ServerResponse } from 'node:http';
import { Socket } from 'node:net';

export function createDispatcher(app) {
  // Auth is a bearer JWT the renderer keeps in localStorage and sends as `Authorization`, which we
  // forward below — no cookies, so there is no jar to manage.
  return async function dispatch(request) {
    const url = new URL(request.url);
    const method = request.method || 'GET';
    const body = ['GET', 'HEAD'].includes(method)
      ? null : Buffer.from(await request.arrayBuffer());

    const req = new IncomingMessage(new Socket());
    req.method = method;
    req.url = url.pathname + url.search;
    req.headers = {};
    for (const [k, v] of request.headers) req.headers[k.toLowerCase()] = v;
    // Express/our own origin check compare against Host; keep them consistent and
    // never let the renderer forge one.
    req.headers.host = url.host;
    delete req.headers.origin;
    if (body) req.headers['content-length'] = String(body.length);
    if (body) req.push(body);
    req.push(null);

    return new Promise((resolve) => {
      const res = new ServerResponse(req);
      const chunks = [];
      const collect = (chunk, enc) => {
        if (!chunk || typeof chunk === 'function') return;
        chunks.push(Buffer.isBuffer(chunk) ? chunk
          : Buffer.from(chunk, typeof enc === 'string' ? enc : 'utf8'));
      };

      res.write = (chunk, enc, cb) => {
        collect(chunk, enc);
        (typeof enc === 'function' ? enc : cb)?.();
        return true;
      };
      res.end = (chunk, enc, cb) => {
        collect(chunk, enc);
        const out = new Headers();
        for (const [k, v] of Object.entries(res.getHeaders())) {
          if (v != null) out.set(k, String(v));
        }
        resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers: out }));
        (typeof chunk === 'function' ? chunk : typeof enc === 'function' ? enc : cb)?.();
        return res;
      };

      app(req, res);
    });
  };
}
