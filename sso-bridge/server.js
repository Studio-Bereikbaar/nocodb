// Keycloak → NocoDB session bridge (facturatie.studiobereikbaar.nl)
//
// NocoDB CE 2026.08.1 has no OIDC strategy, so the oauth2-proxy gate in front of it checks the
// Keycloak identity and NocoDB then asks for its own password a second time. This proxy sits
// between the gate and NocoDB and removes that second login:
//
//   Traefik → auth (oauth2-proxy, sets X-Forwarded-Email) → sso-bridge → nocodb
//
// The NocoDB GUI, finding no session, calls POST /api/v1/auth/token/refresh with its httpOnly
// `refresh_token` cookie before it shows the sign-in page. On that one call the bridge makes sure
// the cookie belongs to the gate's verified email: if it does not, it inserts a fresh row in
// nc_user_refresh_tokens for that user (the same row NocoDB's own signin writes) and forwards the
// request with that token. NocoDB rotates it, sets the cookie and returns the JWT as usual.
// Everything else (API, assets, websockets) is passed through untouched.
//
// Also enforced: password signin only for the gate's own email (a Keycloak identity cannot sign
// in to NocoDB as somebody else). The bridge never writes users, roles or the cache: a user
// without token_version (invited, never signed in) is activated once by scripts/nc_sso_onboard.sh.
//
// Source basis (nocodb 2026.08.1): users.service.ts refreshToken(), models/UserRefreshToken.ts,
// nc_043_user_refresh_token.ts, nc-gui middleware/03.auth.global.ts. Re-check on every NocoDB bump.

'use strict';
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { Pool } = require('pg');

const UPSTREAM = new URL(process.env.UPSTREAM || 'http://nocodb:8080');
const PORT = Number(process.env.PORT || 8081);
const REFRESH_DAYS = Number(process.env.NC_REFRESH_TOKEN_EXP_IN_DAYS || 30);
// Route lists from auth.controller.ts; the GUI itself uses the unprefixed /auth/... form.
const routes = (tail) => ['/auth/', '/api/v1/db/auth/', '/api/v1/auth/', '/api/v2/auth/'].map((p) => p + tail);
const REFRESH_PATHS = new Set(routes('token/refresh'));
// signin and signup carry an email in the body: only the gate's own email may pass
const OWN_EMAIL_PATHS = new Set([...routes('user/signin'), ...routes('user/signup')]);

// Meta DB as the least-privilege role `nc_sso_bridge` (sso-bridge/role.sql): SELECT on five user
// columns, SELECT + INSERT on nc_user_refresh_tokens. Connection from the standard PG* env vars.
const pool = process.env.PGHOST ? new Pool({ max: 3, connectionTimeoutMillis: 3000 }) : null;
const log = (...a) => console.log(new Date().toISOString(), ...a);
// an idle-client error (DB restart) must not kill the process: the bridge is in the request path
if (pool) pool.on('error', (e) => log('meta db pool error:', e.message));

function cookieValue(header, name) {
  for (const part of (header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

function withCookie(header, name, value) {
  const kept = (header || '').split(';').map((s) => s.trim())
    .filter((s) => s && !s.startsWith(name + '='));
  kept.push(`${name}=${value}`);
  return kept.join('; ');
}

function gateEmail(req) {
  const e = req.headers['x-forwarded-email'];
  return typeof e === 'string' && e.includes('@') ? e.trim().toLowerCase() : null;
}

// Returns the refresh token to forward (the caller's own if it already matches the gate email),
// or null to forward the request unchanged.
async function ensureSession(email, current) {
  if (current) {
    const { rows } = await pool.query(
      `SELECT lower(u.email) AS email FROM nc_user_refresh_tokens t
         JOIN nc_users_v2 u ON u.id = t.fk_user_id
        WHERE t.token = $1 AND (t.expires_at IS NULL OR t.expires_at > now())`, [current]);
    if (rows[0] && rows[0].email === email) return current;
  }
  const { rows } = await pool.query(
    `SELECT id, token_version, blocked FROM nc_users_v2
      WHERE lower(email) = $1 AND deleted_at IS NULL`, [email]);
  const u = rows[0];
  if (!u) { log('no nocodb user for', email); return null; }
  if (u.blocked) { log('blocked nocodb user', email); return null; }
  if (!u.token_version) { log('user not activated (token_version null), run nc_sso_onboard.sh:', email); return null; }
  const token = crypto.randomBytes(40).toString('hex');   // same shape as randomTokenString()
  await pool.query(
    `INSERT INTO nc_user_refresh_tokens (fk_user_id, token, meta, expires_at, created_at, updated_at)
     VALUES ($1, $2, NULL, now() + make_interval(days => $3), now(), now())`, [u.id, token, REFRESH_DAYS]);
  log('session minted for', email);
  return token;
}

function forward(req, res, body, headers) {
  const up = http.request({
    host: UPSTREAM.hostname, port: UPSTREAM.port || 80, method: req.method, path: req.url,
    headers: { ...headers, host: req.headers.host },
  }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  up.on('error', (e) => { log('upstream error', e.message); if (!res.headersSent) res.writeHead(502); res.end(); });
  if (body) up.end(body); else req.pipe(up);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  // Express routing in NocoDB is case-insensitive and ignores a trailing slash: match the same way
  const path = req.url.split('?')[0].toLowerCase().replace(/\/{2,}/g, '/').replace(/(.)\/$/, '$1');
  const email = gateEmail(req);
  try {
    if (req.method === 'GET' && path === '/_bridge/health') { res.writeHead(200); return res.end('ok'); }

    if (req.method === 'POST' && REFRESH_PATHS.has(path) && email && pool) {
      const current = cookieValue(req.headers.cookie, 'refresh_token');
      const token = await ensureSession(email, current);
      const headers = { ...req.headers };
      if (token && token !== current) headers.cookie = withCookie(req.headers.cookie, 'refresh_token', token);
      if (!token && current) headers.cookie = withCookie(req.headers.cookie, 'refresh_token', '');  // never ride someone else's session
      return forward(req, res, null, headers);
    }

    if (req.method === 'POST' && OWN_EMAIL_PATHS.has(path) && email) {
      const body = await readBody(req);
      let asked = null;
      // strict: the GUI always posts JSON; anything that is not provably the gate's email is refused
      try { asked = String(JSON.parse(body.toString('utf8')).email || '').trim().toLowerCase(); } catch (_) { asked = null; }
      if (asked !== email) {
        log('signin refused:', email, 'tried', asked);
        res.writeHead(403, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ msg: `Signed in via Microsoft as ${email}; NocoDB signin is only allowed for that account.` }));
      }
      return forward(req, res, body, { ...req.headers, 'content-length': String(body.length) });
    }

    forward(req, res, null, req.headers);
  } catch (e) {
    log('bridge error, passing through:', e.message);
    if (!res.headersSent) forward(req, res, null, req.headers); else res.end();
  }
});

// websockets / socket.io: raw TCP pipe after replaying the upgrade request
server.on('upgrade', (req, socket, head) => {
  const up = net.connect(UPSTREAM.port || 80, UPSTREAM.hostname, () => {
    const lines = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    up.write(lines.join('\r\n') + '\r\n\r\n');
    if (head && head.length) up.write(head);
    socket.pipe(up).pipe(socket);
  });
  const close = () => { up.destroy(); socket.destroy(); };
  up.on('error', close); socket.on('error', close);
});

server.keepAliveTimeout = 65000;
server.listen(PORT, () => log(`sso-bridge on :${PORT} → ${UPSTREAM.href} (meta db ${pool ? 'on' : 'OFF: pass-through only'})`));
