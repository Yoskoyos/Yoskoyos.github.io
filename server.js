// YCA CCTV Monitor — NVR proxy + autentificare
// Rulează pe VPS în /opt/nvr-proxy, ca serviciul systemd "nvr-proxy" (port 3000, în spatele nginx).
// v3 (28.10.2026): /auth/login, /auth/me, /auth/change-password, roluri, secret JWT în fișier,
//                  limitare încercări login, PUT cu body către NVR (sincronizare oră).

const http    = require('http');
const https   = require('https');
const url     = require('url');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');

const PORT           = parseInt(process.env.PORT || '3000', 10);
const BASE_DIR       = process.env.NVR_PROXY_DIR || __dirname;
const DB_FILE        = path.join(BASE_DIR, 'db.json');
const SECRET_FILE    = path.join(BASE_DIR, '.jwt-secret');
const MAX_CONCURRENT = 16;   // cereri simultane către NVR-uri (miniaturile cer multe imagini)
const MAX_BODY       = 5 * 1024 * 1024;   // 5 MB (config sincronizată)
const MIN_PASS_LEN   = 6;

/* ───────────── Secret JWT (generat o singură dată, nu stă în cod) ───────────── */
function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  try {
    const s = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (s.length >= 32) return s;
  } catch {}
  const s = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 });
  return s;
}
const JWT_SECRET = loadSecret();

/* ───────────── Bază de date (db.json) ───────────── */
// Format: { users: [ {id, username, password(bcrypt), role, nvrIds, createdAt} ], configs: { <username>: {...} } }
function loadDb() {
  let db;
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { db = {}; }
  if (!db || typeof db !== 'object') db = {};
  // compatibilitate: users poate fi obiect {username:{hash}} sau listă
  if (db.users && !Array.isArray(db.users)) {
    db.users = Object.entries(db.users).map(([username, u], i) => ({
      id: i + 1, username, password: u.hash || u.password, role: u.role,
    }));
  }
  db.users   = Array.isArray(db.users) ? db.users : [];
  db.configs = db.configs && typeof db.configs === 'object' ? db.configs : {};
  for (const u of db.users) {
    if (!u.role) u.role = (u.username === 'admin' || u.id === 1) ? 'admin' : 'client';
    if (u.role === 'client' && !Array.isArray(u.nvrIds)) u.nvrIds = [];
  }
  return db;
}
function saveDb(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}
function findUser(db, username) {
  const n = String(username || '').trim().toLowerCase();
  return db.users.find(u => String(u.username).toLowerCase() === n) || null;
}
function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, nvrIds: u.role === 'client' ? (u.nvrIds || []) : undefined };
}

/* ───────────── Limitare încercări login ───────────── */
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const FAIL_MAX       = 8;
const fails = new Map(); // cheie: username|ip -> {n, first}
function failKey(req, username) {
  const ip = req.headers['x-real-ip'] || (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
  return String(username || '').toLowerCase() + '|' + ip;
}
function isLocked(key) {
  const f = fails.get(key);
  if (!f) return false;
  if (Date.now() - f.first > FAIL_WINDOW_MS) { fails.delete(key); return false; }
  return f.n >= FAIL_MAX;
}
function addFail(key) {
  const f = fails.get(key);
  if (!f || Date.now() - f.first > FAIL_WINDOW_MS) fails.set(key, { n: 1, first: Date.now() });
  else f.n++;
}

/* ───────────── HTTP helpers ───────────── */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};
function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...CORS });
  res.end(JSON.stringify(obj));
}
function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('Body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  const raw = await readRaw(req);
  try { return JSON.parse(raw.toString('utf8') || '{}'); } catch { return {}; }
}
function getAuth(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer ')) return null;
  try { return jwt.verify(h.slice(7), JWT_SECRET); } catch { return null; }
}
// verifică tokenul și că utilizatorul încă există
function requireUser(req, res) {
  const p = getAuth(req);
  if (!p) { sendJson(res, 401, { error: 'Sesiune invalidă sau expirată' }); return null; }
  const db = loadDb();
  const u = findUser(db, p.id);
  if (!u) { sendJson(res, 401, { error: 'Cont inexistent' }); return null; }
  return { db, user: u };
}

/* ───────────── Digest auth către NVR ───────────── */
function md5(s) { return crypto.createHash('md5').update(s).digest('hex'); }

function buildDigestAuth(user, pass, method, uri, wwwAuth) {
  const realm  = (wwwAuth.match(/realm="([^"]*)"/)  || [])[1] || '';
  const nonce  = (wwwAuth.match(/nonce="([^"]*)"/)  || [])[1] || '';
  const opaque = (wwwAuth.match(/opaque="([^"]*)"/) || [])[1] || '';
  const qopRaw = (wwwAuth.match(/qop="?([^",]*)"?/) || [])[1] || '';
  const qop    = qopRaw.split(',').map(s => s.trim()).includes('auth') ? 'auth' : qopRaw;
  const nc     = '00000001';
  const cnonce = crypto.randomBytes(8).toString('hex');
  const ha1    = md5(`${user}:${realm}:${pass}`);
  const ha2    = md5(`${method}:${uri}`);
  const response = qop ? md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`);
  let header = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}"`;
  if (qop)    header += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  if (opaque) header += `, opaque="${opaque}"`;
  return header;
}

function proxyRequest(opts, nvrUser, nvrPass, body, contentType, res) {
  const lib    = opts.protocol === 'https:' ? https : http;
  const method = opts.method || 'GET';
  const uri    = opts.path;
  const baseHeaders = {};
  if (body && body.length) {
    baseHeaders['Content-Type']   = contentType || 'application/xml';
    baseHeaders['Content-Length'] = body.length;
  }
  const fail = (code, msg) => { try { if (!res.headersSent) res.writeHead(code, CORS); res.end(msg); } catch {} };

  const pipeBack = r => {
    res.writeHead(r.statusCode, {
      'Content-Type': r.headers['content-type'] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      ...CORS,
    });
    r.pipe(res);
  };

  const req1 = lib.request({ ...opts, headers: { ...baseHeaders } }, r1 => {
    if (r1.statusCode === 401) {
      const wwwAuth = r1.headers['www-authenticate'] || '';
      r1.resume();
      if (!wwwAuth.toLowerCase().includes('digest') || !nvrUser) { fail(401, 'Unauthorized'); return; }
      const digestHeader = buildDigestAuth(nvrUser, nvrPass, method, uri, wwwAuth);
      const req2 = lib.request({ ...opts, headers: { ...baseHeaders, Authorization: digestHeader } }, pipeBack);
      req2.on('error', e => fail(502, 'Proxy error: ' + e.message));
      req2.on('timeout', () => { req2.destroy(); fail(504, 'Timeout'); });
      if (body && body.length) req2.write(body);
      req2.end();
    } else {
      pipeBack(r1);
    }
  });
  req1.on('error', e => fail(502, 'Proxy error: ' + e.message));
  req1.on('timeout', () => { req1.destroy(); fail(504, 'Timeout'); });
  if (body && body.length) req1.write(body);
  req1.end();
}

let activeRequests = 0;
const requestQueue = [];
function processQueue() {
  while (requestQueue.length > 0 && activeRequests < MAX_CONCURRENT) {
    const next = requestQueue.shift();
    activeRequests++;
    next();
  }
}

/* ───────────── Rute ───────────── */
async function handleLogin(req, res) {
  const body = await readJson(req);
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!username || !password) return sendJson(res, 400, { error: 'Completează utilizatorul și parola' });

  const key = failKey(req, username);
  if (isLocked(key)) return sendJson(res, 429, { error: 'Prea multe încercări. Încearcă din nou peste 15 minute.' });

  const db = loadDb();
  const u = findUser(db, username);
  const ok = u && u.password ? await bcrypt.compare(password, u.password) : false;
  if (!ok) { addFail(key); return sendJson(res, 401, { error: 'Utilizator sau parolă greșită' }); }
  fails.delete(key);

  const remember = body.remember !== false;
  const token = jwt.sign({ id: u.username, role: u.role }, JWT_SECRET, { expiresIn: remember ? '30d' : '12h' });
  sendJson(res, 200, { token, username: u.username, role: u.role, user: publicUser(u), expiresIn: remember ? '30d' : '12h' });
}

async function handleChangePassword(req, res) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const body = await readJson(req);
  const pass = String(body.password || '');
  if (pass.length < MIN_PASS_LEN) return sendJson(res, 400, { error: `Parola trebuie să aibă minim ${MIN_PASS_LEN} caractere` });
  if (body.oldPassword !== undefined) {
    const ok = await bcrypt.compare(String(body.oldPassword), ctx.user.password || '');
    if (!ok) return sendJson(res, 403, { error: 'Parola actuală e greșită' });
  }
  ctx.user.password = await bcrypt.hash(pass, 10);
  ctx.user.passwordChangedAt = new Date().toISOString();
  saveDb(ctx.db);
  sendJson(res, 200, { ok: true });
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }

    const parsed   = url.parse(req.url, true);
    const pathname = parsed.pathname;

    // ── Autentificare ──
    if ((pathname === '/auth/login' || pathname === '/login') && req.method === 'POST') return await handleLogin(req, res);

    if (pathname === '/auth/me' && req.method === 'GET') {
      const ctx = requireUser(req, res); if (!ctx) return;
      return sendJson(res, 200, { username: ctx.user.username, role: ctx.user.role, user: publicUser(ctx.user) });
    }

    if (pathname === '/auth/change-password' && req.method === 'POST') return await handleChangePassword(req, res);

    if (pathname === '/health') return sendJson(res, 200, { ok: true, version: 3 });

    // ── Configurație sincronizată ──
    if (pathname === '/config' && req.method === 'GET') {
      const ctx = requireUser(req, res); if (!ctx) return;
      return sendJson(res, 200, ctx.db.configs[ctx.user.username] || {});
    }
    if (pathname === '/config' && req.method === 'POST') {
      const ctx = requireUser(req, res); if (!ctx) return;
      const body = await readJson(req);
      ctx.db.configs[ctx.user.username] = body;
      saveDb(ctx.db);
      return sendJson(res, 200, { ok: true });
    }

    // ── Proxy către NVR: /?url=http://user:pass@ip:port/ISAPI/... ──
    const target = parsed.query.url;
    if (!target) { res.writeHead(400, CORS); res.end('Missing ?url='); return; }

    let t;
    try { t = url.parse(decodeURIComponent(target)); } catch { res.writeHead(400, CORS); res.end('Bad url'); return; }
    if (!t.hostname || !/^https?:$/.test(t.protocol || '')) { res.writeHead(400, CORS); res.end('Bad url'); return; }

    // url.parse decodează deja partea user:pass
    const nvrUser = t.auth ? t.auth.split(':')[0] : null;
    const nvrPass = t.auth ? t.auth.split(':').slice(1).join(':') : null;
    const opts = {
      protocol: t.protocol,
      hostname: t.hostname,
      port: t.port || (t.protocol === 'https:' ? 443 : 80),
      path: t.path,
      method: req.method,
      timeout: 10000,
    };
    const body = (req.method === 'GET' || req.method === 'HEAD') ? null : await readRaw(req);
    const contentType = req.headers['content-type'];

    const run = () => {
      let done = false;
      const release = () => { if (done) return; done = true; activeRequests--; processQueue(); };
      res.on('finish', release);
      res.on('close',  release);
      proxyRequest(opts, nvrUser, nvrPass, body, contentType, res);
    };

    if (activeRequests >= MAX_CONCURRENT) {
      if (requestQueue.length >= 120) { res.writeHead(503, CORS); res.end('Queue full'); return; }
      requestQueue.push(run);
    } else {
      activeRequests++;
      run();
    }
  } catch (e) {
    try { sendJson(res, 500, { error: 'Eroare server' }); } catch {}
    console.error('Eroare:', e);
  }
});

server.listen(PORT, () => console.log('NVR Proxy v3 running on port ' + PORT));
