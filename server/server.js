// YCA CCTV Monitor — NVR proxy + autentificare
// Rulează pe VPS în /opt/nvr-proxy, ca serviciul systemd "nvr-proxy" (port 3000, în spatele nginx).
// v3 (28.10.2026): /auth/login, /auth/me, /auth/change-password, roluri, secret JWT în fișier,
//                  limitare încercări login, PUT cu body către NVR (sincronizare oră).
// v3.1 (28.10.2026): email pe cont, „Ai uitat parola?” cu link pe mail (/auth/forgot, /auth/reset),
//                  schimbare parolă cu parola actuală; după schimbare, sesiunile vechi sunt invalidate.
//                  Trimiterea mailurilor: nodemailer + /opt/nvr-proxy/mail.json (vezi mail.example.json).
// v4 (28.10.2026): MONITORIZARE 24/7 pe server — verifică NVR-urile din config-ul fiecărui utilizator
//                  la fiecare minut și trimite alerte pe Telegram (NVR căzut/revenit, cameră căzută/revenită,
//                  HDD cu eroare, înregistrare oprită), raport zilnic. Alertă doar după 2 verificări la rând.
//                  Stare în monitor-state.json. Dezactivare: variabila de mediu MONITOR=0.
// v4.1 (29.10.2026): GET /snap?nvr=&ch=&token= — captură din stream-ul RTSP (ffmpeg) pentru NVR-urile care nu
//                  oferă capturi ISAPI (ex. DS-7104NI-Q1). Credențialele NVR rămân pe server.
// v4.4: GET /company?cui= — datele firmei din serviciul public ANAF (PlatitorTvaRest v9), pt. completarea fișei clientului.
// v4.3: evidență clienți (clients.json) + contracte PDF stocate pe VPS în contracts/ (nu în GitHub).
// v4.2: monitorul ține cont și de canalele marcate în aplicație (seenCh) — ex. cameră pusă „urmărită” deși n-a mers niciodată.

const http    = require('http');
const https   = require('https');
const url     = require('url');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { spawn, execFileSync } = require('child_process');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');

const PORT           = parseInt(process.env.PORT || '3000', 10);
const BASE_DIR       = process.env.NVR_PROXY_DIR || __dirname;
const DB_FILE        = path.join(BASE_DIR, 'db.json');
const SECRET_FILE    = path.join(BASE_DIR, '.jwt-secret');
const MAX_CONCURRENT = 16;   // cereri simultane către NVR-uri (miniaturile cer multe imagini)
const MAX_BODY       = 5 * 1024 * 1024;   // 5 MB (config sincronizată)
const MIN_PASS_LEN   = 6;
const MAIL_FILE      = path.join(BASE_DIR, 'mail.json');
const RESET_TTL_MS   = 30 * 60 * 1000;     // linkul de resetare e valabil 30 minute
const DEFAULT_APP_URL = 'https://app.supraveghere24h.ro/';

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
// Format: { users: [ {id, username, email, password(bcrypt), role, nvrIds, pwv, passwordChangedAt, reset:{hash,exp}} ], configs: { <username>: {...} } }
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
  return { id: u.id, username: u.username, role: u.role, email: u.email || '', nvrIds: u.role === 'client' ? (u.nvrIds || []) : undefined };
}
function findUserByLogin(db, login) {
  const n = String(login || '').trim().toLowerCase();
  if (!n) return null;
  return db.users.find(u => String(u.username).toLowerCase() === n || (u.email && String(u.email).toLowerCase() === n)) || null;
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }
function issueToken(u, remember) {
  // pwv = versiunea parolei; crește la fiecare schimbare/resetare → sesiunile vechi devin invalide
  return jwt.sign({ id: u.username, role: u.role, pwv: u.pwv || 0 }, JWT_SECRET, { expiresIn: remember ? '30d' : '12h' });
}

/* ───────────── Mail (nodemailer, configurat în mail.json) ───────────── */
function loadMailCfg() {
  try { return JSON.parse(fs.readFileSync(MAIL_FILE, 'utf8')); } catch { return null; }
}
function mailReady() {
  const c = loadMailCfg();
  if (!c || !c.host || !c.user || !c.pass) return false;
  try { require.resolve('nodemailer'); return true; } catch { return false; }
}
async function sendMail(to, subject, text, html) {
  const c = loadMailCfg();
  if (!c || !c.host || !c.user || !c.pass) { console.error('Mail neconfigurat (lipsește mail.json)'); return false; }
  let nodemailer;
  try { nodemailer = require('nodemailer'); } catch { console.error('Lipsește nodemailer: rulează „npm install nodemailer” în ' + BASE_DIR); return false; }
  const port = parseInt(c.port || 465, 10);
  const transport = nodemailer.createTransport({
    host: c.host, port, secure: c.secure !== undefined ? !!c.secure : port === 465,
    auth: { user: c.user, pass: c.pass },
  });
  try {
    await transport.sendMail({ from: c.from || c.user, to, subject, text, html });
    return true;
  } catch (e) { console.error('Eroare trimitere mail:', e.message); return false; }
}
function escHtml(s) { return String(s).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }

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
function readRaw(req, limit) {
  const max = limit || MAX_BODY;
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > max) { chunks.length = 0; return; }   // citim până la capăt (fără să păstrăm), ca să putem răspunde 413
      chunks.push(c);
    });
    req.on('end', () => size > max ? reject(new Error('Body too large')) : resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req) {
  const raw = await readRaw(req);
  try { return JSON.parse(raw.toString('utf8') || '{}'); } catch { return {}; }
}
function getAuth(req) {
  const h = req.headers['authorization'] || '';
  let tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!tok) {   // <img src> nu poate trimite antete → tokenul poate veni și în ?token= (doar pentru /snap)
    try {
      const q = url.parse(req.url, true);
      const tokOk = q.pathname === '/snap' || (req.method === 'GET' && /^\/clients\/[\w-]+\/contracts\/[\w-]+$/.test(q.pathname || ''));
      if (tokOk && q.query.token) tok = String(q.query.token);
    } catch {}
  }
  if (!tok) return null;
  try { return jwt.verify(tok, JWT_SECRET); } catch { return null; }
}
// verifică tokenul și că utilizatorul încă există
function requireUser(req, res) {
  const p = getAuth(req);
  if (!p) { sendJson(res, 401, { error: 'Sesiune invalidă sau expirată' }); return null; }
  const db = loadDb();
  const u = findUser(db, p.id);
  if (!u) { sendJson(res, 401, { error: 'Cont inexistent' }); return null; }
  // token emis înainte de ultima schimbare/resetare a parolei → invalid
  if ((p.pwv || 0) !== (u.pwv || 0)) {
    sendJson(res, 401, { error: 'Parola a fost schimbată. Autentifică-te din nou.' }); return null;
  }
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


/* ═════════════ Monitorizare 24/7 (rulează pe server, independent de aplicație) ═════════════ */
const MONITOR_ENABLED     = process.env.MONITOR !== '0';
const MONITOR_INTERVAL_MS = parseInt(process.env.MONITOR_INTERVAL_MS || '60000', 10);
const MON_CONFIRM         = 2;          // câte verificări la rând confirmă o problemă
const MON_PARALLEL        = 4;          // câte NVR-uri verificăm simultan
const MON_STATE_FILE      = path.join(BASE_DIR, 'monitor-state.json');
const TG_API_BASE         = new URL(process.env.TG_API_BASE || 'https://api.telegram.org');   // schimbat doar la teste

let monState = (() => { try { return JSON.parse(fs.readFileSync(MON_STATE_FILE, 'utf8')) || {}; } catch { return {}; } })();
if (!monState.nvr) monState = { nvr: {}, reports: {} };
let monLastRun = null, monRunning = false;

function saveMonState() {
  try {
    const tmp = MON_STATE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(monState), { mode: 0o600 });
    fs.renameSync(tmp, MON_STATE_FILE);
  } catch (e) { console.error('Monitor: nu pot salva starea:', e.message); }
}

// Cerere GET directă către NVR (cu Digest auth), întoarce {status, body}; status 0 = nu răspunde
function nvrGet(nvr, cred, pathName, timeoutMs) {
  return new Promise(resolve => {
    let finished = false;
    const done = (status, body) => { if (!finished) { finished = true; resolve({ status, body: body || '' }); } };
    const opts = { hostname: String(nvr.ip).trim(), port: parseInt(nvr.port, 10) || 80, path: pathName, method: 'GET', timeout: timeoutMs || 8000, headers: {} };
    const collect = (res) => {
      let b = ''; res.setEncoding('utf8');
      res.on('data', d => { if (b.length < 300000) b += d; });
      res.on('end', () => done(res.statusCode, b));
      res.on('error', () => done(0, ''));
    };
    let r1;
    try {
      r1 = http.request(opts, res1 => {
        if (res1.statusCode === 401) {
          const wa = res1.headers['www-authenticate'] || '';
          res1.resume();
          if (!wa.toLowerCase().includes('digest')) return done(401, '');
          const user = cred.user || 'admin';
          const h = buildDigestAuth(user, cred.pass || '', 'GET', pathName, wa);
          const r2 = http.request({ ...opts, headers: { Authorization: h } }, collect);
          r2.on('error', () => done(0, ''));
          r2.on('timeout', () => { r2.destroy(); done(0, ''); });
          r2.end();
          return;
        }
        collect(res1);
      });
    } catch { return done(0, ''); }
    r1.on('error', () => done(0, ''));
    r1.on('timeout', () => { r1.destroy(); done(0, ''); });
    r1.end();
  });
}

// Verifică un NVR: online? + camere (InputProxy) + HDD + înregistrare
async function probeNvr(nvr, cred) {
  const info = await nvrGet(nvr, cred, '/ISAPI/System/deviceInfo', 9000);
  if (!(info.status === 200 || info.status === 401)) return { online: false };
  const out = { online: true, authOk: info.status === 200, cams: null, hdds: null, rec: null };
  const [ip, hdd, rec] = await Promise.all([
    nvrGet(nvr, cred, '/ISAPI/ContentMgmt/InputProxy/channels/status', 8000),
    nvrGet(nvr, cred, '/ISAPI/ContentMgmt/Storage/hdd', 8000),
    nvrGet(nvr, cred, '/ISAPI/ContentMgmt/record/control/manual/status/tracks', 8000),
  ]);
  if (ip.status === 200) {
    const per = {};
    for (const b of ip.body.matchAll(/<InputProxyChannelStatus\b[^>]*>([\s\S]*?)<\/InputProxyChannelStatus>/g)) {
      const id = b[1].match(/<id\b[^>]*>\s*(\d+)\s*<\/id>/);
      const on = b[1].match(/<online\b[^>]*>\s*(true|false)\s*<\/online>/);
      if (id && on) per[parseInt(id[1], 10)] = on[1] === 'true';
    }
    if (Object.keys(per).length) out.cams = per;
  }
  if (hdd.status === 200) {
    out.hdds = [...hdd.body.matchAll(/<hdd\b[^>]*>([\s\S]*?)<\/hdd>/g)].map(b => {
      const get = t => { const m = b[1].match(new RegExp(`<${t}\\b[^>]*>([^<]*)</${t}>`)); return m ? m[1].trim() : null; };
      return { id: get('id') || '?', name: get('hddName') || get('name') || 'HDD', capacity: parseInt(get('capacity') || '0', 10), status: (get('status') || 'unknown').toLowerCase() };
    }).filter(h => h.status !== 'notexist' && h.capacity > 0);
  }
  if (rec.status === 200) {
    out.rec = {};
    for (const m of rec.body.matchAll(/<TrackStatus\b[^>]*>[\s\S]*?<id>(\d+)<\/id>[\s\S]*?<enabled>(true|false)<\/enabled>[\s\S]*?<\/TrackStatus>/g)) {
      const ch = Math.floor(parseInt(m[1], 10) / 100);
      if (ch >= 1) out.rec[ch] = m[2] === 'true';
    }
  }
  return out;
}

const HDD_OK = new Set(['ok', 'idle', 'unknown', 'normal', 'sleep', 'standby']);

// Compară rezultatul cu starea anterioară și întoarce liniile de alertă
function evaluateNvr(key, nvr, res) {
  const st = monState.nvr[key] || (monState.nvr[key] = { status: 'unknown', fail: 0, cams: {}, camFail: {}, seen: {}, hdd: {}, rec: {} });
  st.name = nvr.name; st.addr = `${nvr.ip}:${nvr.port}`;
  const lines = [];
  const now = new Date().toISOString();

  if (!res.online) {
    st.fail++;
    if (st.status !== 'offline' && st.fail >= MON_CONFIRM) {
      st.status = 'offline'; st.since = now;
      lines.push({ kind: 'crit', text: `🔴 NVR nu răspunde (${st.addr})` });
    }
    st.lastCheck = now;
    return lines;
  }

  const wasOffline = st.status === 'offline';
  st.fail = 0;

  // camere
  if (res.cams) {
    const appSeen = nvr.seenCh || {};   // canale văzute online în aplicație sau marcate „urmărește” de utilizator
    for (const [chS, on] of Object.entries(res.cams)) {
      const ch = parseInt(chS, 10);
      if (!on && !st.seen[ch] && appSeen[ch]) st.seen[ch] = true;
      if (on) {
        if (st.cams[ch] === 'err') lines.push({ kind: 'info', text: `🟢 CH${ch} — cameră revenită online` });
        st.cams[ch] = 'ok'; st.camFail[ch] = 0; st.seen[ch] = true;
      } else if (st.seen[ch]) {
        st.camFail[ch] = (st.camFail[ch] || 0) + 1;
        if (st.cams[ch] !== 'err' && st.camFail[ch] >= MON_CONFIRM) {
          st.cams[ch] = 'err';
          lines.push({ kind: 'crit', text: `🔴 CH${ch} — cameră offline` });
        }
      }
    }
    // canale scoase din NVR → uităm de ele
    for (const ch of Object.keys(st.cams)) if (!(ch in res.cams)) { delete st.cams[ch]; delete st.camFail[ch]; delete st.seen[ch]; }
  }
  const camsTotal = Object.keys(st.seen).length;
  const camsOk = Object.entries(st.cams).filter(([ch, v]) => v === 'ok' && st.seen[ch]).length;
  st.camsOk = camsOk; st.camsTotal = camsTotal;

  if (wasOffline) lines.unshift({ kind: 'info', text: `🟢 NVR revenit online${camsTotal ? ` · ${camsOk}/${camsTotal} camere active` : ''}` });

  // HDD
  if (res.hdds) {
    for (const h of res.hdds) {
      const bad = !HDD_OK.has(h.status);
      if (bad && st.hdd[h.id] !== 'bad') lines.push({ kind: 'crit', text: `🔴 ${h.name} — eroare HDD: ${h.status.toUpperCase()}` });
      if (!bad && st.hdd[h.id] === 'bad') lines.push({ kind: 'info', text: `🟢 ${h.name} — HDD revenit OK` });
      st.hdd[h.id] = bad ? 'bad' : 'ok';
    }
  }

  // înregistrare (doar tranziția „înregistra” → „oprit”, pe camere online)
  if (res.rec) {
    for (const [chS, on] of Object.entries(res.rec)) {
      const ch = parseInt(chS, 10);
      if (st.cams[ch] !== 'ok') continue;
      if (on === false && st.rec[ch] === true) lines.push({ kind: 'crit', text: `🔴 CH${ch} — a oprit înregistrarea!` });
      if (on === true && st.rec[ch] === false) lines.push({ kind: 'info', text: `🟢 CH${ch} — înregistrare reluată` });
      st.rec[ch] = on;
    }
  }

  if (st.status !== 'online') st.since = now;
  st.status = Object.values(st.cams).some(v => v === 'err') ? 'warning' : 'online';
  st.lastCheck = now; st.lastSeen = now;
  return lines;
}

function tgSend(ucfg, text) {
  if (!ucfg || !ucfg.tgEnabled || !ucfg.tgToken || !ucfg.tgChatId) return Promise.resolve(false);
  return new Promise(resolve => {
    const body = JSON.stringify({ chat_id: ucfg.tgChatId, text, parse_mode: 'HTML', disable_web_page_preview: true });
    const lib = TG_API_BASE.protocol === 'http:' ? http : https;
    const r = lib.request({
      hostname: TG_API_BASE.hostname, port: TG_API_BASE.port || undefined, path: `/bot${ucfg.tgToken}/sendMessage`, method: 'POST', timeout: 10000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => { res.resume(); res.on('end', () => resolve(res.statusCode === 200)); });
    r.on('error', e => { console.error('Telegram:', e.message); resolve(false); });
    r.on('timeout', () => { r.destroy(); resolve(false); });
    r.end(body);
  });
}
const bucNow = () => new Date().toLocaleString('ro-RO', { timeZone: 'Europe/Bucharest' });

async function monitorRun() {
  if (monRunning) return;
  monRunning = true;
  try {
    const db = loadDb();
    const tasks = [], live = new Set();
    for (const [user, conf] of Object.entries(db.configs || {})) {
      if (!conf || !Array.isArray(conf.nvrs)) continue;
      const credMap = conf.creds || {};
      for (const nvr of conf.nvrs) {
        if (!nvr || !nvr.ip || nvr.id === undefined) continue;
        const key = user + ':' + nvr.id;
        live.add(key);
        tasks.push({ user, key, nvr, cred: credMap[nvr.id] || credMap[String(nvr.id)] || {}, ucfg: conf.cfg || {} });
      }
    }
    const out = {};  // user → { ucfg, blocks: [] }
    let i = 0;
    await Promise.all(Array.from({ length: MON_PARALLEL }, async () => {
      while (i < tasks.length) {
        const t = tasks[i++];
        let res;
        try { res = await probeNvr(t.nvr, t.cred); } catch { res = { online: false }; }
        const lines = evaluateNvr(t.key, t.nvr, res);
        if (lines.length) (out[t.user] || (out[t.user] = { ucfg: t.ucfg, blocks: [] })).blocks.push({ nvr: t.nvr, lines });
      }
    }));
    for (const k of Object.keys(monState.nvr)) if (!live.has(k)) delete monState.nvr[k];

    for (const [user, { ucfg, blocks }] of Object.entries(out)) {
      const anyCrit = blocks.some(b => b.lines.some(l => l.kind === 'crit'));
      const text = `${anyCrit ? '🚨' : '✅'} <b>YCA CCTV Monitor</b>\n\n` +
        blocks.map(b => `<b>${escHtml(b.nvr.name)}</b>\n` + b.lines.map(l => escHtml(l.text)).join('\n')).join('\n\n') +
        `\n\n🕐 ${bucNow()}`;
      for (const b of blocks) for (const l of b.lines) console.log(`[monitor] ${user} · ${b.nvr.name}: ${l.text}`);
      const sent = await tgSend(ucfg, text);
      if (!sent && ucfg.tgEnabled) console.error(`[monitor] Telegram nu a putut trimite pentru ${user}`);
    }

    // raport zilnic
    const hm = new Date().toLocaleTimeString('ro-RO', { timeZone: 'Europe/Bucharest', hour: '2-digit', minute: '2-digit', hour12: false });
    const today = new Date().toLocaleDateString('ro-RO', { timeZone: 'Europe/Bucharest' });
    for (const [user, conf] of Object.entries(db.configs || {})) {
      const ucfg = (conf && conf.cfg) || {};
      if (!ucfg.dailyReport || !Array.isArray(conf.nvrs) || !conf.nvrs.length) continue;
      if ((ucfg.dailyReportTime || '08:00') > hm || monState.reports[user] === today) continue;
      monState.reports[user] = today;
      const rows = conf.nvrs.map(n => {
        const st = monState.nvr[user + ':' + n.id] || {};
        const icon = st.status === 'online' ? '🟢' : st.status === 'offline' ? '🔴' : st.status === 'warning' ? '🟡' : '⚪';
        return `${icon} ${escHtml(n.name)} — ${(st.status || 'necunoscut').toUpperCase()}${st.camsTotal ? ` · ${st.camsOk}/${st.camsTotal} cam` : ''}`;
      });
      const on = conf.nvrs.filter(n => ['online', 'warning'].includes((monState.nvr[user + ':' + n.id] || {}).status)).length;
      await tgSend(ucfg, `📊 <b>Raport zilnic — YCA CCTV Monitor</b>\n🕐 ${bucNow()}\n\n✅ NVR online: <b>${on}/${conf.nvrs.length}</b>\n\n${rows.join('\n')}`);
    }

    monLastRun = new Date().toISOString();
    saveMonState();
  } catch (e) {
    console.error('[monitor] eroare:', e);
  } finally {
    monRunning = false;
  }
}

if (MONITOR_ENABLED) {
  setTimeout(monitorRun, 5000);
  setInterval(monitorRun, MONITOR_INTERVAL_MS);
  console.log(`[monitor] pornit — verificare la ${MONITOR_INTERVAL_MS / 1000}s, alertă după ${MON_CONFIRM} verificări`);
}


/* ═════════════ Capturi din stream RTSP (ffmpeg) ═════════════ */
let _ffmpegOk = null;
function hasFfmpeg() {
  if (_ffmpegOk !== null) return _ffmpegOk;
  try { execFileSync('ffmpeg', ['-version'], { stdio: 'ignore', timeout: 5000 }); _ffmpegOk = true; } catch { _ffmpegOk = false; }
  return _ffmpegOk;
}
const FF_MAX = 3;                 // câte ffmpeg simultan (protejăm procesorul VPS-ului)
let ffActive = 0; const ffQueue = [];
const snapCache = new Map();      // cheie → { t, buf } (3 s)
const snapInflight = new Map();   // cheie → Promise (cereri identice simultane → un singur ffmpeg)

function runFfmpeg(rtspUrl) {
  return new Promise(resolve => {
    const go = () => {
      ffActive++;
      const args = ['-hide_banner', '-loglevel', 'error', '-rtsp_transport', 'tcp', '-i', rtspUrl,
                    '-frames:v', '1', '-vf', 'scale=960:-2', '-q:v', '6', '-f', 'image2', '-c:v', 'mjpeg', 'pipe:1'];
      let p;
      try { p = spawn('ffmpeg', args, { stdio: ['ignore', 'pipe', 'pipe'] }); }
      catch (e) { ffActive--; if (ffQueue.length) ffQueue.shift()(); return resolve({ err: e.message }); }
      const chunks = []; let size = 0, err = '';
      p.stdout.on('data', d => { size += d.length; if (size < 8e6) chunks.push(d); });
      p.stderr.on('data', d => { if (err.length < 2000) err += d; });
      const killer = setTimeout(() => { try { p.kill('SIGKILL'); } catch {} }, 10000);
      let done = false;
      const finish = (code) => {
        if (done) return; done = true;
        clearTimeout(killer); ffActive--; if (ffQueue.length) ffQueue.shift()();
        resolve(code === 0 && size > 0 ? { buf: Buffer.concat(chunks) } : { err: err.trim() || ('ffmpeg ieșire ' + code) });
      };
      p.on('close', finish);
      p.on('error', e => { err += e.message; finish(-1); });
    };
    if (ffActive < FF_MAX) go(); else ffQueue.push(go);
  });
}

async function handleSnap(req, res, parsed) {
  const ctx = requireUser(req, res); if (!ctx) return;
  if (!hasFfmpeg()) return sendJson(res, 501, { error: 'ffmpeg nu e instalat pe server' });
  const conf = ctx.db.configs[ctx.user.username] || {};
  const nvr = (conf.nvrs || []).find(n => String(n.id) === String(parsed.query.nvr));
  const ch = parseInt(parsed.query.ch, 10);
  if (!nvr || !(ch >= 1 && ch <= 64)) return sendJson(res, 404, { error: 'NVR sau canal inexistent' });
  const host = String(nvr.ip || '').trim();
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) return sendJson(res, 400, { error: 'Adresă NVR invalidă' });
  const cred = (conf.creds || {})[nvr.id] || (conf.creds || {})[String(nvr.id)] || {};
  const port = parseInt(nvr.rtspPort, 10) || 554;
  const key = `${ctx.user.username}:${nvr.id}:${ch}`;

  const cached = snapCache.get(key);
  let r = cached && Date.now() - cached.t < 3000 ? { buf: cached.buf } : null;
  if (!r) {
    let pr = snapInflight.get(key);
    if (!pr) {
      pr = (async () => {
        const auth = `${encodeURIComponent(cred.user || 'admin')}:${encodeURIComponent(cred.pass || '')}@`;
        let last = { err: '' };
        for (const stream of ['02', '01']) {           // întâi sub-stream (mai rapid), apoi main
          last = await runFfmpeg(`rtsp://${auth}${host}:${port}/Streaming/Channels/${ch}${stream}`);
          if (last.buf || /401|unauthori/i.test(last.err)) break;
        }
        return last;
      })().finally(() => snapInflight.delete(key));
      snapInflight.set(key, pr);
    }
    r = await pr;
    if (r.buf) {
      snapCache.set(key, { t: Date.now(), buf: r.buf });
      if (snapCache.size > 300) snapCache.delete(snapCache.keys().next().value);
    }
  }
  if (r.buf) {
    res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': r.buf.length, 'Cache-Control': 'no-store', ...CORS });
    return res.end(r.buf);
  }
  const e = String(r.err || '');
  const msg = /401|unauthori/i.test(e) ? 'Utilizator sau parolă greșită (RTSP)'
            : /refused|timed out|timeout|no route|unreachable|connection/i.test(e) ? 'Portul RTSP al NVR-ului nu răspunde'
            : /404|not found/i.test(e) ? 'Canalul nu are stream video'
            : 'Nu s-a putut citi imaginea din stream';
  return sendJson(res, 502, { error: msg });
}


/* ═════════════ Clienți + contracte ═════════════ */
// clients.json: { <username>: [ client, ... ] }   ·   PDF-uri: contracts/<username>/<clientId>/<fileId>.pdf
const CLIENTS_FILE  = path.join(BASE_DIR, 'clients.json');
const CONTRACTS_DIR = path.join(BASE_DIR, 'contracts');
const MAX_PDF       = 20 * 1024 * 1024;
function loadClients() {
  try { const c = JSON.parse(fs.readFileSync(CLIENTS_FILE, 'utf8')); return c && typeof c === 'object' ? c : {}; } catch { return {}; }
}
function saveClients(all) {
  const tmp = CLIENTS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(all, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CLIENTS_FILE);
}
const newId = () => Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
const str = (v, max) => String(v == null ? '' : v).slice(0, max || 300);
const num = v => { const n = parseFloat(String(v).replace(',', '.')); return isFinite(n) ? n : 0; };
const ymd = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) ? String(v) : '';
// păstrăm doar câmpurile cunoscute (datele vin din aplicație)
function cleanClient(b, prev) {
  const e = b.equip || {}, sb = b.sub || {};
  const paid = {};
  for (const [k, v] of Object.entries(sb.paid || {})) if (/^\d{4}-\d{2}$/.test(k)) paid[k] = ymd(v) || new Date().toISOString().slice(0, 10);
  return {
    id: prev ? prev.id : newId(),
    kind: b.kind === 'pj' ? 'pj' : 'pf',
    name: str(b.name, 200).trim(), contact: str(b.contact, 200), code: str(b.code, 40),
    regCom: str(b.regCom, 40), phone: str(b.phone, 60), email: str(b.email, 200),
    address: str(b.address, 400), notes: str(b.notes, 4000),
    equip: { nvr: str(e.nvr, 200), cams: Math.max(0, Math.round(num(e.cams))), installDate: ymd(e.installDate),
             warrantyUntil: ymd(e.warrantyUntil), details: str(e.details, 4000), nvrId: e.nvrId != null ? str(e.nvrId, 40) : '' },
    sub: { active: !!sb.active, amount: Math.max(0, num(sb.amount)), dueDay: Math.min(28, Math.max(1, Math.round(num(sb.dueDay)) || 1)),
           start: /^\d{4}-\d{2}$/.test(sb.start || '') ? sb.start : '', paid },
    contracts: prev ? (prev.contracts || []) : [],
    createdAt: prev ? prev.createdAt : Date.now(), updatedAt: Date.now(),
  };
}
function userClients(all, username) { return Array.isArray(all[username]) ? all[username] : (all[username] = []); }

async function handleClients(req, res, pathname) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const uname = ctx.user.username;
  const all = loadClients(); const list = userClients(all, uname);
  const parts = pathname.split('/').filter(Boolean);           // clients[/id[/contracts[/cid]]]
  const id = parts[1], cid = parts[3];
  if (id && !/^[\w-]+$/.test(id)) return sendJson(res, 400, { error: 'ID invalid' });
  const cl = id ? list.find(c => c.id === id) : null;
  if (id && !cl) return sendJson(res, 404, { error: 'Client inexistent' });
  const dir = id ? path.join(CONTRACTS_DIR, uname.replace(/[^\w.-]/g, '_'), id) : null;

  if (parts.length === 1) {
    if (req.method === 'GET') return sendJson(res, 200, { clients: list });
    if (req.method === 'POST') {
      const b = await readJson(req);
      if (!str(b.name).trim()) return sendJson(res, 400, { error: 'Numele clientului e obligatoriu' });
      const c = cleanClient(b, null); list.push(c); saveClients(all);
      return sendJson(res, 200, { client: c });
    }
  }
  if (parts.length === 2) {
    if (req.method === 'PUT' || req.method === 'POST') {
      const b = await readJson(req);
      if (!str(b.name).trim()) return sendJson(res, 400, { error: 'Numele clientului e obligatoriu' });
      const c = cleanClient(b, cl); list[list.indexOf(cl)] = c; saveClients(all);
      return sendJson(res, 200, { client: c });
    }
    if (req.method === 'DELETE') {
      all[uname] = list.filter(c => c !== cl); saveClients(all);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      return sendJson(res, 200, { ok: true });
    }
  }
  if (parts[2] === 'contracts') {
    if (parts.length === 3 && req.method === 'POST') {
      let buf;
      try { buf = await readRaw(req, MAX_PDF); } catch { return sendJson(res, 413, { error: 'Fișierul e prea mare (maxim 20 MB)' }); }
      if (buf.length < 5 || buf.slice(0, 5).toString('latin1') !== '%PDF-') return sendJson(res, 400, { error: 'Fișierul nu e PDF' });
      const q = url.parse(req.url, true).query;
      const f = { id: newId(), name: (str(q.name, 150).replace(/[\\/:*?"<>|\r\n]/g, '_').trim() || 'contract.pdf'),
                  size: buf.length, uploadedAt: Date.now(), signedAt: ymd(q.signedAt), validUntil: ymd(q.validUntil) };
      if (!/\.pdf$/i.test(f.name)) f.name += '.pdf';
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(dir, f.id + '.pdf'), buf, { mode: 0o600 });
      cl.contracts = (cl.contracts || []).concat(f); cl.updatedAt = Date.now(); saveClients(all);
      return sendJson(res, 200, { contract: f, client: cl });
    }
    if (parts.length === 4) {
      if (!/^[\w-]+$/.test(cid || '')) return sendJson(res, 400, { error: 'ID invalid' });
      const f = (cl.contracts || []).find(x => x.id === cid);
      if (!f) return sendJson(res, 404, { error: 'Contract inexistent' });
      const fp = path.join(dir, f.id + '.pdf');
      if (req.method === 'GET') {
        let data; try { data = fs.readFileSync(fp); } catch { return sendJson(res, 404, { error: 'Fișierul lipsește de pe server' }); }
        const ascii = f.name.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, '');
        res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Length': data.length, 'Cache-Control': 'private, no-store',
          'Content-Disposition': `${url.parse(req.url, true).query.dl ? 'attachment' : 'inline'}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(f.name)}`, ...CORS });
        return res.end(data);
      }
      if (req.method === 'DELETE') {
        try { fs.unlinkSync(fp); } catch {}
        cl.contracts = cl.contracts.filter(x => x !== f); cl.updatedAt = Date.now(); saveClients(all);
        return sendJson(res, 200, { ok: true, client: cl });
      }
    }
  }
  return sendJson(res, 405, { error: 'Operație necunoscută' });
}


/* ═════════════ Date firmă după CUI (ANAF, serviciu public) ═════════════ */
const ANAF_URL = process.env.ANAF_URL || 'https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva';
const anafCache = new Map();           // cui → { t, data }  (24 h)
let anafChain = Promise.resolve();     // ANAF cere maxim 1 cerere/secundă → le punem la rând
function anafPost(cui) {
  const body = JSON.stringify([{ cui: Number(cui), data: new Date().toISOString().slice(0, 10) }]);
  return new Promise(resolve => {
    const u = new URL(ANAF_URL);
    const lib = u.protocol === 'http:' ? http : https;
    const r = lib.request({ hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, method: 'POST', timeout: 12000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, res => {
      let b = ''; res.setEncoding('utf8');
      res.on('data', d => { if (b.length < 500000) b += d; });
      res.on('end', () => { try { resolve({ status: res.statusCode, json: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, json: null }); } });
    });
    r.on('error', () => resolve({ status: 0 }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 0 }); });
    r.end(body);
  });
}
function anafQueued(cui) {
  const p = anafChain.then(() => anafPost(cui));
  anafChain = p.then(() => new Promise(r => setTimeout(r, 1100)), () => new Promise(r => setTimeout(r, 1100)));
  return p;
}
const cap = s => String(s || '').trim();
function anafParse(f) {
  const g = f.date_generale || f;                       // v8/v9: grupat; versiunile vechi: plat
  const tva = f.inregistrare_scop_Tva || f;
  const ina = f.stare_inactiv || f;
  const sa  = f.adresa_sediu_social || f;
  const street = [cap(sa.sdenumire_Strada), cap(sa.snumar_Strada) ? 'nr. ' + cap(sa.snumar_Strada) : ''].filter(Boolean).join(' ');
  const built = [street, cap(sa.sdetalii_Adresa), cap(sa.sdenumire_Localitate), cap(sa.sdenumire_Judet)].filter(Boolean).join(', ');
  return {
    cui: String(g.cui || ''), name: cap(g.denumire), regCom: cap(g.nrRegCom), phone: cap(g.telefon),
    address: cap(g.adresa) || built, postal: cap(g.codPostal || sa.scod_Postal),
    vat: !!tva.scpTVA, inactive: !!ina.statusInactivi, radiat: !!cap(ina.dataRadiere),
    state: cap(g.stare_inregistrare), caen: cap(g.cod_CAEN),
  };
}
async function handleCompany(req, res, parsed) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const cui = String(parsed.query.cui || '').toUpperCase().replace(/^RO/, '').replace(/\s+/g, '');
  if (!/^\d{2,10}$/.test(cui)) return sendJson(res, 400, { error: 'CUI invalid — doar cifre, cu sau fără RO' });
  const c = anafCache.get(cui);
  if (c && Date.now() - c.t < 24 * 3600e3) return sendJson(res, 200, c.data);
  const r = await anafQueued(cui);
  if (!r.status) return sendJson(res, 504, { error: 'ANAF nu răspunde acum — încearcă din nou peste un minut' });
  const found = r.json && Array.isArray(r.json.found) ? r.json.found : [];
  if (r.status !== 200 || !r.json) return sendJson(res, 502, { error: `ANAF a răspuns cu eroare (HTTP ${r.status})` });
  if (!found.length) return sendJson(res, 404, { error: 'CUI-ul nu există în baza ANAF' });
  const data = anafParse(found[0]);
  anafCache.set(cui, { t: Date.now(), data });
  if (anafCache.size > 500) anafCache.delete(anafCache.keys().next().value);
  return sendJson(res, 200, data);
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
  const u = findUserByLogin(db, username);
  const ok = u && u.password ? await bcrypt.compare(password, u.password) : false;
  if (!ok) { addFail(key); return sendJson(res, 401, { error: 'Utilizator sau parolă greșită' }); }
  fails.delete(key);

  const remember = body.remember !== false;
  const token = issueToken(u, remember);
  sendJson(res, 200, { token, username: u.username, role: u.role, user: publicUser(u), expiresIn: remember ? '30d' : '12h' });
}

async function handleChangePassword(req, res) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const body = await readJson(req);
  const pass = String(body.password || '');
  if (pass.length < MIN_PASS_LEN) return sendJson(res, 400, { error: `Parola trebuie să aibă minim ${MIN_PASS_LEN} caractere` });
  if (body.oldPassword === undefined) return sendJson(res, 400, { error: 'Introdu parola actuală' });
  const key = failKey(req, 'chg:' + ctx.user.username);
  if (isLocked(key)) return sendJson(res, 429, { error: 'Prea multe încercări. Încearcă din nou peste 15 minute.' });
  const ok = await bcrypt.compare(String(body.oldPassword), ctx.user.password || '');
  if (!ok) { addFail(key); return sendJson(res, 403, { error: 'Parola actuală e greșită' }); }
  if (await bcrypt.compare(pass, ctx.user.password || '')) return sendJson(res, 400, { error: 'Parola nouă trebuie să fie diferită de cea actuală' });
  ctx.user.password = await bcrypt.hash(pass, 10);
  ctx.user.passwordChangedAt = new Date().toISOString();
  ctx.user.pwv = (ctx.user.pwv || 0) + 1;
  delete ctx.user.reset;
  saveDb(ctx.db);
  // token nou pentru dispozitivul curent; celelalte sesiuni devin invalide
  sendJson(res, 200, { ok: true, token: issueToken(ctx.user, body.remember !== false) });
}

async function handleSetEmail(req, res) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const body = await readJson(req);
  const email = String(body.email || '').trim();
  if (email && !EMAIL_RE.test(email)) return sendJson(res, 400, { error: 'Adresă de email invalidă' });
  if (email && ctx.db.users.some(u => u !== ctx.user && u.email && u.email.toLowerCase() === email.toLowerCase()))
    return sendJson(res, 409, { error: 'Emailul e folosit deja de alt cont' });
  ctx.user.email = email || undefined;
  saveDb(ctx.db);
  sendJson(res, 200, { ok: true, email });
}

async function handleForgot(req, res) {
  const body = await readJson(req);
  const login = String(body.login || '').trim();
  const generic = { ok: true, message: 'Dacă există un cont cu email setat, vei primi în câteva minute un link de resetare.' };
  if (!login) return sendJson(res, 400, { error: 'Scrie utilizatorul sau emailul' });

  const key = failKey(req, 'forgot:' + login);
  if (isLocked(key)) return sendJson(res, 429, { error: 'Prea multe cereri. Încearcă din nou peste 15 minute.' });
  addFail(key); addFail(key); addFail(key); // max ~3 cereri / 15 min

  const db = loadDb();
  const u = findUserByLogin(db, login);
  if (!u || !u.email) return sendJson(res, 200, generic);

  const token = crypto.randomBytes(32).toString('hex');
  u.reset = { hash: sha256(token), exp: Date.now() + RESET_TTL_MS };
  saveDb(db);

  const cfg = loadMailCfg() || {};
  const appUrl = String(cfg.appUrl || DEFAULT_APP_URL);
  const link = appUrl + (appUrl.includes('?') ? '&' : '?') + 'reset=' + token;
  const subject = 'Resetare parolă — CCTV Monitor';
  const text = `Salut, ${u.username}!\n\nAi cerut resetarea parolei pentru CCTV Monitor (Supraveghere24h).\n` +
    `Deschide linkul de mai jos în 30 de minute ca să-ți setezi o parolă nouă:\n\n${link}\n\n` +
    `Dacă nu tu ai cerut asta, ignoră mesajul — parola ta rămâne neschimbată.`;
  const html = `<div style="font-family:Arial,sans-serif;font-size:15px;color:#0f1422;max-width:480px">
    <p>Salut, <b>${escHtml(u.username)}</b>!</p>
    <p>Ai cerut resetarea parolei pentru <b>CCTV Monitor</b> (Supraveghere24h).</p>
    <p><a href="${escHtml(link)}" style="display:inline-block;background:#00d9ff;color:#001018;font-weight:bold;text-decoration:none;padding:12px 22px;border-radius:8px">Setează o parolă nouă</a></p>
    <p style="color:#4a5568;font-size:13px">Linkul e valabil 30 de minute și poate fi folosit o singură dată.<br>Dacă nu tu ai cerut asta, ignoră mesajul — parola ta rămâne neschimbată.</p></div>`;
  const sent = await sendMail(u.email, subject, text, html);
  if (!sent) console.error(`Resetare cerută pentru ${u.username}, dar mailul nu a putut fi trimis.`);
  sendJson(res, 200, generic);
}

async function handleReset(req, res) {
  const body = await readJson(req);
  const token = String(body.token || '');
  const pass  = String(body.password || '');
  if (!/^[a-f0-9]{64}$/.test(token)) return sendJson(res, 400, { error: 'Link de resetare invalid' });
  if (pass.length < MIN_PASS_LEN) return sendJson(res, 400, { error: `Parola trebuie să aibă minim ${MIN_PASS_LEN} caractere` });
  const db = loadDb();
  const h = sha256(token);
  const u = db.users.find(x => x.reset && x.reset.hash === h);
  if (!u || !u.reset || u.reset.exp < Date.now()) {
    if (u) { delete u.reset; saveDb(db); }
    return sendJson(res, 400, { error: 'Linkul a expirat sau a fost deja folosit. Cere unul nou.' });
  }
  u.password = await bcrypt.hash(pass, 10);
  u.passwordChangedAt = new Date().toISOString();
  u.pwv = (u.pwv || 0) + 1;
  delete u.reset;
  saveDb(db);
  for (const k of [...fails.keys()]) if (k.startsWith(String(u.username).toLowerCase() + '|')) fails.delete(k);
  sendJson(res, 200, { ok: true, username: u.username });
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
      return sendJson(res, 200, { username: ctx.user.username, role: ctx.user.role, email: ctx.user.email || '', mail: mailReady(), monitor: MONITOR_ENABLED, user: publicUser(ctx.user) });
    }

    if (pathname === '/auth/change-password' && req.method === 'POST') return await handleChangePassword(req, res);
    if (pathname === '/auth/email'  && req.method === 'POST') return await handleSetEmail(req, res);
    if (pathname === '/auth/forgot' && req.method === 'POST') return await handleForgot(req, res);
    if (pathname === '/auth/reset'  && req.method === 'POST') return await handleReset(req, res);

    if (pathname === '/health') return sendJson(res, 200, { ok: true, version: 4.4, mail: mailReady(), rtsp: hasFfmpeg(), monitor: { enabled: MONITOR_ENABLED, lastRun: monLastRun, nvrs: Object.keys(monState.nvr).length } });
    if (pathname === '/snap' && req.method === 'GET') return await handleSnap(req, res, parsed);
    if (pathname === '/company' && req.method === 'GET') return await handleCompany(req, res, parsed);
    if (pathname === '/clients' || pathname.startsWith('/clients/')) return await handleClients(req, res, pathname);

    // Starea monitorizării pentru utilizatorul logat
    if (pathname === '/monitor' && req.method === 'GET') {
      const ctx = requireUser(req, res); if (!ctx) return;
      const conf = ctx.db.configs[ctx.user.username] || {};
      const list = (conf.nvrs || []).map(n => {
        const st = monState.nvr[ctx.user.username + ':' + n.id] || {};
        return { id: n.id, name: n.name, status: st.status || 'unknown', camsOk: st.camsOk != null ? st.camsOk : null, camsTotal: st.camsTotal != null ? st.camsTotal : null, lastCheck: st.lastCheck || null, since: st.since || null };
      });
      return sendJson(res, 200, { enabled: MONITOR_ENABLED, lastRun: monLastRun, telegram: !!(conf.cfg && conf.cfg.tgEnabled && conf.cfg.tgToken && conf.cfg.tgChatId), nvrs: list });
    }

    // ── Configurație sincronizată ──
    if (pathname === '/config' && req.method === 'GET') {
      const ctx = requireUser(req, res); if (!ctx) return;
      return sendJson(res, 200, ctx.db.configs[ctx.user.username] || {});
    }
    if (pathname === '/config' && req.method === 'POST') {
      const ctx = requireUser(req, res); if (!ctx) return;
      const body = await readJson(req);
      if (!body || typeof body !== 'object' || Array.isArray(body)) return sendJson(res, 400, { error: 'Config invalid' });
      // îmbinare: aplicația poate trimite doar setările (nvrs/creds/cfg) fără alerte/jurnal
      const prev = ctx.db.configs[ctx.user.username] || {};
      ctx.db.configs[ctx.user.username] = { ...prev, ...body, updatedAt: Number(body.updatedAt) || Date.now() };
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

server.listen(PORT, () => console.log('NVR Proxy v4.4 running on port ' + PORT + (hasFfmpeg() ? ' (ffmpeg OK)' : ' (fără ffmpeg)')));
