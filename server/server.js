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
// v5.0: POST /contact — formularele de contact de pe site (Home, Contact) → „mesaje” în lista de oferte + Telegram.
// v4.9: formula de preț de pe site (Webflow): bază 189 lei pt. 3 camere + 50/cameră suplimentară + 150/cameră lift,
//       contract 48 luni, neplătitor TVA; POST /cerere (formularul Webflow) → ofertă + redirect; GET /public/prices.
// v4.8: oferte doar pentru asociații de proprietari — abonament lunar fix pe durata contractului.
// v4.7: oferte — calculator public (/calculator, pentru iframe în WordPress), POST /public/quote, pagina ofertei
//                  /q/<token> cu Accept / Refuz / Cer clarificări, /quotes + /quote-settings (aplicație), Telegram, email.
// v4.6: GET /clients-backup — arhivă ZIP cu toți clienții (JSON + CSV) și documentele lor.
// v4.5: clienți — furnizor echipamente + documente de garanție (PDF/JPG/PNG), câmp `kind` la fișiere.
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
async function sendMail(to, subject, text, html, attachments) {
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
    await transport.sendMail({ from: c.from || c.user, to, subject, text, html, ...(attachments && attachments.length ? { attachments } : {}) });
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
      const tokOk = q.pathname === '/snap' || (req.method === 'GET' && (q.pathname === '/clients-backup' || /^\/clients\/[\w-]+\/contracts\/[\w-]+$/.test(q.pathname || '')));
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

/* ───────────── Notificări push pe telefon (Web Push / VAPID) ─────────────
   Cheile VAPID se generează o singură dată în vapid.json (nu ajung în repo); abonamentele în push-subs.json.
   Necesită modulul „web-push” (update.sh îl instalează). Fără el, restul serverului merge normal. */
const PUSH_FILE = path.join(BASE_DIR, 'push-subs.json');
const VAPID_FILE = path.join(BASE_DIR, 'vapid.json');
let _wp; let _vapid = null;
function webPush() {
  if (_wp !== undefined) return _wp;
  try {
    const wp = require('web-push');
    try { _vapid = JSON.parse(fs.readFileSync(VAPID_FILE, 'utf8')); } catch {}
    if (!_vapid || !_vapid.publicKey) { _vapid = wp.generateVAPIDKeys(); fs.writeFileSync(VAPID_FILE, JSON.stringify(_vapid), { mode: 0o600 }); }
    wp.setVapidDetails('mailto:contact@supraveghere24h.ro', _vapid.publicKey, _vapid.privateKey);
    _wp = wp;
  } catch (e) { console.error('Push: lipsește modulul web-push (rulează update.sh)'); _wp = null; }
  return _wp;
}
function loadPush() { try { return JSON.parse(fs.readFileSync(PUSH_FILE, 'utf8')); } catch { return {}; } }
function savePush(d) { const tmp = PUSH_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(d), { mode: 0o600 }); fs.renameSync(tmp, PUSH_FILE); }
const pushText = t => String(t).replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
async function pushSend(user, title, body, opt = {}) {
  const wp = webPush(); if (!wp) return 0;
  const all = loadPush(); const list = all[user] || []; if (!list.length) return 0;
  const payload = JSON.stringify({ title: pushText(title).slice(0, 120), body: pushText(body).slice(0, 900), tag: opt.tag || 'yca', url: opt.url || '/' });
  let ok = 0; const dead = new Set();
  await Promise.all(list.map(sub => wp.sendNotification({ endpoint: sub.endpoint, keys: sub.keys }, payload, { TTL: 6 * 3600, urgency: opt.urgency || 'high' })
    .then(() => { ok++; }).catch(e => { if (e && (e.statusCode === 404 || e.statusCode === 410)) dead.add(sub.endpoint); else console.error('Push:', e && (e.statusCode || e.message)); })));
  if (dead.size) { const a2 = loadPush(); a2[user] = (a2[user] || []).filter(x => !dead.has(x.endpoint)); savePush(a2); }
  return ok;
}
async function handlePush(req, res, pathname) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const user = ctx.user.username;
  if (pathname === '/push/key' && req.method === 'GET') {
    const wp = webPush(); const all = loadPush();
    return sendJson(res, 200, { ready: !!wp, key: wp ? _vapid.publicKey : null, devices: (all[user] || []).length });
  }
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'Metodă invalidă' });
  const b = await readJson(req);
  if (pathname === '/push/subscribe') {
    if (!webPush()) return sendJson(res, 503, { error: 'Serverul nu are încă notificările push — rulează actualizarea serverului' });
    const sub = b && b.subscription;
    if (!sub || typeof sub.endpoint !== 'string' || !/^https:\/\//.test(sub.endpoint) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return sendJson(res, 400, { error: 'Abonament invalid' });
    const all = loadPush(); const list = (all[user] || []).filter(x => x.endpoint !== sub.endpoint);
    list.push({ endpoint: sub.endpoint, keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) }, device: str(b.device || '', 80), at: Date.now() });
    all[user] = list.slice(-10); savePush(all);
    return sendJson(res, 200, { ok: true, devices: all[user].length });
  }
  if (pathname === '/push/unsubscribe') {
    const all = loadPush(); all[user] = (all[user] || []).filter(x => x.endpoint !== (b && b.endpoint)); savePush(all);
    return sendJson(res, 200, { ok: true, devices: all[user].length });
  }
  if (pathname === '/push/test') {
    const n = await pushSend(user, '🔔 Test CCTV Monitor', 'Notificările merg. Vei primi aici alertele NVR, cererile de ofertă și mesajele de pe site, 24/7.', { tag: 'yca-test' });
    return n ? sendJson(res, 200, { ok: true, sent: n }) : sendJson(res, 400, { error: 'Nu am putut trimite notificarea pe niciun dispozitiv' });
  }
  return sendJson(res, 404, { error: 'Necunoscut' });
}


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
      try {
        const ptitle = blocks.length === 1 ? `${anyCrit ? '🚨' : '✅'} ${blocks[0].nvr.name}` : `${anyCrit ? '🚨' : '✅'} ${blocks.length} NVR-uri`;
        const pbody = blocks.map(b => (blocks.length > 1 ? b.nvr.name + ': ' : '') + b.lines.map(l => l.text).join(' · ')).join('\n');
        await pushSend(user, ptitle, pbody, { tag: 'yca-mon-' + Date.now(), urgency: anyCrit ? 'high' : 'normal' });
      } catch (e) { console.error('[monitor] push:', e.message); }
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
             warrantyUntil: ymd(e.warrantyUntil), details: str(e.details, 4000), nvrId: e.nvrId != null ? str(e.nvrId, 40) : '',
             supplier: str(e.supplier, 200), supplierInvoice: str(e.supplierInvoice, 80), purchaseDate: ymd(e.purchaseDate) },
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
      const q = url.parse(req.url, true).query;
      const kind = q.kind === 'garantie' ? 'garantie' : 'contract';
      const head = buf.slice(0, 8);
      const ext = head.slice(0, 5).toString('latin1') === '%PDF-' ? 'pdf'
                : (kind === 'garantie' && head[0] === 0xFF && head[1] === 0xD8 && head[2] === 0xFF) ? 'jpg'
                : (kind === 'garantie' && head.slice(0, 4).toString('hex') === '89504e47') ? 'png' : null;
      if (!ext) return sendJson(res, 400, { error: kind === 'garantie' ? 'Fișierul trebuie să fie PDF, JPG sau PNG' : 'Fișierul nu e PDF' });
      const f = { id: newId(), kind, ext, name: (str(q.name, 150).replace(/[\\/:*?"<>|\r\n]/g, '_').trim() || (kind + '.' + ext)),
                  size: buf.length, uploadedAt: Date.now(), signedAt: ymd(q.signedAt), validUntil: ymd(q.validUntil) };
      if (!new RegExp('\\.' + (ext === 'jpg' ? 'jpe?g' : ext) + '$', 'i').test(f.name)) f.name += '.' + ext;
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(dir, f.id + '.' + ext), buf, { mode: 0o600 });
      cl.contracts = (cl.contracts || []).concat(f); cl.updatedAt = Date.now(); saveClients(all);
      return sendJson(res, 200, { contract: f, client: cl });
    }
    if (parts.length === 4) {
      if (!/^[\w-]+$/.test(cid || '')) return sendJson(res, 400, { error: 'ID invalid' });
      const f = (cl.contracts || []).find(x => x.id === cid);
      if (!f) return sendJson(res, 404, { error: 'Contract inexistent' });
      const fext = f.ext || 'pdf';
      const fp = path.join(dir, f.id + '.' + fext);
      if (req.method === 'GET') {
        let data; try { data = fs.readFileSync(fp); } catch { return sendJson(res, 404, { error: 'Fișierul lipsește de pe server' }); }
        const ascii = f.name.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, '');
        res.writeHead(200, { 'Content-Type': fext === 'jpg' ? 'image/jpeg' : fext === 'png' ? 'image/png' : 'application/pdf', 'Content-Length': data.length, 'Cache-Control': 'private, no-store',
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


/* ═════════════ Copie de siguranță clienți (ZIP, fără dependențe) ═════════════ */
const CRC_TABLE = (() => { const t = new Int32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c; } return t; })();
function crc32(buf) { let c = -1; for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ -1) >>> 0; }
function dosTime(d) {
  return { time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
           date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate() };
}
// scrie intrările una câte una în răspuns (un singur fișier în memorie odată)
function zipWriter(res) {
  const zlib = require('zlib');
  const central = []; let offset = 0;
  const { time, date } = dosTime(new Date());
  return {
    add(name, data) {
      const nameBuf = Buffer.from(name, 'utf8');
      const crc = crc32(data);
      const comp = data.length > 64 ? zlib.deflateRawSync(data, { level: 6 }) : null;
      const useDeflate = comp && comp.length < data.length;
      const body = useDeflate ? comp : data;
      const h = Buffer.alloc(30);
      h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(0x0800, 6);   // UTF-8
      h.writeUInt16LE(useDeflate ? 8 : 0, 8); h.writeUInt16LE(time, 10); h.writeUInt16LE(date, 12);
      h.writeUInt32LE(crc, 14); h.writeUInt32LE(body.length, 18); h.writeUInt32LE(data.length, 22);
      h.writeUInt16LE(nameBuf.length, 26); h.writeUInt16LE(0, 28);
      res.write(h); res.write(nameBuf); res.write(body);
      central.push({ nameBuf, crc, csize: body.length, size: data.length, method: useDeflate ? 8 : 0, offset });
      offset += 30 + nameBuf.length + body.length;
    },
    end() {
      let size = 0;
      for (const e of central) {
        const c = Buffer.alloc(46);
        c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x0800, 8);
        c.writeUInt16LE(e.method, 10); c.writeUInt16LE(time, 12); c.writeUInt16LE(date, 14);
        c.writeUInt32LE(e.crc, 16); c.writeUInt32LE(e.csize, 20); c.writeUInt32LE(e.size, 24);
        c.writeUInt16LE(e.nameBuf.length, 28); c.writeUInt32LE(e.offset, 42);
        res.write(c); res.write(e.nameBuf); size += 46 + e.nameBuf.length;
      }
      const z = Buffer.alloc(22);
      z.writeUInt32LE(0x06054b50, 0); z.writeUInt16LE(central.length, 8); z.writeUInt16LE(central.length, 10);
      z.writeUInt32LE(size, 12); z.writeUInt32LE(offset, 16);
      res.end(z);
    },
  };
}
const safeName = t => String(t || '').replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/\s+/g, ' ').trim().slice(0, 80) || 'fara-nume';
const csvCell = v => { const t = String(v == null ? '' : v); return /[";\n\r]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };

function handleClientsBackup(req, res) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const uname = ctx.user.username;
  const list = userClients(loadClients(), uname);
  const udir = path.join(CONTRACTS_DIR, uname.replace(/[^\w.-]/g, '_'));
  const stamp = new Date().toISOString().slice(0, 10);
  res.writeHead(200, { 'Content-Type': 'application/zip', 'Cache-Control': 'no-store',
    'Content-Disposition': `attachment; filename="clienti-backup-${stamp}.zip"`, ...CORS });
  const z = zipWriter(res);
  const root = `clienti-backup-${stamp}/`;
  z.add(root + 'clienti.json', Buffer.from(JSON.stringify(list, null, 2), 'utf8'));
  const head = ['Nume', 'Tip', 'CUI/CNP', 'Reg. Com.', 'Persoană contact', 'Telefon', 'Email', 'Adresă', 'NVR', 'Nr. camere',
                'Data montaj', 'Garanție până', 'Furnizor', 'Factură furnizor', 'Data achiziție', 'Abonament (lei/lună)', 'Zi scadentă', 'Luni plătite', 'Documente', 'Observații'];
  const rows = list.map(c => { const e = c.equip || {}, sb = c.sub || {};
    return [c.name, c.kind === 'pj' ? 'PJ' : 'PF', c.code, c.regCom, c.contact, c.phone, c.email, c.address, e.nvr, e.cams || '',
      e.installDate, e.warrantyUntil, e.supplier, e.supplierInvoice, e.purchaseDate, sb.active ? sb.amount : '', sb.active ? sb.dueDay : '',
      Object.keys(sb.paid || {}).sort().join(' '), (c.contracts || []).length, c.notes].map(csvCell).join(';'); });
  z.add(root + 'clienti.csv', Buffer.from('﻿' + [head.join(';'), ...rows].join('\r\n'), 'utf8'));   // BOM → Excel citește diacriticele
  const usedDirs = new Set();
  let missing = 0;
  for (const c of list) {
    let d = safeName(c.name), k = 2; while (usedDirs.has(d.toLowerCase())) d = safeName(c.name) + ' (' + k++ + ')';
    usedDirs.add(d.toLowerCase());
    const usedFiles = new Set();
    for (const f of (c.contracts || [])) {
      let data; try { data = fs.readFileSync(path.join(udir, c.id, f.id + '.' + (f.ext || 'pdf'))); } catch { missing++; continue; }
      const sub = f.kind === 'garantie' ? 'garantii' : 'contracte';
      let fn = safeName(f.name), n = 2; const dot = fn.lastIndexOf('.');
      while (usedFiles.has(sub + '/' + fn.toLowerCase())) fn = (dot > 0 ? f.name.slice(0, dot) : fn) + ' (' + n++ + ')' + (dot > 0 ? fn.slice(dot) : '');
      usedFiles.add(sub + '/' + fn.toLowerCase());
      z.add(`${root}${d}/${sub}/${fn}`, data);
    }
  }
  z.add(root + 'CITESTE-MA.txt', Buffer.from(
    `Copie de siguranță — evidența clienților YCA CCTV Monitor\r\nCreată: ${new Date().toLocaleString('ro-RO')}\r\n` +
    `Clienți: ${list.length}\r\n\r\nclienti.csv  — se deschide în Excel (date de bază, echipamente, abonament)\r\n` +
    `clienti.json — toate datele, pentru restaurare\r\n<Client>/contracte, <Client>/garantii — documentele încărcate\r\n` +
    (missing ? `\r\nATENȚIE: ${missing} fișiere lipseau de pe server.\r\n` : ''), 'utf8'));
  z.end();
}


/* ═════════════ Oferte: calculator public + pagina ofertei + răspunsul clientului ═════════════ */
// quotes.json: { seq, list:[quote] }  ·  setările de preț: db.configs[owner].quoteCfg (editate din aplicație)
const DEFAULT_LOGO = 'data:image/png;base64,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';
const QUOTES_FILE = path.join(BASE_DIR, 'quotes.json');
function loadQuotes() {
  try { const q = JSON.parse(fs.readFileSync(QUOTES_FILE, 'utf8')); if (q && Array.isArray(q.list)) return q; } catch {}
  return { seq: 1000, list: [] };
}
function saveQuotes(q) {
  const tmp = QUOTES_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(q, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, QUOTES_FILE);
}
// contul care primește cererile de pe site: QUOTE_OWNER sau primul administrator
function quoteOwner(db) {
  const want = String(process.env.QUOTE_OWNER || '').toLowerCase();
  return (want && db.users.find(u => u.username.toLowerCase() === want)) || db.users.find(u => u.role === 'admin') || db.users[0] || null;
}
const QUOTE_DEFAULTS = {
  enabled: true,
  company: 'Supraveghere24h',
  phone: '0763 354 355', email: 'contact@supraveghere24h.ro',
  legal: 'Yca Solutions SRL · CUI 45211628 · J40/19754/2021 · Str. Aviator Mircea Petre nr. 10, Sector 1, București',
  website: 'https://supraveghere24h.ro',
  assetBase: '',                                         // gol = imaginile din e-mail se servesc de server (/email-img/, instalate de update.sh)
  // Formula de pe site: prețul de bază include primele `baseCams` camere de interior/exterior + punctul de stocare
  basePrice: 189, baseCams: 3, extraPrice: 50, liftPrice: 150,
  // Ofertă pentru ASOCIAȚII DE PROPRIETARI: abonament lunar fix pe toată durata contractului (montaj gratuit)
  priceInterior: 0, priceExterior: 0, priceLift: 0,     // lei / LUNĂ / cameră
  priceNvr4: 0, priceNvr8: 0, priceNvr16: 0, priceNvr32: 0,  // lei / LUNĂ — punct stocare și control, după nr. camere
  priceSetup: 0,                                         // taxă unică de instalare (0 = gratuit)
  contractMonths: 48,                                    // durata contractului (luni); 0 = nu se afișează
  vatMode: 'none',                                       // Yca Solutions SRL — neplătitor de TVA                                   // 'included' | 'plus' | 'none'
  vatRate: 21,
  validDays: 30,
  intro: 'Vă mulțumim pentru interes! Mai jos găsiți oferta pentru sistemul de supraveghere video al blocului, cu plată lunară fixă.',
  note: 'Oferta poate fi îmbunătățită după inspectarea locației. Abonamentul lunar este singurul cost suportat de asociație pe toată durata contractului.',
  includes: 'Supraveghere video 24/7, rezoluție 5 MP, echipamente Hikvision\nInstalare, punere în funcțiune și instruire gratuite\nGaranție extinsă pe toată durata contractului, inclusiv la furt și vandalism\nMentenanță și service pe toată durata contractului\nLa finalul contractului, echipamentele devin proprietatea asociației',
};
function quoteCfg(db, owner) {
  const c = (owner && db.configs[owner.username] && db.configs[owner.username].quoteCfg) || {};
  return { ...QUOTE_DEFAULTS, ...c };
}
const qNum = v => { const n = parseFloat(String(v == null ? '' : v).replace(',', '.')); return isFinite(n) && n > 0 ? n : 0; };
function quotePriced(c) { return qNum(c.basePrice) > 0 || qNum(c.priceInterior) > 0 || qNum(c.priceExterior) > 0; }
function buildQuote(c, inp) {
  const n = { in: Math.min(64, Math.max(0, Math.round(qNum(inp.interior)))), ex: Math.min(64, Math.max(0, Math.round(qNum(inp.exterior)))), lift: Math.min(16, Math.max(0, Math.round(qNum(inp.lift)))) };
  let total = n.in + n.ex + n.lift;
  const items = [];
  if (qNum(c.basePrice) > 0) {
    // formula site: bază (minim baseCams camere interior/exterior, cu NVR) + camere suplimentare + camere lift
    const bc = Math.max(1, Math.round(qNum(c.baseCams)) || 3), ie = n.in + n.ex;
    items.push({ name: `Sistem de bază: ${bc} camere interior/exterior + punct de stocare și control (NVR + HDD)${ie < bc ? ` — minim ${bc} camere incluse` : ''}`, qty: 1, price: qNum(c.basePrice) });
    if (ie > bc) items.push({ name: 'Cameră suplimentară (interior / exterior)', qty: ie - bc, price: qNum(c.extraPrice) });
    if (n.lift) items.push({ name: 'Cameră pentru lift', qty: n.lift, price: qNum(c.liftPrice) });
    total = Math.max(bc, ie) + n.lift;
  } else {
  if (n.in)   items.push({ name: 'Cameră de interior', qty: n.in,   price: qNum(c.priceInterior) });
  if (n.ex)   items.push({ name: 'Cameră de exterior', qty: n.ex,   price: qNum(c.priceExterior) });
  if (n.lift) items.push({ name: 'Cameră pentru lift', qty: n.lift, price: qNum(c.priceLift) || qNum(c.priceInterior) });
  const nvr = total <= 4 ? ['4', c.priceNvr4] : total <= 8 ? ['8', c.priceNvr8] : total <= 16 ? ['16', c.priceNvr16] : ['32', c.priceNvr32];
  if (total) items.push({ name: `Punct de stocare și control (NVR ${nvr[0]} canale + HDD)`, qty: 1, price: qNum(nvr[1]) });
  }
  for (const it of items) it.total = Math.round(it.qty * it.price * 100) / 100;
  const sub = Math.round(items.reduce((s, it) => s + it.total, 0) * 100) / 100;
  const rate = qNum(c.vatRate) || 21;
  let net = sub, vat = 0, gross = sub;
  if (c.vatMode === 'plus') { vat = Math.round(sub * rate) / 100; gross = Math.round((sub + vat) * 100) / 100; }
  else if (c.vatMode === 'included') { net = Math.round(sub / (1 + rate / 100) * 100) / 100; vat = Math.round((sub - net) * 100) / 100; }
  const months = Math.round(qNum(c.contractMonths));
  return { cams: n, totalCams: total, items, net, vat, total: gross, vatMode: c.vatMode, vatRate: rate, period: 'month',
           months, contractTotal: months ? Math.round(gross * months * 100) / 100 : 0, setup: qNum(c.priceSetup) };
}
const lei = v => (Math.round(v * 100) / 100).toLocaleString('ro-RO', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' lei';
const roDate = t => new Date(t).toLocaleDateString('ro-RO', { timeZone: 'Europe/Bucharest', day: '2-digit', month: '2-digit', year: 'numeric' });
const publicBase = req => process.env.PUBLIC_URL ? process.env.PUBLIC_URL.replace(/\/$/, '') : 'https://' + String(req.headers.host || 'proxy.supraveghere24h.ro').replace(/[^\w.:-]/g, '');
const QSTATUS = { new: 'Mesaj nou', sent: 'Trimisă', viewed: 'Văzută', accepted: 'Acceptată', rejected: 'Refuzată', clarify: 'Cere clarificări', expired: 'Expirată' };
function quoteStatus(q) { return (q.status === 'sent' || q.status === 'viewed') && Date.now() > q.validUntil ? 'expired' : q.status; }

// limitare cereri publice: 6 oferte / oră / IP
const pubHits = new Map();
function pubLimited(req, max) {
  const fwd = req.headers['x-forwarded-for'] || req.headers['x-real-ip'];
  const ip = fwd ? String(fwd).split(',')[0].trim() : 'local:' + (req.socket.remoteAddress || '');
  if (!fwd) max = max * 6;            // fără IP real de la nginx: limită comună, mai largă
  const now = Date.now(), arr = (pubHits.get(ip) || []).filter(t => now - t < 3600e3);
  arr.push(now); pubHits.set(ip, arr);
  if (pubHits.size > 5000) pubHits.clear();
  return arr.length > max;
}
const PUB_CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex', 'Referrer-Policy': 'no-referrer' });
  res.end(html);
}
async function notifyOwner(db, owner, text) {
  try { const ucfg = (db.configs[owner.username] || {}).cfg || {}; await tgSend(ucfg, text); } catch {}
  try { const t = pushText(text).split('\n'); await pushSend(owner.username, t[0], t.slice(1).join('\n'), { tag: 'yca-q-' + Date.now(), urgency: 'normal' }); } catch {}
}

const PAGE_CSS = `
*{box-sizing:border-box;margin:0;padding:0}
:root{--ink:#0f1a2e;--ink2:#4a5568;--ink3:#8a96a8;--line:#e3e8ef;--bg:#f2f6fb;--card:#fff;--brand:#0284c7;--brand2:#0ea5e9;--ok:#16a34a;--err:#dc2626;--warn:#d97706}
body{font-family:'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--ink);font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:760px;margin:0 auto;padding:24px 16px 48px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:0 12px 32px -18px rgba(15,26,46,.25);overflow:hidden}
.hd{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 24px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.hd img{height:44px;width:auto}
.hd .no{text-align:right;font-size:13px;color:var(--ink2)}
.hd .no b{display:block;font-size:18px;color:var(--ink)}
.sec{padding:20px 24px;border-bottom:1px solid var(--line)}
.sec:last-child{border-bottom:0}
h1{font-size:22px;letter-spacing:-.01em;margin-bottom:6px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--ink3);margin-bottom:10px}
.muted{color:var(--ink2)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:6px 24px;font-size:14px}
.grid span{color:var(--ink3)}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--ink3);padding:8px 6px;border-bottom:1px solid var(--line)}
td{padding:10px 6px;border-bottom:1px solid var(--line);vertical-align:top}
td.n,th.n{text-align:right;white-space:nowrap}
.tot{display:flex;flex-direction:column;align-items:flex-end;gap:4px;margin-top:14px;font-size:14px}
.tot .big{font-size:24px;font-weight:800;color:var(--ink)}
.pill{display:inline-block;font-size:12px;font-weight:700;border-radius:999px;padding:4px 10px}
.st-accepted{background:#dcfce7;color:var(--ok)}.st-rejected{background:#fee2e2;color:var(--err)}.st-clarify{background:#fef3c7;color:var(--warn)}.st-expired{background:#eef2f7;color:var(--ink2)}.st-sent,.st-viewed{background:#e0f2fe;color:var(--brand)}
.acts{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.btn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:12px;padding:13px 10px;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit}
.btn.ok{background:var(--ok);border-color:var(--ok);color:#fff}
.btn.no{color:var(--err);border-color:#f3c2c2}
.btn.q{color:var(--warn);border-color:#f5d7a1}
.btn:disabled{opacity:.6;cursor:default}
textarea,input{width:100%;border:1px solid var(--line);border-radius:10px;padding:11px 12px;font-size:15px;font-family:inherit;color:var(--ink);background:#fbfcfe;outline:none}
textarea:focus,input:focus{border-color:var(--brand2);box-shadow:0 0 0 3px rgba(14,165,233,.15)}
textarea{min-height:90px;resize:vertical}
.msg{margin-top:12px;display:none}
.banner{border-radius:12px;padding:14px 16px;font-weight:600}
.banner.ok{background:#dcfce7;color:#14532d}.banner.no{background:#fee2e2;color:#7f1d1d}.banner.q{background:#fef3c7;color:#78350f}.banner.x{background:#eef2f7;color:var(--ink2)}
.foot{text-align:center;color:var(--ink3);font-size:12px;margin-top:18px}
.foot a{color:var(--brand)}
.print{background:none;border:0;color:var(--brand);font-weight:600;cursor:pointer;font-size:13px;font-family:inherit}
@media(max-width:560px){.grid{grid-template-columns:1fr}.acts{grid-template-columns:1fr}.hd .no{text-align:left}.sec,.hd{padding:18px 16px}}
@media print{body{background:#fff}.card{box-shadow:none;border:0}.noprint{display:none!important}}
`;
const apt = (p, c) => { const n = parseInt(c.apartments, 10); return n > 0 ? `<div class="muted">≈ ${lei(p.total / n)} / lună / apartament (${n} apartamente)</div>` : ''; };
function quotePageHtml(q, cfg, logo) {
  const st = quoteStatus(q);
  const c = q.customer, p = q.pricing;
  const rows = p.items.map(it => `<tr><td>${escHtml(it.name)}</td><td class="n">${it.qty}</td><td class="n">${lei(it.price)}</td><td class="n">${lei(it.total)}</td></tr>`).join('');
  const vatLine = p.vatMode === 'plus' ? `<div>Subtotal: ${lei(p.net)}</div><div>TVA ${p.vatRate}%: ${lei(p.vat)}</div>`
                : p.vatMode === 'included' ? `<div class="muted">din care TVA ${p.vatRate}%: ${lei(p.vat)}</div>` : '';
  const done = st === 'accepted' || st === 'rejected' || st === 'expired';      // după „clarificări” clientul poate încă accepta / refuza
  const bannerTxt = { accepted: ['ok', 'Ați acceptat această ofertă. Vă mulțumim! Vă contactăm în cel mai scurt timp pentru programarea montajului.'],
                      rejected: ['no', 'Ați refuzat această ofertă. Vă mulțumim pentru timpul acordat.'],
                      clarify:  ['q', 'Am primit cererea dumneavoastră de clarificări. Vă contactăm în maxim 24 de ore.'],
                      expired:  ['x', 'Această ofertă a expirat. Ne puteți contacta pentru o ofertă actualizată.'] }[st];
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Oferta nr. ${q.no} — ${escHtml(cfg.company)}</title>
<style>${PAGE_CSS}</style></head><body><div class="wrap">
<div class="card">
  <div class="hd">${logo ? `<img src="${logo}" alt="${escHtml(cfg.company)}">` : `<b>${escHtml(cfg.company)}</b>`}
    <div class="no"><b>Ofertă nr. ${q.no}</b>emisă ${roDate(q.createdAt)} · valabilă până ${roDate(q.validUntil)}<br><span class="pill st-${st}">${QSTATUS[st]}</span></div></div>
  <div class="sec"><h1>Bună ziua, ${escHtml(c.name.split(' ')[0] || c.name)}!</h1><p class="muted">${escHtml(cfg.intro)}</p></div>
  <div class="sec"><h2>Date asociație</h2><div class="grid">
    ${c.assoc ? `<div><span>Asociația:</span> ${escHtml(c.assoc)}</div>` : ''}${c.address && c.address !== c.assoc ? `<div><span>Adresa blocului:</span> ${escHtml(c.address)}</div>` : ''}
    <div><span>Persoană de contact:</span> ${escHtml(c.name)}${c.role ? ' (' + escHtml(c.role) + ')' : ''}</div><div><span>Telefon:</span> ${escHtml(c.phone)}</div>
    ${c.email ? `<div><span>Email:</span> ${escHtml(c.email)}</div>` : ''}${c.city ? `<div><span>Localitate:</span> ${escHtml(c.city)}</div>` : ''}
    ${c.apartments ? `<div><span>Apartamente:</span> ${escHtml(c.apartments)}</div>` : ''}
  </div></div>
  <div class="sec"><h2>Sistem propus · ${p.totalCams} ${p.totalCams === 1 ? 'cameră' : 'camere'} · plată lunară</h2>
    <table><thead><tr><th>Descriere</th><th class="n">Cant.</th><th class="n">Lei / lună / buc.</th><th class="n">Lei / lună</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="tot">${vatLine}<div class="big">${lei(p.total)} / lună</div>
      ${p.months ? `<div class="muted">contract ${p.months} luni · fără alte costuri pe durata contractului</div>` : ''}
      ${p.setup ? `<div class="muted">Taxă unică de instalare: ${lei(p.setup)}</div>` : '<div class="muted">Instalare gratuită</div>'}
      ${apt(p, c)}</div>
    ${cfg.includes ? `<h2 style="margin-top:18px">Ce include abonamentul</h2><ul style="padding-left:20px;font-size:14px;line-height:1.7">${String(cfg.includes).split('\n').filter(x => x.trim()).map(x => '<li>' + escHtml(x.trim()) + '</li>').join('')}</ul>` : ''}
    ${cfg.note ? `<p class="muted" style="margin-top:14px;font-size:13px">${escHtml(cfg.note)}</p>` : ''}
    ${c.message ? `<p style="margin-top:12px;font-size:13px"><b>Mesajul dumneavoastră:</b> ${escHtml(c.message)}</p>` : ''}
  </div>
  <div class="sec noprint" id="act">
    ${st === 'clarify' ? `<div class="banner q" style="margin-bottom:14px">${bannerTxt[1]}</div>` : ''}
    ${done ? `<div class="banner ${bannerTxt[0]}">${bannerTxt[1]}</div>${q.response && q.response.message ? `<p class="muted" style="margin-top:10px;font-size:13px">Mesaj trimis: „${escHtml(q.response.message)}”</p>` : ''}`
    : `<h2>Răspunsul dumneavoastră</h2>
    <div class="acts"><button class="btn ok" data-a="accept">✓ Accept oferta</button><button class="btn q" data-a="clarify">? Cer clarificări</button><button class="btn no" data-a="reject">✕ Refuz</button></div>
    <div class="msg" id="msgbox"><textarea id="msg" placeholder=""></textarea><button class="btn" id="send" style="margin-top:10px;width:100%">Trimite</button></div>
    <div id="out" style="margin-top:12px"></div>`}
  </div>
</div>
<div class="foot noprint"><button class="print" onclick="window.print()">Descarcă / printează oferta</button>${cfg.phone ? ` · Telefon: <a href="tel:${escHtml(cfg.phone.replace(/[^\d+]/g, ''))}">${escHtml(cfg.phone)}</a>` : ''}${cfg.email ? ` · <a href="mailto:${escHtml(cfg.email)}">${escHtml(cfg.email)}</a>` : ''}</div>
</div>
${done ? '' : `<script>
(function(){
  var act=null, box=document.getElementById('msgbox'), ta=document.getElementById('msg'), out=document.getElementById('out');
  var ph={accept:'Observații (opțional) — ex. când vă putem contacta pentru programare',clarify:'Ce ați dori să clarificăm? (ex. o cameră în plus, alt tip de cameră, plata în rate…)',reject:'Ne spuneți motivul? (opțional)'};
  function send(){
    var b=document.querySelectorAll('.btn'); for(var i=0;i<b.length;i++) b[i].disabled=true;
    fetch(location.pathname+'/respond',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:act,message:ta.value})})
      .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
      .then(function(x){ if(x.ok) location.replace(location.pathname); else { out.textContent=x.j.error||'Eroare'; for(var i=0;i<b.length;i++) b[i].disabled=false; } })
      .catch(function(){ out.textContent='Nu s-a putut trimite. Verificați conexiunea și încercați din nou.'; for(var i=0;i<b.length;i++) b[i].disabled=false; });
  }
  [].forEach.call(document.querySelectorAll('[data-a]'),function(el){ el.addEventListener('click',function(){
    act=el.getAttribute('data-a'); ta.placeholder=ph[act]; box.style.display='block';
    document.getElementById('send').textContent= act==='accept'?'Confirm acceptarea ofertei': act==='reject'?'Confirm refuzul':'Trimite întrebarea';
    if(act==='clarify') ta.focus();
  });});
  document.getElementById('send').addEventListener('click',function(){
    if(act==='clarify' && !ta.value.trim()){ out.textContent='Scrieți ce ați dori să clarificăm.'; ta.focus(); return; }
    send();
  });
})();
</script>`}
</body></html>`;
}

function calculatorHtml(cfg, logo, base) {
  const goTxt = mailReady() ? 'Primește oferta pe email' : 'Vezi oferta';
  const priced = quotePriced(cfg);
  const P = JSON.stringify({ in: qNum(cfg.priceInterior), ex: qNum(cfg.priceExterior), lift: qNum(cfg.priceLift) || qNum(cfg.priceInterior),
    n4: qNum(cfg.priceNvr4), n8: qNum(cfg.priceNvr8), n16: qNum(cfg.priceNvr16), n32: qNum(cfg.priceNvr32), setup: qNum(cfg.priceSetup),
    vatMode: cfg.vatMode, vatRate: qNum(cfg.vatRate) || 21, months: Math.round(qNum(cfg.contractMonths)),
    base: qNum(cfg.basePrice), bc: Math.round(qNum(cfg.baseCams)) || 3, extra: qNum(cfg.extraPrice), lp: qNum(cfg.liftPrice) });
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Calculează oferta — ${escHtml(cfg.company)}</title><style>${PAGE_CSS}
.wrap{padding:12px 12px 24px}
.step{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}
.step:last-child{border-bottom:0}
.step b{display:block;font-size:15px}.step small{color:var(--ink3);font-size:12.5px}
.ctr{display:flex;align-items:center;gap:6px;flex-shrink:0}
.ctr button{width:40px;height:40px;border-radius:10px;border:1px solid var(--line);background:#fff;font-size:20px;font-weight:700;color:var(--brand);cursor:pointer}
.ctr input{width:56px;text-align:center;font-weight:800;font-size:17px;padding:8px 4px}
.types{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.types label{border:1px solid var(--line);border-radius:12px;padding:12px 8px;text-align:center;font-weight:600;font-size:14px;cursor:pointer;background:#fff}
.types input{display:none}
.types input:checked+span{color:var(--brand)}
.types label:has(input:checked){border-color:var(--brand2);background:#f0f9ff}
.est{display:flex;justify-content:space-between;align-items:baseline;gap:10px;background:#f0f9ff;border:1px solid #bae6fd;border-radius:12px;padding:14px 16px;margin-top:14px}
.est b{font-size:24px}
.f2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.fl{display:flex;flex-direction:column;gap:5px;margin-bottom:10px;font-size:13px;font-weight:600;color:var(--ink2)}
.chk{display:flex;gap:10px;align-items:flex-start;font-size:13px;color:var(--ink2);margin:6px 0 14px}
.chk input{width:18px;height:18px;flex-shrink:0;margin-top:2px}
.go{width:100%;background:var(--brand);border:0;color:#fff;border-radius:12px;padding:15px;font-size:16px;font-weight:800;cursor:pointer;font-family:inherit}
.go:disabled{opacity:.6}
.err{color:var(--err);font-size:13px;margin-top:8px;min-height:18px}
.hp{position:absolute;left:-9999px}
@media(max-width:560px){.f2{grid-template-columns:1fr}.types{grid-template-columns:1fr}}
</style></head><body><div class="wrap"><div class="card">
${!priced || !cfg.enabled ? `<div class="sec"><h1>Calculatorul nu este disponibil momentan</h1><p class="muted">Vă rugăm să ne contactați telefonic${cfg.phone ? ' la ' + escHtml(cfg.phone) : ''}.</p></div>` : `
<form id="f" novalidate>
 <div class="sec"><h1 style="font-size:19px">Ofertă pentru asociații de proprietari</h1><p class="muted" style="font-size:14px">Sistem de supraveghere video pentru bloc, cu <b>abonament lunar fix</b>: montaj gratuit, mentenanță și garanție incluse pe toată durata contractului.</p></div>
 <div class="sec"><h2>1 · Câte camere sunt necesare pentru bloc?</h2>
  <div class="step"><div><b>Camere de interior</b><small>holuri, casa scării, intrare, subsol</small></div><div class="ctr"><button type="button" data-d="-1" data-t="interior">−</button><input id="interior" name="interior" inputmode="numeric" value="0"><button type="button" data-d="1" data-t="interior">+</button></div></div>
  <div class="step"><div><b>Camere de exterior</b><small>intrarea în bloc, parcare, alei, ghene</small></div><div class="ctr"><button type="button" data-d="-1" data-t="exterior">−</button><input id="exterior" name="exterior" inputmode="numeric" value="0"><button type="button" data-d="1" data-t="exterior">+</button></div></div>
  <div class="step"><div><b>Camere pentru lift</b><small>câte o cameră pentru fiecare lift</small></div><div class="ctr"><button type="button" data-d="-1" data-t="lift">−</button><input id="lift" name="lift" inputmode="numeric" value="0"><button type="button" data-d="1" data-t="lift">+</button></div></div>
  <div class="est"><span class="muted">Abonament lunar estimat<br><small id="estsub"></small></span><b id="est">—</b></div>
 </div>
 <div class="sec"><h2>2 · Datele asociației</h2>
  <div class="f2"><label class="fl">Asociația de proprietari<input name="assoc" placeholder="ex. Asociația de Proprietari Bloc M2"></label><label class="fl">Nr. apartamente<input name="apartments" inputmode="numeric" placeholder="opțional"></label></div>
  <label class="fl">Adresa blocului *<input name="address" autocomplete="street-address" placeholder="stradă, număr, bloc, scară" required></label>
  <div class="f2"><label class="fl">Localitate / sector *<input name="city" autocomplete="address-level2" required></label><label class="fl">Calitatea dvs.<select name="role" style="width:100%;border:1px solid var(--line);border-radius:10px;padding:11px 12px;font-size:15px;font-family:inherit;background:#fbfcfe"><option>Președinte asociație</option><option>Administrator</option><option>Membru comitet</option><option>Proprietar / locatar</option></select></label></div>
  <h2 style="margin-top:8px">3 · Persoana de contact</h2>
  <div class="f2"><label class="fl">Nume și prenume *<input name="name" autocomplete="name" required></label><label class="fl">Telefon *<input name="phone" type="tel" autocomplete="tel" required></label></div>
  <label class="fl">Email *<input name="email" type="email" autocomplete="email" required></label>
  <label class="fl">Mesaj (opțional)<textarea name="message" placeholder="Detalii despre bloc, zone de interes…"></textarea></label>
  <input class="hp" name="website" tabindex="-1" autocomplete="off">
  <label class="chk"><input type="checkbox" name="consent" required> Sunt de acord cu prelucrarea datelor personale în scopul ofertării și al contactării mele.</label>
  <button class="go" id="go">${goTxt}</button><div class="err" id="err"></div>
 </div>
</form>`}
</div><div class="foot">Oferta finală se confirmă după inspectarea locației.</div></div>
${!priced || !cfg.enabled ? '' : `<script>
(function(){
  var P=${P}, f=document.getElementById('f');
  function v(id){var x=parseInt(document.getElementById(id).value,10);return isFinite(x)&&x>0?x:0;}
  function lei(x){return (Math.round(x*100)/100).toLocaleString('ro-RO',{minimumFractionDigits:0,maximumFractionDigits:2})+' lei';}
  function calc(){
    var i=v('interior'),e=v('exterior'),l=v('lift'),t=i+e+l;
    if(!t){document.getElementById('est').textContent='—';document.getElementById('estsub').textContent='alegeți numărul de camere';return;}
    var s=P.base?P.base+Math.max(0,i+e-P.bc)*P.extra+l*P.lp:i*P.in+e*P.ex+l*P.lift+(t<=4?P.n4:t<=8?P.n8:t<=16?P.n16:P.n32);
    if(P.base) t=Math.max(P.bc,i+e)+l;
    if(P.vatMode==='plus') s=s*(1+P.vatRate/100);
    document.getElementById('est').textContent=lei(s)+' / lună';
    document.getElementById('estsub').textContent=t+(t===1?' cameră':' camere')+(P.vatMode==='included'?' · TVA inclus':'')+(P.months?' · contract '+P.months+' luni':'')+(P.setup?'':' · montaj gratuit');
  }
  [].forEach.call(document.querySelectorAll('[data-t]'),function(b){b.addEventListener('click',function(){
    var el=document.getElementById(b.getAttribute('data-t')); el.value=Math.max(0,Math.min(64,v(el.id)+parseInt(b.getAttribute('data-d'),10))); calc();});});
  ['interior','exterior','lift'].forEach(function(id){document.getElementById(id).addEventListener('input',calc);});
  calc();
  f.addEventListener('submit',function(ev){
    ev.preventDefault(); var err=document.getElementById('err'); err.textContent='';
    var d={}; new FormData(f).forEach(function(val,k){d[k]=val;}); d.consent=!!f.consent.checked;
    if(!(v('interior')+v('exterior')+v('lift'))) return err.textContent='Alegeți cel puțin o cameră.';
    if(!d.name.trim()||!d.phone.trim()||!d.email.trim()||!d.city.trim()||!d.address.trim()) return err.textContent='Completați câmpurile marcate cu *.';
    if(!/^\\S+@\\S+\\.\\S+$/.test(d.email.trim())) return err.textContent='Adresa de email nu pare corectă.';
    if(!d.consent) return err.textContent='Bifați acordul pentru prelucrarea datelor.';
    var go=document.getElementById('go'); go.disabled=true; go.textContent='Se trimite…';
    fetch('/public/quote',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
     .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
     .then(function(x){ if(!x.ok){err.textContent=x.j.error||'Eroare';go.disabled=false;go.textContent='${goTxt}';return;}
        f.innerHTML='<div class="sec" style="text-align:center"><div style="font-size:44px">✅</div><h1>Oferta nr. '+x.j.no+' este gata!</h1><p class="muted" style="margin:6px 0 18px">'+(x.j.emailed?'V-am trimis-o și pe email. ':'')+'O puteți vedea acum și ne puteți răspunde direct din pagina ofertei.</p><a class="go" style="display:block;text-decoration:none" target="_top" href="'+x.j.url+'">Vezi oferta</a></div>';
        try{ f.scrollIntoView({behavior:'smooth'}); }catch(e){} })
     .catch(function(){err.textContent='Nu s-a putut trimite. Încercați din nou.';go.disabled=false;go.textContent='${goTxt}';});
  });
})();
</script>`}
</body></html>`;
}
function quoteEmailHtml(q, cfg, url, opt = {}) {
  // e-mail cu oferta completă, în stil „broșură”: imagine de antet, pachet cu poze, beneficii cu iconițe, cameră suplimentară, garanții.
  // Doar stiluri inline + tabele (Gmail / Outlook / telefon). Imaginile stau pe site (cfg.assetBase), logo-ul pe server (/q-logo.png).
  const p = q.pricing, c = q.customer, cams = p.cams || {};
  const base = url.replace(/\/q\/[a-f0-9]+$/, '');
  const A = opt.cid ? 'cid:' : String(cfg.assetBase || base + '/email-img/').replace(/\/?$/, '/');
  const CS = opt.cid ? '@s24' : '';   // e-mail: imaginile merg atașate (cid), ca să apară și în Gmail pe Android
  const NAVY = '#0D1F33', ORG = '#F5A100', BLUE = '#0B5FB0', INK = '#14202E', MUT = '#5B6B7C', LINE = '#E3E8EF', SOFT = '#F4F7FB';
  const F = "font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
  const img = (f, w, h, alt = '') => `<img src="${A}${f}${CS}" width="${w}"${h ? ` height="${h}"` : ''} alt="${alt}" style="display:block;border:0;outline:none;width:${w}px;max-width:100%;height:auto">`;
  const head = (t, ic) => `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 6px"><tr>
    <td width="32" style="vertical-align:middle;width:32px;min-width:32px"><img src="${A}${ic}${CS}" width="24" height="24" alt="" style="display:block;border:0;width:24px;height:24px"></td><td style="${F}font-size:17px;font-weight:800;color:${NAVY};letter-spacing:.04em;text-transform:uppercase;vertical-align:middle;padding-right:12px">${t}</td>
    <td width="40%" style="vertical-align:middle;min-width:24px"><div style="height:2px;background:${LINE};line-height:2px;font-size:0">&nbsp;</div></td></tr></table>`;
  const SEC = 'padding:26px 22px 6px';
  // pachetul: echipamentele, din numărul de camere calculat pe site
  const bc = Math.max(1, Math.round(qNum(cfg.baseCams)) || 3);
  const nLift = cams.lift || 0, nIE = Math.max(0, (p.totalCams || 0) - nLift);
  let nEx = Math.min(cams.ex || 0, nIE), nIn = nIE - nEx;
  const pk = [['p-nvr.png', 'NVR Hikvision', 'Unitatea de înregistrare și gestionare video, de înaltă performanță.', '1x']];
  if (nIn) pk.push(['p-turret.png', 'Camere IP interior', `Camere Hikvision de minimum 5 MP pentru scări, holuri și intrări.`, nIn + 'x']);
  if (nEx) pk.push(['p-bullet.png', 'Camere IP exterior', `Camere Hikvision de minimum 5 MP, pentru exterior, cu vedere pe timp de noapte.`, nEx + 'x']);
  if (nLift) pk.push(['p-turret.png', 'Camere pentru lift', 'Camere compacte, montate în cabina liftului.', nLift + 'x']);
  pk.push(['p-hdd.png', 'Stocare pe hard disk', 'Hard disk dedicat pentru păstrarea înregistrărilor video.', '1x'],
          ['p-mon.png', 'Monitor', 'Monitor pentru vizualizarea live și a înregistrărilor, la fața locului.', '1x'],
          ['p-sw.png', 'Switch PoE', 'Alimentare și conectivitate stabilă pentru camerele IP.', '✓'],
          ['p-cab.png', 'Toate materialele de instalare', 'Cablu UTP, doze, pat de cablu, conectori RJ45 și toate accesoriile necesare montajului — incluse.', '✓'],
          ['p-tech.png', 'Manoperă și configurare', 'Montaj, configurare, testare și instruire — fără cost.', '✓']);
  const pkRows = pk.map(([f, t, d, n], k) => `<tr><td style="padding:14px 0;${k ? `border-top:1px solid ${LINE};` : ''}vertical-align:middle;width:92px">${img(f, 84)}</td>
    <td style="${F}padding:14px 8px 14px 12px;${k ? `border-top:1px solid ${LINE};` : ''}vertical-align:middle"><div style="font-size:15px;font-weight:800;color:${NAVY};text-transform:uppercase;letter-spacing:.02em">${t}</div><div style="font-size:13px;line-height:1.5;color:${MUT};margin-top:4px">${d}</div></td>
    <td style="padding:14px 0;${k ? `border-top:1px solid ${LINE};` : ''}vertical-align:middle;width:40px;text-align:right"><div style="${F}display:inline-block;width:38px;height:38px;line-height:38px;border-radius:19px;background:${n === '✓' ? '#FFF4DC' : BLUE};color:${n === '✓' ? '#B57600' : '#FFFFFF'};font-size:${n.length > 3 ? 13 : 16}px;font-weight:800;text-align:center">${n}</div></td></tr>`).join('');
  // costul
  const td = (x, al, extra = '') => `<td style="${F}font-size:14px;color:${INK};padding:11px 10px;border-bottom:1px solid ${LINE};text-align:${al};vertical-align:top;${extra}">${x}</td>`;
  const th = (x, al) => `<th style="${F}font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:${MUT};padding:10px;background:${SOFT};text-align:${al};font-weight:700;white-space:nowrap">${x}</th>`;
  const rows = p.items.map(it => `<tr>${td(`${escHtml(it.name)}<div style="font-size:12px;color:${MUT};margin-top:3px">${it.qty} × ${lei(it.price)} / lună</div>`, 'left')}${td(lei(it.total), 'right', 'white-space:nowrap;font-weight:700')}</tr>`).join('');
  const vat = p.vatMode === 'plus' ? `Subtotal ${lei(p.net)} + TVA ${p.vatRate}% ${lei(p.vat)}` : p.vatMode === 'included' ? `TVA ${p.vatRate}% inclus (${lei(p.vat)})` : '';
  const nApt = parseInt(c.apartments, 10);
  const facts = [`${p.totalCams} ${p.totalCams === 1 ? 'cameră' : 'camere'}`, p.months ? `contract ${p.months} luni` : '', p.setup ? `instalare ${lei(p.setup)}` : 'instalare gratuită'].filter(Boolean).join('&nbsp;&nbsp;·&nbsp;&nbsp;');
  // beneficii (2 coloane) și garanții (2 x 2)
  const ben = [['i-img.png', 'Imagine clară 5 MP', 'Detalii clare pentru identificarea persoanelor, zi și noapte.'],
               ['i-shield.png', 'Acreditați de Poliția Română', 'Sisteme recunoscute oficial pentru supraveghere video.'],
               ['i-rec.png', 'Înregistrare 24/7', 'Înregistrările sunt păstrate în siguranță pe hard disk.'],
               ['i-lock.png', 'Garanție la furt și vandalism', 'Echipamentele sunt acoperite pe toată durata contractului.'],
               ['i-wrench.png', 'Mentenanță și service', 'Incluse în abonament, fără costuri suplimentare.'],
               ['i-phone.png', 'Suport rapid', 'Ne contactați telefonic pentru orice problemă.']];
  const cell = ([f, t, d]) => `<td class="col" style="padding:9px 8px;vertical-align:top"><table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="vertical-align:top;width:52px">${img(f, 44, 44)}</td>
    <td style="${F}vertical-align:top;padding-left:10px"><div style="font-size:14px;font-weight:800;color:${NAVY}">${t}</div><div style="font-size:12.5px;line-height:1.45;color:${MUT};margin-top:3px">${d}</div></td></tr></table></td>`;
  const benRows = ben.map(b => `<tr>${cell(b)}</tr>`).join('');
  const gar = [['s-check.png', 'Instalare gratuită', 'Montaj, punere în funcțiune și instruire.'], ['s-shield.png', 'Garanție completă', 'Pe toată durata contractului.'],
               ['s-tool.png', 'Service inclus', 'Intervenim rapid la orice defecțiune.'], ['s-key.png', 'Rămân ale asociației', 'La final, echipamentele devin ale blocului.']];
  const gcell = ([f, t, d]) => `<td class="col" style="padding:10px 8px;vertical-align:top"><table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="vertical-align:top;width:40px">${img(f, 32, 32)}</td>
    <td style="${F}vertical-align:top;padding-left:10px"><div style="font-size:13px;font-weight:800;color:${NAVY};text-transform:uppercase;letter-spacing:.03em">${t}</div><div style="font-size:12.5px;line-height:1.45;color:${MUT};margin-top:3px">${d}</div></td></tr></table></td>`;
  const tel = cfg.phone ? `<a href="tel:${escHtml(String(cfg.phone).replace(/[^\d+]/g, ''))}" style="color:#FFFFFF;text-decoration:none;font-weight:700;white-space:nowrap">${escHtml(cfg.phone)}</a>` : '';
  const mail = cfg.email ? `<a href="mailto:${escHtml(cfg.email)}" style="color:#FFFFFF;text-decoration:none;font-weight:700">${escHtml(cfg.email)}</a>` : '';
  const extra = qNum(cfg.extraPrice), liftP = qNum(cfg.liftPrice);
  return `<!doctype html><html lang="ro"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light only"><title>Oferta nr. ${q.no}</title><style>@media only screen and (max-width:520px){.col{display:block!important;width:100%!important;box-sizing:border-box}.px{padding-left:14px!important;padding-right:14px!important}.outer{padding:0!important}}</style></head>
<body style="margin:0;padding:0;background:#E9EDF2">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">Oferta nr. ${q.no} · ${lei(p.total)} / lună · ${p.totalCams} camere${p.months ? ' · contract ' + p.months + ' luni' : ''} — valabilă până la ${roDate(q.validUntil)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#E9EDF2"><tr><td align="center" class="outer" style="padding:16px 6px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#FFFFFF;border-radius:14px;overflow:hidden;border-collapse:separate">
<tr><td class="px" style="padding:16px 20px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
  <td style="vertical-align:middle"><a href="${escHtml(cfg.website || '#')}" style="text-decoration:none"><img src="${opt.cid ? 'cid:q-logo.png@s24' : base + '/q-logo.png'}" alt="${escHtml(cfg.company)}" width="170" style="display:block;width:170px;max-width:170px;height:auto;border:0"></a></td>
  <td style="${F}text-align:right;vertical-align:middle;white-space:nowrap"><div style="font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:${MUT};font-weight:700">Ofertă de preț</div><div style="font-size:20px;font-weight:800;color:${INK}">Nr. ${q.no}</div></td></tr></table></td></tr>
<tr><td style="font-size:0;line-height:0"><img src="${A}hero.jpg${CS}" width="640" alt="Ofertă — sistem de supraveghere video complet, pentru bloc" style="display:block;width:100%;max-width:640px;height:auto;border:0"></td></tr>
<tr><td class="px" style="background:${NAVY};padding:24px 22px;border-top:4px solid ${ORG}">
  <div style="${F}font-size:14px;color:#C9D4E0;margin:0 0 6px">Bună ziua, ${escHtml(c.name.split(' ')[0] || c.name)}! Abonamentul lunar propus pentru bloc:</div>
  <div style="${F}font-size:42px;line-height:1.1;font-weight:800;color:${ORG}">${lei(p.total)} <span style="font-size:18px;color:#FFFFFF;font-weight:700">/ lună</span></div>
  <div style="${F}font-size:14px;color:#FFFFFF;margin-top:10px">${facts}</div>
  ${vat ? `<div style="${F}font-size:12px;color:#9FB3C8;margin-top:6px">${vat}</div>` : ''}${nApt > 0 ? `<div style="${F}font-size:13px;color:#C9D4E0;margin-top:6px">≈ ${lei(p.total / nApt)} / lună / apartament (${nApt} apartamente)</div>` : ''}
  <div style="${F}font-size:12px;color:#9FB3C8;margin-top:14px">Emisă ${roDate(q.createdAt)} · valabilă până la <b style="color:#FFFFFF">${roDate(q.validUntil)}</b>${c.assoc ? ' · ' + escHtml(c.assoc) : ''}</div></td></tr>
<tr><td class="px" style="padding:22px 22px 0"><div style="${F}font-size:15px;line-height:1.65;color:#3B4A5A">${escHtml(cfg.intro)}</div></td></tr>
<tr><td class="px" style="${SEC}">${head('Pachetul include', 's-shield.png')}<table role="presentation" width="100%" cellpadding="0" cellspacing="0">${pkRows}</table></td></tr>
<tr><td class="px" style="${SEC}">${head('Costul abonamentului', 's-check.png')}
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid ${LINE};margin-top:8px"><tr>${th('Descriere', 'left')}${th('Total / lună', 'right')}</tr>${rows}
  <tr><td style="${F}font-size:12px;color:${MUT};padding:14px 10px;text-align:right;font-weight:700;text-transform:uppercase;letter-spacing:.08em">Total abonament lunar</td><td style="${F}font-size:18px;color:${INK};padding:14px 10px;text-align:right;font-weight:800;white-space:nowrap">${lei(p.total)}</td></tr></table>
  <div style="${F}font-size:12px;color:${MUT};margin:10px 0 0">${p.months ? `Abonament fix pe toată durata contractului de ${p.months} luni, fără alte costuri. ` : ''}${p.setup ? `Taxă unică de instalare: ${lei(p.setup)}.` : 'Montajul și punerea în funcțiune sunt gratuite.'}</div></td></tr>
<tr><td class="px" style="padding:24px 14px 6px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${SOFT};border-radius:12px"><tr><td style="padding:18px 16px 8px">
  <div style="padding:0 8px">${head('Beneficiile tale', 's-badge.png')}</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0">${benRows}</table></td></tr></table></td></tr>
${extra ? `<tr><td class="px" style="padding:18px 14px 6px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:${NAVY};border-radius:12px;overflow:hidden"><tr><td style="background:${BLUE};padding:12px 22px;${F}font-size:15px;font-weight:800;color:#FFFFFF;letter-spacing:.06em;text-transform:uppercase">Cameră suplimentară</td></tr>
  <tr><td style="padding:16px 22px 18px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td style="${F}vertical-align:middle">
    <div style="font-size:13.5px;line-height:1.5;color:#C9D4E0">Dacă doriți camere în plus, costul este de</div>
    <div style="font-size:32px;line-height:1.2;font-weight:800;color:${ORG};margin:4px 0">${lei(extra).replace(',00', '')} <span style="font-size:17px">/ lună</span></div>
    <div style="font-size:13.5px;line-height:1.5;color:#C9D4E0">pentru fiecare cameră de interior sau exterior adăugată${liftP ? `; cameră pentru lift: <b style="color:#FFFFFF">${lei(liftP).replace(',00', '')} / lună</b>` : ''}.</div></td>
    <td width="84" style="vertical-align:middle;text-align:right">${img('s-cam.png', 76, 56)}</td></tr></table></td></tr></table></td></tr>` : ''}
<tr><td class="px" style="padding:18px 14px 4px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid ${LINE};border-bottom:1px solid ${LINE}">${gar.map(g => `<tr>${gcell(g)}</tr>`).join('')}</table></td></tr>
${cfg.note || c.message ? `<tr><td class="px" style="padding:16px 22px 4px">${cfg.note ? `<div style="${F}font-size:13px;line-height:1.6;color:${MUT};background:${SOFT};border-left:3px solid ${ORG};padding:12px 14px">${escHtml(cfg.note)}</div>` : ''}${c.message ? `<div style="${F}font-size:13px;line-height:1.6;color:${INK};margin-top:12px"><b>Mesajul dumneavoastră:</b> ${escHtml(c.message)}</div>` : ''}</td></tr>` : ''}
<!--CTA--><tr><td class="px" style="padding:22px 22px 26px"><div style="${F}font-size:19px;font-weight:800;color:${INK};margin:0 0 4px">Ce decideți?</div>
  <div style="${F}font-size:13px;color:${MUT};margin:0 0 16px">Alegeți o variantă; se deschide pagina ofertei, unde confirmați răspunsul.</div>
  <a href="${url}?a=accept" style="${F}display:block;background:${ORG};color:${NAVY};text-decoration:none;font-weight:800;font-size:16px;text-align:center;padding:16px 20px;border-radius:10px">Accept oferta</a>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px"><tr>
    <td width="50%" style="padding-right:5px"><a href="${url}?a=clarify" style="${F}display:block;background:#FFFFFF;color:${NAVY};border:1.5px solid ${NAVY};text-decoration:none;font-weight:700;font-size:14px;text-align:center;padding:12px 8px;border-radius:10px">Cer clarificări</a></td>
    <td width="50%" style="padding-left:5px"><a href="${url}?a=reject" style="${F}display:block;background:#FFFFFF;color:${MUT};border:1.5px solid #C5CED8;text-decoration:none;font-weight:700;font-size:14px;text-align:center;padding:12px 8px;border-radius:10px">Refuz oferta</a></td></tr></table>
  <div style="${F}font-size:12px;color:${MUT};margin-top:14px;text-align:center"><a href="${url}" style="color:${NAVY};font-weight:700">Vezi oferta online</a> &nbsp;·&nbsp; de acolo o puteți descărca în PDF</div></td></tr><!--/CTA-->
<tr><td class="px" style="background:${NAVY};padding:20px 22px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
  <td style="vertical-align:top;width:44px">${img('s-note.png', 34, 34)}</td>
  <td style="${F}vertical-align:top;font-size:13px;line-height:1.6;color:#C9D4E0;padding-left:8px">Oferta include toate materialele și accesoriile necesare pentru un sistem de supraveghere complet, funcțional și gata de utilizare.</td></tr>
  <tr><td colspan="2" style="padding-top:16px"><div style="height:1px;background:#24384F;line-height:1px;font-size:0">&nbsp;</div></td></tr>
  <tr><td style="vertical-align:middle;width:44px;padding-top:16px">${img('s-shield2.png', 34, 34)}</td>
  <td style="${F}vertical-align:middle;padding:16px 0 0 8px"><div style="font-size:14px;font-weight:800;color:#6FB3FF;letter-spacing:.04em;text-transform:uppercase">Siguranța blocului, prioritatea noastră!</div>
    <div style="font-size:13px;color:#C9D4E0;margin-top:4px">${[tel, mail].filter(Boolean).join('&nbsp;&nbsp;·&nbsp;&nbsp;')}</div></td></tr></table></td></tr>
</table>
<div style="${F}font-size:11px;color:#8A97A8;margin-top:16px;line-height:1.6;max-width:600px">${escHtml(cfg.legal || cfg.company)}<!--MAILNOTE--><br>Ați primit acest e-mail pentru că ați solicitat o ofertă pe ${escHtml(String(cfg.website || '').replace(/^https?:\/\//, '') || 'site-ul nostru')}.<!--/MAILNOTE--></div>
</td></tr></table></body></html>`;
}

// imaginile referite ca cid:<nume>@s24 în e-mail → atașamente inline (din email-img/ și logo-ul ofertei)
function emailCidAttachments(html) {
  const out = [], seen = new Set();
  for (const m of html.matchAll(/cid:([a-z0-9-]+\.(?:png|jpg))@s24/g)) {
    const n = m[1]; if (seen.has(n)) continue; seen.add(n);
    let content = null, type = n.endsWith('.jpg') ? 'image/jpeg' : 'image/png';
    if (n === 'q-logo.png') { const d = /^data:([^;]+);base64,(.*)$/.exec(quoteLogo() || ''); if (d) { content = Buffer.from(d[2], 'base64'); type = d[1]; } }
    else { try { content = fs.readFileSync(path.join(BASE_DIR, 'email-img', n)); } catch {} }
    if (content) out.push({ filename: n, content, contentType: type, cid: n + '@s24', contentDisposition: 'inline' });
  }
  return out;
}
// formularul de pe site (Webflow): nume, telefon, email, asociatie, mesaj, acord, detalii="interior:3,exterior:1,lift:0"
function mapSiteForm(f) {
  const det = {}; String(f.detalii || '').replace(/(interior|exterior|lift)\s*[:=]\s*(\d+)/gi, (_, k, v) => { det[k.toLowerCase()] = v; });
  return { name: f.nume || f.name, phone: f.telefon || f.phone, email: f.email, assoc: f.asociatie || f.assoc, address: f.adresa || f.address || f.asociatie,
           city: f.localitate || f.city || '', message: f.mesaj || f.message, consent: f.acord || f.consent, website: f.website,
           interior: f.interior || det.interior, exterior: f.exterior || det.exterior, lift: f.lift || det.lift, role: f.calitate || f.role, apartments: f.apartamente || f.apartments, site: true };
}
async function readBodyAny(req) {
  const raw = (await readRaw(req)).toString('utf8');
  if (/application\/x-www-form-urlencoded|multipart\/form-data/i.test(req.headers['content-type'] || '') || /^[\w%.-]+=/.test(raw)) {
    const o = {}; for (const [k, v] of new URLSearchParams(raw)) o[k] = v; return o;
  }
  try { return JSON.parse(raw || '{}'); } catch { return {}; }
}
function handlePublicPrices(req, res) {
  const db = loadDb(); const c = quoteCfg(db, quoteOwner(db));
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'public, max-age=300', ...PUB_CORS });
  res.end(JSON.stringify({ enabled: !!c.enabled, basePrice: qNum(c.basePrice), baseCams: Math.round(qNum(c.baseCams)) || 3, extraPrice: qNum(c.extraPrice),
    liftPrice: qNum(c.liftPrice), months: Math.round(qNum(c.contractMonths)), vatMode: c.vatMode }));
}

// Formularele de contact de pe site (fără calculator) → mesaj în aplicație + Telegram, apoi înapoi pe site cu ?trimis=1
const SITE_HOSTS = /(^|\.)supraveghere24h\.ro$|\.webflow\.io$/i;
async function handleSiteContact(req, res) {
  let back = null;
  try { const r = new URL(String(req.headers.referer || '')); if (SITE_HOSTS.test(r.hostname)) { r.search = ''; r.hash = ''; back = r.toString(); } } catch {}
  const done = (ok, err) => {
    if (back) { res.writeHead(303, { Location: `${back}?${ok ? 'trimis=1' : 'eroare=' + encodeURIComponent(err || '')}#contact`, ...PUB_CORS }); return res.end(); }
    return sendHtml(res, ok ? 200 : 400, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;padding:48px 20px;text-align:center;color:#14202E">${ok
      ? '<div style="font-size:44px">✅</div><h2>Mulțumim! Am primit mesajul tău.</h2><p>Te contactăm în cel mai scurt timp, în zilele lucrătoare.</p>'
      : '<h2>Mesajul nu a putut fi trimis</h2><p>' + escHtml(err || '') + '</p>'}<p><a href="https://supraveghere24h.ro" style="color:#0284c7">« Înapoi pe site</a> · <a href="tel:+40763354355" style="color:#0284c7">0763 354 355</a></p></body>`);
  };
  if (pubLimited(req, 6)) return done(false, 'Prea multe mesaje. Încercați mai târziu sau sunați-ne.');
  const f = await readBodyAny(req);
  if (f.website) return done(true);                                                   // capcană roboți
  const cust = { name: str(f.nume || f.name, 120).trim(), phone: str(f.telefon || f.phone, 40).trim(), email: str(f.email, 160).trim(),
                 assoc: str(f.asociatie || '', 160).trim(), address: str(f.adresa || f.asociatie || '', 300).trim(), city: str(f.localitate || '', 120).trim(),
                 message: str(f.mesaj || f.message, 3000).trim(), page: back ? new URL(back).pathname : '' };
  if (!cust.name || !cust.phone) return done(false, 'Completați numele și telefonul.');
  if (cust.email && !/^\S+@\S+\.\S+$/.test(cust.email)) return done(false, 'Adresa de email nu pare corectă.');
  if (!(f.acord || f.consent)) return done(false, 'Este necesar acordul pentru prelucrarea datelor.');
  const db = loadDb(); const owner = quoteOwner(db);
  if (!owner) return done(false, 'Serviciu indisponibil.');
  const all = loadQuotes();
  const q = { id: newId(), no: ++all.seq, token: crypto.randomBytes(18).toString('hex'), owner: owner.username, source: 'site-contact', kind: 'contact',
              createdAt: Date.now(), validUntil: Date.now() + 365 * 864e5, customer: cust, pricing: null, status: 'new', events: [{ t: Date.now(), type: 'message' }] };
  all.list.push(q); saveQuotes(all);
  notifyOwner(db, owner, `✉️ <b>Mesaj nou de pe site #${q.no}</b>\n${escHtml(cust.name)} · ${escHtml(cust.phone)}${cust.email ? ' · ' + escHtml(cust.email) : ''}${cust.assoc ? '\n' + escHtml(cust.assoc) : ''}${cust.message ? '\n„' + escHtml(cust.message.slice(0, 500)) + '”' : ''}${cust.page ? '\n(pagina ' + escHtml(cust.page) + ')' : ''}`);
  return done(true);
}
async function handlePublicQuote(req, res, fromSite) {
  // formularul clasic (fără JS) primește redirect către pagina ofertei; apelurile JS primesc JSON
  const wantsHtml = fromSite && !/json/i.test(req.headers.accept || '') && !req.headers['x-requested-with'];
  const send = (st, o) => {
    if (wantsHtml) {
      // înapoi pe pagina de pe site, cu mesajul „trimis” (oferta pleacă pe email); fără Referer valid → pagina ofertei
      let back = null;
      try { const r = new URL(String(req.headers.referer || '')); if (SITE_HOSTS.test(r.hostname)) { r.search = ''; r.hash = ''; back = r.toString(); } } catch {}
      if (back) { res.writeHead(303, { Location: `${back}?${o.url ? 'trimis=1' : 'eroare=' + encodeURIComponent(o.error || 'Eroare')}#contact`, ...PUB_CORS }); return res.end(); }
      if (o.url) { res.writeHead(303, { Location: o.url, ...PUB_CORS }); return res.end(); }
      return sendHtml(res, st, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;padding:40px 20px;text-align:center;color:#14202E"><h2>Cererea nu a putut fi trimisă</h2><p>${escHtml(o.error || 'Eroare')}</p><p><a href="javascript:history.back()" style="color:#0284c7">« Înapoi la formular</a> · sau sunați la <a href="tel:+40763354355" style="color:#0284c7">0763 354 355</a></p></body>`);
    }
    res.writeHead(st, { 'Content-Type': 'application/json; charset=utf-8', ...PUB_CORS }); res.end(JSON.stringify(o));
  };
  if (pubLimited(req, 6)) return send(429, { error: 'Prea multe cereri. Încercați din nou mai târziu.' });
  let b = await readBodyAny(req);
  if (fromSite || 'nume' in b || 'telefon' in b) b = mapSiteForm(b);
  if (b.website) return send(200, { url: '/' });                                   // capcană pentru roboți
  const db = loadDb(); const owner = quoteOwner(db);
  if (!owner) return send(503, { error: 'Serviciu indisponibil' });
  const cfg = quoteCfg(db, owner);
  if (!cfg.enabled || !quotePriced(cfg)) return send(503, { error: 'Calculatorul nu este disponibil momentan.' });
  const cust = { name: str(b.name, 120).trim(), phone: str(b.phone, 40).trim(), email: str(b.email, 160).trim(), city: str(b.city, 120).trim(),
                 address: str(b.address, 300).trim(), assoc: str(b.assoc, 160).trim(), role: str(b.role, 60).trim(),
                 apartments: String(Math.min(2000, Math.round(qNum(b.apartments))) || ''), propType: 'Bloc / asociație de proprietari', message: str(b.message, 2000).trim() };
  if (b.site) {   // formularul de pe site are mai puține câmpuri: nume, telefon, (email), asociația / adresa
    if (!cust.name || !cust.phone || !cust.address) return send(400, { error: 'Completați numele, telefonul și asociația sau adresa blocului.' });
    if (cust.email && !/^\S+@\S+\.\S+$/.test(cust.email)) return send(400, { error: 'Adresa de email nu pare corectă.' });
    if (!(qNum(b.interior) + qNum(b.exterior) + qNum(b.lift))) b.interior = 3;      // fără calculator: oferta de bază
  } else if (!cust.name || !cust.phone || !cust.city || !cust.address || !/^\S+@\S+\.\S+$/.test(cust.email)) return send(400, { error: 'Completați numele, telefonul, emailul, adresa blocului și localitatea.' });
  if (!b.consent) return send(400, { error: 'Este necesar acordul pentru prelucrarea datelor.' });
  const pricing = buildQuote(cfg, b);
  if (!pricing.totalCams) return send(400, { error: 'Alegeți cel puțin o cameră.' });
  const all = loadQuotes();
  const q = { id: newId(), no: ++all.seq, token: crypto.randomBytes(18).toString('hex'), owner: owner.username, source: 'site',
              createdAt: Date.now(), validUntil: Date.now() + (Math.round(qNum(cfg.validDays)) || 30) * 864e5,
              customer: cust, pricing, status: 'sent', events: [{ t: Date.now(), type: 'created' }], emailed: false };
  all.list.push(q); saveQuotes(all);
  const url = `${publicBase(req)}/q/${q.token}`;
  if (mailReady() && cust.email) {
    const mhtml = quoteEmailHtml(q, cfg, url, { cid: true });
    q.emailed = await sendMail(cust.email, `Oferta nr. ${q.no} — ${cfg.company}`,
      `Bună ziua, ${cust.name}!\n\nOferta pentru bloc (abonament ${lei(pricing.total)} / lună) poate fi văzută aici:\n${url}\n\nPe pagina ofertei o puteți accepta, refuza sau cere clarificări.\n\n${cfg.company}`,
      mhtml, emailCidAttachments(mhtml));
    const a2 = loadQuotes(); const x = a2.list.find(z => z.id === q.id); if (x) { x.emailed = q.emailed; saveQuotes(a2); }
  }
  notifyOwner(db, owner, `🧾 <b>Cerere nouă de ofertă #${q.no}</b>\n${escHtml(cust.name)} · ${escHtml(cust.phone)}${cust.assoc ? '\n' + escHtml(cust.assoc) : ''}${[cust.address !== cust.assoc ? cust.address : '', cust.city].filter(Boolean).length ? '\n' + escHtml([cust.address !== cust.assoc ? cust.address : '', cust.city].filter(Boolean).join(', ')) : ''}\n${pricing.totalCams} camere · <b>${lei(pricing.total)} / lună</b>${q.emailed ? '\n✉ trimisă și pe email' : !cust.email ? '\n(clientul nu a lăsat email)' : '\n(email neconfigurat pe server — oferta NU a fost trimisă pe mail)'}`);
  return send(200, { ok: true, no: q.no, url, emailed: q.emailed });
}

const LOGO_CACHE = { v: null };
function quoteLogo() {
  if (LOGO_CACHE.v !== null) return LOGO_CACHE.v;
  try { LOGO_CACHE.v = 'data:image/png;base64,' + fs.readFileSync(path.join(BASE_DIR, 'logo.png')).toString('base64'); } catch { LOGO_CACHE.v = DEFAULT_LOGO; }
  return LOGO_CACHE.v;
}

async function handleQuotePublic(req, res, pathname, parsed) {
  const m = pathname.match(/^\/q\/([a-f0-9]{36})(\/respond)?$/);
  if (!m) return sendHtml(res, 404, '<h1>Ofertă inexistentă</h1>');
  const all = loadQuotes(); const q = all.list.find(x => x.token === m[1]);
  if (!q || q.kind === 'contact') return sendHtml(res, 404, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;padding:40px;text-align:center"><h2>Oferta nu a fost găsită</h2><p>Linkul este greșit sau oferta a fost ștearsă.</p></body>`);
  const db = loadDb(); const owner = db.users.find(u => u.username === q.owner) || quoteOwner(db);
  const cfg = quoteCfg(db, owner);
  if (m[2]) {
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Metodă invalidă' });
    if (pubLimited(req, 30)) return sendJson(res, 429, { error: 'Prea multe încercări' });
    const b = await readJson(req);
    const act = { accept: 'accepted', reject: 'rejected', clarify: 'clarify' }[b.action];
    if (!act) return sendJson(res, 400, { error: 'Răspuns invalid' });
    const st = quoteStatus(q);
    if (st === 'accepted' || st === 'rejected') return sendJson(res, 409, { error: 'Ați răspuns deja la această ofertă.' });
    if (st === 'expired') return sendJson(res, 410, { error: 'Oferta a expirat.' });
    const msg = str(b.message, 2000).trim();
    if (act === 'clarify' && !msg) return sendJson(res, 400, { error: 'Scrieți ce ați dori să clarificăm.' });
    q.status = act; q.response = { action: act, message: msg, at: Date.now() };
    q.events.push({ t: Date.now(), type: act, message: msg });
    // la acceptare: clientul apare automat în evidența de clienți
    if (act === 'accepted' && !q.clientId) {
      try {
        const cl = loadClients(); const list = userClients(cl, q.owner);
        const nx = new Date(); nx.setMonth(nx.getMonth() + 1);
        const c = cleanClient({ kind: 'pj', name: q.customer.assoc || ('Asociația de proprietari ' + q.customer.address), contact: [q.customer.name, q.customer.role].filter(Boolean).join(' — '),
          phone: q.customer.phone, email: q.customer.email, address: [q.customer.address, q.customer.city].filter(Boolean).join(', '),
          notes: `Din oferta nr. ${q.no} acceptată pe ${roDate(Date.now())} · ${q.pricing.totalCams} camere · ${lei(q.pricing.total)} / lună${q.pricing.months ? ' · contract ' + q.pricing.months + ' luni' : ''}${msg ? '\nMesaj client: ' + msg : ''}`,
          equip: { cams: q.pricing.totalCams },
          sub: { active: true, amount: q.pricing.total, dueDay: 1, start: nx.toISOString().slice(0, 7), paid: {} } }, null);
        list.push(c); saveClients(cl); q.clientId = c.id;
      } catch (e) { console.error('Oferte: nu am putut crea clientul:', e.message); }
    }
    saveQuotes(all);
    const icon = { accepted: '✅', rejected: '❌', clarify: '❓' }[act];
    notifyOwner(db, owner, `${icon} <b>Oferta #${q.no} — ${QSTATUS[act]}</b>\n${escHtml(q.customer.assoc || q.customer.address)}\n${escHtml(q.customer.name)} · ${escHtml(q.customer.phone)} · ${lei(q.pricing.total)} / lună${msg ? '\n„' + escHtml(msg) + '”' : ''}`);
    return sendJson(res, 200, { ok: true, status: act });
  }
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'Metodă invalidă' });
  // prima deschidere → „Văzută” (nu numărăm vizitele proprietarului din aplicație: ?own=1)
  if (!parsed.query.own) {
    q.views = (q.views || 0) + 1; q.lastViewAt = Date.now();
    if (q.status === 'sent') { q.status = 'viewed'; q.viewedAt = Date.now(); q.events.push({ t: Date.now(), type: 'viewed' }); }
    saveQuotes(all);
  }
  const pre = { accept: 'accept', reject: 'reject', clarify: 'clarify' }[parsed.query.a] || null;
  const html = quotePageV2(q, cfg, publicBase(req), pre);
  return sendHtml(res, 200, html);
}

// Pagina ofertei (linkul din e-mail): același design ca e-mailul, cu răspuns direct pe pagină (fereastra quickAnswerHtml)
function quotePageV2(q, cfg, base, pre) {
  const url = `${base}/q/${q.token}`;
  const st = quoteStatus(q);
  const open = ['sent', 'viewed', 'clarify'].includes(st);
  let html = quoteEmailHtml(q, cfg, url);
  const F = "font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;";
  const B = { accepted: ['#DCFCE7', '#14532D', '✓', 'Ați acceptat această ofertă.', 'Vă mulțumim! Vă contactăm în cel mai scurt timp pentru programarea montajului.'],
              rejected: ['#FEE4E2', '#7A271A', '✕', 'Ați refuzat această ofertă.', 'Vă mulțumim pentru timpul acordat. Ne puteți contacta oricând pentru o ofertă nouă.'],
              expired:  ['#EEF2F7', '#475467', '⏱', 'Această ofertă a expirat.', 'Ne puteți contacta pentru o ofertă actualizată.'],
              clarify:  ['#FEF3C7', '#78350F', '?', 'Am primit întrebarea dumneavoastră.', 'Vă răspundem în maxim 24 de ore. Între timp puteți accepta sau refuza oferta.'] }[st];
  const banner = B ? `<div style="${F}background:${B[0]};color:${B[1]};border-radius:12px;padding:16px 18px;margin:0 0 ${open ? 18 : 6}px"><div style="font-size:17px;font-weight:800">${B[2]}&nbsp; ${B[3]}</div><div style="font-size:14px;line-height:1.5;margin-top:4px">${B[4]}</div>${q.response && q.response.message ? `<div style="font-size:13px;margin-top:8px;opacity:.85">Mesajul dumneavoastră: „${escHtml(q.response.message)}”</div>` : ''}</div>` : '';
  const btn = 'cursor:pointer;display:block;width:100%;box-sizing:border-box;text-align:center;border-radius:10px;';
  const cta = `<tr class="noprint"><td class="px" style="padding:24px 32px 28px">${banner}${open ? `<div style="${F}font-size:19px;font-weight:800;color:#14202E;margin:0 0 4px">Ce decideți?</div>
    <div style="${F}font-size:13px;color:#5B6B7C;margin:0 0 16px">Alegeți o variantă și confirmați — durează câteva secunde.</div>
    <button onclick="qaOpen('accept')" style="${F}${btn}background:#F5A100;color:#0D1F33;border:0;font-weight:800;font-size:17px;padding:17px 20px">Accept oferta</button>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px"><tr>
      <td width="50%" style="padding-right:5px"><button onclick="qaOpen('clarify')" style="${F}${btn}background:#fff;color:#0D1F33;border:1.5px solid #0D1F33;font-weight:700;font-size:15px;padding:13px 8px">Cer clarificări</button></td>
      <td width="50%" style="padding-left:5px"><button onclick="qaOpen('reject')" style="${F}${btn}background:#fff;color:#5B6B7C;border:1.5px solid #C5CED8;font-weight:700;font-size:15px;padding:13px 8px">Refuz oferta</button></td></tr></table>` : ''}
    <div style="${F}text-align:center;margin-top:16px"><button onclick="window.print()" style="${F}background:none;border:0;color:#0D1F33;font-weight:700;font-size:13px;text-decoration:underline;cursor:pointer">Descarcă / printează oferta (PDF)</button></div></td></tr>`;
  html = html.replace(/<!--CTA-->[\s\S]*?<!--\/CTA-->/, cta).replace(/<!--MAILNOTE-->[\s\S]*?<!--\/MAILNOTE-->/, '');
  html = html.replace('<meta name="color-scheme" content="light only">', '<meta name="color-scheme" content="light only"><meta name="robots" content="noindex,nofollow">')
             .replace('</style></head>', '@media print{.noprint{display:none!important}body,table{background:#fff!important}@page{margin:10mm}}</style></head>')
             .replace(`<title>Oferta nr. ${q.no}</title>`, `<title>Oferta nr. ${q.no} — ${escHtml(cfg.company)}</title>`);
  if (open) html = html.replace('</body>', quickAnswerHtml(q, pre) + '</body>');
  return html;
}

// Fereastra de răspuns rapid: când clientul apasă Accept / Clarificări / Refuz în e-mail, pagina se deschide direct cu fereastra
// de confirmare (un singur tap). Nu acceptăm automat la simpla deschidere a linkului (filtrele anti-spam deschid linkurile singure).
function quickAnswerHtml(q, pre) {
  const T = {
    accept:  { h: 'Acceptați oferta?', p: `Confirmați acceptarea ofertei nr. ${q.no} — <b>${lei(q.pricing.total)} / lună</b>. Vă contactăm pentru programarea montajului.`, ph: 'Observații (opțional) — ex. când vă putem suna', b: 'Da, accept oferta', c: '#F5A100', t: '#0D1F33', ok: 'Mulțumim! Ați acceptat oferta.', ok2: 'Vă contactăm în cel mai scurt timp pentru programarea montajului.', req: false },
    clarify: { h: 'Ce doriți să clarificăm?', p: 'Scrieți întrebarea sau ce ați vrea schimbat (ex. o cameră în plus, alt amplasament).', ph: 'Întrebarea dumneavoastră…', b: 'Trimite întrebarea', c: '#0D1F33', t: '#FFFFFF', ok: 'Am primit întrebarea dumneavoastră.', ok2: 'Vă răspundem în maxim 24 de ore, în zilele lucrătoare.', req: true },
    reject:  { h: 'Refuzați oferta?', p: 'Ne pare rău că oferta nu vi se potrivește. Ne spuneți motivul? Ne ajută să facem o ofertă mai bună.', ph: 'Motivul (opțional)', b: 'Confirm refuzul', c: '#B42318', t: '#FFFFFF', ok: 'Am înregistrat răspunsul dumneavoastră.', ok2: 'Vă mulțumim pentru timpul acordat.', req: false },
  };
  const J = JSON.stringify(T).replace(/</g, '\\u003c');
  return `<style>
.qa-bg,.qa-bg *{box-sizing:border-box;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
.qa textarea{display:block;width:100%;border:1.5px solid #C5CED8;border-radius:12px;padding:12px 14px;color:#14202E;background:#F8FAFC;outline:none;resize:vertical}
.qa textarea:focus{border-color:#0B5FB0;box-shadow:0 0 0 3px rgba(11,95,176,.15)}
.qa-bg{position:fixed;inset:0;background:rgba(13,31,51,.55);z-index:50;display:flex;align-items:center;justify-content:center;padding:16px;animation:qaf .2s ease}
.qa{background:#fff;border-radius:18px;width:100%;max-width:440px;padding:24px 22px 20px;box-shadow:0 24px 60px -20px rgba(0,0,0,.45);animation:qau .25s ease}
.qa h3{font-size:21px;margin:0 0 8px;color:#0D1F33;letter-spacing:-.01em}
.qa p{font-size:15px;line-height:1.55;color:#4a5568;margin:0 0 14px}
.qa textarea{min-height:96px;font-size:16px}
.qa .go{display:block;width:100%;border:0;border-radius:12px;padding:16px;font-size:17px;font-weight:800;margin-top:12px;cursor:pointer;font-family:inherit}
.qa .go:disabled{opacity:.6}
.qa .x{display:block;width:100%;background:none;border:0;color:#5B6B7C;font-size:14px;font-weight:600;padding:12px 0 2px;cursor:pointer;font-family:inherit}
.qa .err{color:#B42318;font-size:14px;margin-top:8px;min-height:0}
.qa .ic{width:56px;height:56px;border-radius:28px;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 0 12px}
@keyframes qaf{from{opacity:0}to{opacity:1}}@keyframes qau{from{transform:translateY(24px);opacity:0}to{transform:none;opacity:1}}
@media(max-width:560px){.qa-bg{align-items:flex-end;padding:0}.qa{border-radius:20px 20px 0 0;max-width:none;padding:24px 20px calc(20px + env(safe-area-inset-bottom))}}
</style>
<div class="qa-bg" id="qa" style="display:none"><div class="qa" role="dialog" aria-modal="true"><div id="qa-in"></div></div></div>
<script>(function(){
var T=${J}, a=null, t=null, box=document.getElementById('qa'), inn=document.getElementById('qa-in');
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function close(){box.style.display='none';try{history.replaceState(null,'',location.pathname);}catch(e){}}
box.addEventListener('click',function(e){if(e.target===box)close();});
window.qaOpen=function(x){ a=x; t=T[a]; box.style.display='flex';
inn.innerHTML='<div class="ic" style="background:'+(a==='accept'?'#FFF4DC':a==='reject'?'#FEE4E2':'#E8F1FB')+'">'+(a==='accept'?'✓':a==='reject'?'✕':'?')+'</div><h3>'+t.h+'</h3><p>'+t.p+'</p><textarea id="qa-m" placeholder="'+esc(t.ph)+'"></textarea><div class="err" id="qa-e"></div><button class="go" id="qa-go" style="background:'+t.c+';color:'+t.t+'">'+t.b+'</button><button class="x" id="qa-x">Înapoi la ofertă</button>';
var m=document.getElementById('qa-m'), go=document.getElementById('qa-go'), er=document.getElementById('qa-e');
document.getElementById('qa-x').onclick=close;
if(a==='clarify') setTimeout(function(){m.focus();},300);
go.onclick=function(){
  if(t.req && !m.value.trim()){er.textContent='Scrieți ce ați dori să clarificăm.';m.focus();return;}
  go.disabled=true; go.textContent='Se trimite…'; er.textContent='';
  fetch(location.pathname+'/respond',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:a,message:m.value})})
   .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})
   .then(function(x){ if(!x.ok){er.textContent=x.j.error||'Eroare';go.disabled=false;go.textContent=t.b;return;}
     inn.innerHTML='<div class="ic" style="background:#DCFCE7;color:#16a34a">✓</div><h3>'+t.ok+'</h3><p>'+t.ok2+'</p><button class="go" id="qa-done" style="background:#0D1F33;color:#fff">Vezi oferta</button>';
     document.getElementById('qa-done').onclick=function(){location.replace(location.pathname);}; })
   .catch(function(){er.textContent='Nu s-a putut trimite. Verificați conexiunea și încercați din nou.';go.disabled=false;go.textContent=t.b;});
};
};
var pre=${JSON.stringify(pre)}; if(pre) window.qaOpen(pre);
})();</script>`;
}

async function handleQuotesApi(req, res, pathname, parsed) {
  const ctx = requireUser(req, res); if (!ctx) return;
  const uname = ctx.user.username;
  if (pathname === '/quote-settings') {
    if (req.method === 'GET') return sendJson(res, 200, { settings: quoteCfg(ctx.db, ctx.user), mail: mailReady(), base: publicBase(req) });
    if (req.method === 'PUT' || req.method === 'POST') {
      const b = await readJson(req); const out = {};
      for (const k of Object.keys(QUOTE_DEFAULTS)) {
        if (!(k in b)) continue;
        out[k] = typeof QUOTE_DEFAULTS[k] === 'number' ? qNum(b[k]) : typeof QUOTE_DEFAULTS[k] === 'boolean' ? !!b[k] : str(b[k], k === 'intro' || k === 'note' || k === 'includes' ? 2000 : 160);
      }
      if (!['included', 'plus', 'none'].includes(out.vatMode)) delete out.vatMode;
      const conf = ctx.db.configs[uname] = ctx.db.configs[uname] || {};
      conf.quoteCfg = { ...(conf.quoteCfg || {}), ...out };
      saveDb(ctx.db);
      return sendJson(res, 200, { settings: quoteCfg(ctx.db, ctx.user) });
    }
  }
  const all = loadQuotes();
  const mine = all.list.filter(q => q.owner === uname);
  const view = q => ({ ...q, status: quoteStatus(q), url: `${publicBase(req)}/q/${q.token}` });
  if (pathname === '/quotes' && req.method === 'GET') return sendJson(res, 200, { quotes: mine.map(view).reverse(), mail: mailReady() });
  const id = pathname.split('/')[2];
  const q = mine.find(x => x.id === id);
  if (!q) return sendJson(res, 404, { error: 'Ofertă inexistentă' });
  if (req.method === 'PUT') {
    const b = await readJson(req);
    if (b.status && QSTATUS[b.status] && b.status !== 'expired' && b.status !== q.status && (q.kind === 'contact') === (b.status === 'new')) { q.status = b.status; q.events.push({ t: Date.now(), type: b.status, manual: true }); }
    if ('notes' in b) q.notes = str(b.notes, 4000);
    if ('handled' in b) q.handled = !!b.handled;
    if (b.extendDays) { q.validUntil = Math.max(Date.now(), q.validUntil) + Math.min(365, qNum(b.extendDays)) * 864e5; q.events.push({ t: Date.now(), type: 'extended' }); }
    saveQuotes(all);
    return sendJson(res, 200, { quote: view(q) });
  }
  if (req.method === 'DELETE') { all.list = all.list.filter(x => x !== q); saveQuotes(all); return sendJson(res, 200, { ok: true }); }
  return sendJson(res, 405, { error: 'Operație necunoscută' });
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

    if (pathname === '/health') return sendJson(res, 200, { ok: true, version: 6.0, mail: mailReady(), rtsp: hasFfmpeg(), push: !!webPush(), monitor: { enabled: MONITOR_ENABLED, lastRun: monLastRun, nvrs: Object.keys(monState.nvr).length } });
    if (pathname === '/snap' && req.method === 'GET') return await handleSnap(req, res, parsed);
    if (pathname === '/clients-backup' && req.method === 'GET') return handleClientsBackup(req, res);
    // ── Oferte (public: calculator, pagina ofertei; privat: listă și setări) ──
    if (pathname.startsWith('/email-img/') && req.method === 'GET') {
      const m = /^\/email-img\/([a-z0-9-]+)\.(png|jpg)$/.exec(pathname);
      let buf = null; try { if (m) buf = fs.readFileSync(path.join(BASE_DIR, 'email-img', m[1] + '.' + m[2])); } catch {}
      if (!buf) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': m[2] === 'png' ? 'image/png' : 'image/jpeg', 'Cache-Control': 'public, max-age=604800', ...PUB_CORS }); return res.end(buf);
    }
    if (pathname === '/q-logo.png' && req.method === 'GET') {
      const m = /^data:([^;]+);base64,(.*)$/.exec(quoteLogo() || '');
      if (!m) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'Content-Type': m[1], 'Cache-Control': 'public, max-age=86400', ...PUB_CORS }); return res.end(Buffer.from(m[2], 'base64'));
    }
    if (pathname === '/calculator' && req.method === 'GET') {
      const db = loadDb(); const owner = quoteOwner(db);
      return sendHtml(res, 200, calculatorHtml(quoteCfg(db, owner), quoteLogo(), publicBase(req)));
    }
    if (pathname === '/public/quote' && req.method === 'POST') return await handlePublicQuote(req, res, false);
    if ((pathname === '/contact' || pathname === '/public/contact') && req.method === 'POST') return await handleSiteContact(req, res);
    if ((pathname === '/cerere' || pathname === '/public/cerere') && req.method === 'POST') return await handlePublicQuote(req, res, true);
    if (pathname === '/public/prices' && req.method === 'GET') return handlePublicPrices(req, res);
    if (pathname.startsWith('/q/')) return await handleQuotePublic(req, res, pathname, parsed);
    if (pathname === '/quotes' || pathname.startsWith('/quotes/') || pathname === '/quote-settings') return await handleQuotesApi(req, res, pathname, parsed);
    if (pathname === '/company' && req.method === 'GET') return await handleCompany(req, res, parsed);
    if (pathname === '/clients' || pathname.startsWith('/clients/')) return await handleClients(req, res, pathname);
    if (pathname.startsWith('/push/')) return await handlePush(req, res, pathname);

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

server.listen(PORT, () => console.log('NVR Proxy v6.0 running on port ' + PORT + (hasFfmpeg() ? ' (ffmpeg OK)' : ' (fără ffmpeg)')));
