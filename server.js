const http    = require('http');
const https   = require('https');
const url     = require('url');
const fs      = require('fs');
const path    = require('path');
const jwt     = require('/opt/nvr-proxy/node_modules/jsonwebtoken');
const bcrypt  = require('/opt/nvr-proxy/node_modules/bcryptjs');

const PORT       = 3000;
const DB_FILE    = '/opt/nvr-proxy/db.json';
const JWT_SECRET = 'yca-secret-2024-supraveghere24h';

// ── DB simplu (JSON pe disk) ──────────────────────────────────────────
function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { users: [], configs: {} }; }
}
function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// Creează userul admin implicit dacă nu există
const db = loadDb();
if (!db.users.length) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.users.push({ id: 1, username: 'admin', password: hash });
  saveDb(db);
  console.log('User implicit creat: admin / admin123');
}

// ── Helper: parse body JSON ───────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => { try { resolve(JSON.parse(data||'{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

// ── Helper: verify JWT ────────────────────────────────────────────────
function authMiddleware(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ── HTTP Server ───────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ── POST /auth/login ─────────────────────────────────────────────
  if (pathname === '/auth/login' && req.method === 'POST') {
    const body = await parseBody(req);
    const db   = loadDb();
    const user = db.users.find(u => u.username === body.username);
    if (!user || !bcrypt.compareSync(body.password, user.password)) {
      res.writeHead(401, {'Content-Type':'application/json'});
      res.end(JSON.stringify({ error: 'User sau parolă greșită' }));
      return;
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({ token, username: user.username }));
    return;
  }

  // ── POST /auth/change-password ───────────────────────────────────
  if (pathname === '/auth/change-password' && req.method === 'POST') {
    const user = authMiddleware(req);
    if (!user) { res.writeHead(401); res.end('Unauthorized'); return; }
    const body = await parseBody(req);
    const db   = loadDb();
    const idx  = db.users.findIndex(u => u.id === user.id);
    if (idx === -1) { res.writeHead(404); res.end('User negăsit'); return; }
    db.users[idx].password = bcrypt.hashSync(body.password, 10);
    saveDb(db);
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── GET /config ──────────────────────────────────────────────────
  if (pathname === '/config' && req.method === 'GET') {
    const user = authMiddleware(req);
    if (!user) { res.writeHead(401); res.end('Unauthorized'); return; }
    const db  = loadDb();
    const cfg = db.configs[user.id] || {};
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify(cfg));
    return;
  }

  // ── POST /config ─────────────────────────────────────────────────
  if (pathname === '/config' && req.method === 'POST') {
    const user = authMiddleware(req);
    if (!user) { res.writeHead(401); res.end('Unauthorized'); return; }
    const body = await parseBody(req);
    const db   = loadDb();
    db.configs[user.id] = body;
    saveDb(db);
    res.writeHead(200, {'Content-Type':'application/json'});
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── GET / (proxy NVR) ────────────────────────────────────────────
  const target = parsed.query.url;
  if (!target) { res.writeHead(400); res.end('Missing ?url='); return; }

  const t    = url.parse(target);
  const auth = req.headers['authorization'];
  const opts = {
    hostname: t.hostname, port: t.port || (t.protocol === 'https:' ? 443 : 80), path: t.path,
    method: req.method, headers: {},
    timeout: 10000,
  };
  // Credentiale din URL (user:pass@host) au prioritate
  if (t.auth) {
    opts.headers['Authorization'] = 'Basic ' + Buffer.from(t.auth).toString('base64');
  } else if (auth) {
    opts.headers['Authorization'] = auth;
  }

  const lib = t.protocol === 'https:' ? https : http;
  const pr  = lib.request(opts, r => {
    res.writeHead(r.statusCode, {
      'Content-Type': r.headers['content-type'] || 'application/octet-stream',
      'Access-Control-Allow-Origin': '*',
    });
    r.pipe(res);
  });
  pr.on('error',   e => { res.writeHead(502); res.end('Proxy error: ' + e.message); });
  pr.on('timeout', () => { pr.destroy(); res.writeHead(504); res.end('Timeout'); });
  pr.end();

}).listen(PORT, () => console.log(`NVR Proxy + Auth running on port ${PORT}`));
