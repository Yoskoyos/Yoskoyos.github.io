const http = require('http');
const crypto = require('crypto');
const NVRS = [
  { name: 'Depozit Caldararu', ip: '5.2.140.62', port: 81, user: 'admin', pass: 'Florin1987' },
];
const DRIFT_THRESHOLD_SEC = 120;
function pad(n) { return String(n).padStart(2, '0'); }
function getBucharestTime() {
  const now = new Date();
  const localD = new Date(now.toLocaleString('en-US', { timeZone: 'Europe/Bucharest' }));
  const utcD   = new Date(now.toLocaleString('en-US', { timeZone: 'UTC' }));
  const offsetH = Math.round((localD - utcD) / 3600000);
  const offsetStr = (offsetH >= 0 ? '+' : '-') + pad(Math.abs(offsetH)) + ':00';
  const iso = localD.getFullYear() + '-' + pad(localD.getMonth()+1) + '-' + pad(localD.getDate()) +
              'T' + pad(localD.getHours()) + ':' + pad(localD.getMinutes()) + ':' + pad(localD.getSeconds());
  return { iso, offsetStr, nowMs: now.getTime() };
}
function digestAuth(method, path, body, nvr) {
  return new Promise((resolve, reject) => {
    const req1 = http.request({ host: nvr.ip, port: nvr.port, path: path, method: 'GET',
      headers: { 'Accept': 'application/xml' } }, function(res1) {
      const wwwAuth = res1.headers['www-authenticate'] || '';
      res1.resume();
      const get = function(key) {
        const m = wwwAuth.match(new RegExp(key + '="([^"]*)"'));
        return m ? m[1] : '';
      };
      const realm = get('realm'), nonce = get('nonce'), qop = get('qop');
      const nc = '00000001', cnonce = crypto.randomBytes(4).toString('hex');
      const md5 = function(s) { return crypto.createHash('md5').update(s).digest('hex'); };
      const ha1 = md5(nvr.user + ':' + realm + ':' + nvr.pass);
      const ha2 = md5(method + ':' + path);
      const response = qop
        ? md5(ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2)
        : md5(ha1 + ':' + nonce + ':' + ha2);
      const authHeader = 'Digest username="' + nvr.user + '", realm="' + realm + '", nonce="' + nonce +
        '", uri="' + path + '", ' + (qop ? 'qop=' + qop + ', nc=' + nc + ', cnonce="' + cnonce + '", ' : '') +
        'response="' + response + '"';
      const bodyBuf = Buffer.from(body || '', 'utf8');
      const req2 = http.request({ host: nvr.ip, port: nvr.port, path: path, method: method,
        headers: { 'Authorization': authHeader, 'Content-Type': 'application/xml', 'Content-Length': bodyBuf.length }
      }, function(res2) {
        let data = '';
        res2.on('data', function(d) { data += d; });
        res2.on('end', function() { resolve({ status: res2.statusCode, body: data }); });
      });
      req2.on('error', reject);
      if (body) req2.write(bodyBuf);
      req2.end();
    });
    req1.on('error', reject);
    req1.setTimeout(8000, function() { req1.destroy(); reject(new Error('timeout')); });
    req1.end();
  });
}
async function syncNvr(nvr) {
  try {
    const r = await digestAuth('GET', '/ISAPI/System/status', null, nvr);
    if (r.status !== 200) { console.log('[' + nvr.name + '] status ' + r.status + ' skip'); return; }
    const m = r.body.match(/<currentDeviceTime>([^<]+)<\/currentDeviceTime>/);
    if (!m) { console.log('[' + nvr.name + '] nu gasesc currentDeviceTime'); return; }
    const nvrTime = new Date(m[1]);
    const t = getBucharestTime();
    const driftSec = Math.abs(t.nowMs - nvrTime.getTime()) / 1000;
    console.log('[' + nvr.name + '] deriva: ' + Math.round(driftSec) + 's');
    if (driftSec <= DRIFT_THRESHOLD_SEC) { console.log('[' + nvr.name + '] ora OK'); return; }
    const body = '<?xml version="1.0" encoding="UTF-8"?><Time><timeMode>manual</timeMode><localTime>' +
      t.iso + t.offsetStr + '</localTime><timeZone>EET-2:00:00EEST01:00:00,M3.5.0/3,M10.5.0/4</timeZone></Time>';
    const r2 = await digestAuth('PUT', '/ISAPI/System/time', body, nvr);
    console.log('[' + nvr.name + '] sync ' + (r2.status === 200 ? 'OK' : 'FAIL ' + r2.status) + ' -> ' + t.iso + t.offsetStr);
  } catch(e) { console.log('[' + nvr.name + '] eroare: ' + e.message); }
}
async function main() {
  console.log('=== Sync ora NVR ' + new Date().toLocaleString('ro-RO', {timeZone:'Europe/Bucharest'}) + ' ===');
  for (const nvr of NVRS) await syncNvr(nvr);
  console.log('Done');
}
main();
