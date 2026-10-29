#!/usr/bin/env node
// Diagnostic: ce raportează un NVR despre camerele lui (rulat MANUAL pe VPS, nu modifică nimic).
// Folosire:  node diag-cam.js "Coafor"      (caută NVR-ul după nume, în /opt/nvr-proxy/db.json)
// Nu afișează parole.
'use strict';
const fs = require('fs'), http = require('http'), crypto = require('crypto'), path = require('path');
const DIR = process.env.NVR_PROXY_DIR || '/opt/nvr-proxy';
const q = (process.argv[2] || '').toLowerCase();
if (!q) { console.log('Scrie o parte din numele NVR-ului, ex: node diag-cam.js Coafor'); process.exit(1); }
const db = JSON.parse(fs.readFileSync(path.join(DIR, 'db.json'), 'utf8'));
const md5 = s => crypto.createHash('md5').update(s).digest('hex');

function digest(user, pass, uri, wa) {
  const g = k => (wa.match(new RegExp(k + '="?([^",]*)"?')) || [])[1] || '';
  const realm = g('realm'), nonce = g('nonce'), opaque = g('opaque');
  const qop = g('qop').split(',').map(s => s.trim()).includes('auth') ? 'auth' : '';
  const nc = '00000001', cn = crypto.randomBytes(8).toString('hex');
  const ha1 = md5(`${user}:${realm}:${pass}`), ha2 = md5(`GET:${uri}`);
  const resp = qop ? md5(`${ha1}:${nonce}:${nc}:${cn}:${qop}:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`);
  let h = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${resp}"`;
  if (qop) h += `, qop=${qop}, nc=${nc}, cnonce="${cn}"`;
  if (opaque) h += `, opaque="${opaque}"`;
  return h;
}
function get(nvr, cred, uri) {
  return new Promise(res => {
    const o = { hostname: String(nvr.ip).trim(), port: parseInt(nvr.port, 10) || 80, path: uri, timeout: 8000 };
    const col = r => { let b = ''; r.setEncoding('utf8'); r.on('data', d => b += d); r.on('end', () => res({ s: r.statusCode, b })); };
    const r1 = http.get(o, a => {
      if (a.statusCode !== 401) return col(a);
      a.resume();
      const r2 = http.get({ ...o, headers: { Authorization: digest(cred.user || 'admin', cred.pass || '', uri, a.headers['www-authenticate'] || '') } }, col);
      r2.on('error', e => res({ s: 0, b: e.message })); r2.on('timeout', () => r2.destroy());
    });
    r1.on('error', e => res({ s: 0, b: e.message })); r1.on('timeout', () => r1.destroy());
  });
}
const short = b => b.replace(/<\?xml[^>]*>/, '').replace(/\s+/g, ' ').replace(/ xmlns="[^"]*"/g, '').slice(0, 900);

(async () => {
  let found = 0;
  for (const [user, conf] of Object.entries(db.configs || {})) {
    for (const nvr of (conf.nvrs || [])) {
      if (!String(nvr.name || '').toLowerCase().includes(q)) continue;
      found++;
      const cred = (conf.creds || {})[nvr.id] || {};
      console.log(`\n===== ${nvr.name}  (${nvr.ip}:${nvr.port}, ${nvr.channels} canale) =====`);
      for (const uri of ['/ISAPI/System/deviceInfo',
                         '/ISAPI/ContentMgmt/InputProxy/channels/status',
                         ]) {
        const r = await get(nvr, cred, uri);
        console.log(`\n--- ${uri}  → HTTP ${r.s}`);
        if (uri.endsWith('channels/status') && r.s === 200) {
          // rezumat pe canal: id · IP cameră · online · motiv
          for (const b of r.b.matchAll(/<InputProxyChannelStatus\b[^>]*>([\s\S]*?)<\/InputProxyChannelStatus>/g)) {
            const t = b[1], g = k => (t.match(new RegExp(`<${k}\\b[^>]*>\\s*([^<]*?)\\s*<`)) || [])[1] || '-';
            console.log(`CH${g('id')}  ${g('ipAddress').padEnd(15)}  online=${g('online').padEnd(5)}  motiv=${g('chanDetectResult')}`);
          }
          continue;
        }
        if (uri.endsWith('deviceInfo')) {
          const m = t => (r.b.match(new RegExp(`<${t}>([^<]*)<`)) || [])[1] || '?';
          console.log(`model ${m('model')} · firmware ${m('firmwareVersion')} ${m('firmwareReleasedDate')}`);
        } else console.log(short(r.b));
      }
    }
  }
  if (!found) console.log('Nu am găsit niciun NVR cu numele „' + q + '”.');
})();
