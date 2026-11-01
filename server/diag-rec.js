#!/usr/bin/env node
// Diagnostic înregistrare: ce răspunde un NVR la programul de înregistrare și la căutarea de înregistrări.
// Folosire:  node diag-rec.js "Depozit" 14,22 24   sau   node diag-rec.js "Depozit" toate 24   (NVR, canale, câte ore în urmă; rulat MANUAL pe VPS; nu modifică nimic, nu afișează parole)
'use strict';
const fs = require('fs'), http = require('http'), crypto = require('crypto'), path = require('path');
const DIR = process.env.NVR_PROXY_DIR || '/opt/nvr-proxy';
const q = (process.argv[2] || '').toLowerCase();
if (!q) { console.log('Scrie o parte din numele NVR-ului, ex: node diag-rec.js Coafor'); process.exit(1); }
const db = JSON.parse(fs.readFileSync(path.join(DIR, 'db.json'), 'utf8'));
const md5 = s => crypto.createHash('md5').update(s).digest('hex');
function digest(user, pass, method, uri, wa) {
  const g = k => (wa.match(new RegExp(k + '="?([^",]*)"?')) || [])[1] || '';
  const realm = g('realm'), nonce = g('nonce'), opaque = g('opaque');
  const qop = g('qop').split(',').map(s => s.trim()).includes('auth') ? 'auth' : '';
  const nc = '00000001', cn = crypto.randomBytes(8).toString('hex');
  const ha1 = md5(`${user}:${realm}:${pass}`), ha2 = md5(`${method}:${uri}`);
  const resp = qop ? md5(`${ha1}:${nonce}:${nc}:${cn}:${qop}:${ha2}`) : md5(`${ha1}:${nonce}:${ha2}`);
  let h = `Digest username="${user}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${resp}"`;
  if (qop) h += `, qop=${qop}, nc=${nc}, cnonce="${cn}"`;
  if (opaque) h += `, opaque="${opaque}"`;
  return h;
}
function req(nvr, cred, method, uri, body) {
  return new Promise(res => {
    const hb = body ? { 'Content-Type': 'application/xml', 'Content-Length': Buffer.byteLength(body) } : {};
    const o = { hostname: String(nvr.ip).trim(), port: parseInt(nvr.port, 10) || 80, path: uri, method, timeout: 15000, headers: hb };
    const col = r => { let b = ''; r.setEncoding('utf8'); r.on('data', d => b += d); r.on('end', () => res({ s: r.statusCode, b })); };
    const r1 = http.request(o, a => {
      if (a.statusCode !== 401) return col(a);
      a.resume();
      const r2 = http.request({ ...o, headers: { ...hb, Authorization: digest(cred.user || 'admin', cred.pass || '', method, uri, a.headers['www-authenticate'] || '') } }, col);
      r2.on('error', e => res({ s: 0, b: e.message })); r2.on('timeout', () => r2.destroy()); r2.end(body || undefined);
    });
    r1.on('error', e => res({ s: 0, b: e.message })); r1.on('timeout', () => r1.destroy()); r1.end(body || undefined);
  });
}
const short = (b, n) => b.replace(/<\?xml[^>]*>/, '').replace(/\s+/g, ' ').replace(/ xmlns="[^"]*"/g, '').slice(0, n || 1500);
const pad2 = n => String(n).padStart(2, '0');
const ALL = String(process.argv[3] || '').toLowerCase() === 'toate';
let chs = String(process.argv[3] || '1').split(',').map(x => parseInt(x, 10)).filter(Boolean);
const hours = parseFloat(process.argv[4] || '1') || 1;
(async () => {
  let found = 0;
  for (const conf of Object.values(db.configs || {})) for (const nvr of (conf.nvrs || [])) {
    if (!String(nvr.name || '').toLowerCase().includes(q)) continue;
    found++;
    const cred = (conf.creds || {})[nvr.id] || {};
    console.log(`\n===== ${nvr.name}  (${nvr.ip}:${nvr.port}) =====`);
    const t = await req(nvr, cred, 'GET', '/ISAPI/System/time');
    const m = /<localTime>(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})/.exec(t.b);
    if (!m) { console.log('(nu am putut citi ora NVR-ului) HTTP ' + t.s); continue; }
    const wall = new Date(m[1] + 'T' + m[2] + ':' + m[3] + ':' + m[4] + 'Z');
    console.log('Ora NVR: ' + m[1] + ' ' + m[2] + ':' + m[3]);
    const st = await req(nvr, cred, 'GET', '/ISAPI/ContentMgmt/InputProxy/channels/status');
    const di = await req(nvr, cred, 'GET', '/ISAPI/System/deviceInfo');
    const an = await req(nvr, cred, 'GET', '/ISAPI/System/Video/inputs/channels');
    const ip = [...st.b.matchAll(/<InputProxyChannelStatus\b[^>]*>[\s\S]*?<id>(\d+)<\/id>/g)].map(x => +x[1]);
    console.log(`Model: ${(/<model>([^<]*)/.exec(di.b) || [])[1] || '?'} · tip: ${(/<deviceType>([^<]*)/.exec(di.b) || [])[1] || '?'} · canale analogice: ${[...an.b.matchAll(/<VideoInputChannel\b/g)].length} · canale IP: ${ip.length} (id-uri ${ip.join(',')})`);
    if (ALL) {
      const tl = await req(nvr, cred, 'GET', '/ISAPI/ContentMgmt/record/tracks');
      chs = [...tl.b.matchAll(/<Track\b[^>]*>[\s\S]*?<id>(\d+)<\/id>/g)].map(x => +x[1]).filter(id => id % 100 === 1).map(id => Math.floor(id / 100));
      console.log('Track-uri principale: ' + chs.map(c => c * 100 + 1).join(','));
    }
    const f = d => `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}T${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}Z`;
    for (const ch of chs) {
      const id = ch * 100 + 1;
      const tr = await req(nvr, cred, 'GET', '/ISAPI/ContentMgmt/record/tracks/' + id);
      const acts = [...tr.b.matchAll(/<ScheduleAction\b[^>]*>([\s\S]*?)<\/ScheduleAction>/g)].map(x => x[1]);
      const modes = {}; for (const a of acts) { const r = /<Record>\s*true/i.test(a) ? ((/<ActionRecordingMode>\s*([^<\s]+)/i.exec(a) || [])[1] || '?') : 'oprit'; modes[r] = (modes[r] || 0) + 1; }
      const cs = new RegExp(`<InputProxyChannelStatus\\b[^>]*>(?:(?!</InputProxyChannelStatus>)[\\s\\S])*?<id>${ch}</id>[\\s\\S]*?</InputProxyChannelStatus>`).exec(st.b);
      const on = cs ? ((/<online>([^<]*)/.exec(cs[0]) || [])[1] + ' / ' + ((/<chanDetectResult>([^<]*)/.exec(cs[0]) || [])[1] || '')) : 'canal negăsit';
      console.log(`\nCH${ch} (track ${id}) — HTTP ${tr.s} · online: ${on} · program: ${JSON.stringify(modes)} · implicit: ${(/<DefaultRecordingMode>([^<]*)/.exec(tr.b) || [])[1] || '-'}`);
      const body = `<?xml version="1.0" encoding="UTF-8"?><CMSearchDescription><searchID>${crypto.randomUUID()}</searchID><trackList><trackID>${id}</trackID></trackList><timeSpanList><timeSpan><startTime>${f(new Date(wall - hours * 3600e3))}</startTime><endTime>${f(wall)}</endTime></timeSpan></timeSpanList><maxResults>40</maxResults><searchResultPostion>0</searchResultPostion><metadataList><metadataDescriptor>//recordType.meta.std-cgi.com</metadataDescriptor></metadataList></CMSearchDescription>`;
      const r = await req(nvr, cred, 'POST', '/ISAPI/ContentMgmt/search', body);
      const items = [...r.b.matchAll(/<startTime>([^<]*)<\/startTime>\s*<endTime>([^<]*)<\/endTime>/g)].map(x => x[1].slice(5, 16).replace('T', ' ') + '→' + x[2].slice(11, 16)).sort();
      console.log(`  căutare ultimele ${hours} h → HTTP ${r.s} · ${(/<responseStatusStrg>([^<]*)/.exec(r.b) || [])[1] || ''} · ${(/<numOfMatches>(\d+)/.exec(r.b) || [])[1] || 0} rezultate${items.length ? ' · ultimele: ' + items.slice(-4).join(', ') : ''}`);
      if (r.s !== 200) console.log('  ' + short(r.b, 300));
    }
  }
  if (!found) console.log('Niciun NVR nu se potrivește cu: ' + q);
})();
