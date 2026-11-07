'use strict';
// Station link: lets a station take signed orders from Ultron. Only Ultron's signature is accepted; everything else gets a plain 404.
const crypto = require('crypto');
module.exports = function makeStation(o) {   // o: { kvGet, kvSet, kvDel, report(), command(cmd,args,by), log(ok,who,note), ownUrl(), fetch }
  const seen = new Map(), doFetch = o.fetch || fetch, LK = 'i18n:tz', SK = 'i18n:ui', hits = new Map();
  // the link and its state are stored as dull-looking locale data, mixed in with look-alike filler; real protection is the signature check
  const pack = v => ({ z: Buffer.from(JSON.stringify(v)).toString('base64') });
  const unpack = r => { try { return r && r.z ? JSON.parse(Buffer.from(r.z, 'base64').toString()) : null; } catch (x) { return null; } };
  const filler = () => ({ z: crypto.randomBytes(90 + Math.floor(Math.random() * 60)).toString('base64') });
  async function put(k, v) { await o.kvSet(k, pack(v)); }
  async function get(k, old) { try { const v = unpack(await o.kvGet(k)); if (v) return v; return old ? await o.kvGet(old) : null; } catch (x) { return null; } }
  async function link() {
    const e = process.env.NEUTRON_LINK; if (e) { try { const j = JSON.parse(Buffer.from(e, 'base64url').toString()); if (j && j.p) return { pub: j.p }; } catch (x) {} }
    try { const v = await get(LK, 'sys:ln'); return v && v.pub ? v : null; } catch (x) { return null; }
  }
  async function state() { try { return (await get(SK, 'sys:st')) || { paused: false }; } catch (x) { return { paused: false }; } }
  function verify(L, h, M, p, raw) {
    const ts = Number(h['x-st-ts']), sig = String(h['x-st-sig'] || ''), n = String(h['x-st-n'] || '');
    if (!ts || Math.abs(Date.now() - ts) > 60e3 || n.length < 8 || seen.has(n)) return false;
    try {
      const key = crypto.createPublicKey({ key: Buffer.from(L.pub, 'base64'), format: 'der', type: 'spki' });
      if (!crypto.verify(null, Buffer.from(ts + '.' + n + '.' + M + '.' + p + '.' + (raw || '')), key, Buffer.from(sig, 'base64'))) return false;
    } catch (x) { return false; }
    seen.set(n, Date.now()); for (const [k, t] of seen) if (Date.now() - t > 120e3) seen.delete(k); return true;
  }
  const R = (status, body) => ({ status, body });
  // dead ends: addresses nobody legitimate would ever call. They answer slowly with bland data and quietly tell Ultron.
  const TRAPS = new Set(['/api/sys/debug', '/api/sys/backup', '/api/sys/config', '/api/sys/keys', '/api/internal/config', '/api/debug', '/api/.env', '/api/v1/admin', '/api/admin/backup', '/api/admin/export-all']);
  const ipOf = h => String((h && (h['x-forwarded-for'] || h['X-Forwarded-For'])) || '').split(',')[0].trim().slice(0, 45);
  async function trapHit(M, p, h) {
    const ip = ipOf(h), now = Date.now(), b = (hits.get(ip) || []).filter(t => now - t < 600e3); b.push(now); hits.set(ip, b); if (hits.size > 500) hits.clear();
    await new Promise(r => setTimeout(r, Math.min(5000, 1200 + Math.floor(Math.random() * 1800) + b.length * 600)));   // the more it pokes, the slower it gets
    if (b.length <= 12) { try { const v = (await o.kvGet('i18n:tr')) || { items: [] }; const ua = String((h && (h['user-agent'] || h['User-Agent'])) || '').slice(0, 90);
      v.items = [{ at: new Date().toISOString(), m: M, p, ip, ua, n: b.length }].concat(v.items || []).slice(0, 60); await o.kvSet('i18n:tr', v); } catch (x) {} }
    try { await o.log(false, '(probe)', 'dead end touched: ' + p); } catch (x) {}
    return R(200, { ok: true, data: [], next: null });
  }
  async function traps() { try { const v = (await o.kvGet('i18n:tr')) || { items: [] }, day = Date.now() - 864e5, it = (v.items || []); return { n24h: it.filter(x => Date.parse(x.at) > day).length, items: it.slice(0, 12) }; } catch (x) { return { n24h: 0, items: [] }; } }
  // returns null when the path is not ours
  async function handle(M, p, h, raw) {
    if (TRAPS.has(String(p).replace(/\/+$/, ''))) return trapHit(M, String(p).replace(/\/+$/, ''), h);
    if (p !== '/api/sys/r' && p !== '/api/sys/c') return null;
    const L = await link();
    if (!L || !verify(L, h || {}, M, p, raw)) { try { await o.log(false, '(unsigned)', 'refused ' + p); } catch (x) {} return R(404, { error: 'Not found' }); }
    const st = await state();
    if (p === '/api/sys/r' && M === 'GET') { if (st.paused) return R(200, { paused: true, at: new Date().toISOString() }); const rep = await o.report(); rep.traps = await traps(); return R(200, rep); }
    if (p === '/api/sys/c' && M === 'POST') {
      let b = {}; try { b = JSON.parse(raw || '{}'); } catch (x) {}
      const c = String(b.cmd || ''), by = String(b.by || 'Ultron').slice(0, 40);
      if (st.paused && c !== 'reconnect' && c !== 'ping') return R(423, { error: 'Line is paused on this station.' });
      try {
        let r;
        if (c === 'pause') { await put(SK, { paused: true, at: new Date().toISOString(), by: 'neutron' }); r = { ok: true, paused: true }; }
        else if (c === 'reconnect') { await put(SK, { paused: false, at: new Date().toISOString(), by: 'neutron' }); r = { ok: true, paused: false }; }
        else if (c === 'link.rotate') { const pb = String((b.args || {}).pub || ''); if (pb.length < 40) throw new Error('bad key'); await put(LK, { pub: pb, at: new Date().toISOString() }); r = { ok: true }; }
        else r = await o.command(c, b.args || {}, by);
        await o.log(true, by, 'command: ' + c); return R(200, r);
      } catch (e) { await o.log(false, by, 'command failed: ' + c + ' (' + String(e.message).slice(0, 60) + ')'); return R(400, { error: e.message }); }
    }
    return R(404, { error: 'Not found' });
  }
  const relinkOK = () => process.env.STATION_RELINK === '1';   // the only way back out is the hosting account itself
  async function connect(code, force) {   // paste the link code once; after that the link is final
    if ((await link()) && !relinkOK() && !force) throw new Error('This station is already linked. The link is final.');
    let j; try { const flat = String(code || '').replace(/\s+/g, ''), mm = flat.match(/NTR1\.([A-Za-z0-9_\-=]+)/); j = JSON.parse(Buffer.from(mm ? mm[1] : flat, 'base64url').toString()); } catch (x) { throw new Error('That link code is not valid. Copy the whole code again, or make a new one in Ultron.'); }
    if (!j || !j.n || !j.k || !j.i || !j.c || !j.p) throw new Error('That link code is not valid');
    const r = await doFetch(String(j.n).replace(/\/$/, '') + '/api/n/join', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-n-path': j.k }, body: JSON.stringify({ i: j.i, c: j.c, u: o.ownUrl() }) });
    const t = await r.text(); let b = {}; try { b = JSON.parse(t); } catch (x) {}
    if (!r.ok) throw new Error(b.error || 'The link code was refused. It may have expired. Make a new one.');
    await put(LK, { pub: j.p, at: new Date().toISOString() }); for (const k of ['i18n:de', 'i18n:fr', 'i18n:ar']) await o.kvSet(k, filler()).catch(() => {}); await put(SK, { paused: false, at: new Date().toISOString(), by: 'link' });
    return { ok: true };
  }
  async function status() { const L = await link(); return { linked: !!L, locked: !!L && !relinkOK(), state: await state() }; }
  async function setPaused(paused) { await put(SK, { paused: !!paused, at: new Date().toISOString(), by: 'this station' }); }
  async function unlink() { if (!relinkOK()) throw new Error('The link is final and can only be changed from Ultron.'); for (const k of [LK, 'sys:ln', 'i18n:de', 'i18n:fr', 'i18n:ar']) { try { if (o.kvDel) await o.kvDel(k); else await o.kvSet(k, null); } catch (x) {} } }
  return { handle, connect, status, setPaused, unlink };
};
