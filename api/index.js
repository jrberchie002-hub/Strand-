'use strict';
const crypto = require('crypto');
const SHIELD = require('../shield');
const E = process.env;
const SECRET = () => String(E.STORES_SECRET || 'dev-only-secret-change-me-please-0123456789');
/* ---------- storage: Firebase Firestore if configured, else memory ---------- */
const mem = new Map();
// strips accidental wrapping quotes and leading/trailing whitespace/newlines that commonly sneak in when
// pasting a credential into a dashboard's env var field - the single most common cause of a "valid-looking"
// Firebase key failing to auth.
const cleanEnv = v => String(v || '').trim().replace(/^['"]|['"]$/g, '').trim();
const fbProjectId = () => cleanEnv(E.FIREBASE_PROJECT_ID), fbClientEmail = () => cleanEnv(E.FIREBASE_CLIENT_EMAIL), fbPrivateKey = () => cleanEnv(E.FIREBASE_PRIVATE_KEY).replace(/\\n/g, '\n');
const fbOn = () => fbProjectId() && fbClientEmail() && fbPrivateKey();
const b64u = s => Buffer.from(s).toString('base64url');
let _fbTok = '', _fbTokExp = 0;
async function fbToken() {   // trades the service account key for a short-lived access token; cached until near expiry
  if (_fbTok && Date.now() < _fbTokExp) return _fbTok;
  const now = Math.floor(Date.now() / 1000);
  const unsigned = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' + b64u(JSON.stringify({ iss: fbClientEmail(), scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
  const key = fbPrivateKey();
  let jwt; try { jwt = unsigned + '.' + crypto.createSign('RSA-SHA256').update(unsigned).sign(key, 'base64url'); } catch (e) { throw new Error('firebase key invalid: ' + e.message); }
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt });
  const j = await r.json().catch(() => ({})); if (!r.ok || !j.access_token) throw new Error('firebase auth ' + r.status + ' ' + (j.error_description || j.error || ''));
  _fbTok = j.access_token; _fbTokExp = Date.now() + (j.expires_in || 3600) * 1000 - 60000; return _fbTok;
}
function toFs(v) {   // JS value -> Firestore's typed "Value" wire format
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFs) } };
  if (typeof v === 'object') return { mapValue: { fields: Object.fromEntries(Object.entries(v).map(([k, vv]) => [k, toFs(vv)])) } };
  return { stringValue: String(v) };
}
function fromFs(v) {   // and back
  if (!v) return null;
  if ('nullValue' in v) return null;
  if ('booleanValue' in v) return v.booleanValue;
  if ('integerValue' in v) return parseInt(v.integerValue, 10);
  if ('doubleValue' in v) return v.doubleValue;
  if ('stringValue' in v) return v.stringValue;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromFs);
  if ('mapValue' in v) { const o = {}; for (const [k, vv] of Object.entries(v.mapValue.fields || {})) o[k] = fromFs(vv); return o; }
  return null;
}
async function fs(method, docId, body) {
  const tok = await fbToken();
  const url = 'https://firestore.googleapis.com/v1/projects/' + fbProjectId() + '/databases/(default)/documents/strand_kv/' + encodeURIComponent(docId) + (method === 'PATCH' ? '?updateMask.fieldPaths=value' : '');
  const r = await fetch(url, { method, headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  if (r.status === 404) return null;
  const t = await r.text(); if (!r.ok) throw new Error('db ' + r.status + ' ' + t.slice(0, 200)); return t ? JSON.parse(t) : null;
}
const kvGet = async k => { if (!fbOn()) return mem.get(k) || null; const r = await fs('GET', k); return (r && r.fields && r.fields.value) ? fromFs(r.fields.value) : null; };
const kvSet = async (k, v) => {
  const clean = v && typeof v === 'object' ? JSON.parse(JSON.stringify(v, (kk, vv) => (kk[0] === '_' ? undefined : vv))) : v;
  if (!fbOn()) { if (clean === null || clean === undefined) mem.delete(k); else mem.set(k, clean); return; }
  if (clean === null || clean === undefined) { await fs('DELETE', k).catch(() => {}); return; }
  await fs('PATCH', k, { fields: { value: toFs(clean) } });
};
/* ---------- images: Supabase Storage if configured, else kept as base64 inline ---------- */
const sbOn = () => E.SUPABASE_URL && E.SUPABASE_SERVICE_KEY;
const MIME_EXT = { jpeg: 'jpg', png: 'png', webp: 'webp' };
async function sbUpload(dataUri, kind) {
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(dataUri); if (!m) return dataUri;
  const mime = m[1], buf = Buffer.from(m[2], 'base64'), ext = MIME_EXT[mime];
  const path = 'u/' + String(kind || 'img') + '-' + crypto.createHash('sha256').update(buf).digest('hex').slice(0, 24) + '.' + ext;
  const url = String(E.SUPABASE_URL).replace(/\/$/, '') + '/storage/v1/object/strand-images/' + path;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: 'Bearer ' + E.SUPABASE_SERVICE_KEY, 'Content-Type': 'image/' + mime, 'x-upsert': 'true' }, body: buf });
  if (!r.ok && r.status !== 409) { const t = await r.text().catch(() => ''); throw new Error('image upload ' + r.status + ' ' + t.slice(0, 160)); }
  return String(E.SUPABASE_URL).replace(/\/$/, '') + '/storage/v1/object/public/strand-images/' + path;
}
// validates+checks a freshly submitted picture (base64 data URI), then returns what should be stored:
// the Supabase CDN URL when configured, otherwise the base64 itself (old inline behaviour), or '' to clear it.
async function picIn(im, b, errLabel) {
  im = String(im || ''); if (!im) return { img: '' };
  if (!/^data:image\/(jpeg|png|webp);base64,/.test(im) || im.length > 450000) return { error: errLabel + ' is too large. Try a smaller one.' };
  const bp = badPic(im, b); if (bp) return { error: bp };
  if (!sbOn()) return { img: im };
  try { return { img: await sbUpload(im, 'p') }; } catch (e) { return { error: 'Could not save that picture. Try again.' }; }
}
/* ---------- helpers ---------- */
const J = (s, o) => ({ statusCode: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(o) });
const sha = x => crypto.createHash('sha256').update(String(x)).digest('hex');
const b64 = x => Buffer.from(x).toString('base64url');
const sign = o => { const p = b64(JSON.stringify(o)); return p + '.' + crypto.createHmac('sha256', SECRET()).update(p).digest('base64url'); };
const unsign = t => { try { const [p, s] = String(t).split('.'); const ok = crypto.createHmac('sha256', SECRET()).update(p).digest('base64url'); if (s.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(ok))) return null; const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch (e) { return null; } };
const phoneKey = p => { let d = String(p || '').replace(/\D/g, ''); if (d.startsWith('0') && d.length === 10) d = '233' + d.slice(1); return d.length >= 9 && d.length <= 15 ? d : ''; };
const str = (x, n) => String(x == null ? '' : x).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const slugify = s => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30);
const hits = new Map(); const limited = (ip, k, n, ms) => { const key = k + ip, now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < ms); a.push(now); hits.set(key, a); if (hits.size > 5000) hits.clear(); return a.length > n; };
const ekey = () => crypto.createHash('sha256').update('k:' + SECRET()).digest();
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', ekey(), iv), d = Buffer.concat([c.update(String(t), 'utf8'), c.final()]); return b64(Buffer.concat([iv, c.getAuthTag(), d])); };
const dec = t => { try { const r = Buffer.from(String(t), 'base64url'), d = crypto.createDecipheriv('aes-256-gcm', ekey(), r.subarray(0, 12)); d.setAuthTag(r.subarray(12, 28)); return Buffer.concat([d.update(r.subarray(28)), d.final()]).toString('utf8'); } catch (e) { return ''; } };
async function ps(key, path, body) { const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 9000); try { const r = await fetch('https://api.paystack.co' + path, { method: body ? 'POST' : 'GET', signal: ac.signal, headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; } finally { clearTimeout(tm); } }
const payMethods = s => { const p = s.pay || {}, m = []; if (p.paystack) m.push('paystack'); if (p.momo && p.momo.number) m.push('momo'); if (p.link) m.push('link'); if (p.cod !== false) m.push('cod'); return m; };
const pinHash = (pin, salt) => crypto.scryptSync(String(pin), salt, 32).toString('hex');
const RESERVED = ['app', 'api', 's', 'admin', 'login', 'signup', 'sample', 'www', 'help', 'about', 'explore', 'themes', 'security'];
const TYPES = { food: 'Food & drinks', thrift: 'Thrift & fashion', shoes: 'Shoes & sneakers', phones: 'Phones & gadgets', beauty: 'Beauty & care', home: 'Home & living', shipping: 'Shipping & delivery', other: 'Something else' };
const GOALS = ['sell', 'stock', 'pay', 'person', 'brand', 'deliver', 'team'];
const WEAK = new Set(['123456', '1234567', '12345678', '123456789', '0000000', '000000', '111111', '222222', '333333', '444444', '555555', '666666', '777777', '888888', '999999', '654321', 'password', 'qwerty', 'abc123', 'iloveyou', 'admin', 'letmein', 'welcome', 'strand']);
const passOk = p => { p = String(p || ''); if (p.length < 6 || p.length > 64) return 'Choose a password with at least 6 characters.'; const l = p.toLowerCase(); if (WEAK.has(l) || /^(.)\1+$/.test(p) || '01234567890123456789'.includes(l) || '98765432109876543210'.includes(l) || 'abcdefghijklmnopqrstuvwxyz'.includes(l) || /^(qwerty|asdf|zxcv|password)/.test(l)) return 'That password is too easy to guess. Try something harder.'; return ''; };
const emailKey = e => { e = String(e || '').trim().toLowerCase(); return e.length <= 254 && /^[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,}$/.test(e) ? e : ''; };
const acctKey = id => { const e = emailKey(id); if (e) return 'email:' + e; const p = phoneKey(id); return p ? 'phone:' + p : ''; };
const maskIp = ip => String(ip).replace(/^(\d+\.\d+)\.\d+\.\d+$/, '$1.x.x').replace(/(:[0-9a-f]*){4}$/i, ':x:x:x:x').slice(0, 24);
async function secLog(slug, what, ip) { try { const x = (await kvGet('sec:' + slug)) || { l: [] }; x.l.unshift({ at: new Date().toISOString(), what, ip: maskIp(ip) }); x.l = x.l.slice(0, 30); await kvSet('sec:' + slug, x); } catch (e) {} }
const FAKE_SALT = 'f'.repeat(24);
const ROLES = { owner: 'Owner', admin: 'Admin', manager: 'Store manager', sales: 'Sales manager', cashier: 'Cashier', assistant: 'Assistant', inventory: 'Stock keeper', developer: 'Developer' };
const PERM_ALL = ['orders', 'orders_edit', 'products', 'costs', 'stock', 'pos', 'pay_view', 'pay_confirm', 'pay_settings', 'analytics', 'team', 'settings', 'design', 'apps', 'domain', 'policies', 'notify', 'security', 'billing'];
const PERMS = { owner: PERM_ALL, admin: PERM_ALL.filter(x => x !== 'billing'), manager: ['orders', 'orders_edit', 'products', 'costs', 'stock', 'pos', 'pay_view', 'pay_confirm', 'analytics', 'policies', 'notify'], sales: ['orders', 'orders_edit', 'pos', 'pay_view', 'pay_confirm', 'analytics'], cashier: ['orders', 'pos', 'pay_confirm'], assistant: ['orders', 'orders_edit'], inventory: ['stock'], developer: ['design', 'apps', 'domain'] };
const hasPerm = (role, x) => (PERMS[role] || []).includes(x);
const planOf = s => { const p = s.plan || 'base'; if (p === 'base') return 'base'; if (s.paidUntil && Date.parse(s.paidUntil) + 3 * 864e5 < Date.now()) return 'base'; return p; };
const NOTE_PERM = { order: 'orders', lowstock: 'stock', payment: 'pay_view', team: 'security', security: 'security', billing: 'billing' };
async function note(s, type, text) { try { const pr = s.notify || {}; if (pr[type] === false) return; const x = (await kvGet('notes:' + s.slug)) || { l: [] }; x.l.unshift({ id: 'n' + Date.now().toString(36) + crypto.randomBytes(2).toString('hex'), at: new Date().toISOString(), type, text: str(text, 160), read: false }); x.l = x.l.slice(0, 100); await kvSet('notes:' + s.slug, x); if (pr.email && s.email && E.RESEND_API_KEY && (type === 'order' || type === 'security')) { fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: 'Bearer ' + E.RESEND_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ from: E.MAIL_FROM || 'Strand <onboarding@resend.dev>', to: [s.email], subject: str(text, 70), text: str(text, 300) + '\n\nOpen your shop to see more.' }) }).catch(() => {}); } } catch (e) {} }
const PRICE = () => ({ pro: +E.PRICE_PRO || 0, expert: +E.PRICE_EXPERT || 0 });
const saleOn = s => !!(s.sale && s.sale.on && s.sale.pct >= 1);
const salePx = (s, p) => saleOn(s) ? Math.round(p.price * (100 - s.sale.pct)) / 100 : p.price;
const pubProd = p => ({ id: p.id, name: p.name, price: p.price, was: p.was || 0, desc: p.desc || '', img: p.img || '', cat: p.cat || '', badge: p.badge || '', on: p.on, stock: p.stock == null ? null : p.stock });
const LAYP = { hdr: ['center', 'left', 'dark', 'mini'], hero: ['photo', 'split', 'center', 'bold', 'tiles', 'spot'], cats: ['tiles', 'circles', 'pills', 'cards', 'text'], cards: ['plain', 'border', 'tight', 'big', 'over'], promo: ['banner', 'duo', 'strip'], trust: ['icons', 'bar', 'none'], foot: ['simple', 'cols', 'dark'], shape: ['soft', 'sharp', 'round'], font: ['sans', 'serif'] }, LAYS = ['hero', 'trust', 'cats', 'items', 'promo', 'story'], PALS = ['white', 'cream', 'black', 'sage', 'blush', 'sky', 'sand'];
const cleanLayout = (b, old) => { const o = Object.assign({}, old || {}); if (b && typeof b === 'object') { const n = parseInt(b.n, 10); if (n >= 1 && n <= 120) o.n = n; if (b.parts && typeof b.parts === 'object') { const p = {}; for (const k of Object.keys(LAYP)) if (LAYP[k].includes(b.parts[k])) p[k] = b.parts[k]; o.parts = p; } if (Array.isArray(b.ord)) { const q = []; for (const x of b.ord) if (LAYS.includes(x) && !q.includes(x)) q.push(x); for (const x of LAYS) if (!q.includes(x)) q.push(x); o.ord = q; } if (Array.isArray(b.off)) o.off = b.off.filter(x => LAYS.includes(x)); } return o; };
const AIMARK = /trainedAlgorithmicMedia|algorithmicMedia|midjourney|dall[-·. ]?e|stable ?diffusion|adobe firefly|made with google ai|openai|novelai|leonardo\.ai|comfyui|sdxl|Sampler: |Negative prompt/i;
const aiPic = im => { try { return AIMARK.test(Buffer.from(String(im).split(',')[1] || '', 'base64').toString('latin1')); } catch (e) { return false; } };
const badPic = (im, b) => im && (b.own !== true ? 'Please tick the box to confirm your pictures are real photos, not AI-made.' : aiPic(im) ? 'AI-made pictures are not allowed. Please use a real photo.' : '');
const PLANS = ['base', 'pro', 'expert'], THEMES = ['classic', 'noir', 'linen', 'fresh', 'tech', 'soft', 'spotlight', 'editorial', 'aura'];
const FREE_PROMO_UNTIL = Date.parse('2026-12-01T00:00:00Z'); // launch promo: Pro/Expert auto-granted free through end of November; planOf()'s grace period then drops unpaid shops back to Base a few days into December
const THEME_EXPERT = new Set(['editorial', 'aura']);   // these two looks need the Expert plan, not just Pro - everything else is unchanged
const LAYOUT_EXPERT = new Set([13, 14]);   // the two named layouts that go with 'editorial' and 'aura' (positions in the frontend's LPRE list)
const THEME_LAYOUT = { editorial: 13, aura: 14 };   // picking one of these looks also switches to its matching layout, so it actually looks different, not just a colour change
const pubStore = (s, full) => ({ slug: s.slug, name: s.name, about: s.about || '', whatsapp: (s.wa !== false && s.phone) ? s.phone : '', call: (s.wa === false && s.phone) ? s.phone : '', type: s.type || 'other', typeName: TYPES[s.type] || TYPES.other, types: (s.types && s.types.length ? s.types : [s.type || 'other']).filter(t => TYPES[t]), area: s.area || '', hours: s.hours || '', delivery: s.delivery || '', open: s.open !== false, accent: s.accent || '#d4001a', plan: planOf(s), theme: s.theme || 'classic', layout: s.layout || null, pal: s.pal || '', verified: !!s.verified, dl: !!(s.apps || {}).delivery, fee: (s.apps || {}).delivery ? (s.fee || 0) : 0, freeAbove: (s.apps || {}).delivery ? (s.freeAbove || 0) : 0, dc: !!(s.apps || {}).discounts, announce: s.announce || '', policies: s.policies || {}, minOrder: (s.rules || {}).minOrder || 0, maxQty: (s.rules || {}).maxQty || 0, domain: (s.domain && s.domain.status === 'active') ? s.domain.name : '', pay: payMethods(s), hero: s.hero || {}, banner: s.banner || {}, social: s.social || {}, products: (s.products || []).filter(p => full || p.on !== false).map(p => full ? Object.assign(pubProd(p), { cost: p.cost || 0, sku: p.sku || '' }) : (saleOn(s) ? Object.assign(pubProd(p), { price: salePx(s, p), was: p.price, badge: p.badge || '-' + s.sale.pct + '%' }) : pubProd(p))) });
/* ---------- seed sample store so the platform can be shown at once ---------- */
async function addIdx(slug) { const x = (await kvGet('idx')) || { l: [] }; if (!x.l.includes(slug)) { x.l.push(slug); await kvSet('idx', x); } }
const STYPE = { classic: 'food', noir: 'thrift', linen: 'thrift', fresh: 'home', tech: 'phones', soft: 'beauty', spotlight: 'shoes' };
const SAMPLES = {
  classic: ['Sample Kitchen', 'Food', [['Smash burger', 45, 'Food'], ['Loaded fries', 30, 'Food'], ['Chicken wrap', 38, 'Food'], ['Fresh lemonade', 15, 'Drinks']], 'Fresh and hot, every day', '#d4001a'],
  noir: ['Sample Thrift', 'Streetwear', [['Dark Dreams Hoodie', 220, 'Hoodies'], ['Vintage Washed Tee', 95, 'T-shirts'], ['Utility Cargo Pants', 180, 'Pants'], ['Essential Cap', 70, 'Accessories'], ['Oversized Tee', 110, 'T-shirts'], ['Bomber Jacket', 340, 'Jackets']], 'Thrifted. Curated.', '#000000'],
  linen: ['Sample Atelier', 'Boutique', [['Embroidered Tee', 150, 'Tees'], ['Linen Shirt', 210, 'Shirts'], ['Canvas Tote', 80, 'Bags'], ['Silk Scarf', 120, 'Accessories']], 'Made with care, worn with ease', '#b08d62'],
  fresh: ['Sample Everyday', 'Lifestyle', [['Urban Backpack', 260, 'Bags'], ['Minimal Sneakers', 320, 'Footwear'], ['Classic Watch', 540, 'Watches'], ['Sunglasses', 160, 'Accessories'], ['Face Serum', 110, 'Beauty']], 'Premium products for every day', '#1f6b3a'],
  tech: ['Sample Gadgets', 'Tech', [['Wireless Earbuds', 350, 'Audio'], ['Smart Watch', 680, 'Wearables'], ['Bluetooth Speaker', 420, 'Audio'], ['Gaming Mouse', 190, 'Accessories']], 'Top tech gear for your lifestyle', '#2e9c2e'],
  soft: ['Sample Market', 'Everything', [['Travel Backpack', 240, 'Bags'], ['Wireless Headphones', 380, 'Electronics'], ['Running Shoes', 300, 'Sports'], ['Perfume', 260, 'Beauty'], ['Smart Watch', 450, 'Electronics']], 'Discover the best for you', '#6f7f3a'],
  spotlight: ['Sample Kicks', 'Sneakers', [['Air Cloud 270', 1200, 'Sneakers'], ['Street Black', 950, 'Sneakers'], ['Pure White', 1100, 'Sneakers']], 'Feel the future. Move with air.', '#111111']
};
function tile(name, hue) { const c = encodeURIComponent(String(name).charAt(0).toUpperCase()); return 'data:image/svg+xml;utf8,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="hsl(' + hue + ',18%,90%)"/><stop offset="1" stop-color="hsl(' + hue + ',22%,78%)"/></linearGradient></defs><rect width="400" height="400" fill="url(#g)"/><circle cx="200" cy="190" r="86" fill="hsl(' + hue + ',25%,28%)" opacity=".9"/><text x="200" y="222" font-family="Inter,Arial" font-weight="800" font-size="92" text-anchor="middle" fill="#fff">' + String(name).charAt(0).toUpperCase() + '</text></svg>'); }
async function seed() {
  if (await kvGet('seeded:v4')) return;
  let n = 0;
  for (const th of Object.keys(SAMPLES)) { const [name, area, prods, tag, acc] = SAMPLES[th], slug = th === 'classic' ? 'sample' : 'sample-' + th;
    await kvSet('store:' + slug, { slug, name, phone: '233200000000', wa: true, type: STYPE[th], listed: true, sample: true, sv: 0, area: 'Accra', about: tag, hours: 'Every day, 10am to 9pm', delivery: 'Delivery within Accra, from GH₵ 15', open: true, accent: acc, theme: th, layout: { n: Object.keys(SAMPLES).indexOf(th) * 3 + 1 }, pal: ({ classic: 'white', noir: 'black', linen: 'cream', fresh: 'sage', tech: 'black', soft: 'blush', spotlight: 'sky' })[th], plan: 'pro', announce: 'Free delivery on orders above GH₵ 300', hero: { title: tag, sub: 'Handpicked pieces. Priced for you.', cta: 'Shop now', img: '' }, banner: { title: 'New drops every week', sub: 'Order on WhatsApp in a minute', cta: 'See what is new', img: '' }, social: { instagram: 'yourshop', whatsapp: '233200000000' },
      products: prods.map((p, i) => ({ id: 'p' + i, name: p[0], price: p[1], was: i === 1 ? Math.round(p[1] * 1.25) : 0, desc: 'A sample item. Replace it with your own.', cat: p[2], badge: i === 0 ? 'New' : i === 1 ? 'Sale' : '', stock: i === 2 ? 3 : null, on: true, img: tile(p[0], (i * 47 + 12) % 360) })) }); n++; }
  for (const th of Object.keys(SAMPLES)) await addIdx(th === 'classic' ? 'sample' : 'sample-' + th);
  await kvSet('seeded:v4', { n });
}
async function auth(h) { const t = unsign(String(h.authorization || '').replace(/^Bearer /, '')); if (!t || t.r !== 'seller') return null; const s = await kvGet('store:' + t.slug); if (!s || (t.sv | 0) !== (s.sv | 0)) return null; const role = t.role || 'owner'; if (role !== 'owner') { const m = (s.staff || []).find(x => x.id === t.sid); if (!m || m.off || (t.uv | 0) !== (m.uv | 0)) return null; s._me = m; } s._role = role; s._sid = t.sid || ''; if (role === 'owner') s._me = null; return s; }
const tok = (s, role, sid) => sign({ r: 'seller', slug: s.slug, role, sid: sid || '', sv: s.sv | 0, uv: sid ? (((s.staff || []).find(x => x.id === sid) || {}).uv | 0) : 0, exp: Date.now() + (role === 'owner' ? 14 : 7) * 864e5 });
const isAdmin = h => E.STORES_ADMIN && String(E.STORES_ADMIN).length >= 16 && String(h['x-admin'] || '').length >= 16 && crypto.timingSafeEqual(Buffer.from(sha(h['x-admin'])), Buffer.from(sha(E.STORES_ADMIN)));
/* ---------- handler ---------- */
/* ---------- link to the command center (Neutron): signed orders only; the first link happens automatically from NEUTRON_LINK_CODE ---------- */
const ctlGet = async () => (await kvGet('ctl')) || { banner: '', maint: false };
const STN = require('../station')({
  kvGet: async k => (await kvGet('sys:' + k)) || null, kvSet: async (k, v) => { await kvSet('sys:' + k, v); }, kvDel: async k => { await kvSet('sys:' + k, null); },
  report: async () => {
    const x = (await kvGet('idx')) || { l: [] }, day = new Date().toISOString().slice(0, 10), c = await ctlGet(); let shops = 0, real = 0, verified = 0, closed = 0, dom = 0, newToday = 0; const plans = { base: 0, pro: 0, expert: 0 };
    for (const sl of x.l) { const s = await kvGet('store:' + sl); if (!s) continue; shops++; if (s.sample) continue; real++; plans[planOf(s)]++; if (s.verified) verified++; if (s.open === false) closed++; if (s.domain && s.domain.status === 'pending') dom++; if (String(s.createdAt || '').slice(0, 10) === day) newToday++; }
    const rq = (await kvGet('reqs')) || { l: [] };
    return { at: new Date().toISOString(), name: 'Strand', kind: 'platform', version: 'strand-1', shops: { total: real, newToday, verified, closed, plans }, waiting: { domains: dom, requests: (rq.l || []).filter(r => !r.done).length }, control: { banner: c.banner || '', maintenance: !!c.maint }, health: { store: fbOn() ? 'firestore' : 'memory', images: sbOn() ? 'supabase' : 'inline', paystack: !!E.PAYSTACK_PLATFORM_KEY, email: !!E.RESEND_API_KEY } };
  },
  command: async (c, a, by) => {
    const cur = await ctlGet(), t = (x, n) => String(x == null ? '' : x).slice(0, n);
    if (c === 'ping') return { pong: Date.now() };
    if (c === 'notice.set' || c === 'banner.set') { cur.banner = t(a.text || [a.head, a.l1].filter(Boolean).join(' '), 160); await kvSet('ctl', cur); return { ok: true }; }
    if (c === 'notice.clear' || c === 'banner.clear') { cur.banner = ''; await kvSet('ctl', cur); return { ok: true }; }
    if (c === 'maint.on') { cur.maint = true; await kvSet('ctl', cur); return { ok: true }; }
    if (c === 'maint.off') { cur.maint = false; await kvSet('ctl', cur); return { ok: true }; }
    if (['shop.close', 'shop.open', 'shop.verify', 'shop.unverify', 'plan.set'].includes(c)) { const s = await kvGet('store:' + t(a.slug, 40)); if (!s) throw new Error('No such shop'); if (c === 'shop.close') s.open = false; if (c === 'shop.open') s.open = true; if (c === 'shop.verify') s.verified = true; if (c === 'shop.unverify') s.verified = false; if (c === 'plan.set') { if (!PLANS.includes(a.plan)) throw new Error('Unknown plan'); s.plan = a.plan; if (a.until) s.paidUntil = t(a.until, 10); } await kvSet('store:' + s.slug, s); return { ok: true }; }
    throw new Error('Not available on this app');
  },
  log: async (ok, who, note) => { const v = (await kvGet('sys:log')) || { items: [] }; v.items = [{ at: new Date().toISOString(), ok: !!ok, who: String(who).slice(0, 40), note: String(note).slice(0, 120) }].concat(v.items || []).slice(0, 100); await kvSet('sys:log', v); },
  ownUrl: () => E.SITE_URL ? String(E.SITE_URL).replace(/\/$/, '') : (curHost ? 'https://' + curHost : ''), fetch: (u, o) => fetch(u, o)
});
let curHost = '', linkTried = false;
const handler = async (event) => {
  const M = event.httpMethod, h = Object.fromEntries(Object.entries(event.headers || {}).map(([k, v]) => [k.toLowerCase(), v])), ip = String(h['x-forwarded-for'] || '').split(',')[0].trim() || 'ip';
  const p = String(event.path || '').replace(/\/+$/, '') || '/', raw = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64').toString() : (event.body || '');
  if (E.VERCEL_ENV === 'production' && String(E.STORES_SECRET || '').length < 32) return J(503, { error: 'This service is not set up yet.' });
  if (raw.length > 700000) return J(413, { error: 'That was too large.' });
  const sh = await SHIELD.check(ip, p, event.queryStringParameters || {}, raw, h['user-agent'] || ''); if (sh) return J(404, { error: 'Not found' });
  curHost = String(h.host || '');
  if (!linkTried && E.NEUTRON_LINK_CODE) { linkTried = true; try { const st = await STN.status(); if (!st.linked && curHost && !/^localhost|^127\./.test(curHost)) await STN.connect(E.NEUTRON_LINK_CODE, true); } catch (e) { linkTried = false; } }
  { const sr = await STN.handle(M, p, h, raw); if (sr) return J(sr.status, sr.body); }
  let b = {}; try { b = raw ? JSON.parse(raw) : {}; } catch (e) { return J(400, { error: 'That did not look right. Try again.' }); }
  try {
    try { await seed(); } catch (e) { console.error('[strand] seed() failed (continuing without sample shops):', e && e.stack || e); }
    let m;
    if (M === 'GET' && (m = p.match(/^\/api\/store\/([a-z0-9-]{1,30})$/))) { const s = await kvGet('store:' + m[1]); if (!s) return J(404, { error: "We couldn't find that shop. Check the link and try again." }); { const cc = await ctlGet(); return J(200, { store: pubStore(s), notice: cc.banner || '', maint: !!cc.maint }); } }
    if (M === 'POST' && p === '/api/signup') {
      if (limited(ip, 'su', 6, 3600e3)) return J(429, { error: 'Too many tries. Wait a little and try again.' });
      if (b.hp) return J(400, { error: 'That did not look right. Try again.' });
      const ph = phoneKey(b.phone), em = emailKey(b.email), name = str(b.storeName, 40), pw = String(b.pin || '');
      if (name.length < 2) return J(400, { error: 'Give your shop a name.' });
      if (b.phone && !ph) return J(400, { error: 'That phone number does not look right. Try 024 123 4567.' }); if (b.email && !em) return J(400, { error: 'That email does not look right.' });
      if (!ph && !em) return J(400, { error: 'Add a phone number or an email so you can log in.' });
      const pe = passOk(pw); if (pe) return J(400, { error: pe });
      if ((ph && await kvGet('phone:' + ph)) || (em && await kvGet('email:' + em))) return J(409, { error: 'An account with those details already exists. Log in instead.' });
      let slug = slugify(b.slug || name) || 'shop'; if (RESERVED.includes(slug)) slug += '-shop'; let i = 1, base = slug; while (await kvGet('store:' + slug)) slug = base + '-' + (++i);
      const typesIn = (Array.isArray(b.types) ? b.types : b.type ? [b.type] : []).filter(t => TYPES[t]), types = [...new Set(typesIn)].slice(0, 6); if (!types.length) types.push('other');
      const type = types[0], goals = (Array.isArray(b.goals) ? b.goals : []).filter(g => GOALS.includes(g)).slice(0, 7);
      const suLayout = cleanLayout(b.layout, null); if (suLayout.n && LAYOUT_EXPERT.has(suLayout.n)) suLayout.n = 1;   // a brand-new shop starts on Base, so an Expert-only layout can't be smuggled in here
      const salt = crypto.randomBytes(16).toString('hex'), s = { slug, name, phone: ph, email: em, wa: !!(ph && b.wa), type, types, goals, listed: true, sv: 0, salt, pin: pinHash(pw, salt), about: '', area: str(b.area, 40), hours: '', delivery: '', open: true, accent: '#d4001a', theme: THEMES.includes(b.theme) && !THEME_EXPERT.has(b.theme) ? b.theme : 'classic', layout: suLayout, pal: PALS.includes(b.pal) ? b.pal : 'white', plan: 'base', products: [], staff: [], createdAt: new Date().toISOString() };
      await kvSet('store:' + slug, s); if (ph) await kvSet('phone:' + ph, { slug }); if (em) await kvSet('email:' + em, { slug }); await addIdx(slug); await secLog(slug, 'Account created', ip);
      return J(200, { token: tok(s, 'owner'), slug });
    }
    if (M === 'POST' && p === '/api/login') {
      if (limited(ip, 'li', 12, 600e3)) return J(429, { error: 'Too many tries. Wait a few minutes and try again.' });
      const key = acctKey(b.id || b.phone), lk = 'fail:' + (key || 'x'), f = (await kvGet(lk)) || { n: 0, until: 0 };
      if (f.until > Date.now()) return J(429, { error: 'Too many wrong tries. This account is locked for a while. Try again later.' });
      const l = key && await kvGet(key), s = l && await kvGet('store:' + l.slug), who = s && (l.staff ? (s.staff || []).find(x => x.id === l.staff) : s);
      const salt = who ? who.salt : FAKE_SALT, calc = pinHash(String(b.pin || '').slice(0, 64), salt), good = who && calc.length === who.pin.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(who.pin));
      if (!good) { if (key) { f.n++; if (f.n >= 5) f.until = Date.now() + Math.min(864e5, 15 * 60e3 * Math.pow(2, f.n - 5)); await kvSet(lk, f); } if (s) await secLog(s.slug, f.until > Date.now() ? 'Account locked after wrong passwords' : 'Wrong password', ip); return J(401, { error: "We couldn't find a shop with those details. Check them and try again." }); }
      if (f.n) await kvSet(lk, null); if (who && who.off) return J(401, { error: "We couldn't find a shop with those details. Check them and try again." }); const role = l.staff ? who.role : 'owner'; if (l.staff) who.lastLogin = new Date().toISOString(), await kvSet('store:' + s.slug, s); await secLog(s.slug, 'Logged in' + (l.staff ? ' (' + who.name + ')' : ''), ip);
      return J(200, { token: tok(s, role, l.staff || ''), slug: s.slug, role });
    }
    if (M === 'GET' && p === '/api/host') { const d = await kvGet('domain:' + str((event.queryStringParameters || {}).h, 100).toLowerCase().replace(/^www\./, '')); if (d && d.status === 'active') return J(200, { slug: d.slug }); return J(404, { error: 'Not found' }); }
    if (M === 'GET' && p === '/api/explore') {
      if (limited(ip, 'ex', 60, 600e3)) return J(429, { error: 'Slow down a little.' }); const q = event.queryStringParameters || {}, ty = TYPES[q.type] ? q.type : '', x = (await kvGet('idx')) || { l: [] }, out = [], counts = {};
      for (const sl of x.l.slice(0, 400)) { const st = await kvGet('store:' + sl); if (!st || st.listed === false || !(st.products || []).some(pp => pp.on !== false)) continue; const ts = (st.types && st.types.length ? st.types : [st.type || 'other']).filter(t => TYPES[t]); const t = ts[0] || 'other'; for (const tt of ts) counts[tt] = (counts[tt] || 0) + 1; if (ty && !ts.includes(ty)) continue; out.push({ slug: st.slug, name: st.name, type: t, typeName: TYPES[t], area: st.area || '', verified: !!st.verified, open: st.open !== false, accent: st.accent || '#d4001a', items: (st.products || []).filter(pp => pp.on !== false).slice(0, 3).map(pp => pp.name) }); }
      out.sort((m1, m2) => (m2.verified - m1.verified) || m1.name.localeCompare(m2.name)); return J(200, { types: TYPES, counts, shops: out.slice(0, 60) });
    }
    if (M === 'GET' && p === '/api/pay/verify') {
      if (limited(ip, 'pv', 30, 600e3)) return J(429, { error: 'Slow down a little.' }); const q = event.queryStringParameters || {}, st = await kvGet('store:' + str(q.slug, 40)); if (!st || !st.pay || !st.pay.paystack) return J(404, { error: 'Not found' });
      const ord = (await kvGet('orders:' + st.slug)) || { l: [] }, o = ord.l.find(x => x.no === str(q.no, 12)); if (!o) return J(404, { error: 'Order not found' }); if (o.paid) return J(200, { paid: true });
      try { const r = await ps(dec(st.pay.paystack.k), '/transaction/verify/' + encodeURIComponent(st.slug + '-' + o.no)); if (r.j && r.j.data && r.j.data.status === 'success' && r.j.data.amount >= Math.round(o.total * 100)) { o.paid = true; o.paidAt = new Date().toISOString(); o.paidBy = 'Paystack'; o.log = (o.log || []).concat([{ at: o.paidAt, by: 'Paystack', what: 'Payment confirmed online' }]); await kvSet('orders:' + st.slug, ord); await note(st, 'payment', 'Online payment received for ' + o.no + ' · GH₵ ' + o.total); return J(200, { paid: true }); } } catch (e) {} return J(200, { paid: false });
    }
    if (M === 'POST' && p === '/api/order') {
      if ((await ctlGet()).maint) return J(503, { error: 'Orders are paused for a short while. Please try again soon.' });
      if (limited(ip, 'or', 20, 600e3)) return J(429, { error: 'Slow down a little.' });
      if (b.hp) return J(400, { error: 'That did not look right. Try again.' });
      const s = await kvGet('store:' + str(b.slug, 40)); if (!s) return J(404, { error: "We couldn't find that shop." }); if (limited(s.slug, 'os', 80, 3600e3)) return J(429, { error: 'This shop is very busy. Try again in a little while.' }); if (s.open === false) return J(400, { error: 'This shop is closed right now.' });
      const items = (Array.isArray(b.items) ? b.items : []).slice(0, 40).map(i => { const pr = (s.products || []).find(x => x.id === i.id && x.on !== false); const q = Math.max(1, Math.min(50, +i.qty || 1)); return pr ? { id: pr.id, name: pr.name, price: salePx(s, pr), cost: pr.cost || 0, qty: q } : null; }).filter(Boolean);
      if (!items.length) return J(400, { error: 'Your basket is empty.' });
      { const rl = s.rules || {}, st0 = items.reduce((t, i) => t + i.price * i.qty, 0); if (rl.minOrder > 0 && st0 < rl.minOrder) return J(400, { error: 'This shop needs a minimum order of GH₵ ' + rl.minOrder + '.' }); if (rl.maxQty > 0 && items.some(i => i.qty > rl.maxQty)) return J(400, { error: 'You can order up to ' + rl.maxQty + ' of each item.' }); }
      for (const it of items) { const pr = s.products.find(x => x.id === it.id); if (pr.stock != null && pr.stock < it.qty) return J(400, { error: pr.name + ' only has ' + pr.stock + ' left. Reduce the amount and try again.' }); }
      for (const it of items) { const pr = s.products.find(x => x.id === it.id); if (pr.stock != null) pr.stock -= it.qty; } await kvSet('store:' + s.slug, s);
      const sub = items.reduce((t, i) => t + i.price * i.qty, 0), no = 'O' + Date.now().toString(36).slice(-5).toUpperCase(), ap = s.apps || {};
      let disc = 0, code = ''; if (ap.discounts && b.code) { const cd = (s.codes || []).find(x => x.on !== false && x.code === String(b.code).trim().toUpperCase().slice(0, 20)); if (cd) { disc = Math.round(sub * cd.pct) / 100; code = cd.code; } else return J(400, { error: 'That discount code is not valid.' }); }
      const fee = (ap.delivery && b.deliver && s.fee > 0 && !(s.freeAbove > 0 && sub - disc >= s.freeAbove)) ? s.fee : 0, total = Math.round((sub - disc + fee) * 100) / 100;
      const methods = payMethods(s), method = methods.includes(b.pay) ? b.pay : methods[methods.length - 1] || 'cod';
      const o = { no, items, sub, disc, code, fee, total, name: str(b.name, 60), phone: str(b.phone, 20), address: str(b.address, 160), note: str(b.note, 200), status: 'new', src: 'shop', pay: method, paid: false, at: new Date().toISOString() };
      if (!o.name || phoneKey(o.phone) === '') return J(400, { error: 'Add your name and phone number so the shop can reach you.' });
      const ord = (await kvGet('orders:' + s.slug)) || { l: [] }; ord.l.unshift(o); ord.l = ord.l.slice(0, 500); await kvSet('orders:' + s.slug, ord);
      await note(s, 'order', 'New order ' + no + ' · GH₵ ' + total + ' from ' + o.name); for (const it of items) { const pr2 = s.products.find(x => x.id === it.id); if (pr2 && pr2.stock != null && pr2.stock <= 3) await note(s, 'lowstock', pr2.name + ' is running low (' + pr2.stock + ' left)'); }
      const msg = 'New order ' + no + '\n' + items.map(i => i.qty + ' x ' + i.name + ' (GH₵ ' + i.price * i.qty + ')').join('\n') + '\nTotal: GH₵ ' + total + '\nName: ' + o.name + '\nPhone: ' + o.phone + (o.address ? '\nAddress: ' + o.address : '') + (o.note ? '\nNote: ' + o.note : '');
      const out = { ok: true, no, total, pay: method }; if (s.wa !== false && s.phone) out.wa = 'https://wa.me/' + s.phone + '?text=' + encodeURIComponent(msg + '\nPayment: ' + ({ paystack: 'online (card or mobile money)', momo: 'mobile money', link: 'payment link', cod: 'pay on delivery' })[method]); else if (s.phone) out.call = s.phone; out.contact = o.phone;
      if (method === 'momo') out.momo = s.pay.momo; if (method === 'link') out.link = s.pay.link;
      if (method === 'paystack') { try { const em = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(b.email || '') ? b.email : (phoneKey(o.phone) + '@customer.pay'), r = await ps(dec(s.pay.paystack.k), '/transaction/initialize', { email: em, amount: Math.round(total * 100), currency: 'GHS', reference: s.slug + '-' + no, callback_url: (h['x-forwarded-proto'] || 'https') + '://' + h.host + '/s/' + s.slug + '?paid=' + no }); if (r.j && r.j.status && r.j.data) out.payUrl = r.j.data.authorization_url; } catch (e) {} if (!out.payUrl) out.payNote = 'Online payment is not available right now. Send the order on WhatsApp and pay the shop directly.'; }
      return J(200, out);
    }
    if (M === 'GET' && p === '/api/admin/health') {
      // deliberately checks the key as either a header or a ?key= query param, so it can be opened directly
      // in a browser address bar for a quick diagnostic - everything it reveals is non-secret (booleans/status only).
      const given = String(h['x-admin'] || (event.queryStringParameters || {}).key || '');
      if (!E.STORES_ADMIN || String(E.STORES_ADMIN).length < 16 || given.length < 16 || !crypto.timingSafeEqual(Buffer.from(sha(given)), Buffer.from(sha(E.STORES_ADMIN)))) { if (limited(ip, 'ad', 8, 600e3)) return J(429, { error: 'Too many tries.' }); return J(404, { error: 'Not found' }); }
      const out = { env: { FIREBASE_PROJECT_ID: !!E.FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL: !!E.FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY: !!E.FIREBASE_PRIVATE_KEY, SUPABASE_URL: !!E.SUPABASE_URL, SUPABASE_SERVICE_KEY: !!E.SUPABASE_SERVICE_KEY, STORES_SECRET_ok: String(E.STORES_SECRET || '').length >= 32, STORES_ADMIN_ok: String(E.STORES_ADMIN || '').length >= 16 } };
      if (fbOn()) { try { const testKey = 'healthcheck:' + Date.now(); await kvSet(testKey, { at: new Date().toISOString() }); const back = await kvGet(testKey); await kvSet(testKey, null); out.firestore = back ? 'ok - read/write round-trip succeeded' : 'wrote but could not read back'; } catch (e) { out.firestore = 'FAILED: ' + e.message; } } else out.firestore = 'not configured (missing one of the three FIREBASE_* vars) - running on in-memory storage';
      return J(200, out);
    }
    if (p.startsWith('/api/admin')) {
      if (!isAdmin(h)) { if (limited(ip, 'ad', 8, 600e3)) return J(429, { error: 'Too many tries.' }); return J(404, { error: 'Not found' }); }
      if (M === 'GET' && p === '/api/admin/shops') { const x = (await kvGet('idx')) || { l: [] }; const out = []; for (const sl of x.l) { const st = await kvGet('store:' + sl); if (!st) continue; const o = (await kvGet('orders:' + sl)) || { l: [] }; out.push({ slug: sl, name: st.name, phone: st.phone || '', email: st.email || '', type: st.type || 'other', plan: st.plan || 'base', theme: st.theme || 'classic', verified: !!st.verified, domain: st.domain || null, paidUntil: st.paidUntil || '', orders: o.l.length, revenue: o.l.filter(q => q.status !== 'cancelled').reduce((t, q) => t + q.total, 0), products: (st.products || []).length, createdAt: st.createdAt || '' }); } return J(200, { shops: out }); }
      if (M === 'POST' && p === '/api/admin/shop') { const st = await kvGet('store:' + str(b.slug, 40)); if (!st) return J(404, { error: 'No such shop' }); if (PLANS.includes(b.plan)) st.plan = b.plan; if (THEMES.includes(b.theme)) st.theme = b.theme; if (typeof b.verified === 'boolean') st.verified = b.verified; if (b.paidUntil !== undefined) st.paidUntil = /^\d{4}-\d{2}-\d{2}/.test(b.paidUntil) ? new Date(b.paidUntil).toISOString() : ''; if (b.invoice && typeof b.invoice === 'object') { const iv = (await kvGet('inv:' + st.slug)) || { l: [] }; iv.l.unshift({ id: 'M' + Date.now().toString(36), plan: str(b.invoice.plan, 10), amount: Math.max(0, +b.invoice.amount || 0), at: new Date().toISOString(), via: str(b.invoice.via, 30) || 'Manual' }); await kvSet('inv:' + st.slug, iv); } if (b.domainStatus && st.domain) { st.domain.status = b.domainStatus === 'active' ? 'active' : 'pending'; await kvSet('domain:' + st.domain.name, { slug: st.slug, status: st.domain.status }); await note(st, 'billing', 'Your domain ' + st.domain.name + ' is ' + st.domain.status); } if (b.design && typeof b.design === 'object') { for (const k of ['announce']) if (b.design[k] !== undefined) st[k] = str(b.design[k], 90); for (const k of ['hero', 'banner']) if (b.design[k]) st[k] = Object.assign(st[k] || {}, { title: str(b.design[k].title, 80), sub: str(b.design[k].sub, 140), cta: str(b.design[k].cta, 24) }); if (/^#[0-9a-f]{6}$/i.test(b.design.accent || '')) st.accent = b.design.accent; } await kvSet('store:' + st.slug, st); return J(200, { ok: true }); }
      if (M === 'GET' && p === '/api/admin/requests') return J(200, { reqs: ((await kvGet('reqs')) || { l: [] }).l });
      if (M === 'POST' && p === '/api/admin/request') { const r = (await kvGet('reqs')) || { l: [] }, q = r.l.find(x => x.id === b.id); if (q) { q.done = !!b.done; await kvSet('reqs', r); } return J(200, { ok: true }); }
    }
    const s = await auth(h);
    if (p.startsWith('/api/seller')) {
      if (!s) return J(401, { error: 'Please log in again.' });
      const role = s._role, owner = role === 'owner', can = x => hasPerm(role, x), canOrders = can('orders'), canStock = can('stock');
      const paid = planOf(s) !== 'base';
      if (M === 'GET' && p === '/api/seller/me') {
        const ord = canOrders ? ((await kvGet('orders:' + s.slug)) || { l: [] }) : { l: [] }, d = new Date().toISOString().slice(0, 10), today = ord.l.filter(o => o.at.slice(0, 10) === d && o.status !== 'cancelled'), pr = s.products || [];
        const full = pubStore(s, true); if (can('settings')) { full.goals = s.goals || []; full.sale = s.sale || { on: false, pct: 10 }; full.email = s.email || ''; full.phone = s.phone || ''; full.wa = s.wa !== false && !!s.phone; full.listed = s.listed !== false; full.apps = s.apps || {}; full.codes = s.codes || []; full.fee = s.fee || 0; full.freeAbove = s.freeAbove || 0; } if (can('pay_settings')) full.payCfg = { cod: (s.pay || {}).cod !== false, momo: (s.pay || {}).momo || null, link: (s.pay || {}).link || '', paystack: (s.pay || {}).paystack ? { last4: s.pay.paystack.last4, mode: s.pay.paystack.mode } : null }; if (!can('costs')) full.products.forEach(x => { delete x.cost; }); full.domain = s.domain || null; full.rules = s.rules || {}; full.notify = s.notify || {}; full.paidUntil = s.paidUntil || ''; full.planRaw = s.plan || 'base';
        return J(200, { role, store: full, orders: ord.l.slice(0, 100), perms: PERM_ALL.filter(x => can(x)), matrix: PERMS, roles: ROLES, me: s._me ? { id: s._me.id, name: s._me.name } : { id: '', name: 'Owner' }, staff: can('team') ? (s.staff || []).map(x => ({ id: x.id, name: x.name, role: x.role, off: !!x.off, lastLogin: x.lastLogin || '', login: String(x.key || '').replace(/^(phone|email):/, '').replace(/^(.{3}).*(.{3})$/, '$1•••$2') })) : [], paid, stats: { today: today.length, revenueToday: can('analytics') ? today.reduce((t, o) => t + o.total, 0) : 0, total: ord.l.length, newCount: ord.l.filter(o => o.status === 'new').length, low: pr.filter(x => x.stock != null && x.stock <= 3).length, stockValue: can('costs') ? pr.reduce((t, x) => t + (x.stock || 0) * (x.cost || 0), 0) : 0, retailValue: can('costs') ? pr.reduce((t, x) => t + (x.stock || 0) * x.price, 0) : 0 } });
      }
      if (M === 'POST' && p === '/api/seller/store') {
        { const dz0 = ['name', 'theme', 'accent', 'announce', 'hero', 'banner', 'social'].some(k => b[k] !== undefined), pl0 = ['about', 'area', 'hours', 'delivery', 'open', 'type', 'types', 'listed', 'wa', 'team'].some(k => b[k] !== undefined), lz0 = ['layout', 'pal'].some(k => b[k] !== undefined); if (lz0 && !can('design')) return J(403, { error: 'You do not have access to change this.' }); if ((pl0 && !can('settings')) || (dz0 && !can('design')) || (!pl0 && !dz0 && !lz0)) return J(403, { error: 'You do not have access to change this.' }); }
        for (const k of ['about', 'area', 'hours', 'delivery']) if (b[k] !== undefined) s[k] = str(b[k], k === 'about' ? 200 : 60); if (b.open !== undefined) s.open = !!b.open; if (Array.isArray(b.types)) { const ts = [...new Set(b.types.filter(t => TYPES[t]))].slice(0, 6); if (ts.length) { s.types = ts; s.type = ts[0]; } } else if (TYPES[b.type]) { s.type = b.type; s.types = [b.type]; } if (b.listed !== undefined) s.listed = !!b.listed; if (b.team !== undefined) { const g = (s.goals || []).filter(x => x !== 'team'); if (b.team) g.push('team'); s.goals = g; } if (b.wa !== undefined) s.wa = !!(s.phone && b.wa);
        if (b.layout !== undefined) { const cl = cleanLayout(b.layout, s.layout); if (cl.n && LAYOUT_EXPERT.has(cl.n) && planOf(s) !== 'expert') return J(402, { error: 'That layout is part of the Expert plan.', upgrade: true }); s.layout = cl; } if (PALS.includes(b.pal)) s.pal = b.pal;
        const design = ['name', 'theme', 'accent', 'announce', 'hero', 'banner', 'social'].some(k => b[k] !== undefined);
        if (design && !paid) return J(402, { error: 'Changing your name, theme and look is part of the Pro plan.', upgrade: true });
        if (b.name !== undefined && str(b.name, 40).length >= 2) s.name = str(b.name, 40);
        if (THEMES.includes(b.theme) && b.theme !== s.theme) { if (THEME_EXPERT.has(b.theme) && planOf(s) !== 'expert') return J(402, { error: 'That look is part of the Expert plan.', upgrade: true }); s.theme = b.theme; if (THEME_LAYOUT[b.theme]) s.layout = cleanLayout({ n: THEME_LAYOUT[b.theme] }, s.layout); }
        if (/^#[0-9a-f]{6}$/i.test(b.accent || '')) s.accent = b.accent; if (b.announce !== undefined) s.announce = str(b.announce, 90);
        for (const k of ['hero', 'banner']) if (b[k] && typeof b[k] === 'object') { const o = s[k] || {}; if (b[k].title !== undefined) o.title = str(b[k].title, 80); if (b[k].sub !== undefined) o.sub = str(b[k].sub, 140); if (b[k].cta !== undefined) o.cta = str(b[k].cta, 24); if (b[k].img !== undefined) { const pi = await picIn(b[k].img, b, 'That picture'); if (pi.error) return J(400, { error: pi.error }); o.img = pi.img; } s[k] = o; }
        if (b.social && typeof b.social === 'object') s.social = { instagram: str(b.social.instagram, 40).replace(/^@/, ''), tiktok: str(b.social.tiktok, 40).replace(/^@/, ''), whatsapp: s.phone };
        await kvSet('store:' + s.slug, s); return J(200, { ok: true });
      }
      if (M === 'POST' && p === '/api/seller/pay') {
        if (!can('pay_settings')) return J(403, { error: 'You do not have access to payment settings.' }); const pay = s.pay || {};
        if (b.cod !== undefined) pay.cod = !!b.cod;
        if (b.momo !== undefined) { const n = String(b.momo && b.momo.number || '').replace(/\D/g, ''); pay.momo = n ? { net: str(b.momo.net, 14), number: n.slice(0, 15), name: str(b.momo.name, 40) } : null; }
        if (b.link !== undefined) { const u = String(b.link || '').trim(); if (u && !/^https:\/\/[^\s]{4,300}$/.test(u)) return J(400, { error: 'The payment link must start with https://' }); pay.link = u; }
        if (b.paystackKey !== undefined) { const k = String(b.paystackKey || '').trim(); if (!k) pay.paystack = null; else { if (!/^sk_(live|test)_[A-Za-z0-9]{10,80}$/.test(k)) return J(400, { error: 'That does not look like a Paystack secret key. It starts with sk_live_ or sk_test_.' }); try { const r = await ps(k, '/balance'); if (r.status === 401 || r.status === 403) return J(400, { error: 'Paystack did not accept that key. Copy it again from your Paystack settings.' }); } catch (e) {} pay.paystack = { k: enc(k), last4: k.slice(-4), mode: k.startsWith('sk_live') ? 'live' : 'test' }; } }
        if (pay.cod === false && !pay.paystack && !(pay.momo && pay.momo.number) && !pay.link) return J(400, { error: 'Keep at least one way to get paid.' });
        s.pay = pay; await kvSet('store:' + s.slug, s); return J(200, { ok: true });
      }
      if (M === 'POST' && p === '/api/seller/stock') {
        if (!canStock) return J(403, { error: 'You do not have access to stock.' }); const pr = (s.products || []).find(x => x.id === b.id); if (!pr) return J(404, { error: 'Item not found.' });
        if (b.delta !== undefined) pr.stock = Math.max(0, (pr.stock || 0) + Math.max(-1000, Math.min(1000, Math.round(+b.delta || 0)))); else if (b.stock === null || b.stock === '') pr.stock = null; else pr.stock = Math.max(0, Math.min(100000, Math.round(+b.stock || 0)));
        await kvSet('store:' + s.slug, s); return J(200, { ok: true, stock: pr.stock });
      }
      if (M === 'POST' && p === '/api/seller/product') {
        if (!can('products')) return J(403, { error: 'You do not have access to edit products.' });
        s.products = s.products || []; if (b.del) { s.products = s.products.filter(x => x.id !== b.id); await kvSet('store:' + s.slug, s); return J(200, { ok: true }); }
        const price = Math.round((+b.price || 0) * 100) / 100, name = str(b.name, 60); if (!name || !(price > 0)) return J(400, { error: 'Add a name and a price.' });
        const pi = await picIn(b.img, b, 'That photo'); if (pi.error) return J(400, { error: pi.error }); const img = pi.img;
        let pr = b.id && s.products.find(x => x.id === b.id); if (!pr) { if (s.products.length >= 200) return J(400, { error: 'You have reached 200 items.' }); pr = { id: 'p' + crypto.randomBytes(4).toString('hex') }; s.products.push(pr); }
        Object.assign(pr, { name, price, desc: str(b.desc, 140), cat: str(b.cat, 24), badge: ['', 'New', 'Sale', 'Best seller'].includes(b.badge) ? b.badge : '', was: +b.was > price ? Math.round(+b.was * 100) / 100 : 0, cost: Math.max(0, +b.cost || 0), sku: str(b.sku, 20), on: b.on !== false });
        if (b.stock !== undefined) pr.stock = (b.stock === null || b.stock === '') ? null : Math.max(0, Math.round(+b.stock || 0)); if (b.img !== undefined) pr.img = img; await kvSet('store:' + s.slug, s); return J(200, { ok: true, id: pr.id });
      }
      if (M === 'POST' && p === '/api/seller/order') {
        if (!canOrders) return J(403, { error: 'You do not have access to orders.' }); const ord = (await kvGet('orders:' + s.slug)) || { l: [] };
        if (b.confirmPay || b.unpay) { const o2 = ord.l.find(x => x.no === b.no); if (!o2) return J(404, { error: 'Order not found.' }); const by = s._me ? s._me.name : 'Owner'; o2.log = o2.log || []; if (b.unpay) { if (!can('pay_settings')) return J(403, { error: 'Only an owner or admin can undo a confirmed payment.' }); o2.paid = false; o2.log.push({ at: new Date().toISOString(), by, what: 'Payment unconfirmed' }); } else { if (!can('pay_confirm')) return J(403, { error: 'You cannot confirm payments.' }); o2.paid = true; o2.paidAt = new Date().toISOString(); o2.paidBy = by; o2.payRef = str(b.ref, 40); o2.log.push({ at: o2.paidAt, by, what: 'Payment confirmed' + (o2.payRef ? ' · ref ' + o2.payRef : '') }); await note(s, 'payment', 'Payment confirmed for ' + o2.no + ' · GH₵ ' + o2.total); } await kvSet('orders:' + s.slug, ord); return J(200, { ok: true }); }
        if (b.pos) { if (!can('pos')) return J(403, { error: 'You cannot record sales.' }); const items = (Array.isArray(b.items) ? b.items : []).map(i => { const pr = (s.products || []).find(x => x.id === i.id); return pr ? { id: pr.id, name: pr.name, price: pr.price, cost: pr.cost || 0, qty: Math.max(1, Math.min(50, +i.qty || 1)) } : null; }).filter(Boolean); if (!items.length) return J(400, { error: 'Pick at least one item.' }); for (const it of items) { const pr = s.products.find(x => x.id === it.id); if (pr.stock != null) { if (pr.stock < it.qty) return J(400, { error: pr.name + ' only has ' + pr.stock + ' left.' }); pr.stock -= it.qty; } } await kvSet('store:' + s.slug, s); const o = { no: 'S' + Date.now().toString(36).slice(-5).toUpperCase(), items, total: items.reduce((t, i) => t + i.price * i.qty, 0), name: str(b.name, 60) || 'Walk-in', phone: '', address: '', note: '', status: 'done', src: 'pos', at: new Date().toISOString() }; ord.l.unshift(o); ord.l = ord.l.slice(0, 500); await kvSet('orders:' + s.slug, ord); return J(200, { ok: true, no: o.no }); }
        const o = ord.l.find(x => x.no === b.no); if (!can('orders_edit')) return J(403, { error: 'You cannot change orders.' }); if (!o || !['new', 'accepted', 'done', 'cancelled'].includes(b.status)) return J(400, { error: 'Try again.' }); o.log = o.log || []; o.log.push({ at: new Date().toISOString(), by: s._me ? s._me.name : 'Owner', what: 'Marked ' + b.status });
        if (b.status === 'cancelled' && o.status !== 'cancelled') { for (const it of o.items) { const pr = (s.products || []).find(x => x.id === it.id); if (pr && pr.stock != null) pr.stock += it.qty; } await kvSet('store:' + s.slug, s); } o.status = b.status; await kvSet('orders:' + s.slug, ord); return J(200, { ok: true });
      }
      if (M === 'POST' && p === '/api/seller/staff') {
        if (!can('team')) return J(403, { error: 'You do not have access to the team.' }); s.staff = s.staff || [];
        const grant = r0 => r0 !== 'owner' && ROLES[r0] && (owner || r0 !== 'admin');
        if (!b.del && planOf(s) === 'base') return J(402, { error: 'Team members are part of the Pro plan.', upgrade: true });
        if (b.del) { const m = s.staff.find(x => x.id === b.del); if (m) { if (!grant(m.role)) return J(403, { error: 'Only the owner can remove an admin.' }); s.staff = s.staff.filter(x => x.id !== b.del); await kvSet(m.key || ('phone:' + m.phone), null); await kvSet('store:' + s.slug, s); await secLog(s.slug, 'Team member removed: ' + m.name, ip); await note(s, 'team', m.name + ' was removed from the team'); } return J(200, { ok: true }); }
        if (b.id) { const m = s.staff.find(x => x.id === b.id); if (!m) return J(404, { error: 'Not found.' }); if (!grant(m.role)) return J(403, { error: 'Only the owner can change an admin.' });
          if (b.off !== undefined) { m.off = !!b.off; m.uv = (m.uv | 0) + 1; await secLog(s.slug, (m.off ? 'Suspended ' : 'Reactivated ') + m.name, ip); }
          if (b.role !== undefined) { if (!grant(b.role)) return J(403, { error: 'You cannot give that role.' }); m.role = b.role; m.uv = (m.uv | 0) + 1; await secLog(s.slug, m.name + ' is now ' + ROLES[b.role], ip); }
          if (b.reset !== undefined) { const pe = passOk(b.reset); if (pe) return J(400, { error: pe }); m.salt = crypto.randomBytes(16).toString('hex'); m.pin = pinHash(String(b.reset), m.salt); m.uv = (m.uv | 0) + 1; await secLog(s.slug, 'Password reset for ' + m.name, ip); }
          await kvSet('store:' + s.slug, s); return J(200, { ok: true }); }
        const key = acctKey(b.phone || b.id), nm = str(b.name, 40), pin = String(b.pin || '');
        if (b.role === 'admin' && !owner) return J(403, { error: 'Only the owner can add an admin.' });
        if (!key || nm.length < 2 || !grant(b.role)) return J(400, { error: 'Add a name, a phone number or email, a password and pick a role.' }); if (passOk(pin)) return J(400, { error: passOk(pin) }); if (s.staff.length >= 25) return J(400, { error: 'Teams are limited to 25 people.' });
        if (await kvGet(key)) return J(409, { error: 'Those details are already used.' }); const salt = crypto.randomBytes(16).toString('hex'), id = 't' + crypto.randomBytes(3).toString('hex');
        s.staff.push({ id, name: nm, key, role: b.role, salt, pin: pinHash(pin, salt), uv: 0, createdAt: new Date().toISOString() }); await kvSet(key, { slug: s.slug, staff: id }); await secLog(s.slug, 'Team member added: ' + nm + ' (' + ROLES[b.role] + ')', ip); await note(s, 'team', nm + ' joined as ' + ROLES[b.role]); await kvSet('store:' + s.slug, s); return J(200, { ok: true });
      }
      if (p === '/api/seller/apps' && M === 'POST') {
        if (b.sale !== undefined && can('apps')) { const pct = Math.round(+(b.sale || {}).pct || 0); s.sale = { on: !!(b.sale || {}).on && pct >= 1 && pct <= 90, pct: Math.max(0, Math.min(90, pct)) }; await kvSet('store:' + s.slug, s); return J(200, { ok: true }); }
        if (!can('apps')) return J(403, { error: 'You do not have access to apps.' }); const APPS = ['discounts', 'delivery', 'statuspic', 'export', 'lowstock']; s.apps = s.apps || {};
        if (b.id !== undefined) { if (!APPS.includes(b.id)) return J(400, { error: 'Try again.' }); s.apps[b.id] = !!b.on; }
        if (b.fee !== undefined) { s.fee = Math.max(0, Math.min(10000, Math.round((+b.fee || 0) * 100) / 100)); s.freeAbove = Math.max(0, Math.min(1e6, Math.round((+b.freeAbove || 0) * 100) / 100)); }
        if (b.code !== undefined) { s.codes = s.codes || []; const c = String(b.code || '').trim().toUpperCase(); if (b.del) s.codes = s.codes.filter(x => x.code !== c); else { const pct = Math.round(+b.pct || 0); if (!/^[A-Z0-9]{3,20}$/.test(c) || pct < 1 || pct > 90) return J(400, { error: 'Use 3 to 20 letters or numbers, and a discount between 1 and 90 percent.' }); if (s.codes.length >= 20 && !s.codes.some(x => x.code === c)) return J(400, { error: 'You can have up to 20 codes.' }); const e = s.codes.find(x => x.code === c); if (e) { e.pct = pct; e.on = b.on !== false; } else s.codes.push({ code: c, pct, on: true }); } }
        await kvSet('store:' + s.slug, s); return J(200, { ok: true });
      }
      if (M === 'GET' && p === '/api/seller/insights') {
        if (!can('analytics')) return J(403, { error: 'You do not have access to this.' }); const days = Math.max(1, Math.min(90, +(event.queryStringParameters || {}).days || 30)), ord = ((await kvGet('orders:' + s.slug)) || { l: [] }).l, since = Date.now() - days * 864e5, pr = s.products || [];
        const ok = ord.filter(o => o.status !== 'cancelled'), cur = ok.filter(o => Date.parse(o.at) >= since), prev = ok.filter(o => Date.parse(o.at) < since && Date.parse(o.at) >= since - days * 864e5);
        const costOf = i => (i.cost != null ? i.cost : ((pr.find(x => x.id === i.id) || {}).cost || 0)), profitOf = o => o.items.reduce((t, i) => t + (i.price - costOf(i)) * i.qty, 0) - (o.disc || 0), rev = o => o.total - (o.fee || 0);
        const sum = (l, f) => Math.round(l.reduce((t, o) => t + f(o), 0) * 100) / 100, series = [], byP = {}, wk = [0, 0, 0, 0, 0, 0, 0], hr = new Array(24).fill(0), pay = {}, cust = {};
        for (let d = Math.min(days, 30) - 1; d >= 0; d--) { const day = new Date(Date.now() - d * 864e5).toISOString().slice(0, 10), l = cur.filter(o => o.at.slice(0, 10) === day); series.push({ d: day, revenue: sum(l, rev), profit: sum(l, profitOf), orders: l.length }); }
        for (const o of cur) { const dt = new Date(o.at); wk[dt.getUTCDay()]++; hr[dt.getUTCHours()]++; pay[o.pay || o.src] = (pay[o.pay || o.src] || 0) + 1; if (o.phone) cust[o.phone] = (cust[o.phone] || 0) + 1; for (const i of o.items) { const r = byP[i.id] = byP[i.id] || { id: i.id, name: i.name, qty: 0, revenue: 0, profit: 0 }; r.qty += i.qty; r.revenue += i.price * i.qty; r.profit += (i.price - costOf(i)) * i.qty; } }
        const top = Object.values(byP).sort((x, y) => y.qty - x.qty), soldIds = new Set(top.map(x => x.id)), missingCost = pr.filter(x => !(x.cost > 0)).length;
        return J(200, { days, revenue: sum(cur, rev), profit: sum(cur, profitOf), orders: cur.length, aov: cur.length ? Math.round(sum(cur, rev) / cur.length * 100) / 100 : 0, prevRevenue: sum(prev, rev), prevProfit: sum(prev, profitOf), prevOrders: prev.length, series, top: top.slice(0, 8), slow: pr.filter(x => x.on !== false && !soldIds.has(x.id)).slice(0, 8).map(x => ({ id: x.id, name: x.name, stock: x.stock })), weekday: wk, hours: hr, pay, customers: Object.keys(cust).length, repeat: Object.values(cust).filter(n => n > 1).length, missingCost, lowStock: pr.filter(x => x.stock != null && x.stock <= 3).map(x => ({ id: x.id, name: x.name, stock: x.stock })) });
      }
      if (M === 'GET' && p === '/api/seller/market') {
        if (!can('analytics')) return J(403, { error: 'You do not have access to this.' }); const x = (await kvGet('idx')) || { l: [] }, ty = s.type || 'other', peers = [], counts = {}, catP = {};
        for (const sl of x.l.slice(0, 400)) { const st = await kvGet('store:' + sl); if (!st || st.listed === false || st.slug === s.slug) continue; const t = st.type || 'other'; counts[t] = (counts[t] || 0) + 1; if (t !== ty) continue; peers.push(st); for (const q of (st.products || [])) if (q.on !== false && q.price > 0) (catP[(q.cat || 'Other').toLowerCase()] = catP[(q.cat || 'Other').toLowerCase()] || []).push(q.price); }
        const med = l => { const a2 = l.slice().sort((m1, m2) => m1 - m2); return a2.length ? a2[Math.floor(a2.length / 2)] : 0; };
        const cats = Object.keys(catP).map(k => ({ cat: k, shops: catP[k].length, median: Math.round(med(catP[k]) * 100) / 100, low: Math.min(...catP[k]), high: Math.max(...catP[k]) })).filter(c => c.shops >= 3).sort((m1, m2) => m2.shops - m1.shops).slice(0, 8);
        const mine = (s.products || []).filter(q => q.on !== false).map(q => { const c = cats.find(z => z.cat === (q.cat || 'Other').toLowerCase()); return c ? { id: q.id, name: q.name, price: q.price, median: c.median, pos: q.price < c.median * 0.9 ? 'below' : q.price > c.median * 1.1 ? 'above' : 'near' } : null; }).filter(Boolean).slice(0, 20);
        return J(200, { type: ty, typeName: TYPES[ty], peers: peers.length, others: counts, cats, mine, note: peers.length < 3 ? 'Prices appear once at least 3 other shops in your category are on Strand.' : '' });
      }
      if (p === '/api/seller/security') {
        if (M === 'GET') { if (!can('security')) return J(403, { error: 'You do not have access to this.' }); return J(200, { log: ((await kvGet('sec:' + s.slug)) || { l: [] }).l }); }
        if (limited(ip, 'sc', 10, 900e3)) return J(429, { error: 'Too many tries. Wait a few minutes.' });
        if (b.action === 'logout_all') { if (s._me) { s._me.uv = (s._me.uv | 0) + 1; } else s.sv = (s.sv | 0) + 1; await kvSet('store:' + s.slug, s); await secLog(s.slug, 'Logged out of all devices' + (s._me ? ' (' + s._me.name + ')' : ''), ip); return J(200, { ok: true, token: tok(s, role, s._sid) }); }
        if (b.action === 'password') { const who = s._me || s, old = pinHash(String(b.old || '').slice(0, 64), who.salt); if (old.length !== who.pin.length || !crypto.timingSafeEqual(Buffer.from(old), Buffer.from(who.pin))) return J(400, { error: 'Your current password is not right.' }); const pe = passOk(b.next); if (pe) return J(400, { error: pe }); who.salt = crypto.randomBytes(16).toString('hex'); who.pin = pinHash(String(b.next), who.salt); if (s._me) s._me.uv = (s._me.uv | 0) + 1; else s.sv = (s.sv | 0) + 1; await kvSet('store:' + s.slug, s); await secLog(s.slug, 'Password changed' + (s._me ? ' (' + s._me.name + ')' : ''), ip); return J(200, { ok: true, token: tok(s, role, s._sid) }); }
        return J(400, { error: 'Try again.' });
      }
      if (M === 'GET' && p === '/api/seller/payments') {
        if (!(can('pay_view') || can('pay_confirm'))) return J(403, { error: 'You do not have access to payments.' }); const ord = ((await kvGet('orders:' + s.slug)) || { l: [] }).l, d = new Date().toISOString().slice(0, 10), act = ord.filter(o => o.status !== 'cancelled'), sm = l => Math.round(l.reduce((t, o) => t + o.total, 0) * 100) / 100;
        return J(200, { collectedToday: sm(act.filter(o => o.paid && (o.paidAt || o.at).slice(0, 10) === d)), awaiting: sm(act.filter(o => !o.paid && o.src !== 'pos' && o.pay !== 'cod')), cod: sm(act.filter(o => !o.paid && o.pay === 'cod' && o.status !== 'new')), awaitingCount: act.filter(o => !o.paid && o.src !== 'pos' && o.pay !== 'cod').length, orders: ord.slice(0, 200).map(o => ({ no: o.no, at: o.at, total: o.total, name: o.name, phone: o.phone, pay: o.pay || o.src, paid: !!o.paid, paidAt: o.paidAt || '', paidBy: o.paidBy || '', ref: o.payRef || '', status: o.status, log: o.log || [] })) });
      }
      if (M === 'GET' && p === '/api/seller/customers') {
        if (!can('orders') || !can('analytics')) return J(403, { error: 'You do not have access to customers.' }); const ord = ((await kvGet('orders:' + s.slug)) || { l: [] }).l.filter(o => o.status !== 'cancelled' && o.phone), m = {};
        for (const o of ord) { const k = phoneKey(o.phone) || o.phone, c = m[k] = m[k] || { name: o.name, phone: o.phone, orders: 0, spent: 0, last: o.at }; c.orders++; c.spent += o.total; if (o.at > c.last) c.last = o.at; } return J(200, { customers: Object.values(m).sort((x, y) => y.spent - x.spent).slice(0, 200) });
      }
      if (p === '/api/seller/notes') {
        const x = (await kvGet('notes:' + s.slug)) || { l: [] };
        if (M === 'POST') { if (b.read) { x.l.forEach(n => { n.read = true; }); await kvSet('notes:' + s.slug, x); } if (b.prefs && typeof b.prefs === 'object') { if (!can('notify')) return J(403, { error: 'You cannot change notification settings.' }); s.notify = {}; for (const k of ['order', 'lowstock', 'payment', 'team', 'security', 'billing', 'email']) s.notify[k] = b.prefs[k] !== false && b.prefs[k] !== 0 && b.prefs[k] !== undefined ? !!b.prefs[k] : (k === 'email' ? !!b.prefs[k] : b.prefs[k] === undefined); await kvSet('store:' + s.slug, s); } return J(200, { ok: true }); }
        const vis = x.l.filter(n => hasPerm(role, NOTE_PERM[n.type] || 'orders')); return J(200, { unread: vis.filter(n => !n.read).length, notes: vis.slice(0, 60), prefs: s.notify || {}, canEdit: can('notify'), emailOn: !!E.RESEND_API_KEY });
      }
      if (p === '/api/seller/policies' && M === 'POST') {
        if (!can('policies')) return J(403, { error: 'You do not have access to store policies.' }); s.policies = s.policies || {}; for (const k of ['returns', 'shipping', 'privacy', 'terms']) if (b[k] !== undefined) s.policies[k] = String(b[k] || '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').slice(0, 2500);
        if (b.rules && typeof b.rules === 'object') s.rules = { minOrder: Math.max(0, Math.min(1e6, Math.round((+b.rules.minOrder || 0) * 100) / 100)), maxQty: Math.max(0, Math.min(500, Math.round(+b.rules.maxQty || 0))) }; await kvSet('store:' + s.slug, s); return J(200, { ok: true });
      }
      if (p === '/api/seller/domain') {
        if (!can('domain')) return J(403, { error: 'You do not have access to domains.' }); const info = { a: '76.76.21.21', cname: 'cname.vercel-dns.com' };
        if (M === 'GET') return J(200, { domain: s.domain || null, dns: info });
        if (limited(ip, 'dm', 10, 3600e3)) return J(429, { error: 'Too many tries. Try again later.' });
        if (b.remove) { if (s.domain) { await kvSet('domain:' + s.domain.name, null); } s.domain = null; await kvSet('store:' + s.slug, s); return J(200, { ok: true }); }
        const dn = String(b.domain || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, ''); if (!/^(?=.{4,100}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/.test(dn) || /(\.vercel\.app|\.local|localhost)$/.test(dn)) return J(400, { error: 'Enter a domain like myshop.com.' });
        const ex = await kvGet('domain:' + dn); if (ex && ex.slug !== s.slug) return J(409, { error: 'That domain is already connected to another shop.' });
        s.domain = { name: dn, status: 'pending', at: new Date().toISOString() }; await kvSet('domain:' + dn, { slug: s.slug, status: 'pending' }); await kvSet('store:' + s.slug, s);
        let v = null; if (E.VERCEL_TOKEN && E.VERCEL_PROJECT_ID) { try { const r = await fetch('https://api.vercel.com/v10/projects/' + E.VERCEL_PROJECT_ID + '/domains', { method: 'POST', headers: { Authorization: 'Bearer ' + E.VERCEL_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: dn }) }); v = await r.json(); } catch (e) {} }
        await secLog(s.slug, 'Domain requested: ' + dn, ip); return J(200, { ok: true, domain: s.domain, dns: info, auto: !!v && !v.error });
      }
      if (p === '/api/seller/billing') {
        if (!can('billing')) return J(403, { error: 'Only the owner can see billing.' }); const pr = PRICE(), inv = ((await kvGet('inv:' + s.slug)) || { l: [] }).l;
        if (M === 'GET') return J(200, { plan: s.plan || 'base', eff: planOf(s), paidUntil: s.paidUntil || '', prices: pr, online: !!E.PAYSTACK_PLATFORM_KEY, invoices: inv.slice(0, 24) });
        if (limited(ip, 'bl', 10, 3600e3)) return J(429, { error: 'Too many tries. Try again later.' });
        if (b.verify) { const bl = await kvGet('bill:' + str(b.verify, 60)); if (!bl || bl.slug !== s.slug) return J(404, { error: 'Not found.' }); if (bl.done) return J(200, { ok: true, plan: s.plan }); try { const r = await ps(E.PAYSTACK_PLATFORM_KEY, '/transaction/verify/' + encodeURIComponent(b.verify)); if (r.j && r.j.data && r.j.data.status === 'success' && r.j.data.amount >= Math.round(bl.amount * 100)) { bl.done = true; await kvSet('bill:' + b.verify, bl); s.plan = bl.plan; s.paidUntil = new Date(Math.max(Date.now(), Date.parse(s.paidUntil || 0) || 0) + 30 * 864e5).toISOString(); await kvSet('store:' + s.slug, s); const iv = (await kvGet('inv:' + s.slug)) || { l: [] }; iv.l.unshift({ id: b.verify, plan: bl.plan, amount: bl.amount, at: new Date().toISOString(), via: 'Paystack' }); await kvSet('inv:' + s.slug, iv); await note(s, 'billing', 'Payment received. You are on ' + bl.plan + ' until ' + s.paidUntil.slice(0, 10)); return J(200, { ok: true, plan: s.plan }); } } catch (e) {} return J(200, { ok: false }); }
        if (!['pro', 'expert'].includes(b.plan)) return J(400, { error: 'Pick a plan.' });
        if (Date.now() < FREE_PROMO_UNTIL) { s.plan = b.plan; s.paidUntil = new Date(FREE_PROMO_UNTIL).toISOString(); await kvSet('store:' + s.slug, s); await note(s, 'billing', 'You are on ' + b.plan + ', free through the end of November.'); return J(200, { ok: true, plan: s.plan, free: true, until: s.paidUntil }); }
        if (E.PAYSTACK_PLATFORM_KEY && pr[b.plan] > 0) { const ref = 'B' + s.slug.slice(0, 12) + '-' + Date.now().toString(36); await kvSet('bill:' + ref, { slug: s.slug, plan: b.plan, amount: pr[b.plan] }); try { const r = await ps(E.PAYSTACK_PLATFORM_KEY, '/transaction/initialize', { email: s.email || (s.phone + '@customer.pay'), amount: Math.round(pr[b.plan] * 100), currency: 'GHS', reference: ref, callback_url: (h['x-forwarded-proto'] || 'https') + '://' + h.host + '/app?bill=' + ref }); if (r.j && r.j.data) return J(200, { payUrl: r.j.data.authorization_url }); } catch (e) {} return J(502, { error: 'Payment is not available right now. Try again soon.' }); }
        const rq = (await kvGet('reqs')) || { l: [] }; rq.l.unshift({ id: 'r' + Date.now().toString(36), slug: s.slug, shop: s.name, phone: s.phone || '', email: s.email || '', kind: b.plan, text: 'Wants to subscribe to ' + b.plan, at: new Date().toISOString(), done: false }); await kvSet('reqs', rq); return J(200, { manual: true });
      }
      if (M === 'POST' && p === '/api/seller/request') {
        if (!can('billing')) return J(403, { error: 'Only the owner can do this.' }); if (!['pro', 'expert', 'design'].includes(b.kind)) return J(400, { error: 'Try again.' }); const r = (await kvGet('reqs')) || { l: [] };
        r.l.unshift({ id: 'r' + Date.now().toString(36), slug: s.slug, shop: s.name, phone: s.phone || '', email: s.email || '', kind: b.kind, text: str(b.text, 800), at: new Date().toISOString(), done: false }); r.l = r.l.slice(0, 300); await kvSet('reqs', r); return J(200, { ok: true });
      }
    }
    return J(404, { error: 'Not found' });
  } catch (e) { console.error('[strand] ' + M + ' ' + p + ' failed:', e && e.stack || e); return J(500, { error: 'Something went wrong on our side. Please try again.' }); }
};

module.exports = async (req, res) => {
  const chunks = []; for await (const c of req) chunks.push(c); const raw = Buffer.concat(chunks).toString();
  const u = new URL(req.url, 'http://x');
  const r = await handler({ httpMethod: req.method, path: u.pathname, headers: req.headers, queryStringParameters: Object.fromEntries(u.searchParams), body: raw });
  res.statusCode = r.statusCode; Object.entries(r.headers || {}).forEach(([k, v]) => res.setHeader(k, v)); res.end(r.body);
};
module.exports.config = { api: { bodyParser: false } };
module.exports.handler = handler;
