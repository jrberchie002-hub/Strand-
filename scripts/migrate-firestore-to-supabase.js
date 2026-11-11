#!/usr/bin/env node
/*
 * One-time migration: copies every document in Firestore's "strand_kv" collection into the
 * Supabase "kv_store" table (see README.txt's MAIN DATABASE section for the SQL to create that
 * table first). This is additive only - it never deletes or modifies anything in Firestore, so
 * Firestore stays intact and usable as the live backup/reservoir described in README.txt.
 *
 * Run it from the project root with the same five environment variables your Vercel deployment
 * already has (copy them from Vercel > Settings > Environment Variables, or run `vercel env pull`
 * to get a local .env file and then `node -r dotenv/config scripts/migrate-firestore-to-supabase.js`):
 *
 *   FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY   (source: Firestore)
 *   SUPABASE_DB_URL, SUPABASE_DB_KEY                                   (destination: Supabase)
 *
 * Usage:
 *   node scripts/migrate-firestore-to-supabase.js            # does the real migration
 *   node scripts/migrate-firestore-to-supabase.js --dry-run  # lists what it would copy, writes nothing
 *
 * Safe to re-run: every write is an upsert (same key overwrites), so running it twice just re-copies
 * the same data. Run it once, check the summary at the end, then set SUPABASE_DB_URL/SUPABASE_DB_KEY
 * on your actual deployment (if you were only testing them locally) and redeploy.
 */
'use strict';
const crypto = require('crypto');

const DRY_RUN = process.argv.includes('--dry-run');
const E = process.env;
const need = ['FIREBASE_PROJECT_ID', 'FIREBASE_CLIENT_EMAIL', 'FIREBASE_PRIVATE_KEY', 'SUPABASE_DB_URL', 'SUPABASE_DB_KEY'];
const missing = need.filter(k => !E[k]);
if (missing.length) {
  console.error('Missing required environment variable(s): ' + missing.join(', '));
  console.error('Set them (e.g. export each one, or use `vercel env pull` + a .env loader) and try again.');
  process.exit(1);
}

const cleanEnv = v => String(v || '').trim().replace(/^['"]|['"]$/g, '').trim();
const fbProjectId = cleanEnv(E.FIREBASE_PROJECT_ID);
const fbClientEmail = cleanEnv(E.FIREBASE_CLIENT_EMAIL);
const fbPrivateKey = cleanEnv(E.FIREBASE_PRIVATE_KEY).replace(/\\n/g, '\n');
const sbUrl = cleanEnv(E.SUPABASE_DB_URL).replace(/\/$/, '');
const sbKey = cleanEnv(E.SUPABASE_DB_KEY);

const b64u = s => Buffer.from(s).toString('base64url');
async function fbToken() {
  const now = Math.floor(Date.now() / 1000);
  const unsigned = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' + b64u(JSON.stringify({ iss: fbClientEmail, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
  const jwt = unsigned + '.' + crypto.createSign('RSA-SHA256').update(unsigned).sign(fbPrivateKey, 'base64url');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt });
  const j = await r.json();
  if (!r.ok || !j.access_token) throw new Error('Firebase auth failed: ' + r.status + ' ' + (j.error_description || j.error || ''));
  return j.access_token;
}

function fromFs(v) {
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

async function listAllDocs(token) {
  const base = 'https://firestore.googleapis.com/v1/projects/' + fbProjectId + '/databases/(default)/documents/strand_kv';
  const out = [];
  let pageToken = '';
  for (;;) {
    const url = base + '?pageSize=300' + (pageToken ? '&pageToken=' + encodeURIComponent(pageToken) : '');
    const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
    const j = await r.json();
    if (!r.ok) throw new Error('Firestore list failed: ' + r.status + ' ' + JSON.stringify(j).slice(0, 300));
    for (const doc of (j.documents || [])) {
      const name = doc.name || '';
      const key = name.slice(name.lastIndexOf('/') + 1);
      const value = (doc.fields && doc.fields.value) ? fromFs(doc.fields.value) : null;
      out.push({ key, value });
    }
    if (!j.nextPageToken) break;
    pageToken = j.nextPageToken;
  }
  return out;
}

async function upsertToSupabase(key, value) {
  const r = await fetch(sbUrl + '/rest/v1/kv_store?on_conflict=key', {
    method: 'POST',
    headers: { apikey: sbKey, Authorization: 'Bearer ' + sbKey, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify({ key, value, updated_at: new Date().toISOString() })
  });
  if (!r.ok) { const t = await r.text().catch(() => ''); throw new Error('Supabase upsert failed: ' + r.status + ' ' + t.slice(0, 300)); }
}

(async () => {
  console.log((DRY_RUN ? '[dry run] ' : '') + 'Fetching every document from Firestore collection "strand_kv"...');
  const token = await fbToken();
  const docs = await listAllDocs(token);
  console.log('Found ' + docs.length + ' document(s) in Firestore.');
  if (!docs.length) { console.log('Nothing to migrate.'); return; }

  let ok = 0, failed = 0;
  const failures = [];
  for (const { key, value } of docs) {
    if (DRY_RUN) { console.log('  would copy: ' + key); ok++; continue; }
    try {
      await upsertToSupabase(key, value);
      ok++;
      if (ok % 50 === 0) console.log('  ...' + ok + ' copied so far');
    } catch (e) {
      failed++;
      failures.push({ key, error: e.message });
      console.error('  FAILED on key "' + key + '": ' + e.message);
    }
  }

  console.log('');
  console.log((DRY_RUN ? '[dry run] ' : '') + 'Done. ' + ok + ' succeeded, ' + failed + ' failed, out of ' + docs.length + ' total.');
  if (failures.length) {
    console.log('Failed keys (nothing was deleted from Firestore, so it is safe to fix the issue and re-run - already-copied keys will just be overwritten with the same data):');
    for (const f of failures) console.log('  - ' + f.key + ': ' + f.error);
    process.exitCode = 1;
  } else if (!DRY_RUN) {
    console.log('Firestore was not modified - it still has every record, ready to act as your live backup.');
  }
})().catch(e => { console.error('Migration aborted: ' + e.message); process.exit(1); });
