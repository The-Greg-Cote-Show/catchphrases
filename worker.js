// Greg Cote's Top 75 Catchphrase Countdown: Worker
// Thin "Bird Feeder" API: validate, hash the IP, verify Turnstile, store one row.
// All analysis happens in the admin dashboard's browser, never here.
// Secrets (Cloudflare secrets only): ADMIN_KEY, IP_SALT, TURNSTILE_SECRET, VIEW_KEY (Greg's read-only dashboard)
// Vars (wrangler.toml): ALLOWED_ORIGINS, SITE_URL, MAX_PER_CONNECTION
//
// Vote limits: one vote per device per exercise (random device id kept in the browser),
// plus a cap of MAX_PER_CONNECTION votes per exercise from one connection (hashed IP),
// plus a Turnstile check on every vote. Shared Wi-Fi and carrier NAT can still vote.

const EXERCISES = ['top10', 'number1', 'rearrange', 'omissions'];
const NEEDED = { top10: 10, number1: 1, rearrange: 75 };
const TOTAL = 75;
const MAX_OMISSIONS = 5;
const MAX_OMISSION_CHARS = 80;
const REVIEW_KEY = 'omissions_review';
const MAX_VOTE_BODY = 8 * 1024;
const MAX_ADMIN_BODY = 256 * 1024;
const DEFAULT_PER_CONNECTION = 10;

const MSG = {
  duplicate: 'Looks like you already voted on this one.',
  full: "We've had a lot of votes from this connection already, so we can't take another one from here.",
  busy: 'Voting is busy, try again later.',
  closed: "Voting isn't open right now. Check back soon.",
  notSetUp: "Voting isn't set up yet. Check back soon.",
  human: "We couldn't confirm you're a human. Give it another shot.",
  bad: "Something's off with that vote. Refresh the page and try again.",
  tooBig: 'That was way too much data.',
};

const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (err) {
      console.error('Unhandled error:', err && err.message);
      return json({ ok: false, error: MSG.busy }, 503);
    }
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  if (path.startsWith('/api/')) return publicApi(request, env, url, path);
  if (path === '/admin' || path.startsWith('/admin/')) return adminApi(request, env, url, path);
  if (path === '/view' || path.startsWith('/view/')) return viewApi(request, env, url, path);
  return new Response('Not found', { status: 404 });
}

// ---------------------------------------------------------------- public API

async function publicApi(request, env, url, path) {
  const origin = request.headers.get('Origin');
  const okOrigin = isAllowedOrigin(origin, env) ? origin : null;
  if (origin && !okOrigin) return json({ ok: false, error: 'Not allowed.' }, 403);
  const cors = okOrigin
    ? {
        'Access-Control-Allow-Origin': okOrigin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
        Vary: 'Origin',
      }
    : { Vary: 'Origin' };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (path === '/api/status' && request.method === 'GET') return handleStatus(request, env, url, cors);
  if (path === '/api/results' && request.method === 'GET') return handleResults(env, cors);
  if (path === '/api/submit' && request.method === 'POST') {
    if (!okOrigin) return json({ ok: false, error: 'Not allowed.' }, 403);
    return handleSubmit(request, env, cors);
  }
  return json({ ok: false, error: 'Not found.' }, 404, cors);
}

function isAllowedOrigin(origin, env) {
  if (!origin) return false;
  return String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim().replace(/\/+$/, ''))
    .filter(Boolean)
    .includes(origin);
}

async function handleStatus(request, env, url, cors) {
  const done = { top10: false, number1: false, rearrange: false, omissions: false };
  let flags;
  try {
    const devHash = await hashDevice(request, env, url.searchParams.get('d'));
    const stmts = [flagsStmt(env)];
    if (devHash) stmts.push(env.DB.prepare('SELECT exercise FROM submissions WHERE device_hash = ?').bind(devHash));
    const out = await env.DB.batch(stmts);
    flags = readFlags(out[0].results);
    if (out[1]) for (const r of out[1].results) if (r.exercise in done) done[r.exercise] = true;
  } catch (err) {
    console.error('status db error:', err && err.message);
    return json({ ok: false, error: MSG.busy }, 503, cors);
  }
  return json({ ok: true, voting_open: flags.voting_open, results_public: flags.results_public, done }, 200, cors);
}

async function handleSubmit(request, env, cors) {
  if (!env.IP_SALT || !env.TURNSTILE_SECRET) return json({ ok: false, error: MSG.notSetUp }, 503, cors);

  const body = await readBody(request, MAX_VOTE_BODY);
  if (body === null) return json({ ok: false, error: MSG.tooBig }, 413, cors);
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return json({ ok: false, error: MSG.bad }, 400, cors);
  }
  if (!data || typeof data !== 'object') return json({ ok: false, error: MSG.bad }, 400, cors);

  const { exercise, token, device } = data;
  const checked = exercise === 'omissions' ? cleanOmissions(data.entries) : { payload: data.ids, problem: validateVote(exercise, data.ids) };
  const problem = checked.problem;
  if (problem) return json({ ok: false, error: MSG.bad, detail: problem }, 400, cors);
  const payload = checked.payload;
  if (typeof token !== 'string' || !token || token.length > 2048) {
    return json({ ok: false, error: MSG.human }, 400, cors);
  }
  const ip = request.headers.get('CF-Connecting-IP');
  if (!ip) return json({ ok: false, error: MSG.bad }, 400, cors);

  let flags;
  try {
    flags = readFlags((await flagsStmt(env).all()).results);
  } catch (err) {
    console.error('submit flags error:', err && err.message);
    return json({ ok: false, error: MSG.busy }, 503, cors);
  }
  if (!flags.voting_open) return json({ ok: false, error: MSG.closed }, 403, cors);

  if (!(await verifyTurnstile(token, ip, env))) return json({ ok: false, error: MSG.human }, 403, cors);

  const ipHash = await hashIp(request, env);
  const devHash = await hashDevice(request, env, device);
  const cap = Math.max(1, parseInt(env.MAX_PER_CONNECTION, 10) || DEFAULT_PER_CONNECTION);
  // Cloudflare's location guess for the connection (free on every plan). Never the IP itself.
  const cf = request.cf || {};
  const country = cf.country ? String(cf.country).slice(0, 2) : null;
  const region = cf.region ? String(cf.region).slice(0, 80) : null;
  const city = cf.city ? String(cf.city).slice(0, 80) : null;
  try {
    // One statement: insert only if this connection is under its cap, and never twice per device.
    const res = await env.DB.prepare(
      'INSERT INTO submissions (exercise, ip_hash, device_hash, payload, country, region, city) ' +
        'SELECT ?1, ?2, ?3, ?4, ?5, ?7, ?8 ' +
        'WHERE (SELECT COUNT(*) FROM submissions WHERE ip_hash = ?2 AND exercise = ?1) < ?6 ' +
        'ON CONFLICT (device_hash, exercise) DO NOTHING'
    )
      .bind(exercise, ipHash, devHash, JSON.stringify(payload), country, cap, region, city)
      .run();
    if (!res.meta || !res.meta.changes) {
      const dup = await env.DB.prepare('SELECT 1 AS x FROM submissions WHERE device_hash = ? AND exercise = ?')
        .bind(devHash, exercise)
        .first();
      if (dup) return json({ ok: false, duplicate: true, error: MSG.duplicate }, 409, cors);
      return json({ ok: false, full: true, error: MSG.full }, 429, cors);
    }
  } catch (err) {
    console.error('submit db error:', err && err.message);
    return json({ ok: false, error: MSG.busy }, 503, cors);
  }
  return json({ ok: true }, 200, cors);
}

// Biggest Omissions: 1 to 5 short free-text answers. Whitespace is tidied, blanks dropped,
// repeats within one ballot dropped (ignoring case). Text is stored as typed otherwise;
// grouping similar answers happens later in the admin review.
function cleanOmissions(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_OMISSIONS) return { problem: 'entries must be a list of up to 5' };
  const out = [];
  const seen = new Set();
  for (const e of entries) {
    if (typeof e !== 'string') return { problem: 'entries must be text' };
    if (/[\u0000-\u001f\u007f]/.test(e)) return { problem: 'no control characters' };
    const t = e.replace(/\s+/g, ' ').trim();
    if (!t) continue;
    if (t.length > MAX_OMISSION_CHARS) return { problem: 'each entry is 80 characters max' };
    const k = t.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(t);
  }
  if (!out.length) return { problem: 'name at least one' };
  return { payload: out, problem: null };
}

function validateVote(exercise, ids) {
  if (!EXERCISES.includes(exercise)) return 'unknown exercise';
  if (!Array.isArray(ids)) return 'ids must be a list';
  const need = NEEDED[exercise];
  if (exercise === 'top10') {
    // Top 10 is "up to 10": fans can lock in fewer if they want.
    if (ids.length < 1 || ids.length > need) return 'need 1 to ' + need + ' ids';
  } else if (ids.length !== need) return 'need exactly ' + need + ' ids';
  const seen = new Set();
  for (const id of ids) {
    if (!Number.isInteger(id) || id < 1 || id > TOTAL) return 'ids must be whole numbers from 1 to 75';
    if (seen.has(id)) return 'no repeats';
    seen.add(id);
  }
  return null;
}

async function handleResults(env, cors) {
  try {
    const flags = readFlags((await flagsStmt(env).all()).results);
    const snap = flags.results_public ? await latestSnapshot(env) : null;
    if (!snap) return json({ ok: true, public: false, message: 'Results coming soon' }, 200, cors);
    // snap.data was validated as JSON when it was saved, so it is spliced in without re-parsing.
    return new Response(
      '{"ok":true,"public":true,"created_at":' + JSON.stringify(snap.created_at) + ',"snapshot":' + snap.data + '}',
      { status: 200, headers: { ...jsonHeaders(), ...cors } }
    );
  } catch (err) {
    console.error('results db error:', err && err.message);
    return json({ ok: false, error: MSG.busy }, 503, cors);
  }
}

// ---------------------------------------------------------------- admin

const ADMIN_HEADERS = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Robots-Tag': 'noindex, nofollow',
  'X-Frame-Options': 'DENY',
};

async function adminApi(request, env, url, path) {
  if (!env.ADMIN_KEY) return new Response('Admin is not set up yet.', { status: 503, headers: ADMIN_HEADERS });
  const key = url.searchParams.get('key') || '';
  if (!(await keyMatches(key, env.ADMIN_KEY))) {
    return new Response('Wrong or missing key.', { status: 401, headers: ADMIN_HEADERS });
  }
  const get = request.method === 'GET';
  const post = request.method === 'POST';

  try {
    if (path === '/admin' && get) return adminPage(key, env);
    if (path === '/admin/api/state' && get) return json(await adminState(env), 200, ADMIN_HEADERS);
    if (path === '/admin/api/rows' && get) return adminRows(env, url);
    if (path === '/admin/export.csv' && get) return adminCsv(env, url);
    if (path === '/admin/api/settings' && post) return adminSettings(request, env);
    if (path === '/admin/api/snapshot' && post) return adminSnapshot(request, env);
    if (path === '/admin/api/clear' && post) return adminClear(request, env);
    if (path === '/admin/api/review' && get) return adminReviewGet(env);
    if (path === '/admin/api/review' && post) return adminReviewSave(request, env);
    if (path === '/admin/preview' && get) return adminPreview(env);
  } catch (err) {
    console.error('admin error:', err && err.message);
    return json({ ok: false, error: 'Database error: ' + (err && err.message) }, 503, ADMIN_HEADERS);
  }
  return json({ ok: false, error: 'Not found.' }, 404, ADMIN_HEADERS);
}

// Greg's read-only dashboard. Its own key (VIEW_KEY) so the admin key never gets shared;
// the admin key opens it too. Reads only: the page, the rows (without ip_hash) and the saved
// omissions review. The VIEW_KEY does not open any /admin route.
async function viewApi(request, env, url, path) {
  const key = url.searchParams.get('key') || '';
  const ok =
    (env.VIEW_KEY && (await keyMatches(key, env.VIEW_KEY))) || (env.ADMIN_KEY && (await keyMatches(key, env.ADMIN_KEY)));
  if (!ok) return new Response('Wrong or missing key.', { status: 401, headers: ADMIN_HEADERS });
  if (request.method !== 'GET') return json({ ok: false, error: 'Not found.' }, 404, ADMIN_HEADERS);
  try {
    if (path === '/view') return adminPage(key, env, true);
    if (path === '/view/api/rows') {
      const { after, limit } = pageParams(url, 1000, 2000);
      const { results, next } = await fetchRows(env, after, limit);
      const rows = results.map(({ ip_hash, ...rest }) => rest);
      return json({ ok: true, rows, next }, 200, ADMIN_HEADERS);
    }
    if (path === '/view/api/review') return adminReviewGet(env);
  } catch (err) {
    console.error('view error:', err && err.message);
    return json({ ok: false, error: 'Database error.' }, 503, ADMIN_HEADERS);
  }
  return json({ ok: false, error: 'Not found.' }, 404, ADMIN_HEADERS);
}

async function keyMatches(given, expected) {
  if (!given) return false;
  const [a, b] = await Promise.all([sha256(given), sha256(expected)]);
  return crypto.subtle.timingSafeEqual(a, b);
}

async function adminState(env) {
  const out = await env.DB.batch([
    flagsStmt(env),
    env.DB.prepare('SELECT id, created_at FROM snapshots ORDER BY id DESC LIMIT 1'),
  ]);
  const flags = readFlags(out[0].results);
  return { ok: true, ...flags, snapshot: out[1].results[0] || null };
}

function pageParams(url, def, max) {
  const after = Math.max(0, parseInt(url.searchParams.get('after') || '0', 10) || 0);
  const limit = Math.min(max, Math.max(1, parseInt(url.searchParams.get('limit') || String(def), 10) || def));
  return { after, limit };
}

async function fetchRows(env, after, limit) {
  const { results } = await env.DB.prepare(
    'SELECT id, exercise, ip_hash, device_hash, payload, created_at, country, region, city FROM submissions WHERE id > ? ORDER BY id LIMIT ?'
  )
    .bind(after, limit)
    .all();
  const next = results.length === limit ? results[results.length - 1].id : null;
  return { results, next };
}

async function adminRows(env, url) {
  const { after, limit } = pageParams(url, 1000, 2000);
  const { results, next } = await fetchRows(env, after, limit);
  return json({ ok: true, rows: results, next }, 200, ADMIN_HEADERS);
}

async function adminCsv(env, url) {
  const { after, limit } = pageParams(url, 5000, 5000);
  const { results, next } = await fetchRows(env, after, limit);
  const lines = after === 0 ? ['id,exercise,created_at,country,region,city,ip_hash,device_hash,payload'] : [];
  for (const r of results) {
    lines.push(
      [r.id, r.exercise, r.created_at, r.country || '', r.region || '', r.city || '', r.ip_hash, r.device_hash, r.payload]
        .map(csvField)
        .join(',')
    );
  }
  const headers = {
    ...ADMIN_HEADERS,
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="catchphrase-submissions' + (after ? '-after-' + after : '') + '.csv"',
  };
  if (next !== null) headers['X-Next-After'] = String(next);
  return new Response(lines.join('\r\n') + '\r\n', { status: 200, headers });
}

function csvField(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function adminSettings(request, env) {
  const body = await readBody(request, MAX_ADMIN_BODY);
  let data;
  try {
    data = JSON.parse(body || '');
  } catch {
    return json({ ok: false, error: 'Bad JSON.' }, 400, ADMIN_HEADERS);
  }
  const stmts = [];
  for (const name of ['voting_open', 'results_public']) {
    if (data[name] === undefined) continue;
    if (typeof data[name] !== 'boolean') return json({ ok: false, error: name + ' must be true or false.' }, 400, ADMIN_HEADERS);
    stmts.push(
      env.DB.prepare(
        'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value'
      ).bind(name, data[name] ? '1' : '0')
    );
  }
  if (!stmts.length) return json({ ok: false, error: 'Nothing to change.' }, 400, ADMIN_HEADERS);
  if (data.results_public === true && !(await latestSnapshot(env))) {
    return json({ ok: false, error: 'Save a snapshot before going live.' }, 409, ADMIN_HEADERS);
  }
  await env.DB.batch(stmts);
  return json(await adminState(env), 200, ADMIN_HEADERS);
}

async function adminSnapshot(request, env) {
  const body = await readBody(request, MAX_ADMIN_BODY);
  if (body === null) return json({ ok: false, error: 'Snapshot is too big (256 KB max).' }, 413, ADMIN_HEADERS);
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return json({ ok: false, error: 'Bad JSON.' }, 400, ADMIN_HEADERS);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return json({ ok: false, error: 'Snapshot must be an object.' }, 400, ADMIN_HEADERS);
  }
  await env.DB.prepare('INSERT INTO snapshots (data) VALUES (?)').bind(JSON.stringify(data)).run();
  return json(await adminState(env), 200, ADMIN_HEADERS);
}

// Wipes every vote. Snapshots go too (they were computed from those votes), and results go
// back to private so an old snapshot can never be published by accident.
async function adminClear(request, env) {
  const body = await readBody(request, MAX_ADMIN_BODY);
  let data;
  try {
    data = JSON.parse(body || '');
  } catch {
    data = null;
  }
  if (!data || data.confirm !== 'CLEAR') {
    return json({ ok: false, error: 'Type CLEAR to confirm.' }, 400, ADMIN_HEADERS);
  }
  const out = await env.DB.batch([
    env.DB.prepare('DELETE FROM submissions'),
    env.DB.prepare('DELETE FROM snapshots'),
    env.DB.prepare("UPDATE settings SET value = '0' WHERE key = 'results_public'"),
    env.DB.prepare('DELETE FROM settings WHERE key = ?').bind(REVIEW_KEY),
  ]);
  const state = await adminState(env);
  return json({ ...state, cleared: (out[0].meta && out[0].meta.changes) || 0 }, 200, ADMIN_HEADERS);
}

// The admin's Biggest Omissions review (which answers count as the same thing, display names,
// what's excluded). Built and used in the admin browser; the Worker just stores the JSON.
async function adminReviewGet(env) {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(REVIEW_KEY).first();
  return new Response('{"ok":true,"review":' + (row ? row.value : 'null') + '}', {
    status: 200,
    headers: { ...jsonHeaders(), ...ADMIN_HEADERS },
  });
}

async function adminReviewSave(request, env) {
  const body = await readBody(request, MAX_ADMIN_BODY);
  if (body === null) return json({ ok: false, error: 'Review is too big (256 KB max).' }, 413, ADMIN_HEADERS);
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return json({ ok: false, error: 'Bad JSON.' }, 400, ADMIN_HEADERS);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return json({ ok: false, error: 'Review must be an object.' }, 400, ADMIN_HEADERS);
  }
  data.saved_at = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value'
  )
    .bind(REVIEW_KEY, JSON.stringify(data))
    .run();
  return json({ ok: true, saved_at: data.saved_at }, 200, ADMIN_HEADERS);
}

async function adminPreview(env) {
  const site = String(env.SITE_URL || '').replace(/\/+$/, '');
  const snap = await latestSnapshot(env);
  let html;
  try {
    const r = await fetch(site + '/results.html', { headers: { 'Cache-Control': 'no-cache' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    html = await r.text();
  } catch (err) {
    return new Response(
      'Could not load results.html from ' + site + ' (' + (err && err.message) + '). Is GitHub Pages live and SITE_URL right?',
      { status: 502, headers: { ...ADMIN_HEADERS, 'Content-Type': 'text/plain; charset=utf-8' } }
    );
  }
  const preview = { snapshot: snap ? JSON.parse(snap.data) : null, created_at: snap ? snap.created_at : null };
  const inject =
    '<base href="' + escapeHtml(site) + '/">' +
    '<meta name="referrer" content="no-referrer">' +
    '<script>window.__PREVIEW__=' + safeJson(preview) + ';</script>';
  html = html.replace(/<head[^>]*>/i, (m) => m + inject);
  return new Response(html, { status: 200, headers: { ...ADMIN_HEADERS, 'Content-Type': 'text/html; charset=utf-8' } });
}

// The admin page doubles as Greg's viewer: same analysis, controls hidden, read-only API base.
function adminPage(key, env, viewer = false) {
  const config = safeJson({
    key,
    siteUrl: String(env.SITE_URL || '').replace(/\/+$/, ''),
    base: viewer ? '/view' : '/admin',
    viewer,
  });
  let html = ADMIN_HTML.replace('__ADMIN_CONFIG__', () => config);
  if (viewer) {
    html = html
      .replace('<title>Catchphrase Admin</title>', '<title>Catchphrase Countdown Results</title>')
      .replace('<h1>Catchphrase Countdown Admin</h1>', '<h1>Catchphrase Countdown: Fan Votes</h1>')
      .replace('<body>', '<body class="viewer">');
  }
  return new Response(html, {
    status: 200,
    headers: { ...ADMIN_HEADERS, 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ---------------------------------------------------------------- helpers

function flagsStmt(env) {
  return env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('voting_open', 'results_public')");
}

function readFlags(rows) {
  const flags = { voting_open: false, results_public: false };
  for (const r of rows || []) if (r.key in flags) flags[r.key] = r.value === '1';
  return flags;
}

async function latestSnapshot(env) {
  return env.DB.prepare('SELECT id, created_at, data FROM snapshots ORDER BY id DESC LIMIT 1').first();
}

async function verifyTurnstile(token, ip, env) {
  try {
    const form = new FormData();
    form.append('secret', env.TURNSTILE_SECRET);
    form.append('response', token);
    form.append('remoteip', ip);
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
    const out = await r.json();
    return !!(out && out.success === true);
  } catch (err) {
    console.error('turnstile error:', err && err.message);
    return false;
  }
}

// HMAC-SHA-256 of the visitor's network address, keyed with IP_SALT. The raw IP is never stored or logged.
async function hashIp(request, env) {
  const ip = request.headers.get('CF-Connecting-IP');
  if (!env.IP_SALT || !ip) return null;
  const key = await crypto.subtle.importKey('raw', enc.encode(env.IP_SALT), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(normalizeIp(ip))));
}

// HMAC of the random device id the page keeps in localStorage. A page that sends no
// (or a malformed) id falls back to its connection, which means one vote per connection.
async function hashDevice(request, env, device) {
  const ip = request.headers.get('CF-Connecting-IP');
  if (!env.IP_SALT) return null;
  let msg;
  if (typeof device === 'string' && /^[A-Za-z0-9-]{16,64}$/.test(device)) msg = 'dev|' + device;
  else if (ip) msg = 'nodev|' + normalizeIp(ip);
  else return null;
  const key = await crypto.subtle.importKey('raw', enc.encode(env.IP_SALT), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(msg)));
}

// IPv4 stays as is. IPv6 is cut to its /64 network, because phones rotate the second half.
function normalizeIp(raw) {
  let ip = String(raw).trim().toLowerCase().split('%')[0];
  if (!ip.includes(':')) return ip;
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  const toGroups = (s) => {
    if (!s) return [];
    const parts = s.split(':');
    if (parts[parts.length - 1].includes('.')) parts.splice(parts.length - 1, 1, '0', '0');
    return parts;
  };
  let groups;
  if (ip.includes('::')) {
    const [head, tail] = ip.split('::');
    const h = toGroups(head);
    const t = toGroups(tail);
    groups = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  } else {
    groups = toGroups(ip);
  }
  return (
    groups
      .slice(0, 4)
      .map((g) => (parseInt(g || '0', 16) || 0).toString(16))
      .join(':') + '::/64'
  );
}

async function sha256(s) {
  return crypto.subtle.digest('SHA-256', enc.encode(s));
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Reads the body but gives up (returns null) as soon as it passes max bytes.
async function readBody(request, max) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > max) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      try {
        await reader.cancel();
      } catch {}
      return null;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(buf);
}

function jsonHeaders() {
  return { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
}

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { ...jsonHeaders(), ...extra } });
}

function safeJson(obj) {
  return JSON.stringify(obj).replace(/</g, '\\u003c');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---------------------------------------------------------------- admin dashboard page
// Plain HTML + JS. All analysis runs here, in the browser. Kept free of template-literal
// placeholders on purpose: the only server-side injection is __ADMIN_CONFIG__.

const ADMIN_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>Catchphrase Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.5.1/chart.umd.min.js" integrity="sha512-WoViKhKD4qI2WruSZqv9+kvM4WfFhUMQCLN4QlDTt5aU56fLQy2gYoxWIqlEnXqJy/+Ac5q/hk1oWfqnMDhwMA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<style>
/* ===== STYLE BLOCK (restyle here) =====
   Miami Dolphins palette. To use the CoteCup palette instead, swap in:
   --brand:#e8b84b; --hot:#e05252; --bg:#080c14; --surface:#0f1623; --surface-2:#141d2e;
   --line:#24304a; --ink:#eef2f7; --ink-2:#b9c4d6; --ink-3:#7a8ba8; --on-brand:#0b0f17; --on-hot:#ffffff; */
:root {
  --brand: #00A3AD;
  --hot: #FC4C02;
  --bg: #061a22;
  --surface: #0b2631;
  --surface-2: #10313e;
  --line: #1d4655;
  --ink: #eef6f7;
  --ink-2: #b4cdd2;
  --ink-3: #7c9aa2;
  --on-brand: #04161c;
  --on-hot: #1a0800;
  --good: #4fd18b;
  --font: "Barlow Condensed", "Arial Narrow", "Roboto Condensed", "Helvetica Neue", Arial, sans-serif;
}
/* ===== END STYLE BLOCK ===== */
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--font); font-size: 18px; line-height: 1.35; }
header, main { max-width: 1100px; margin: 0 auto; padding: 16px; }
h1 { font-size: 30px; margin: 4px 0 12px; color: var(--brand); letter-spacing: .5px; }
h2 { font-size: 26px; margin: 28px 0 8px; color: var(--brand); border-bottom: 2px solid var(--line); padding-bottom: 4px; }
h3 { font-size: 20px; margin: 14px 0 6px; color: var(--ink-2); }
.flags { display: flex; gap: 10px; flex-wrap: wrap; }
.flag { padding: 8px 14px; border-radius: 8px; font-weight: 700; font-size: 20px; background: var(--surface-2); border: 2px solid var(--line); }
.flag.on { border-color: var(--good); color: var(--good); }
.flag.off { border-color: var(--hot); color: var(--hot); }
.snapinfo { margin: 10px 0; color: var(--ink-2); }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
button, .btn { font: inherit; font-weight: 600; font-size: 18px; padding: 9px 14px; border-radius: 8px; border: 2px solid var(--line); background: var(--surface-2); color: var(--ink); cursor: pointer; text-decoration: none; display: inline-block; }
button:hover, .btn:hover { border-color: var(--brand); }
button.primary { background: var(--brand); color: var(--on-brand); border-color: var(--brand); }
button.danger { background: var(--hot); color: var(--on-hot); border-color: var(--hot); }
button:disabled { opacity: .4; cursor: not-allowed; }
#msg { min-height: 1.4em; color: var(--ink-2); }
#msg.bad { color: var(--hot); font-weight: 600; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; }
.tile { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 12px; }
.tile .n { font-size: 34px; font-weight: 700; color: var(--ink); }
.tile .l { color: var(--ink-3); }
.grid2 { display: grid; grid-template-columns: 1fr; gap: 16px; }
@media (min-width: 800px) { .grid2 { grid-template-columns: 1fr 1fr; } }
.chartbox { position: relative; height: 280px; background: var(--surface); border-radius: 10px; padding: 8px; }
.chartbox.tall { height: 560px; }
.note { color: var(--ink-3); margin: 4px 0 10px; }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 17px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--ink-3); font-weight: 600; position: sticky; top: 0; background: var(--bg); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
.up { color: var(--good); }
.down { color: var(--hot); }
details summary { cursor: pointer; color: var(--brand); margin: 10px 0; font-weight: 600; }
ol { padding-left: 22px; margin: 4px 0; }
.om-input { font: inherit; font-size: 17px; width: 100%; min-width: 180px; padding: 5px 8px; border-radius: 6px; border: 2px solid var(--line); background: var(--surface); color: var(--ink); }
.om-input:focus { outline: none; border-color: var(--brand); }
.variants { color: var(--ink-3); font-size: 15px; }
.badge { display: inline-block; font-size: 14px; font-weight: 700; padding: 1px 8px; border-radius: 99px; background: var(--hot); color: var(--on-hot); white-space: nowrap; }
.badge.new { background: var(--brand); color: var(--on-brand); }
.sugg { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 8px 10px; margin: 0 0 6px; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; }
.sugg .pair { flex: 1; min-width: 260px; }
.sugg .score { color: var(--ink-3); font-variant-numeric: tabular-nums; }
.sugg button, .smallbtn { font-size: 15px; padding: 4px 10px; }
.saveinfo { color: var(--ink-3); margin-left: 8px; align-self: center; }
.saveinfo.dirty { color: var(--hot); font-weight: 700; }
.jump { margin: 4px 0 0; }
.jump a { color: var(--brand); font-weight: 700; text-decoration: none; }
.jump a:hover { text-decoration: underline; }
.tabs { display: flex; gap: 6px; margin-top: 10px; border-bottom: 2px solid var(--line); }
.tab { font-size: 22px; font-weight: 700; padding: 8px 18px; color: var(--ink-3); text-decoration: none; border: 2px solid transparent; border-bottom: none; border-radius: 8px 8px 0 0; margin-bottom: -2px; }
.tab:hover { color: var(--ink); }
.tab.active { color: var(--brand); background: var(--surface); border-color: var(--line); border-bottom: 2px solid var(--surface); }
.geo-toggle { display: flex; gap: 8px; margin: 6px 0 10px; }
.geo-btn.active { background: var(--brand); color: var(--on-brand); border-color: var(--brand); }
.mapgrid { display: grid; grid-template-columns: 1fr; gap: 16px; margin-bottom: 18px; }
@media (min-width: 900px) { .mapgrid { grid-template-columns: 2fr 1fr; } }
.mapbox { background: var(--surface); border-radius: 10px; padding: 8px; min-height: 200px; }
.mapbox svg { display: block; width: 100%; height: auto; }
.map-area { stroke: var(--bg); stroke-width: .5; cursor: pointer; }
.map-area:hover { stroke: var(--hot); stroke-width: 1.5; }
.map-area.sel { stroke: var(--hot); stroke-width: 2; }
.drill { background: var(--surface); border-radius: 10px; padding: 10px 14px; max-height: 520px; overflow-y: auto; }
.drill h3 { margin-top: 4px; color: var(--brand); }
.bar-row { display: grid; grid-template-columns: minmax(0, 1fr) 90px 34px; gap: 8px; align-items: center; padding: 3px 0; font-size: 17px; }
.bar-row .nm { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-wrap { height: 10px; background: var(--surface-2); border-radius: 5px; overflow: hidden; }
.bar-fill { height: 100%; background: var(--brand); border-radius: 5px; }
.bar-row .ct { text-align: right; font-variant-numeric: tabular-nums; }
.maptip { position: fixed; z-index: 10; pointer-events: none; background: var(--bg); color: var(--ink); border: 1px solid var(--brand); border-radius: 6px; padding: 4px 10px; font-size: 16px; }
.grid3 { display: grid; grid-template-columns: 1fr; gap: 16px; }
@media (min-width: 900px) { .grid3 { grid-template-columns: 1fr 1fr 1fr; } }
.tablewrap.scroll { max-height: 420px; overflow-y: auto; }
.viewer-only { display: none; }
body.viewer .viewer-only { display: block; }
body.viewer .admin-only { display: none !important; }
</style>
</head>
<body>
<header>
  <h1>Catchphrase Countdown Admin</h1>
  <div class="flags admin-only">
    <div class="flag" id="flagVoting">Voting: ...</div>
    <div class="flag" id="flagResults">Results: ...</div>
  </div>
  <div class="snapinfo admin-only" id="snapInfo"></div>
  <div class="actions admin-only">
    <button id="btnVoting">Open voting</button>
    <button id="btnSnapshot" class="primary">Save snapshot</button>
    <a id="lnkPreview" class="btn" target="_blank" rel="noreferrer">Preview public page</a>
    <button id="btnLive" class="danger">Go live</button>
    <button id="btnOffline">Take offline</button>
    <button id="btnReload">Reload data</button>
    <button id="btnCsv">Download CSV</button>
    <button id="btnClear" class="danger">Clear all votes</button>
  </div>
  <p id="msg" role="status"></p>
  <p class="jump admin-only"><a href="#omissions-review">Jump to Biggest Omissions review &darr;</a></p>
  <nav class="tabs" aria-label="Views">
    <a href="#votes" class="tab" id="tabVotes">Votes</a>
    <a href="#map" class="tab" id="tabMap">Map</a>
  </nav>
</header>
<main id="viewVotes">
  <section>
    <h2>Total Submissions: <span id="totalSubs">0</span></h2>
    <div class="tiles" id="tiles"></div>
    <p class="note">Total = people who voted. Each person counts once, whether they voted in one category or all four, even if they came back days later to finish. Counted by device, so someone voting on both a phone and a laptop counts twice. The boxes count votes per category.</p>
    <h3>Votes per day (UTC)</h3>
    <div class="chartbox"><canvas id="chDays" aria-label="Votes per day"></canvas></div>
  </section>

  <section>
    <h2>Top 10 picks</h2>
    <p class="note">Fans pick 10, in no particular order. % = share of Top 10 voters who picked it. Chart shows the top 20.</p>
    <div class="chartbox tall"><canvas id="chTop10" aria-label="Top 10 picks"></canvas></div>
    <details><summary>All 75 in a table</summary><div class="tablewrap"><table id="tblTop10"></table></div></details>
  </section>

  <section>
    <h2>Number 1</h2>
    <p class="note">% = share of Number 1 votes.</p>
    <div class="chartbox"><canvas id="chNum1" aria-label="Number 1 votes"></canvas></div>
    <div class="tablewrap"><table id="tblNum1"></table></div>
  </section>

  <section>
    <h2>Rearrange</h2>
    <p class="note">Fan rank 1 = the fans' favorite. "Moved" = Greg's rank minus fan rank (plus means fans like it more than Greg did). "Higher" = % of fans who put it closer to #1 than Greg did. Spread = standard deviation of where fans put it (low = fans agree).</p>
    <div class="grid2">
      <div><h3>Most agreement (lowest spread)</h3><ol id="lstConsensus"></ol></div>
      <div><h3>Most split (highest spread)</h3><ol id="lstSplit"></ol></div>
    </div>
    <div class="tablewrap"><table id="tblRearr"></table></div>
  </section>

  <section id="omissions-review">
    <h2>Biggest Omissions</h2>
    <p class="note viewer-only">Catchphrases fans say Greg left off. Fans type these themselves, so similar answers are grouped together.</p>
    <p class="note admin-only">Fans type these themselves, so the same phrase shows up spelled a dozen ways. Answers that only differ by capitals, spacing, punctuation or stretched letters ("nowwww") are grouped automatically. Then you finish the job here: look at <b>Possible matches</b>, merge what's the same, fix group names the way you want them shown, exclude junk, and click <b>Save review</b>. Snapshots and the public results use this review.</p>
    <div class="actions admin-only">
      <button id="btnSaveReview" class="primary">Save review</button>
      <span id="reviewInfo" class="saveinfo"></span>
    </div>
    <h3 class="admin-only">Possible matches <span class="note" id="suggCount"></span></h3>
    <div id="omSuggest" class="admin-only"></div>
    <h3 class="admin-only">Groups</h3>
    <div class="actions admin-only">
      <button id="btnMerge">Merge checked</button>
      <span class="note" style="align-self:center">Merges every checked group into the biggest checked one. Rename it after if you like.</span>
    </div>
    <div class="tablewrap"><table id="tblOm"></table></div>
    <h3 class="admin-only">Excluded</h3>
    <div id="omExcluded" class="note admin-only"></div>
  </section>
</main>

<main id="viewMap" hidden>
  <section>
    <h2>Where People Voted From</h2>
    <p class="note">Counted per person, from where they cast their first vote. This is Cloudflare's best guess from the internet connection, so cities can be off (phones often show up in a nearby city). The first 128 votes (before the evening of October 5) only have the country.</p>
    <div class="geo-toggle">
      <button class="geo-btn active" data-geo="world">World</button>
      <button class="geo-btn" data-geo="us">United States</button>
    </div>
    <div class="mapgrid">
      <div class="mapbox" id="mapWrap"><p class="note">Loading map...</p></div>
      <div class="drill">
        <h3 id="drillHdr">Click a country</h3>
        <p class="note" id="drillHint"></p>
        <div id="drillList"></div>
      </div>
    </div>
    <div class="grid3">
      <div><h3>Countries</h3><div class="tablewrap scroll"><table id="tblCountries"></table></div></div>
      <div><h3>States / regions</h3><div class="tablewrap scroll"><table id="tblRegions"></table></div></div>
      <div><h3>Cities</h3><div class="tablewrap scroll"><table id="tblCities"></table></div></div>
    </div>
  </section>
</main>
<div id="mapTip" class="maptip" hidden></div>

<script>
var CFG = __ADMIN_CONFIG__;
var K = encodeURIComponent(CFG.key);
var BASE = CFG.base || '/admin';   // '/view' on Greg's read-only page
var VIEWER = !!CFG.viewer;
var TEXT = {};
var STATE = null;
var ROWS = [];
var charts = {};
var BAR = getComputedStyle(document.documentElement).getPropertyValue('--brand').trim() || '#00A3AD';
var GRID = 'rgba(238,246,247,0.08)', INK2 = getComputedStyle(document.documentElement).getPropertyValue('--ink-2').trim() || '#b4cdd2';
var CHART_FONT = '"Barlow Condensed", "Arial Narrow", "Roboto Condensed", Arial, sans-serif';

function $(id) { return document.getElementById(id); }
function api(p) { return p + (p.indexOf('?') >= 0 ? '&' : '?') + 'key=' + K; }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function phrase(id) { return TEXT[id] || ('#' + id); }
function short(id) { var t = phrase(id); return t.length > 38 ? t.slice(0, 36) + '...' : t; }
function pct(n, d) { return d ? Math.round(n / d * 1000) / 10 : 0; }
function say(t, bad) { var m = $('msg'); m.textContent = t; m.className = bad ? 'bad' : ''; }
function when(iso) { if (!iso) return ''; var d = new Date(iso.indexOf('Z') > 0 || iso.indexOf('+') > 0 ? iso : iso.replace(' ', 'T') + 'Z'); return isNaN(d) ? iso : d.toLocaleString(); }

async function getJson(path) {
  var r = await fetch(api(path), { cache: 'no-store' });
  var d = await r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; });
  if (!d.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}
async function postJson(path, body) {
  var r = await fetch(api(path), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  var d = await r.json().catch(function () { return { ok: false, error: 'HTTP ' + r.status }; });
  if (!d.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

async function loadText() {
  try {
    var r = await fetch(CFG.siteUrl + '/catchphrases.json', { cache: 'no-store' });
    var list = await r.json();
    list.forEach(function (c) { TEXT[c.id] = c.text; });
  } catch (e) {
    say('Could not load catchphrases.json from ' + CFG.siteUrl + '. Showing ids only.', true);
  }
}

async function loadState() { STATE = await getJson('/admin/api/state'); renderFlags(); }

async function loadRows() {
  ROWS = [];
  var after = 0;
  for (;;) {
    var d = await getJson(BASE + '/api/rows?limit=2000&after=' + after);
    ROWS = ROWS.concat(d.rows);
    say('Loaded ' + ROWS.length + ' submissions...');
    if (d.next === null || d.next === undefined) break;
    after = d.next;
  }
}

function renderFlags() {
  var v = $('flagVoting'), r = $('flagResults');
  v.textContent = 'Voting: ' + (STATE.voting_open ? 'OPEN' : 'CLOSED');
  v.className = 'flag ' + (STATE.voting_open ? 'on' : 'off');
  r.textContent = 'Results: ' + (STATE.results_public ? 'PUBLIC' : 'PRIVATE');
  r.className = 'flag ' + (STATE.results_public ? 'on' : 'off');
  $('btnVoting').textContent = STATE.voting_open ? 'Close voting' : 'Open voting';
  $('btnLive').disabled = !!STATE.results_public;
  $('btnOffline').disabled = !STATE.results_public;
  $('snapInfo').textContent = STATE.snapshot
    ? 'Last snapshot: ' + when(STATE.snapshot.created_at) + ' (this is what fans see when results are public)'
    : 'No snapshot saved yet. Save one before going live.';
}

// ---- analysis: everything is computed here in the browser ----
function compute() {
  var by = { top10: [], number1: [], rearrange: [], omissions: [] }, days = {}, people = {}, nPeople = 0;
  ROWS.forEach(function (r) {
    // One person = one device, however many categories it voted in. Rows come in id order,
    // so the first row seen for a device is its first vote (used for location).
    if (r.device_hash && !people[r.device_hash]) { people[r.device_hash] = r; nPeople++; }
    var p;
    try { p = JSON.parse(r.payload); } catch (e) { return; }
    if (!by[r.exercise] || !Array.isArray(p)) return;
    by[r.exercise].push(p);
    var d = String(r.created_at || '').slice(0, 10) || '?';
    days[d] = (days[d] || 0) + 1;
  });
  // geo: labels for the tables. byCountry / byRegion / byCity: keyed by code for the maps.
  var geo = { countries: {}, regions: {}, cities: {}, byCountry: {}, byRegion: {}, byCity: {} };
  function bump(o, k) { o[k] = (o[k] || 0) + 1; }
  Object.keys(people).forEach(function (dev) {
    var r = people[dev], c = r.country || '', st = r.region || '', ci = r.city || '';
    bump(geo.countries, c ? countryName(c) : 'Unknown');
    bump(geo.regions, st ? st + ', ' + (c || '?') : 'Unknown');
    bump(geo.cities, ci ? ci + (st ? ', ' + st : '') + ', ' + (c || '?') : 'Unknown');
    if (c) bump(geo.byCountry, c);
    if (c && st) bump(geo.byRegion, c + '|' + st);
    if (c && st && ci) bump(geo.byCity, c + '|' + st + '|' + ci);
  });
  var ids = [];
  for (var i = 75; i >= 1; i--) ids.push(i);

  // Top 10 ballots are 10 picks in no particular order.
  var n10 = by.top10.length, c10 = {};
  by.top10.forEach(function (p) { p.forEach(function (id) { c10[id] = (c10[id] || 0) + 1; }); });
  var top10 = ids.map(function (id) { return { id: id, count: c10[id] || 0, pct: pct(c10[id] || 0, n10) }; })
    .sort(function (a, b) { return b.count - a.count || a.id - b.id; });

  OM = omAnalyze(by.omissions);

  var n1 = by.number1.length, c1 = {};
  by.number1.forEach(function (p) { c1[p[0]] = (c1[p[0]] || 0) + 1; });
  var number1 = ids.map(function (id) { return { id: id, count: c1[id] || 0, pct: pct(c1[id] || 0, n1) }; })
    .filter(function (x) { return x.count > 0; })
    .sort(function (a, b) { return b.count - a.count || a.id - b.id; })
    .slice(0, 10);

  var nr = by.rearrange.length, sum = {}, sq = {}, hi = {}, lo = {};
  by.rearrange.forEach(function (p) {
    p.forEach(function (id, idx) {
      var rank = 75 - idx;
      sum[id] = (sum[id] || 0) + rank;
      sq[id] = (sq[id] || 0) + rank * rank;
      if (rank < id) hi[id] = (hi[id] || 0) + 1;
      else if (rank > id) lo[id] = (lo[id] || 0) + 1;
    });
  });
  var rearrange = [];
  if (nr) {
    rearrange = ids.map(function (id) {
      var avg = sum[id] / nr;
      var sd = Math.sqrt(Math.max(0, sq[id] / nr - avg * avg));
      return { id: id, greg: id, avg: Math.round(avg * 100) / 100, sd: Math.round(sd * 100) / 100,
        pct_higher: pct(hi[id] || 0, nr), pct_lower: pct(lo[id] || 0, nr) };
    }).sort(function (a, b) { return a.avg - b.avg || a.id - b.id; });
    rearrange.forEach(function (x, idx) { x.fan_rank = idx + 1; });
  }

  return {
    snapshot: {
      version: 3,
      generated_at: new Date().toISOString(),
      totals: { top10: n10, number1: n1, rearrange: nr, omissions: OM.voters },
      top10: top10,
      number1: number1,
      rearrange: rearrange,
      omissions: OM.groups.slice(0, 20).map(function (g) { return { label: g.label, count: g.voters, pct: pct(g.voters, OM.voters) }; })
    },
    days: days,
    geo: geo,
    people: nPeople,
    total: ROWS.length
  };
}

var REGION_NAMES = null;
try { REGION_NAMES = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (e) {}
function countryName(code) {
  try { return REGION_NAMES ? REGION_NAMES.of(code) : code; } catch (e) { return code; }
}

// Location table: biggest first, Unknown always last.
function geoTable(id, label, counts, total) {
  var keys = Object.keys(counts).sort(function (a, b) {
    if ((a === 'Unknown') !== (b === 'Unknown')) return a === 'Unknown' ? 1 : -1;
    return counts[b] - counts[a] || (a < b ? -1 : 1);
  });
  table(id, [{ t: label }, { t: 'People', num: 1 }, { t: '% of people', num: 1 }],
    keys.map(function (k) { return [k, counts[k], pct(counts[k], total) + '%']; }));
}

function barChart(id, labels, data, horizontal, fmt) {
  if (typeof Chart === 'undefined') return;
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), {
    type: 'bar',
    data: { labels: labels, datasets: [{ data: data, backgroundColor: BAR, borderRadius: 4, borderSkipped: 'start', maxBarThickness: 22 }] },
    options: {
      indexAxis: horizontal ? 'y' : 'x',
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: function (c) { return fmt ? fmt(c.raw, c.dataIndex) : String(c.raw); } } } },
      scales: {
        x: { grid: { color: GRID }, ticks: { color: INK2, font: { family: CHART_FONT, size: 14 } }, beginAtZero: true },
        y: { grid: { color: GRID }, ticks: { color: INK2, font: { family: CHART_FONT, size: 14 } }, beginAtZero: true }
      }
    }
  });
}

function table(id, head, rows) {
  var h = '<thead><tr>' + head.map(function (c) { return '<th' + (c.num ? ' class="num"' : '') + '>' + esc(c.t) + '</th>'; }).join('') + '</tr></thead><tbody>';
  rows.forEach(function (r) {
    h += '<tr>' + r.map(function (cell, i) {
      var cls = head[i].num ? 'num' : '';
      if (cell && typeof cell === 'object') { cls += ' ' + cell.cls; cell = cell.v; }
      return '<td class="' + cls + '">' + esc(cell) + '</td>';
    }).join('') + '</tr>';
  });
  $(id).innerHTML = h + '</tbody>';
}

function render() {
  var R = compute(), S = R.snapshot, T = S.totals;
  $('totalSubs').textContent = R.people;
  $('tiles').innerHTML = [['Top 10', T.top10], ['Number 1', T.number1], ['Rearrange', T.rearrange], ['Omissions', T.omissions]]
    .map(function (x) { return '<div class="tile"><div class="n">' + x[1] + '</div><div class="l">' + esc(x[0]) + '</div></div>'; }).join('');

  var dayKeys = Object.keys(R.days).sort();
  barChart('chDays', dayKeys, dayKeys.map(function (d) { return R.days[d]; }), false);
  geoTable('tblCountries', 'Country', R.geo.countries, R.people);
  geoTable('tblRegions', 'State / region', R.geo.regions, R.people);
  geoTable('tblCities', 'City', R.geo.cities, R.people);
  GEO = R.geo;
  GEO_PEOPLE = R.people;
  if (!$('viewMap').hidden) drawMap();

  var t20 = S.top10.slice(0, 20);
  barChart('chTop10', t20.map(function (x) { return short(x.id); }), t20.map(function (x) { return x.pct; }), true,
    function (v, i) { return v + '% of voters (' + t20[i].count + ' picks), Greg #' + t20[i].id; });
  table('tblTop10', [{ t: '', num: 1 }, { t: 'Catchphrase' }, { t: 'Greg #', num: 1 }, { t: 'Picks', num: 1 }, { t: '% of voters', num: 1 }],
    S.top10.map(function (x, i) { return [i + 1, phrase(x.id), x.id, x.count, x.pct + '%']; }));

  renderOmissions();

  barChart('chNum1', S.number1.map(function (x) { return short(x.id); }), S.number1.map(function (x) { return x.pct; }), true,
    function (v, i) { return v + '% share (' + S.number1[i].count + ' votes), Greg #' + S.number1[i].id; });
  table('tblNum1', [{ t: '', num: 1 }, { t: 'Catchphrase' }, { t: 'Greg #', num: 1 }, { t: 'Votes', num: 1 }, { t: '% share', num: 1 }],
    S.number1.map(function (x, i) { return [i + 1, phrase(x.id), x.id, x.count, x.pct + '%']; }));

  var rr = S.rearrange;
  var bySd = rr.slice().sort(function (a, b) { return a.sd - b.sd; });
  $('lstConsensus').innerHTML = bySd.slice(0, 5).map(function (x) { return '<li>' + esc(phrase(x.id)) + ' <span class="note">(spread ' + x.sd + ', fan #' + x.fan_rank + ')</span></li>'; }).join('');
  $('lstSplit').innerHTML = bySd.slice(-5).reverse().map(function (x) { return '<li>' + esc(phrase(x.id)) + ' <span class="note">(spread ' + x.sd + ', fan #' + x.fan_rank + ')</span></li>'; }).join('');
  table('tblRearr', [{ t: 'Fan #', num: 1 }, { t: 'Catchphrase' }, { t: 'Greg #', num: 1 }, { t: 'Avg spot', num: 1 }, { t: 'Moved', num: 1 }, { t: 'Higher', num: 1 }, { t: 'Lower', num: 1 }, { t: 'Spread', num: 1 }],
    rr.map(function (x) {
      var mv = x.greg - x.fan_rank;
      return [x.fan_rank, phrase(x.id), x.greg, x.avg, { v: (mv > 0 ? '+' : '') + mv, cls: mv > 0 ? 'up' : (mv < 0 ? 'down' : '') }, x.pct_higher + '%', x.pct_lower + '%', x.sd];
    }));
  return R;
}

// ---- Biggest Omissions: automatic grouping + your manual review (all in this browser) ----
// REVIEW.map pins an answer key to a group name. REVIEW.excluded hides a group.
// REVIEW.dismissed remembers "these two are different" so the suggestion goes away.
var OM = null, OM_BALLOTS = [], SUGG = [], GREG_KEYS = null;
var REVIEW = { map: {}, excluded: {}, dismissed: {} };
var REVIEW_SAVED_AT = null, REVIEW_DIRTY = false;

// Lowercase, drop accents and apostrophes, punctuation to spaces, stretched letters ("nowwww", "gooooo") to one.
function omNorm(s) {
  return String(s == null ? '' : s).toLowerCase()
    .normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/&/g, ' and ')
    .replace(/['‘’]/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/([a-z])\1{2,}/g, '$1')
    .replace(/\s+/g, ' ').trim();
}
// Grouping key ignores spaces too, so "ThatKindaThing" and "that kinda thing" land together.
function omKey(s) { return omNorm(s).replace(/ /g, ''); }

function lev(a, b) {
  if (a === b) return 0;
  var m = a.length, n = b.length, i, j;
  if (!m) return n;
  if (!n) return m;
  var prev = new Array(n + 1), cur = new Array(n + 1), tmp;
  for (j = 0; j <= n; j++) prev[j] = j;
  for (i = 1; i <= m; i++) {
    cur[0] = i;
    for (j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1));
    }
    tmp = prev; prev = cur; cur = tmp;
  }
  return prev[n];
}

// 0..1. Best of: spelling closeness, shared words, or one answer containing the other.
function omSim(a, b) {
  var ka = a.replace(/ /g, ''), kb = b.replace(/ /g, '');
  if (!ka || !kb) return 0;
  var maxLen = Math.max(ka.length, kb.length), minLen = Math.min(ka.length, kb.length);
  var spell = minLen / maxLen >= 0.6 ? 1 - lev(ka, kb) / maxLen : 0;
  var sa = {}, sb = {}, inter = 0, union = 0;
  a.split(' ').forEach(function (w) { sa[w] = 1; });
  b.split(' ').forEach(function (w) { sb[w] = 1; });
  Object.keys(sa).forEach(function (w) { union++; if (sb[w]) inter++; });
  Object.keys(sb).forEach(function (w) { if (!sa[w]) union++; });
  var words = union ? inter / union : 0;
  var contain = minLen >= 4 && (ka.indexOf(kb) >= 0 || kb.indexOf(ka) >= 0) ? 0.8 : 0;
  return Math.max(spell, words, contain);
}

function topRaw(raws) {
  var best = null, n = -1;
  Object.keys(raws).forEach(function (r) { if (raws[r] > n) { n = raws[r]; best = r; } });
  return best;
}

function omAnalyze(ballots) {
  OM_BALLOTS = ballots;
  var keys = {}, rows = [];
  ballots.forEach(function (p) {
    var seen = {}, list = [];
    p.forEach(function (raw) {
      if (typeof raw !== 'string') return;
      var k = omKey(raw);
      if (!k) return;
      var e = keys[k] || (keys[k] = { key: k, norm: omNorm(raw), raws: {}, voters: 0 });
      e.raws[raw] = (e.raws[raw] || 0) + 1;
      if (!seen[k]) { seen[k] = 1; e.voters++; list.push(k); }
    });
    rows.push(list);
  });
  function labelOf(k) { return REVIEW.map[k] || topRaw(keys[k].raws); }
  var groups = {};
  Object.keys(keys).forEach(function (k) {
    var L = labelOf(k);
    var g = groups[L] || (groups[L] = { label: L, keys: [], voters: 0, isNew: false });
    g.keys.push(k);
    if (!REVIEW.map[k]) g.isNew = true;
  });
  rows.forEach(function (list) {
    var seenL = {};
    list.forEach(function (k) { var L = labelOf(k); if (!seenL[L]) { seenL[L] = 1; groups[L].voters++; } });
  });
  var all = Object.keys(groups).map(function (L) {
    var g = groups[L];
    g.keys.sort(function (a, b) { return keys[b].voters - keys[a].voters; });
    g.norm = omNorm(g.label) || keys[g.keys[0]].norm;
    return g;
  }).sort(function (a, b) { return b.voters - a.voters || (a.label < b.label ? -1 : 1); });
  return {
    voters: ballots.length,
    keys: keys,
    groups: all.filter(function (g) { return !REVIEW.excluded[g.label]; }),
    excluded: all.filter(function (g) { return REVIEW.excluded[g.label]; })
  };
}

function gregMatch(norm) {
  if (!GREG_KEYS || !GREG_KEYS.length) GREG_KEYS = Object.keys(TEXT).map(function (id) { return { id: Number(id), norm: omNorm(TEXT[id]) }; });
  var best = null;
  GREG_KEYS.forEach(function (g) { var s = omSim(norm, g.norm); if (s >= 0.85 && (!best || s > best.s)) best = { id: g.id, s: s }; });
  return best;
}

function pairKey(x, y) { return x < y ? x + '||' + y : y + '||' + x; }

function omSuggestions() {
  var gs = OM.groups.slice(0, 300), out = [];
  for (var i = 0; i < gs.length; i++) {
    for (var j = i + 1; j < gs.length; j++) {
      if (REVIEW.dismissed[pairKey(gs[i].label, gs[j].label)]) continue;
      var s = omSim(gs[i].norm, gs[j].norm);
      if (s >= 0.75) out.push({ a: gs[i], b: gs[j], s: s });
    }
  }
  out.sort(function (x, y) { return y.s - x.s || (y.a.voters + y.b.voters) - (x.a.voters + x.b.voters); });
  return out.slice(0, 50);
}

function omVariants(g, max) {
  var variants = [];
  g.keys.forEach(function (k) { var raws = OM.keys[k].raws; Object.keys(raws).forEach(function (r) { variants.push({ r: r, n: raws[r] }); }); });
  variants.sort(function (a, b) { return b.n - a.n; });
  return variants.slice(0, max).map(function (v) { return esc(v.r) + ' (' + v.n + ')'; }).join(', ') + (variants.length > max ? ', +' + (variants.length - max) + ' more' : '');
}

// Greg's page: the groups as the saved review has them, read only. Excluded groups stay hidden.
function renderOmissionsViewer() {
  var h = '<thead><tr><th class="num"></th><th>Omission</th><th class="num">Voters</th><th class="num">% of omission voters</th><th>How fans typed it</th></tr></thead><tbody>';
  OM.groups.forEach(function (g, i) {
    h += '<tr><td class="num">' + (i + 1) + '</td><td>' + esc(g.label) + '</td><td class="num">' + g.voters + '</td><td class="num">' + pct(g.voters, OM.voters) + '%</td>' +
      '<td class="variants">' + omVariants(g, 8) + '</td></tr>';
  });
  if (!OM.groups.length) h += '<tr><td colspan="5" class="note">No omission answers yet.</td></tr>';
  $('tblOm').innerHTML = h + '</tbody>';
}

function renderOmissions() {
  if (!OM) return;
  if (VIEWER) { renderOmissionsViewer(); return; }
  var h ='<thead><tr><th></th><th>Group name (what the public sees)</th><th class="num">Voters</th><th class="num">% of omission voters</th><th>Answers in this group</th><th></th><th></th></tr></thead><tbody>';
  OM.groups.forEach(function (g, i) {
    var vtxt = omVariants(g, 8);
    var m = gregMatch(g.norm);
    var flags = (m ? '<span class="badge" title="' + esc("Looks like Greg's #" + m.id + ': ' + phrase(m.id)) + '">On Greg\'s list #' + m.id + '</span> ' : '') +
      (g.isNew && REVIEW_SAVED_AT ? '<span class="badge new">New</span>' : '');
    h += '<tr><td><input type="checkbox" class="om-check" data-i="' + i + '" aria-label="Select group"></td>' +
      '<td><input class="om-input" data-i="' + i + '" value="' + esc(g.label) + '" aria-label="Group name"></td>' +
      '<td class="num">' + g.voters + '</td><td class="num">' + pct(g.voters, OM.voters) + '%</td>' +
      '<td class="variants">' + vtxt + '</td><td>' + flags + '</td>' +
      '<td><button class="smallbtn om-ex" data-i="' + i + '">Exclude</button></td></tr>';
  });
  if (!OM.groups.length) h += '<tr><td colspan="7" class="note">No omission answers yet.</td></tr>';
  $('tblOm').innerHTML = h + '</tbody>';
  $('omExcluded').innerHTML = OM.excluded.length
    ? OM.excluded.map(function (g, i) { return '<div class="sugg"><span class="pair">' + esc(g.label) + ' (' + g.voters + ')</span><button class="smallbtn om-restore" data-i="' + i + '">Restore</button></div>'; }).join('')
    : 'Nothing excluded.';
  SUGG = omSuggestions();
  $('suggCount').textContent = SUGG.length ? '(' + SUGG.length + ')' : '';
  $('omSuggest').innerHTML = SUGG.length
    ? SUGG.map(function (s, i) {
        return '<div class="sugg"><span class="pair"><b>' + esc(s.a.label) + '</b> (' + s.a.voters + ') and <b>' + esc(s.b.label) + '</b> (' + s.b.voters + ')</span>' +
          '<span class="score">' + Math.round(s.s * 100) + '% alike</span>' +
          '<button class="smallbtn primary om-same" data-i="' + i + '">Same thing</button><button class="smallbtn om-diff" data-i="' + i + '">Different</button></div>';
      }).join('')
    : '<p class="note">No likely duplicates left to check.</p>';
  paintReviewInfo();
}

function paintReviewInfo() {
  var el = $('reviewInfo');
  if (REVIEW_DIRTY) { el.textContent = 'Unsaved changes. Click Save review.'; el.className = 'saveinfo dirty'; }
  else { el.textContent = REVIEW_SAVED_AT ? 'Saved ' + when(REVIEW_SAVED_AT) : 'Not reviewed yet.'; el.className = 'saveinfo'; }
}

function pinGroup(g, label) { g.keys.forEach(function (k) { REVIEW.map[k] = label; }); }
function mergeInto(target, others) {
  pinGroup(target, target.label);
  others.forEach(function (g) { if (g !== target) pinGroup(g, target.label); });
}
function omChanged() {
  REVIEW_DIRTY = true;
  OM = omAnalyze(OM_BALLOTS);
  renderOmissions();
}

$('tblOm').addEventListener('change', function (e) {
  var t = e.target;
  if (!t.classList.contains('om-input')) return;
  var g = OM.groups[Number(t.dataset.i)];
  var nv = t.value.replace(/\s+/g, ' ').trim();
  if (!g || !nv || nv === g.label) { if (g) t.value = g.label; return; }
  pinGroup(g, nv);
  omChanged();
  say('Renamed. If that name matches another group, they are now one group.');
});
$('tblOm').addEventListener('click', function (e) {
  var b = e.target.closest('.om-ex');
  if (!b) return;
  var g = OM.groups[Number(b.dataset.i)];
  pinGroup(g, g.label);
  REVIEW.excluded[g.label] = true;
  omChanged();
});
$('omExcluded').addEventListener('click', function (e) {
  var b = e.target.closest('.om-restore');
  if (!b) return;
  var g = OM.excluded[Number(b.dataset.i)];
  delete REVIEW.excluded[g.label];
  omChanged();
});
$('omSuggest').addEventListener('click', function (e) {
  var b = e.target.closest('button');
  if (!b) return;
  var s = SUGG[Number(b.dataset.i)];
  if (!s) return;
  if (b.classList.contains('om-same')) {
    var big = s.a.voters >= s.b.voters ? s.a : s.b;
    mergeInto(big, [big === s.a ? s.b : s.a]);
  } else {
    REVIEW.dismissed[pairKey(s.a.label, s.b.label)] = true;
  }
  omChanged();
});
$('btnMerge').onclick = function () {
  var checked = Array.prototype.map.call(document.querySelectorAll('.om-check:checked'), function (c) { return OM.groups[Number(c.dataset.i)]; });
  if (checked.length < 2) { say('Check at least two groups to merge.', true); return; }
  checked.sort(function (a, b) { return b.voters - a.voters; });
  mergeInto(checked[0], checked.slice(1));
  omChanged();
  say('Merged ' + checked.length + ' groups into "' + checked[0].label + '".');
};

async function loadReview() {
  var d = await getJson(BASE + '/api/review');
  var r = d.review || {};
  REVIEW = { map: r.map || {}, excluded: r.excluded || {}, dismissed: r.dismissed || {} };
  REVIEW_SAVED_AT = r.saved_at || null;
  REVIEW_DIRTY = false;
}
// Pins every answer on screen to its current group, so groups stay put as new votes come in.
async function saveReview() {
  if (OM) OM.groups.concat(OM.excluded).forEach(function (g) { pinGroup(g, g.label); });
  var d = await postJson('/admin/api/review', { version: 1, map: REVIEW.map, excluded: REVIEW.excluded, dismissed: REVIEW.dismissed });
  REVIEW_SAVED_AT = d.saved_at;
  REVIEW_DIRTY = false;
  OM = omAnalyze(OM_BALLOTS);
  renderOmissions();
}
$('btnSaveReview').onclick = async function () {
  try { await saveReview(); say('Omissions review saved.'); }
  catch (e) { say('Save failed: ' + e.message, true); }
};

// ---- Map tab: flat world map + US states map, same idea as PFPI. Counts people (first vote's location).
// d3 + topojson load the first time the tab opens, so the Votes tab never pays for them.
var GEO = null, GEO_PEOPLE = 0, GEO_VIEW = 'world', MAP_SEL = null, MAP_SEL_NAME = '';
var D3_URL = 'https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js';
var D3_SRI = 'sha512-vc58qvvBdrDR4etbxMdlTt4GBQk1qjvyORR2nrsPsFPyrs+/u5c3+1Ct6upOgdZoIl7eq6k3a1UPDSNAQi/32A==';
var TOPO_URL = 'https://cdn.jsdelivr.net/npm/topojson-client@3.1.0/dist/topojson-client.min.js';
var TOPO_SRI = 'sha512-F6LRbyw1ZdEE2Lfw8JXPeqsPkl4gl3ZdjxfQ+TA9CwJuZTB+N5DANb0qQtENki+X3IMAVJnRsc3NTgBH3zcorA==';
var WORLD_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json';
var US_URL = 'https://cdn.jsdelivr.net/npm/us-atlas@3.0.1/states-10m.json';
var mapLibs = null, mapData = {};
// ISO alpha-2 -> world-atlas numeric id (copied from PFPI). A country missing here just shows as no data.
var A2N = {
  AF:"004",AX:"248",AL:"008",DZ:"012",AS:"016",AD:"020",AO:"024",AI:"660",AQ:"010",AG:"028",
  AR:"032",AM:"051",AW:"533",AU:"036",AT:"040",AZ:"031",BS:"044",BH:"048",BD:"050",BB:"052",
  BY:"112",BE:"056",BZ:"084",BJ:"204",BM:"060",BT:"064",BO:"068",BA:"070",BW:"072",BR:"076",
  IO:"086",BN:"096",BG:"100",BF:"854",BI:"108",CV:"132",KH:"116",CM:"120",CA:"124",KY:"136",
  CF:"140",TD:"148",CL:"152",CN:"156",CX:"162",CC:"166",CO:"170",KM:"174",CG:"178",CD:"180",
  CK:"184",CR:"188",CI:"384",HR:"191",CU:"192",CW:"531",CY:"196",CZ:"203",DK:"208",DJ:"262",
  DM:"212",DO:"214",EC:"218",EG:"818",SV:"222",GQ:"226",ER:"232",EE:"233",SZ:"748",ET:"231",
  FK:"238",FO:"234",FJ:"242",FI:"246",FR:"250",GF:"254",PF:"258",GA:"266",GM:"270",GE:"268",
  DE:"276",GH:"288",GI:"292",GR:"300",GL:"304",GD:"308",GP:"312",GU:"316",GT:"320",GG:"831",
  GN:"324",GW:"624",GY:"328",HT:"332",HN:"340",HK:"344",HU:"348",IS:"352",IN:"356",ID:"360",
  IR:"364",IQ:"368",IE:"372",IM:"833",IL:"376",IT:"380",JM:"388",JP:"392",JE:"832",JO:"400",
  KZ:"398",KE:"404",KI:"296",KW:"414",KG:"417",LA:"418",LV:"428",LB:"422",LS:"426",LR:"430",
  LY:"434",LI:"438",LT:"440",LU:"442",MO:"446",MG:"450",MW:"454",MY:"458",MV:"462",ML:"466",
  MT:"470",MH:"584",MQ:"474",MR:"478",MU:"480",YT:"175",MX:"484",FM:"583",MD:"498",MC:"492",
  MN:"496",ME:"499",MS:"500",MA:"504",MZ:"508",MM:"104",NA:"516",NR:"520",NP:"524",NL:"528",
  NC:"540",NZ:"554",NI:"558",NE:"562",NG:"566",NU:"570",NF:"574",KP:"408",MK:"807",MP:"580",
  NO:"578",OM:"512",PK:"586",PW:"585",PS:"275",PA:"591",PG:"598",PY:"600",PE:"604",PH:"608",
  PN:"612",PL:"616",PT:"620",PR:"630",QA:"634",RE:"638",RO:"642",RU:"643",RW:"646",BL:"652",
  SH:"654",KN:"659",LC:"662",MF:"663",PM:"666",VC:"670",WS:"882",SM:"674",ST:"678",SA:"682",
  SN:"686",RS:"688",SC:"690",SL:"694",SG:"702",SX:"534",SK:"703",SI:"705",SB:"090",SO:"706",
  ZA:"710",KR:"410",SS:"728",ES:"724",LK:"144",SD:"729",SR:"740",SJ:"744",SE:"752",CH:"756",
  SY:"760",TW:"158",TJ:"762",TZ:"834",TH:"764",TL:"626",TG:"768",TK:"772",TO:"776",TT:"780",
  TN:"788",TR:"792",TM:"795",TC:"796",TV:"798",UG:"800",UA:"804",AE:"784",GB:"826",US:"840",
  UY:"858",UZ:"860",VU:"548",VA:"336",VE:"862",VN:"704",VG:"092",VI:"850",WF:"876",EH:"732",
  YE:"887",ZM:"894",ZW:"716"
};
var N2A = {};
Object.keys(A2N).forEach(function (a) { N2A[A2N[a]] = a; });

function loadScript(src, sri) {
  return new Promise(function (ok, bad) {
    var s = document.createElement('script');
    s.src = src;
    s.integrity = sri;
    s.crossOrigin = 'anonymous';
    s.referrerPolicy = 'no-referrer';
    s.onload = function () { ok(); };
    s.onerror = function () { bad(new Error('could not load ' + src)); };
    document.head.appendChild(s);
  });
}
function ensureMap(which) {
  if (!mapLibs) mapLibs = loadScript(D3_URL, D3_SRI).then(function () { return loadScript(TOPO_URL, TOPO_SRI); });
  if (!mapData[which]) {
    mapData[which] = mapLibs.then(function () {
      return fetch(which === 'us' ? US_URL : WORLD_URL, { referrerPolicy: 'no-referrer' }).then(function (r) {
        if (!r.ok) throw new Error('map data HTTP ' + r.status);
        return r.json();
      });
    });
  }
  return mapData[which];
}

function sortedEntries(obj) {
  return Object.keys(obj).map(function (k) { return [k, obj[k]]; })
    .sort(function (a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); });
}
function bars(entries) {
  if (!entries.length) return '';
  var max = entries[0][1] || 1;
  return entries.map(function (e) {
    return '<div class="bar-row"><span class="nm" title="' + esc(e[0]) + '">' + esc(e[0]) + '</span>' +
      '<span class="bar-wrap"><span class="bar-fill" style="display:block;width:' + Math.max(2, Math.round(e[1] / max * 100)) + '%"></span></span>' +
      '<span class="ct">' + e[1] + '</span></div>';
  }).join('');
}
// The side panel before anything is clicked: the top countries (World) or states (US).
function resetDrill() {
  var us = GEO_VIEW === 'us', list = {};
  $('drillHdr').textContent = us ? 'Top states' : 'Top countries';
  $('drillHint').textContent = 'Brighter = more people. Click a shaded ' + (us ? 'state for its cities.' : 'country for its states / regions.');
  if (us) Object.keys(GEO.byRegion).forEach(function (k) { var p = k.split('|'); if (p[0] === 'US') list[p[1]] = GEO.byRegion[k]; });
  else Object.keys(GEO.byCountry).forEach(function (c) { list[countryName(c)] = GEO.byCountry[c]; });
  $('drillList').innerHTML = bars(sortedEntries(list)) || '<p class="note">No location data yet.</p>';
}
function showDrill(key, name) {
  var us = GEO_VIEW === 'us', list = {}, total = 0;
  if (us) {
    Object.keys(GEO.byCity).forEach(function (k) { var p = k.split('|'); if (p[0] === 'US' && p[1] === key) list[p[2]] = GEO.byCity[k]; });
    Object.keys(GEO.byRegion).forEach(function (k) { if (k === 'US|' + key) total = GEO.byRegion[k]; });
  } else {
    Object.keys(GEO.byRegion).forEach(function (k) { var p = k.split('|'); if (p[0] === key) list[p[1]] = GEO.byRegion[k]; });
    total = GEO.byCountry[key] || 0;
  }
  $('drillHdr').textContent = name + ': ' + total + (total === 1 ? ' person' : ' people');
  $('drillHint').textContent = us ? 'By city.' : 'By state / region.';
  $('drillList').innerHTML = bars(sortedEntries(list)) ||
    '<p class="note">No ' + (us ? 'city' : 'state or city') + ' data for ' + esc(name) + ' yet.</p>';
}

async function drawMap() {
  if (!GEO) return;
  var view = GEO_VIEW, wrap = $('mapWrap'), topo;
  try { topo = await ensureMap(view); }
  catch (e) {
    mapLibs = null; mapData = {};
    wrap.innerHTML = '<p class="note">Could not load the map (' + esc(e.message) + '). The tables below still work.</p>';
    return;
  }
  if (view !== GEO_VIEW) return; // switched views while it loaded
  var W = 900, H, feats, proj, counts = {}, keyOf, nameOf;
  if (view === 'us') {
    feats = topojson.feature(topo, topo.objects.states).features;
    keyOf = function (f) { return (f.properties && f.properties.name) || ''; };
    nameOf = keyOf;
    Object.keys(GEO.byRegion).forEach(function (k) { var p = k.split('|'); if (p[0] === 'US') counts[p[1]] = GEO.byRegion[k]; });
    H = 560;
    proj = d3.geoAlbersUsa().fitSize([W - 10, H - 10], { type: 'FeatureCollection', features: feats });
  } else {
    feats = topojson.feature(topo, topo.objects.countries).features;
    keyOf = function (f) { return N2A[String(f.id).padStart(3, '0')] || ''; };
    nameOf = function (f) { return (f.properties && f.properties.name) || keyOf(f) || 'Unknown'; };
    counts = GEO.byCountry;
    H = 470;
    proj = d3.geoNaturalEarth1().fitSize([W - 10, H - 10], { type: 'Sphere' });
  }
  var max = 1;
  Object.keys(counts).forEach(function (k) { if (counts[k] > max) max = counts[k]; });
  var color = d3.scaleSequential(d3.interpolateRgb('#0f5f69', '#9ff8fc')).domain([0, Math.sqrt(max)]);
  var path = d3.geoPath(proj), tip = $('mapTip');
  wrap.innerHTML = '';
  var svg = d3.select(wrap).append('svg').attr('viewBox', '0 0 ' + W + ' ' + H)
    .attr('role', 'img').attr('aria-label', view === 'us' ? 'Map of the United States' : 'World map');
  if (view === 'world') svg.append('path').attr('d', path({ type: 'Sphere' })).attr('fill', 'rgba(255,255,255,0.03)');
  svg.selectAll('path.map-area').data(feats).join('path')
    .attr('class', function (f) { return 'map-area' + (MAP_SEL && keyOf(f) === MAP_SEL ? ' sel' : ''); })
    .attr('d', path)
    .attr('data-key', function (f) { return keyOf(f); })
    .attr('fill', function (f) { var n = counts[keyOf(f)] || 0; return n ? color(Math.sqrt(n)) : 'rgba(255,255,255,0.08)'; })
    .on('mousemove', function (ev, f) {
      var n = counts[keyOf(f)] || 0;
      tip.hidden = false;
      tip.style.left = (ev.clientX + 14) + 'px';
      tip.style.top = (ev.clientY + 10) + 'px';
      tip.textContent = nameOf(f) + ': ' + n + (n === 1 ? ' person' : ' people');
    })
    .on('mouseleave', function () { tip.hidden = true; })
    .on('click', function (ev, f) {
      var k = keyOf(f);
      if (!k) return;
      MAP_SEL = k;
      MAP_SEL_NAME = nameOf(f);
      svg.selectAll('path.map-area').classed('sel', function (g) { return keyOf(g) === k; });
      showDrill(k, MAP_SEL_NAME);
    });
  if (MAP_SEL) showDrill(MAP_SEL, MAP_SEL_NAME); else resetDrill();
}

document.querySelectorAll('.geo-btn').forEach(function (b) {
  b.onclick = function () {
    GEO_VIEW = b.dataset.geo;
    MAP_SEL = null;
    document.querySelectorAll('.geo-btn').forEach(function (x) { x.classList.toggle('active', x === b); });
    $('mapWrap').innerHTML = '<p class="note">Loading map...</p>';
    drawMap();
  };
});

// Tabs: #map shows the Map view, anything else the Votes view.
function showTab() {
  var map = location.hash === '#map';
  $('viewVotes').hidden = map;
  $('viewMap').hidden = !map;
  $('tabVotes').classList.toggle('active', !map);
  $('tabMap').classList.toggle('active', map);
  $('mapTip').hidden = true;
  if (map) { drawMap(); return; }
  var target = location.hash.length > 1 && document.getElementById(location.hash.slice(1));
  if (target) target.scrollIntoView();
}
window.addEventListener('hashchange', showTab);
showTab();

async function refresh() {
  try {
    if (!VIEWER) await loadState();
    if (!REVIEW_DIRTY) await loadReview();
    await loadRows();
    render();
    say('Loaded ' + ROWS.length + ' submissions at ' + new Date().toLocaleTimeString() + '.');
  } catch (e) { say('Load failed: ' + e.message, true); }
}

async function setFlag(body, okMsg) {
  try { STATE = await postJson('/admin/api/settings', body); renderFlags(); say(okMsg); }
  catch (e) { say('Failed: ' + e.message, true); }
}

$('btnVoting').onclick = function () {
  var open = !STATE.voting_open;
  if (!confirm(open ? 'Open voting? Fans will be able to submit.' : 'Close voting? Fans will not be able to submit.')) return;
  setFlag({ voting_open: open }, open ? 'Voting is OPEN.' : 'Voting is CLOSED.');
};
$('btnSnapshot').onclick = async function () {
  try {
    await loadRows();
    render();
    await saveReview(); // the snapshot always uses a saved omissions review
    var R = render();
    STATE = await postJson('/admin/api/snapshot', R.snapshot);
    renderFlags();
    say('Snapshot saved from ' + R.total + ' submissions. Use Preview to check it.');
  } catch (e) { say('Snapshot failed: ' + e.message, true); }
};
$('btnLive').onclick = function () {
  if (!STATE.snapshot) { say('Save a snapshot first.', true); return; }
  if (!confirm('GO LIVE? Anyone will be able to see the results from the snapshot saved ' + when(STATE.snapshot.created_at) + '.')) return;
  setFlag({ results_public: true }, 'Results are PUBLIC.');
};
$('btnOffline').onclick = function () {
  if (!confirm('Take results offline? The public page goes back to "coming soon".')) return;
  setFlag({ results_public: false }, 'Results are PRIVATE.');
};
$('btnReload').onclick = refresh;
$('btnClear').onclick = async function () {
  var typed = prompt('This deletes EVERY vote, every saved snapshot and the omissions review, and sets results back to private. Everyone (you included) can vote again. It cannot be undone from here.\n\nTip: click Download CSV first if you want a copy.\n\nType CLEAR to delete all votes.');
  if (typed === null) return;
  if (typed.trim() !== 'CLEAR') { say('Nothing deleted. You have to type CLEAR exactly.', true); return; }
  try {
    var d = await postJson('/admin/api/clear', { confirm: 'CLEAR' });
    STATE = d;
    REVIEW = { map: {}, excluded: {}, dismissed: {} };
    REVIEW_SAVED_AT = null;
    REVIEW_DIRTY = false;
    renderFlags();
    await loadRows();
    render();
    say('Deleted ' + d.cleared + ' votes. Everyone can vote again. Snapshots and the omissions review were cleared, results are private.');
  } catch (e) { say('Clear failed: ' + e.message, true); }
};
$('btnCsv').onclick = async function () {
  try {
    var parts = [], after = 0;
    for (;;) {
      var r = await fetch(api('/admin/export.csv?after=' + after), { cache: 'no-store' });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      parts.push(await r.text());
      var next = r.headers.get('X-Next-After');
      if (!next) break;
      after = next;
    }
    var blob = new Blob(parts, { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'catchphrase-submissions-' + new Date().toISOString().slice(0, 10) + '.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    say('CSV downloaded.');
  } catch (e) { say('CSV failed: ' + e.message, true); }
};
$('lnkPreview').href = api('/admin/preview');

loadText().then(refresh);
</script>
</body>
</html>`;
