// Greg Cote's Top 75 Catchphrase Countdown: Worker
// Thin "Bird Feeder" API: validate, hash the IP, verify Turnstile, store one row.
// All analysis happens in the admin dashboard's browser, never here.
// Secrets (Cloudflare secrets only): ADMIN_KEY, IP_SALT, TURNSTILE_SECRET
// Vars (wrangler.toml): ALLOWED_ORIGINS, SITE_URL

const EXERCISES = ['top10', 'number1', 'rearrange'];
const NEEDED = { top10: 10, number1: 1, rearrange: 75 };
const TOTAL = 75;
const MAX_VOTE_BODY = 8 * 1024;
const MAX_ADMIN_BODY = 256 * 1024;

const MSG = {
  duplicate: 'Looks like a vote from this connection is already in for this one.',
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
  if (path.startsWith('/api/')) return publicApi(request, env, path);
  if (path === '/admin' || path.startsWith('/admin/')) return adminApi(request, env, url, path);
  return new Response('Not found', { status: 404 });
}

// ---------------------------------------------------------------- public API

async function publicApi(request, env, path) {
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
  if (path === '/api/status' && request.method === 'GET') return handleStatus(request, env, cors);
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

async function handleStatus(request, env, cors) {
  const done = { top10: false, number1: false, rearrange: false };
  let flags;
  try {
    const ipHash = await hashIp(request, env);
    const stmts = [flagsStmt(env)];
    if (ipHash) stmts.push(env.DB.prepare('SELECT exercise FROM submissions WHERE ip_hash = ?').bind(ipHash));
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

  const { exercise, ids, token } = data;
  const problem = validateVote(exercise, ids);
  if (problem) return json({ ok: false, error: MSG.bad, detail: problem }, 400, cors);
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
  const country = request.cf && request.cf.country ? String(request.cf.country).slice(0, 2) : null;
  try {
    const res = await env.DB.prepare(
      'INSERT INTO submissions (exercise, ip_hash, payload, country) VALUES (?, ?, ?, ?) ' +
        'ON CONFLICT (ip_hash, exercise) DO NOTHING'
    )
      .bind(exercise, ipHash, JSON.stringify(ids), country)
      .run();
    if (!res.meta || !res.meta.changes) {
      return json({ ok: false, duplicate: true, error: MSG.duplicate }, 409, cors);
    }
  } catch (err) {
    console.error('submit db error:', err && err.message);
    return json({ ok: false, error: MSG.busy }, 503, cors);
  }
  return json({ ok: true }, 200, cors);
}

function validateVote(exercise, ids) {
  if (!EXERCISES.includes(exercise)) return 'unknown exercise';
  if (!Array.isArray(ids)) return 'ids must be a list';
  const need = NEEDED[exercise];
  if (ids.length !== need) return 'need exactly ' + need + ' ids';
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
    if (path === '/admin/preview' && get) return adminPreview(env);
  } catch (err) {
    console.error('admin error:', err && err.message);
    return json({ ok: false, error: 'Database error: ' + (err && err.message) }, 503, ADMIN_HEADERS);
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
    'SELECT id, exercise, ip_hash, payload, created_at, country FROM submissions WHERE id > ? ORDER BY id LIMIT ?'
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
  const lines = after === 0 ? ['id,exercise,created_at,country,ip_hash,payload'] : [];
  for (const r of results) {
    lines.push([r.id, r.exercise, r.created_at, r.country || '', r.ip_hash, r.payload].map(csvField).join(','));
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

function adminPage(key, env) {
  const config = safeJson({ key, siteUrl: String(env.SITE_URL || '').replace(/\/+$/, '') });
  return new Response(ADMIN_HTML.replace('__ADMIN_CONFIG__', () => config), {
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
/* ===== STYLE BLOCK (restyle here) ===== */
:root {
  --amber: #EF9F27;
  --coral: #D85A30;
  --bg: #15130f;
  --surface: #211d18;
  --surface-2: #2b261f;
  --line: #3a332a;
  --ink: #f4ede3;
  --ink-2: #c9bfb1;
  --ink-3: #8f8679;
  --good: #6cc68a;
  --font: "Barlow Condensed", "Arial Narrow", "Roboto Condensed", "Helvetica Neue", Arial, sans-serif;
}
/* ===== END STYLE BLOCK ===== */
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font-family: var(--font); font-size: 18px; line-height: 1.35; }
header, main { max-width: 1100px; margin: 0 auto; padding: 16px; }
h1 { font-size: 30px; margin: 4px 0 12px; color: var(--amber); letter-spacing: .5px; }
h2 { font-size: 26px; margin: 28px 0 8px; color: var(--amber); border-bottom: 2px solid var(--line); padding-bottom: 4px; }
h3 { font-size: 20px; margin: 14px 0 6px; color: var(--ink-2); }
.flags { display: flex; gap: 10px; flex-wrap: wrap; }
.flag { padding: 8px 14px; border-radius: 8px; font-weight: 700; font-size: 20px; background: var(--surface-2); border: 2px solid var(--line); }
.flag.on { border-color: var(--good); color: var(--good); }
.flag.off { border-color: var(--coral); color: var(--coral); }
.snapinfo { margin: 10px 0; color: var(--ink-2); }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
button, .btn { font: inherit; font-weight: 600; font-size: 18px; padding: 9px 14px; border-radius: 8px; border: 2px solid var(--line); background: var(--surface-2); color: var(--ink); cursor: pointer; text-decoration: none; display: inline-block; }
button:hover, .btn:hover { border-color: var(--amber); }
button.primary { background: var(--amber); color: #1a1208; border-color: var(--amber); }
button.danger { background: var(--coral); color: #fff; border-color: var(--coral); }
button:disabled { opacity: .4; cursor: not-allowed; }
#msg { min-height: 1.4em; color: var(--ink-2); }
#msg.bad { color: var(--coral); font-weight: 600; }
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
.down { color: var(--coral); }
details summary { cursor: pointer; color: var(--amber); margin: 10px 0; font-weight: 600; }
ol { padding-left: 22px; margin: 4px 0; }
</style>
</head>
<body>
<header>
  <h1>Catchphrase Countdown Admin</h1>
  <div class="flags">
    <div class="flag" id="flagVoting">Voting: ...</div>
    <div class="flag" id="flagResults">Results: ...</div>
  </div>
  <div class="snapinfo" id="snapInfo"></div>
  <div class="actions">
    <button id="btnVoting">Open voting</button>
    <button id="btnSnapshot" class="primary">Save snapshot</button>
    <a id="lnkPreview" class="btn" target="_blank" rel="noreferrer">Preview public page</a>
    <button id="btnLive" class="danger">Go live</button>
    <button id="btnOffline">Take offline</button>
    <button id="btnReload">Reload data</button>
    <button id="btnCsv">Download CSV</button>
  </div>
  <p id="msg" role="status"></p>
</header>
<main>
  <section>
    <h2>Submissions</h2>
    <div class="tiles" id="tiles"></div>
    <div class="grid2">
      <div><h3>Per day (UTC)</h3><div class="chartbox"><canvas id="chDays" aria-label="Submissions per day"></canvas></div></div>
      <div><h3>Top countries</h3><div class="tablewrap"><table id="tblCountries"></table></div></div>
    </div>
  </section>

  <section>
    <h2>Top 10 picks</h2>
    <p class="note">% = share of Top 10 voters who picked it. Chart shows the top 20.</p>
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
</main>

<script>
var CFG = __ADMIN_CONFIG__;
var K = encodeURIComponent(CFG.key);
var TEXT = {};
var STATE = null;
var ROWS = [];
var charts = {};
var AMBER = '#EF9F27', GRID = 'rgba(244,237,227,0.08)', INK2 = '#c9bfb1';
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
    var d = await getJson('/admin/api/rows?limit=2000&after=' + after);
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
  var by = { top10: [], number1: [], rearrange: [] }, days = {}, countries = {};
  ROWS.forEach(function (r) {
    var p;
    try { p = JSON.parse(r.payload); } catch (e) { return; }
    if (!by[r.exercise] || !Array.isArray(p)) return;
    by[r.exercise].push(p);
    var d = String(r.created_at || '').slice(0, 10) || '?';
    days[d] = (days[d] || 0) + 1;
    var c = r.country || '??';
    countries[c] = (countries[c] || 0) + 1;
  });
  var ids = [];
  for (var i = 75; i >= 1; i--) ids.push(i);

  var n10 = by.top10.length, c10 = {};
  by.top10.forEach(function (p) { p.forEach(function (id) { c10[id] = (c10[id] || 0) + 1; }); });
  var top10 = ids.map(function (id) { return { id: id, count: c10[id] || 0, pct: pct(c10[id] || 0, n10) }; })
    .sort(function (a, b) { return b.count - a.count || a.id - b.id; });

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
      version: 1,
      generated_at: new Date().toISOString(),
      totals: { top10: n10, number1: n1, rearrange: nr },
      top10: top10,
      number1: number1,
      rearrange: rearrange
    },
    days: days,
    countries: countries,
    total: ROWS.length
  };
}

function barChart(id, labels, data, horizontal, fmt) {
  if (typeof Chart === 'undefined') return;
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart($(id), {
    type: 'bar',
    data: { labels: labels, datasets: [{ data: data, backgroundColor: AMBER, borderRadius: 4, borderSkipped: 'start', maxBarThickness: 22 }] },
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
  $('tiles').innerHTML = [['Top 10', T.top10], ['Number 1', T.number1], ['Rearrange', T.rearrange], ['All', R.total]]
    .map(function (x) { return '<div class="tile"><div class="n">' + x[1] + '</div><div class="l">' + esc(x[0]) + '</div></div>'; }).join('');

  var dayKeys = Object.keys(R.days).sort();
  barChart('chDays', dayKeys, dayKeys.map(function (d) { return R.days[d]; }), false);
  var cKeys = Object.keys(R.countries).sort(function (a, b) { return R.countries[b] - R.countries[a]; }).slice(0, 15);
  table('tblCountries', [{ t: 'Country' }, { t: 'Submissions', num: 1 }, { t: '% of all', num: 1 }],
    cKeys.map(function (c) { return [c, R.countries[c], pct(R.countries[c], R.total) + '%']; }));

  var t20 = S.top10.slice(0, 20);
  barChart('chTop10', t20.map(function (x) { return short(x.id); }), t20.map(function (x) { return x.pct; }), true,
    function (v, i) { return v + '% of voters (' + t20[i].count + ' picks), Greg #' + t20[i].id; });
  table('tblTop10', [{ t: '' , num: 1 }, { t: 'Catchphrase' }, { t: 'Greg #', num: 1 }, { t: 'Picks', num: 1 }, { t: '% of voters', num: 1 }],
    S.top10.map(function (x, i) { return [i + 1, phrase(x.id), x.id, x.count, x.pct + '%']; }));

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

async function refresh() {
  try {
    await loadState();
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
