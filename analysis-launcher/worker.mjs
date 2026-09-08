// Credential boundary: this Worker calls GitHub APIs only; it never runs source code.
const encoder = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const bytes = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const random = () => b64(crypto.getRandomValues(new Uint8Array(32)));
export async function seal(value, secret) {
  const key = await crypto.subtle.importKey('raw', bytes(secret), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return `${b64(iv)}.${b64(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(value)))))}`;
}
export async function unseal(value, secret, type) {
  try {
    const [iv, data] = value.split('.');
    const key = await crypto.subtle.importKey('raw', bytes(secret), 'AES-GCM', false, ['decrypt']);
    const decoded = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(iv) }, key, bytes(data))));
    if (decoded.type !== type || decoded.exp <= Date.now()) throw new Error();
    return decoded;
  } catch { throw new Failure(401, 'Sign in again; the session is invalid or expired.'); }
}
class Failure extends Error { constructor(status, message) { super(message); this.status = status; } }
const cookie = (value, age) => `__Host-analysis-oauth=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${age}`;
function settings(env) {
  for (const key of ['SOURCE_REPOSITORY', 'ANALYSIS_REPOSITORY']) {
    if (!/^[\w.-]+\/[\w.-]+$/.test(env[key] || '')) throw new Failure(503, 'Launcher repository configuration is unavailable.');
  }
  if (env.SOURCE_REPOSITORY.toLowerCase() === env.ANALYSIS_REPOSITORY.toLowerCase()) throw new Failure(503, 'Source and analysis repositories must be separate.');
  if (new URL(env.DASHBOARD_ORIGIN).origin !== env.DASHBOARD_ORIGIN || !env.DASHBOARD_ORIGIN.startsWith('https://') || !env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET || !env.SESSION_KEY) throw new Failure(503, 'Launcher authentication is not configured.');
}
async function github(path, token, init = {}) {
  const response = await fetch(`https://api.github.com/${path}`, { ...init, headers: {
    Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'code-analysis-launcher', Authorization: `Bearer ${token}`, ...init.headers,
  } });
  if (!response.ok) throw new Failure(response.status === 401 ? 401 : response.status === 403 || response.status === 404 ? 403 : 502,
    'GitHub could not authorize or complete this request. Check App installation, repository access, and API limits.');
  return response.status === 204 ? null : response.json();
}
async function access(env, token) {
  const repo = await github(`repos/${env.ANALYSIS_REPOSITORY}`, token);
  if (!repo.permissions?.push) throw new Failure(403, 'Write access to the configured analysis repository is required.');
  return repo;
}
async function pages(path, token) {
  const all = [];
  for (let page = 1; page <= 20; page++) {
    const rows = await github(`${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`, token);
    if (!Array.isArray(rows)) throw new Failure(502, 'GitHub returned an incomplete target inventory.');
    all.push(...rows);
    if (rows.length < 100) return all;
  }
  throw new Failure(422, 'Target inventory exceeds the launcher pagination limit. Use GitHub Actions to launch this repository.');
}
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
async function route(request, env) {
  settings(env);
  const url = new URL(request.url);
  if (request.method === 'GET' && url.pathname === '/auth/login') {
    const nonce = url.searchParams.get('nonce');
    if (!/^[a-f0-9]{64}$/.test(nonce || '')) throw new Failure(400, 'Invalid login request.');
    const state = random();
    const verifier = random();
    const challenge = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(verifier))));
    const pending = await seal({ type: 'oauth', state, nonce, verifier, exp: Date.now() + 600000 }, env.SESSION_KEY);
    const authorize = new URL('https://github.com/login/oauth/authorize');
    authorize.search = new URLSearchParams({ client_id: env.GITHUB_CLIENT_ID, state, redirect_uri: `${url.origin}/auth/callback`, code_challenge: challenge, code_challenge_method: 'S256' }).toString();
    return new Response(null, { status: 302, headers: { Location: authorize.toString(), 'Set-Cookie': cookie(pending, 600) } });
  }
  if (request.method === 'GET' && url.pathname === '/auth/callback') {
    const stored = (request.headers.get('Cookie') || '').split(';').map(s => s.trim()).find(s => s.startsWith('__Host-analysis-oauth='))?.split('=')[1];
    const pending = await unseal(stored || '', env.SESSION_KEY, 'oauth');
    if (!url.searchParams.get('code') || pending.state !== url.searchParams.get('state')) throw new Failure(401, 'GitHub sign-in state did not match. Start sign-in again.');
    const exchange = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code: url.searchParams.get('code'), redirect_uri: `${url.origin}/auth/callback`, code_verifier: pending.verifier }) });
    const grant = await exchange.json();
    if (!exchange.ok || !grant.access_token) throw new Failure(401, 'GitHub sign-in failed. Start sign-in again.');
    await access(env, grant.access_token);
    const user = await github('user', grant.access_token);
    const token = await seal({ type: 'session', token: grant.access_token, exp: Date.now() + Math.min(3600, grant.expires_in || 3600) * 1000 }, env.SESSION_KEY);
    const scriptNonce = random();
    const message = JSON.stringify({ type: 'analysis-auth', nonce: pending.nonce, token, login: user.login }).replaceAll('<', '\\u003c');
    return new Response(`<!doctype html><meta charset="utf-8"><title>Analysis sign-in</title><p>Signed in. Return to the dashboard to start your analysis.</p><script nonce="${scriptNonce}">if(window.opener){window.opener.postMessage(${message},${JSON.stringify(env.DASHBOARD_ORIGIN)});window.close();}</script>`, { headers: {
      'Content-Type': 'text/html; charset=utf-8', 'Set-Cookie': cookie('', 0),
      'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${scriptNonce}'; base-uri 'none'; frame-ancestors 'none'`,
    } });
  }
  if (!url.pathname.startsWith('/api/')) throw new Failure(404, 'Not found.');
  if (request.headers.get('Origin') !== env.DASHBOARD_ORIGIN) throw new Failure(403, 'Dashboard origin required.');
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });
  const session = await unseal((request.headers.get('Authorization') || '').replace(/^Bearer /, ''), env.SESSION_KEY, 'session');
  const repo = await access(env, session.token); // Recheck current permissions for every API call.
  if (request.method === 'GET' && url.pathname === '/api/targets') {
    const [branches, prs] = await Promise.all([pages(`repos/${env.SOURCE_REPOSITORY}/branches`, session.token), pages(`repos/${env.SOURCE_REPOSITORY}/pulls?state=open`, session.token)]);
    const checked_at = new Date().toISOString();
    if (prs.some(p => !p.head.repo)) throw new Failure(502, 'A PR source is unavailable; target discovery is incomplete.');
    return json({ repository: env.SOURCE_REPOSITORY, analysis_repository: env.ANALYSIS_REPOSITORY, targets: [
      ...branches.map(b => ({ id: `branch:${b.name}`, repository: env.SOURCE_REPOSITORY, source_repository: env.SOURCE_REPOSITORY, kind: 'branch', branch: b.name, label: b.name, head_sha: b.commit.sha, checked_at })),
      ...prs.map(p => ({ id: `pr:${p.number}`, repository: env.SOURCE_REPOSITORY, source_repository: p.head.repo.full_name, kind: 'pr', branch: p.head.ref, pr: p.number, label: `PR #${p.number}: ${p.head.ref}`, head_sha: p.head.sha, base_branch: p.base.ref, checked_at })),
    ] });
  }
  if (request.method === 'POST' && url.pathname === '/api/launch') {
    if (!(request.headers.get('Content-Type') || '').startsWith('application/json')) throw new Failure(415, 'JSON required.');
    const reader = request.body?.getReader();
    let raw = '', length = 0;
    const decoder = new TextDecoder();
    if (reader) while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 2048) { await reader.cancel(); throw new Failure(413, 'Request too large.'); }
      raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();
    let body;
    try { body = JSON.parse(raw); } catch { throw new Failure(400, 'Invalid JSON.'); }
    if (!body || body.repository !== env.SOURCE_REPOSITORY || !['branch', 'pr', 'commit'].includes(body.kind) || typeof body.ref !== 'string' || !body.ref || body.ref.length > 255) throw new Failure(400, 'Choose a configured codebase and revision.');
    let path;
    if (body.kind === 'pr') {
      if (!/^[1-9][0-9]*$/.test(body.ref)) throw new Failure(400, 'Invalid PR number.');
      path = `pulls/${body.ref}`;
    } else if (body.kind === 'commit') {
      if (!/^[a-fA-F0-9]{40}$/.test(body.ref)) throw new Failure(400, 'Full commit SHA required.');
      path = `commits/${body.ref}`;
    } else path = `branches/${encodeURIComponent(body.ref)}`;
    await github(`repos/${env.SOURCE_REPOSITORY}/${path}`, session.token);
    const dispatched = await github(`repos/${env.ANALYSIS_REPOSITORY}/actions/workflows/10-analysis-discovery.yml/dispatches`, session.token, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ref: repo.default_branch, return_run_details: true,
        inputs: { refresh_target: JSON.stringify({ repository: env.SOURCE_REPOSITORY, kind: body.kind, ref: body.ref }) } }),
    });
    const id = dispatched?.workflow_run_id;
    return json({ status: 'submitted', run_id: id || null, url: `https://github.com/${env.ANALYSIS_REPOSITORY}/actions/${id ? `runs/${id}` : 'workflows/10-analysis-discovery.yml'}` }, 202);
  }
  throw new Failure(404, 'Not found.');
}
export default { async fetch(request, env) {
  let response;
  try { response = await route(request, env); } catch (e) { response = json({ error: e instanceof Failure ? e.message : 'Launcher unavailable. No successful launch has been confirmed; check GitHub Actions before retrying.' }, e instanceof Failure ? e.status : 503); }
  const headers = new Headers(response.headers);
  headers.set('Cache-Control', 'no-store'); headers.set('Referrer-Policy', 'no-referrer'); headers.set('X-Content-Type-Options', 'nosniff');
  if (request.headers.get('Origin') === env.DASHBOARD_ORIGIN) {
    headers.set('Access-Control-Allow-Origin', env.DASHBOARD_ORIGIN); headers.set('Vary', 'Origin');
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'); headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  }
  return new Response(response.body, { status: response.status, headers });
} };
