import test from 'node:test';
import assert from 'node:assert/strict';
import worker, { seal, unseal } from './worker.mjs';

const env = { SOURCE_REPOSITORY: 'source/app', ANALYSIS_REPOSITORY: 'host/scanners', DASHBOARD_ORIGIN: 'https://owner.github.io', GITHUB_CLIENT_ID: 'app-id', GITHUB_CLIENT_SECRET: 'test-secret', SESSION_KEY: Buffer.alloc(32, 7).toString('base64url') };
const reply = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
async function request(path, body, overrides = {}) {
  const session = await seal({ type: 'session', token: 'github-test-token', exp: Date.now() + 60000 }, env.SESSION_KEY);
  return new Request(`https://launcher.example${path}`, { method: body ? 'POST' : 'GET', headers: { Origin: env.DASHBOARD_ORIGIN, Authorization: `Bearer ${session}`, 'Content-Type': 'application/json', ...overrides }, ...(body ? { body: JSON.stringify(body) } : {}) });
}
test('session confidentiality, integrity, expiry and purpose separation', async () => {
  const token = await seal({ type: 'session', token: 'secret', exp: Date.now() + 60000 }, env.SESSION_KEY);
  assert.ok(!token.includes('secret'));
  assert.equal((await unseal(token, env.SESSION_KEY, 'session')).token, 'secret');
  await assert.rejects(unseal(token + 'x', env.SESSION_KEY, 'session'));
  await assert.rejects(unseal(token, env.SESSION_KEY, 'oauth'));
  await assert.rejects(unseal(await seal({ type: 'session', exp: 1 }, env.SESSION_KEY), env.SESSION_KEY, 'session'));
});
test('unauthenticated and cross-origin launches never reach GitHub', async t => {
  const calls = t.mock.method(globalThis, 'fetch', () => { throw new Error('must not call GitHub'); });
  assert.equal((await worker.fetch(new Request('https://launcher.example/api/launch', { method: 'POST', headers: { Origin: env.DASHBOARD_ORIGIN } }), env)).status, 401);
  const denied = await worker.fetch(await request('/api/launch', { repository: 'source/app', kind: 'branch', ref: 'main' }, { Origin: 'https://attacker.example' }), env);
  assert.equal(denied.status, 403); assert.equal(denied.headers.get('Access-Control-Allow-Origin'), null);
  assert.equal(calls.mock.calls.length, 0);
});
test('read-only users cannot trigger analysis', async t => {
  t.mock.method(globalThis, 'fetch', async () => reply({ permissions: { pull: true, push: false } }));
  assert.equal((await worker.fetch(await request('/api/launch', { repository: 'source/app', kind: 'branch', ref: 'main' }), env)).status, 403);
});
test('dispatch verifies source and forces configured host and actual default branch', async t => {
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    calls.push([url, init]);
    if (url.endsWith('repos/host/scanners')) return reply({ permissions: { push: true }, default_branch: 'trusted' });
    if (url.includes('/branches/')) return reply({ commit: { sha: 'a'.repeat(40) } });
    return reply({ workflow_run_id: 42 });
  });
  const response = await worker.fetch(await request('/api/launch', { repository: 'source/app', kind: 'branch', ref: 'feature/next', host: 'evil/repo', tooling: 'untrusted' }), env);
  assert.equal(response.status, 202);
  assert.equal((await response.json()).url, 'https://github.com/host/scanners/actions/runs/42');
  assert.ok(calls[1][0].endsWith('/branches/feature%2Fnext'));
  assert.ok(calls[2][0].includes('/repos/host/scanners/actions/workflows/10-analysis-discovery.yml/dispatches'));
  const body = JSON.parse(calls[2][1].body);
  assert.equal(body.ref, 'trusted');
  assert.deepEqual(JSON.parse(body.inputs.refresh_target), { repository: 'source/app', kind: 'branch', ref: 'feature/next' });
});
test('wrong repository, malformed commit and missing source cannot dispatch', async t => {
  const calls = t.mock.method(globalThis, 'fetch', async url => url.endsWith('repos/host/scanners') ? reply({ permissions: { push: true } }) : new Response('', { status: 404 }));
  for (const body of [{ repository: 'other/app', kind: 'branch', ref: 'main' }, { repository: 'source/app', kind: 'commit', ref: 'abc' }]) {
    assert.equal((await worker.fetch(await request('/api/launch', body), env)).status, 400);
  }
  assert.equal((await worker.fetch(await request('/api/launch', { repository: 'source/app', kind: 'pr', ref: '12' }), env)).status, 403);
  assert.ok(calls.mock.calls.every(call => !call.arguments[0].includes('dispatches')));
});
test('target discovery paginates and attributes fork PR source and base', async t => {
  t.mock.method(globalThis, 'fetch', async url => {
    if (url.endsWith('repos/host/scanners')) return reply({ permissions: { push: true } });
    if (url.includes('/pulls?')) return reply([{ number: 4, head: { repo: { full_name: 'fork/app' }, ref: 'feature', sha: 'b'.repeat(40) }, base: { ref: 'main' } }]);
    if (url.endsWith('page=1')) return reply(Array.from({ length: 100 }, (_, i) => ({ name: `branch-${i}`, commit: { sha: 'a'.repeat(40) } })));
    return reply([{ name: 'last', commit: { sha: 'c'.repeat(40) } }]);
  });
  const response = await worker.fetch(await request('/api/targets'), env);
  const data = await response.json();
  assert.equal(data.targets.length, 102);
  assert.equal(data.targets.at(-1).source_repository, 'fork/app');
  assert.equal(data.targets.at(-1).base_branch, 'main');
});
test('OAuth binds callback to cookie and nonce, uses PKCE and exposes only encrypted session', async t => {
  const nonce = 'a'.repeat(64);
  const login = await worker.fetch(new Request(`https://launcher.example/auth/login?nonce=${nonce}`), env);
  assert.equal(login.status, 302);
  const location = new URL(login.headers.get('Location'));
  assert.equal(location.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(login.headers.get('Set-Cookie').includes('HttpOnly; SameSite=Lax'));
  const cookie = login.headers.get('Set-Cookie').split(';')[0];
  const wrong = await worker.fetch(new Request('https://launcher.example/auth/callback?code=x&state=wrong', { headers: { Cookie: cookie } }), env);
  assert.equal(wrong.status, 401);
  t.mock.method(globalThis, 'fetch', async url => url.includes('access_token') ? reply({ access_token: 'never-show-github-token' }) : url.endsWith('/user') ? reply({ login: 'developer' }) : reply({ permissions: { push: true } }));
  const response = await worker.fetch(new Request(`https://launcher.example/auth/callback?code=x&state=${location.searchParams.get('state')}`, { headers: { Cookie: cookie } }), env);
  const html = await response.text();
  assert.equal(response.status, 200); assert.ok(!html.includes('never-show-github-token'));
  assert.ok(html.includes(nonce)); assert.ok(html.includes('https://owner.github.io'));
  assert.ok(response.headers.get('Content-Security-Policy').includes("default-src 'none'"));
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
});
test('GitHub dispatch errors are failures, never successful scan confirmations', async t => {
  t.mock.method(globalThis, 'fetch', async url => url.includes('dispatches') ? new Response('vendor-secret-error', { status: 500 }) : reply({ permissions: { push: true }, default_branch: 'main' }));
  const response = await worker.fetch(await request('/api/launch', { repository: 'source/app', kind: 'commit', ref: 'a'.repeat(40) }), env);
  assert.equal(response.status, 502); assert.ok(!(await response.text()).includes('vendor-secret-error'));
});
