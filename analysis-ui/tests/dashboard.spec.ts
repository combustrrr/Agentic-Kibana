import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

test('retained dataset preserves source identity, filters and issue provenance', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Agentic-Kibana');
  await expect(page.getByText('ANALYZED COMMIT')).toBeVisible();
  await page.getByRole('tab', { name: /^Issues/ }).click();
  await expect(page.getByLabel('Search issues')).toBeVisible();
  await page.getByLabel('Search issues').fill('assert');
  await expect(page.locator('.ant-table-tbody > tr.ant-table-row').first()).toBeVisible();
  await page.locator('.issue-link').first().click();
  await expect(page.getByRole('region', { name: 'Issue detail' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Why this was reported' })).toBeVisible();
  await expect(page.getByText('Detected condition, not a proven root cause')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Supporting observations' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Related findings' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open exact source revision' })).toHaveAttribute('href', /\/blob\/[a-f0-9]{40}\//);
  const url = page.url(); await page.reload();
  await expect(page.getByRole('heading', { name: 'Supporting observations' })).toBeVisible();
  expect(page.url()).toEqual(url);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('region', { name: 'Issue detail' })).not.toBeVisible();
  expect(new URL(page.url()).hash).not.toContain('issue=');
  expect(errors).toEqual([]);
});

test('developers can group findings by rule and inspect a relationship', async ({page}) => {
  await page.goto('/');
  await page.getByRole('tab', {name:/^Issues/}).click();
  await page.getByLabel('Group issues').click();
  await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:'Group by rule'}).click();
  const group = page.locator('.issue-groups .ant-collapse-item').first();
  await expect(group).toBeVisible();
  await group.locator('.ant-collapse-header').click();
  await expect(group.locator('.related-finding').first()).toBeVisible();
});

test('overview visualizes issue composition and offers cautious investigation priorities', async ({page}) => {
  await page.goto('/');
  await expect(page.getByRole('img', {name:'Finding distribution by severity'})).toBeVisible();
  await expect(page.getByRole('img', {name:'Finding distribution by scanner overlap'})).toBeVisible();
  await expect(page.getByRole('heading', {name:'Investigation priorities'})).toBeVisible();
  await expect(page.getByText('Heuristic guidance')).toBeVisible();
  const action = page.getByRole('button', {name:'Investigate cluster'}).first();
  await expect(action).toBeVisible();
  await action.click();
  await expect(page.getByText('Group by rule', {exact:true})).toBeVisible();
  await expect(page.getByText(/^Directory:/)).toBeVisible();
});

test('scanner failures remain separate from findings and navigation works on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/'); await page.getByRole('tab', { name: 'Scanners', exact: true }).click();
  await expect(page.getByText('Unavailable', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Atheris', { exact: true })).toBeVisible();
  await expect(page.getByText('Schemathesis', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Branch or pull request')).toBeVisible();
});

test('untrusted messages render as text', async ({ page }) => {
  await page.route('**/findings.json', async route => {
    const response = await route.fetch(); const rows = await response.json();
    rows[0].message = '<img src=x onerror="window.injected=true">';
    await route.fulfill({ response, json: rows });
  });
  await page.goto('/'); await page.getByRole('tab', { name: /^Issues/ }).click();
  await page.getByLabel('Search issues').fill('window.injected');
  await expect(page.locator('.issue-link').first()).toContainText('<img');
  expect(await page.evaluate(() => (window as any).injected)).toBeUndefined();
});

test('Ant Design filters, pagination and responsive layout remain usable', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Browse issues', exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('overview.png'), fullPage: true });
  await page.getByRole('tab', { name: /^Issues/ }).click();
  const first = await page.locator('.issue-link').first().textContent();
  await page.getByTitle('Next Page').click();
  await expect(page.locator('.issue-link').first()).not.toHaveText(first!);
  await page.getByLabel('Severity', { exact: true }).click();
  await page.getByTitle('HIGH', { exact: true }).click();
  await expect(page.locator('.ant-table-tbody > tr.ant-table-row').first()).toContainText('HIGH');
  await page.screenshot({ path: testInfo.outputPath('issues.png'), fullPage: true });
  await page.locator('.issue-link').first().click();
  await expect(page.getByRole('heading', { name: 'Supporting observations' })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('detail.png') });
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('tab', { name: 'Overview', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Browse issues', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('mobile.png'), fullPage: true });
  await page.getByLabel('Branch or pull request').click();
  await expect(page.getByRole('listbox')).toBeAttached();
  await page.keyboard.press('Escape');
});


test('overview drilldown, scanner filters and provenance use retained evidence', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Directories with most findings' })).toBeVisible();
  const directory = page.locator('.directory-row .ant-btn').first();
  const path = await directory.innerText();
  await directory.click();
  await expect(page.getByText(`Directory: ${path}`, {exact:true})).toBeVisible();
  await expect(page.locator('.ant-table-tbody > tr.ant-table-row').first()).toContainText(path);
  await page.getByRole('tab', {name:'Scanners',exact:true}).click();
  await page.getByLabel('Execution status').click();
  await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({hasText:'NOT AVAILABLE'}).click();
  const rows=page.locator('.ant-table-tbody > tr.ant-table-row');
  await expect(rows.first()).toContainText('NOT AVAILABLE');
  for (const row of await rows.all()) await expect(row).toContainText('NOT AVAILABLE');
  await page.getByRole('tab', {name:'Provenance',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Analysis identity'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Producing workflows'})).toBeVisible();
  await expect(page.locator('.panel').filter({hasText:'Producing workflows'}).getByRole('link').first()).toHaveAttribute('href', /github.com.*actions\/runs\/\d+/);
});

test('mobile issue evidence opens accessibly and closes with Escape', async ({page}) => {
  await page.setViewportSize({width:390,height:844});
  await page.goto('/');
  await page.getByRole('tab',{name:/^Issues/}).click();
  await page.locator('.issue-link').first().click();
  await expect(page.getByRole('dialog',{name:'Issue detail'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Supporting observations'})).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog',{name:'Issue detail'})).not.toBeVisible();
});


test('theme persists and analysis handoff exposes the trusted workflow', async ({page}) => {
  await page.route('**/index.json', async route => { const data = JSON.parse(readFileSync('public/data/index.json','utf8')); data.analysis_default_branch = 'Testing'; await route.fulfill({json:data}); });
  await page.goto('/');
  await page.getByText('Light', {exact:true}).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme','light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme','light');
  await page.getByRole('button',{name:'Run analysis',exact:true}).click();
  await page.getByRole('button',{name:'Choose revision',exact:true}).click();
  await page.getByText('Commit SHA', {exact:true}).click();
  await page.getByLabel('Analysis target',{exact:true}).fill('a'.repeat(40));
  await page.getByRole('button',{name:'Review analysis',exact:true}).click();
  await page.getByText('Use the GitHub Actions fallback', {exact:true}).click();
  await expect(page.getByRole('link',{name:'Open GitHub Actions'})).toHaveAttribute('href', /actions\/workflows\/10-analysis-discovery.yml$/);
  await expect(page.getByText('refresh_target',{exact:true})).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button',{name:'Refresh results',exact:true}).click();
  await expect(page.getByText(/Reports checked:/)).toBeVisible();
});


test('authenticated developer selects live source and directly starts analysis', async ({page, context}) => {
  const source = 'combustrrr/Agentic-Kibana';
  let submitted: any;
  await page.route('**/index.json', async route => {
    const data = JSON.parse(readFileSync('public/data/index.json','utf8'));
    Object.assign(data, {launch_endpoint:'https://launcher.example', source_repository:source, analysis_default_branch:'Testing'});
    await route.fulfill({json:data});
  });
  await context.route('https://launcher.example/**', async route => {
    const url = new URL(route.request().url());
    const headers = {'Access-Control-Allow-Origin':'http://127.0.0.1:4178', 'Access-Control-Allow-Headers':'Authorization, Content-Type', 'Access-Control-Allow-Methods':'GET, POST, OPTIONS'};
    if (route.request().method() === 'OPTIONS') return route.fulfill({status:204, headers});
    if (url.pathname === '/auth/login') return route.fulfill({contentType:'text/html', body:`<script>window.opener.postMessage({type:'analysis-auth',nonce:'${url.searchParams.get('nonce')}',token:'opaque-session',login:'developer'},'http://127.0.0.1:4178');window.close();</script>`});
    if (url.pathname === '/api/targets') return route.fulfill({headers, json:{repository:source, analysis_repository:source, targets:[{id:'branch:latest',kind:'branch',branch:'latest',label:'latest',repository:source,source_repository:source,head_sha:'b'.repeat(40),checked_at:new Date().toISOString()}]}});
    expect(route.request().headers().authorization).toBe('Bearer opaque-session');
    submitted = route.request().postDataJSON();
    return route.fulfill({status:202, headers, json:{status:'submitted',run_id:42,url:`https://github.com/${source}/actions/runs/42`}});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'Run analysis',exact:true}).click();
  await expect(page.getByLabel('Analysis repository')).toBeVisible();
  await expect(page.getByRole('heading',{name:'Choose your project'})).toBeVisible();
  await page.getByRole('button',{name:'Sign in with GitHub'}).click();
  await expect(page.getByText('Signed in as developer')).toBeVisible();
  await page.getByRole('button',{name:'Choose revision',exact:true}).click();
  await page.getByLabel('Available analysis targets').click();
  await expect(page.getByRole('option',{name:'latest',exact:true})).toBeAttached();
  await page.getByLabel('Available analysis targets').press('ArrowDown');
  await page.getByLabel('Available analysis targets').press('Enter');
  await expect(page.getByRole('dialog').getByTitle('latest')).toBeVisible();
  await expect(page.getByText('b'.repeat(40),{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Review analysis',exact:true}).click();
  await expect(page.getByText('Awaiting confirmation on GitHub')).not.toBeVisible();
  await expect(page.getByText('Use the GitHub Actions fallback')).not.toBeVisible();
  await expect(page.getByRole('button',{name:'Start analysis',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Start analysis',exact:true}).click();
  await expect(page.getByText('Analysis request submitted',{exact:true})).toBeVisible();
  expect(submitted).toEqual({repository:source,kind:'branch',ref:'latest'});
  await expect(page.getByRole('link',{name:'Track run 42'})).toHaveAttribute('href',/actions\/runs\/42$/);
  await expect(page.getByRole('button',{name:'Start analysis',exact:true})).not.toBeVisible();
  await page.getByRole('button',{name:'View results on dashboard'}).click();
  await expect(page.getByText('Request submitted — awaiting a new published result')).toBeVisible();
  expect(await page.evaluate(() => JSON.stringify({...localStorage,...sessionStorage}))).not.toContain('opaque-session');
});

test('commit selection survives sign-in and old output is not mistaken for new results', async ({page, context}) => {
  const data = JSON.parse(readFileSync('public/data/index.json','utf8'));
  const source = data.analysis_repository;
  const sha = 'c'.repeat(40);
  const oldTarget = {...data.targets[0], id:'manual-commit', kind:'commit', head_sha:sha, scan_run_id:41, status:'partial'};
  data.targets = [oldTarget];
  Object.assign(data, {launch_endpoint:'https://launcher.example', source_repository:source, analysis_default_branch:'Testing'});
  await page.route('**/index.json', route => route.fulfill({json:data}));
  let submitted: unknown;
  await context.route('https://launcher.example/**', async route => {
    const url = new URL(route.request().url());
    const headers = {'Access-Control-Allow-Origin':'http://127.0.0.1:4178', 'Access-Control-Allow-Headers':'Authorization, Content-Type', 'Access-Control-Allow-Methods':'GET, POST, OPTIONS'};
    if (route.request().method() === 'OPTIONS') return route.fulfill({status:204,headers});
    if (url.pathname === '/auth/login') return route.fulfill({contentType:'text/html',body:`<script>window.opener.postMessage({type:'analysis-auth',nonce:'${url.searchParams.get('nonce')}',token:'test-session',login:'developer'},'http://127.0.0.1:4178');window.close();</script>`});
    if (url.pathname === '/api/targets') return route.fulfill({headers,json:{repository:source,analysis_repository:source,targets:[]}});
    submitted = route.request().postDataJSON();
    return route.fulfill({headers,status:202,json:{run_id:42,url:`https://github.com/${source}/actions/runs/42`}});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'Run analysis',exact:true}).click();
  await page.getByRole('button',{name:'Choose revision'}).click();
  await page.getByLabel('Analysis target',{exact:true}).fill(sha.toUpperCase());
  await page.getByRole('button',{name:'Back',exact:true}).click();
  await page.getByRole('button',{name:'Sign in with GitHub'}).click();
  await expect(page.getByText('Signed in as developer')).toBeVisible();
  await page.getByRole('button',{name:'Choose revision'}).click();
  await expect(page.getByLabel('Analysis target',{exact:true})).toHaveValue(sha.toUpperCase());
  await page.getByRole('button',{name:'Review analysis'}).click();
  await expect(page.getByText('Pinned to this SHA')).toBeVisible();
  await page.getByRole('button',{name:'Start analysis',exact:true}).click();
  await page.getByRole('button',{name:'View results on dashboard'}).click();
  expect(submitted).toEqual({repository:source,kind:'commit',ref:sha});
  await page.getByRole('button',{name:'Check for results'}).click();
  await expect(page.getByText('Request submitted — awaiting a new published result')).toBeVisible();
  await expect(page.getByText('New report available for your selected target')).not.toBeVisible();
  data.targets[0] = {...oldTarget, scan_run_id:43, status:'scanning'};
  await page.getByRole('button',{name:'Check for results'}).click();
  await expect(page.getByText('Analysis is running',{exact:true})).toBeVisible();
  data.targets[0] = {...oldTarget, scan_run_id:43, status:'partial', report:'reports/new-output'};
  await page.getByRole('button',{name:'Check for results'}).click();
  await expect(page.getByText('New report available for your selected target')).toBeVisible();
  await expect(page.getByRole('button',{name:'Open new report'})).toBeVisible();
});

test('commit validation prevents an invalid launch and distinguishes PR input', async ({page}) => {
  await page.goto('/');
  await page.getByRole('button',{name:'Run analysis',exact:true}).click();
  await page.getByRole('button',{name:'Choose revision',exact:true}).click();
  await page.getByText('Commit SHA',{exact:true}).click();
  await page.getByLabel('Analysis target',{exact:true}).fill('abc');
  await expect(page.getByText('Enter the full 40-character commit SHA.')).toBeVisible();
  await expect(page.getByRole('button',{name:'Review analysis',exact:true})).toBeDisabled();
  await page.getByText('Pull request',{exact:true}).click();
  await page.getByLabel('Analysis target',{exact:true}).fill('-1');
  await expect(page.getByText('Enter a positive PR number.')).toBeVisible();
});
