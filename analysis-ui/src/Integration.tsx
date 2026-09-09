import { useEffect, useState } from 'react';
import { Alert, Button, Descriptions, Space, Steps, Tag } from 'antd';
import type { useLaunchAuth } from './useLaunchAuth';

type Auth = ReturnType<typeof useLaunchAuth>;
type Configuration = { source_repository: string; analysis_repository: string; publishing_repository?: string; workflow_branch: string; workflow_state: string; configuration_matches: boolean; ready: boolean; enabled_scanners: string[]; checked_at: string };

export function Connections({ auth, source, host, publisher, endpoint, start }: { auth: Auth; source?: string; host?: string; publisher?: string; endpoint?: string; start: () => void }) {
  const [configuration, setConfiguration] = useState<Configuration>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let active = true;
    setConfiguration(undefined); setError(''); setBusy(!!auth.session);
    if (auth.session) auth.api<Configuration>('integration').then(value => {
      if (!active) return;
      if (value.source_repository !== source || value.analysis_repository !== host || publisher && value.publishing_repository !== publisher) throw Error('Published dashboard and live service configuration disagree. Check the repository configuration before launching.');
      setConfiguration(value);
    }).catch(e => { if (active) setError(e.message); }).finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [auth.session, source, host, publisher, refresh]);
  return <section className="connections-panel">
    <h2>Application connections</h2><p>One configured codebase, an authenticated launch gateway, GitHub scanner execution, and a published collection of current reports.</p>
    <Steps responsive={false} titlePlacement="vertical" items={[{title:'Git repository'}, {title:'Cloudflare login'}, {title:'GitHub Actions'}, {title:'Dashboard'}]} current={-1}/>
    <Descriptions column={1} bordered items={[
      {key:'source',label:'Source codebase',children:source || 'Unavailable'},
      {key:'gateway',label:'Authentication and launch gateway',children:endpoint || 'Not configured'},
      {key:'analysis',label:'Scanner execution repository',children:host ? <a href={`https://github.com/${host}/actions`} target="_blank" rel="noreferrer">{host}</a> : 'Unavailable'},
      {key:'reports',label:'Current reports and website',children:publisher ? <a href={`https://github.com/${publisher}/actions`} target="_blank" rel="noreferrer">{publisher}</a> : 'Unavailable'},
      {key:'identity',label:'GitHub session',children:auth.session ? `Signed in as ${auth.session.login}` : 'Not signed in'},
    ]}/>
    <Space wrap>{auth.session ? <><Button loading={busy} onClick={() => setRefresh(n => n + 1)}>Verify connections</Button><Button onClick={auth.signOut}>Sign out</Button></> : <Button disabled={!auth.available} onClick={auth.signIn}>Sign in to verify connections</Button>}<Button type="primary" onClick={start}>Choose revision to analyze</Button></Space>
    {(error || auth.error) && <Alert showIcon type="error" title="Connection check unavailable" description={error || auth.error}/>}
    {configuration && <Alert showIcon type={configuration.ready ? 'success' : 'warning'} title={configuration.ready ? 'Launch configuration verified' : 'Configuration needs attention'} description={<><p>Configuration match: {configuration.configuration_matches ? 'yes' : 'no'}. Discovery workflow: {configuration.workflow_state}. Trusted workflow branch: {configuration.workflow_branch}. Checked {new Date(configuration.checked_at).toLocaleString()}.</p><p>{configuration.enabled_scanners.length} enabled channels: {configuration.enabled_scanners.join(', ')}.</p><p>This verifies routing and workflow availability. Scanner results determine which channels actually completed.</p></>}/>}
    <h3>How analysis reaches this application</h3><ol><li>Sign in and select a branch, PR, or full commit SHA.</li><li>Cloudflare checks your GitHub permissions and submits the request to the configured workflow.</li><li>GitHub resolves the source revision and queues the scanners. Source execution has no publishing credentials.</li><li>The publisher validates current evidence, updates the target report, and deploys the dashboard. Superseded assets are cleaned after deployment.</li></ol>
    <p>Repository setup is managed through the versioned service configuration and scanner profile. Changing codebases requires updating and validating that configuration; this page does not silently scan an arbitrary repository with the wrong profile.</p>
  </section>;
}

export function RequestStatus({ auth, runId }: { auth: Auth; runId?: number }) {
  const [run, setRun] = useState<{status: string; conclusion: string | null; attempt: number; checked_at: string}>();
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true; let timer: number | undefined;
    setRun(undefined); setError('');
    async function update() {
      try {
        const value = await auth.api<NonNullable<typeof run>>(`runs/${runId}`);
        if (!active) return;
        if (typeof value.status !== 'string') throw Error('Request status is unavailable. Use the GitHub request link.');
        setRun(value); setError('');
        if (value.status !== 'completed') timer = window.setTimeout(update, 20000);
      } catch(e) { if (active) setError(e instanceof Error ? e.message : 'Request status unavailable.'); }
    }
    if (auth.session && runId) void update();
    return () => { active = false; window.clearTimeout(timer); };
  }, [auth.session, runId]);
  if (!runId) return null;
  return <div className="request-status" role="status">{!auth.session ? 'Sign in to check the request workflow directly.' : error || !run ? error || 'Checking request workflow…' : <><Tag color={run.conclusion === 'success' ? 'green' : run.conclusion ? 'orange' : 'blue'}>Request workflow: {run.conclusion || run.status}</Tag><span>Attempt {run.attempt}. Checked {new Date(run.checked_at).toLocaleTimeString()}.</span><p>{run.conclusion === 'success' ? 'Discovery completed. Scanner execution and report publication are separate stages; check the target status and producing runs below.' : run.status === 'completed' ? 'The request workflow did not succeed. Inspect its GitHub log before retrying; a new report is not confirmed.' : 'GitHub is processing the request. This is not a scanner completion status.'}</p></>}</div>;
}
