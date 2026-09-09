import { useEffect, useState } from 'react';
import { Alert, Button, Collapse, Descriptions, Input, Modal, Segmented, Select, Space, Steps, Tag, Typography } from 'antd';
import { GithubOutlined, PlayCircleOutlined } from '@ant-design/icons';

type Target = { id: string; repository: string; source_repository: string; kind: string; branch: string; pr?: number; label: string; head_sha: string; base_branch?: string; checked_at: string };
export type LaunchRequest = { kind: string; ref: string; url: string; submittedAt: string };
type Auth = ReturnType<typeof import('./useLaunchAuth').useLaunchAuth>;
type Props = { onSubmitted: (request: LaunchRequest) => void; auth: Auth; open: boolean; close: () => void; repository?: string; host?: string; workflowBranch?: string; preferredBranch?: string; targets: Target[]; initial?: Target; follow: (target: string) => void; channelCount?: number; completedChannels?: number; queued?: number; scanning?: number };

export function AnalysisLauncher({ onSubmitted, auth, open, close, repository, host, workflowBranch, preferredBranch, targets, initial, follow, queued, scanning }: Props) {
  const [step, setStep] = useState(0);
  const [kind, setKind] = useState(initial?.kind || 'branch');
  // Store semantic refs, not IDs: authenticated discovery uses different target IDs.
  const [value, setValue] = useState(initial?.kind === 'commit' ? initial.head_sha : initial?.kind === 'pr' ? String(initial.pr) : initial?.branch || preferredBranch || '');
  const [liveTargets, setLiveTargets] = useState<Target[]>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [handoff, setHandoff] = useState(false);
  const [submitted, setSubmitted] = useState<{ url: string; run_id?: number }>();
  useEffect(() => {
    let active = true;
    setLiveTargets(undefined);
    if (auth.session) auth.api<{ repository: string; analysis_repository: string; targets: Target[] }>('targets').then(data => {
      if (!active) return;
      if (data.repository !== repository || data.analysis_repository !== host) throw new Error('Launcher configuration does not match this dashboard.');
      setLiveTargets(data.targets); setError('');
    }).catch(e => { if (active) setError(e.message); });
    return () => { active = false; };
  }, [auth.session, repository, host, refresh]);
  const choices = auth.session ? liveTargets || [] : targets;
  const input = value.trim();
  const selected = choices.find(t => t.kind === kind && (kind === 'pr' ? String(t.pr) === input : kind === 'commit' ? t.head_sha === input : t.branch === input));
  const valid = !!repository && !!host && (kind === 'commit' ? /^[a-fA-F0-9]{40}$/.test(input) : kind === 'pr' ? /^[1-9][0-9]*$/.test(input) : !!selected);
  const ref = kind === 'commit' ? input.toLowerCase() : input;
  const request = JSON.stringify({ repository, kind, ref });
  const reset = (next: string) => { setValue(next); setHandoff(false); setError(''); };
  const launch = async () => {
    if (!valid || busy || submitted) return;
    setBusy(true); setError('');
    const submittedAt = new Date().toISOString();
    try {
      const result = await auth.api<{ url: string; run_id?: number }>('launch', { repository, kind, ref });
      setSubmitted(result); setStep(3);
      onSubmitted({ kind, ref, url: result.url, submittedAt });
    } catch (e) { setError(e instanceof Error ? e.message : 'Launch failed.'); }
    finally { setBusy(false); }
  };
  const viewResults = () => {
    const current = targets.find(t => t.kind === kind && (kind === 'pr' ? String(t.pr) === ref : kind === 'commit' ? t.head_sha.toLowerCase() === ref : t.branch === ref));
    if (current) follow(current.id);
    close();
  };
  return <Modal className="launch-modal" title={<div className="launch-title"><span>RUN ANALYSIS</span><strong>Analyze your code</strong><p>Select a repository revision, review the scan, and follow its results.</p></div>} open={open} onCancel={busy ? undefined : close} closable={!busy} maskClosable={!busy} keyboard={!busy} footer={null} width={760}>
    <div className="analysis-launcher">
      <Steps size="small" responsive={false} titlePlacement="vertical" current={step} items={[{ title: 'Project' }, { title: 'Revision' }, { title: 'Review' }, { title: 'Results' }]}/>
      {step === 0 && <section className="launch-section"><h3>Choose your project</h3>
        <div className="project-choice" role="group" aria-label="Analysis repository"><GithubOutlined/><div><small>CONFIGURED CODEBASE</small><strong>{repository || 'Configuration unavailable'}</strong><p>This instance uses the scanner profile configured for this repository.</p></div></div>
        <div className="launch-meta"><span>Scanners run on <Typography.Text code>{host || 'Unavailable'}</Typography.Text></span><span>Workflow branch <Typography.Text code>{workflowBranch || 'Unavailable'}</Typography.Text></span></div>
        <div className="wizard-auth">{auth.available ? auth.session ? <Space wrap><Tag color="green">Signed in as {auth.session.login}</Tag><Button onClick={auth.signOut}>Sign out</Button></Space> : <><p>Sign in with GitHub to load current branches and pull requests and start analysis here.</p><Button type="primary" icon={<GithubOutlined/>} onClick={auth.signIn}>Sign in with GitHub</Button></> : <Alert type="info" title="Use GitHub Actions to launch" description="Direct launching is not configured. You can still choose a revision and open the workflow from the review step."/>}</div>
      </section>}
      {step === 1 && <section className="launch-section"><h3>Select a revision</h3>
        <Segmented block aria-label="Revision type" value={kind} options={[{ label: 'Branch', value: 'branch' }, { label: 'Pull request', value: 'pr' }, { label: 'Commit SHA', value: 'commit' }]} onChange={next => { setKind(next); reset(next === 'branch' ? preferredBranch || '' : ''); }}/>
        {kind !== 'commit' && <Select className="revision-picker" aria-label="Available analysis targets" loading={!!auth.session && !liveTargets} showSearch optionFilterProp="label" placeholder={kind === 'branch' ? 'Choose a branch' : 'Choose an open PR'} value={selected ? input : undefined} options={choices.filter(t => t.kind === kind).map(t => ({ value: kind === 'pr' ? String(t.pr) : t.branch, label: t.label }))} onChange={reset}/>}
        {auth.session && kind !== 'commit' && <Button size="small" className="refresh-targets" onClick={() => setRefresh(n => n + 1)}>Refresh from GitHub</Button>}
        {kind !== 'branch' && <Input aria-label="Analysis target" value={value} onChange={e => reset(e.target.value)} placeholder={kind === 'commit' ? 'Paste the full 40-character commit SHA' : 'Or enter a PR number'}/>}
        {kind === 'commit' && input && !valid && <Alert type="warning" title="Enter the full 40-character commit SHA."/>}
        {kind === 'pr' && input && !valid && <Alert type="warning" title="Enter a positive PR number."/>}
        <p className="developer-note">{kind === 'commit' ? 'This scans exactly the SHA you enter, even if a branch has moved ahead. GitHub verifies that the commit exists in the configured repository.' : 'The workflow fetches GitHub again when the request is processed and scans the latest head then. The preview below may change before execution.'}</p>
        {(selected || kind === 'commit' && valid) && <div className="revision-preview"><Descriptions column={1} size="small" items={[
          { key: 'source', label: 'Source repository', children: selected?.source_repository || repository },
          { key: 'sha', label: kind === 'commit' ? 'Requested SHA' : 'Last discovered head', children: <Typography.Text copyable code>{kind === 'commit' ? ref : selected?.head_sha}</Typography.Text> },
          ...(kind === 'pr' ? [{ key: 'base', label: 'PR target branch', children: selected?.base_branch || 'Resolved by GitHub' }] : []),
        ]}/></div>}
      </section>}
      {step === 2 && <section className="launch-section"><h3>Review your analysis</h3><Descriptions column={1} items={[
        { key: 'repo', label: 'Codebase', children: repository },
        { key: 'ref', label: kind === 'commit' ? 'Exact commit SHA' : kind === 'pr' ? 'Pull request' : 'Branch', children: <Typography.Text code copyable>{kind === 'pr' ? `#${ref}` : ref}</Typography.Text> },
        { key: 'mode', label: 'Revision policy', children: kind === 'commit' ? 'Pinned to this SHA' : 'Latest head when GitHub processes the request' },
        { key: 'scan', label: 'Scanner profile', children: 'Run every enabled, applicable channel. Unavailable checks remain visible.' },
        { key: 'storage', label: 'Report retention', children: 'Replace the selected target’s previous report after validation. Superseded assets are removed after deployment.' },
      ]}/><p>A fresh scan is requested even if this head was analyzed before. Scanners can report partial results; publication never reruns analysis.</p><p>PR results describe the PR head and preserve its base context. They are not merge validation.</p><small>{queued ?? 'Unavailable'} queued / {scanning ?? 'Unavailable'} scanning in the last published inventory.</small>
        {auth.session ? <Button size="large" icon={<PlayCircleOutlined aria-hidden="true"/>} type="primary" loading={busy} disabled={!valid || !liveTargets || !!submitted} onClick={launch}>Start analysis</Button> : <><p>Sign in to submit here, or use the Actions fallback below.</p>{auth.available && <Button onClick={() => setStep(0)}>Back to sign in</Button>}<Collapse className="manual-handoff" items={[{ key: 'fallback', label: 'Use the GitHub Actions fallback', children: <><ol><li>Copy <Typography.Text copyable code>{request}</Typography.Text></li><li>Open Actions, choose <strong>Run workflow</strong> on <strong>{workflowBranch || 'the configured branch'}</strong>, and paste it into <strong>refresh_target</strong>.</li></ol><Button disabled={!valid || !workflowBranch} href={valid && workflowBranch ? `https://github.com/${host}/actions/workflows/10-analysis-discovery.yml` : undefined} target="_blank" rel="noreferrer" onClick={() => setHandoff(true)}>Open GitHub Actions</Button>{handoff && <Alert type="info" title="Awaiting confirmation on GitHub" description="Confirm Run workflow in GitHub to submit. Opening the link alone does not start analysis."/>}</> }]}/></>}
      </section>}
      {step === 3 && submitted && <section className="launch-section run-receipt"><h3>Analysis request submitted</h3><p>GitHub accepted the request. Scanning and publication have not yet been confirmed.</p><p><a href={submitted.url} target="_blank" rel="noreferrer">Track run {submitted.run_id || 'in GitHub'}</a></p><p>The dashboard will keep the request visible and refresh published data every minute. A new validated report for this target replaces the previous output; older findings retain their original SHA while you wait.</p><Button type="primary" onClick={viewResults}>View results on dashboard</Button></section>}
      {(error || auth.error) && <Alert type="error" title="Analysis launcher" description={error || auth.error}/>}
      {step < 3 && <div className="wizard-navigation"><Button disabled={step === 0 || busy} onClick={() => setStep(n => n - 1)}>Back</Button><span>Step {step + 1} of 3</span>{step < 2 ? <Button type="primary" disabled={!repository || !host || step === 1 && !valid} onClick={() => setStep(n => n + 1)}>{step === 0 ? 'Choose revision' : 'Review analysis'}</Button> : <Button disabled={busy} onClick={close}>Cancel</Button>}</div>}
      <p className="launch-footnote">Current report per active branch and open PR, plus one manual commit or closed-PR selection. Publication runs about every 10 minutes.</p>
    </div>
  </Modal>;
}
