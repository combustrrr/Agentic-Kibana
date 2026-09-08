import { useEffect, useState } from 'react';
import { Alert, Button, Collapse, Descriptions, Input, Modal, Segmented, Select, Space, Steps, Tag, Typography } from 'antd';
import { BranchesOutlined, CheckCircleOutlined, GithubOutlined, PlayCircleOutlined, SafetyCertificateOutlined } from '@ant-design/icons';

type Target = { id: string; repository: string; source_repository: string; kind: string; branch: string; pr?: number; label: string; head_sha: string; base_branch?: string; checked_at: string };
type Auth = ReturnType<typeof import('./useLaunchAuth').useLaunchAuth>;
type Props = { onSubmitted: (request: { kind: string; ref: string }) => void; auth: Auth; open: boolean; close: () => void; repository?: string; host?: string; workflowBranch?: string; preferredBranch?: string; targets: Target[]; initial?: Target; follow: (target: string) => void; channelCount?: number; completedChannels?: number; queued?: number; scanning?: number };

export function AnalysisLauncher({ onSubmitted, auth, open, close, repository, host, workflowBranch, preferredBranch, targets, initial, follow, channelCount = 0, completedChannels = 0, queued = 0, scanning = 0 }: Props) {
  const [kind, setKind] = useState(initial?.kind || 'branch');
  const [value, setValue] = useState(initial?.kind === 'commit' ? initial.head_sha : initial?.id || '');
  const [handoff, setHandoff] = useState(false);
  const [liveTargets, setLiveTargets] = useState<Target[]>();
  const [launchError, setLaunchError] = useState('');
  const [busy, setBusy] = useState(false);
  const [submitted, setSubmitted] = useState<{ url: string; run_id?: number }>();
  useEffect(() => {
    let active = true;
    setLiveTargets(undefined);
    if (auth.session) auth.api<{ repository: string; analysis_repository: string; targets: Target[] }>('targets').then(data => {
      if (!active) return;
      if (data.repository !== repository || data.analysis_repository !== host) throw new Error('Launcher configuration does not match this dashboard.');
      setLiveTargets(data.targets);
      const sameTarget = data.targets.find(t => t.kind === initial?.kind && (t.kind === 'pr' ? t.pr === initial?.pr : t.kind === 'commit' ? t.head_sha === initial?.head_sha : t.branch === initial?.branch));
      const preferred = data.targets.find(t => t.kind === 'branch' && t.branch === preferredBranch);
      const next = sameTarget || preferred || data.targets.find(t => t.kind === 'branch') || data.targets[0];
      if (next) { setKind(next.kind); setValue(next.id); }
      setHandoff(false);
    }).catch(e => { if (active) setLaunchError(e.message); });
    return () => { active = false; };
  }, [auth.session, repository, host]);
  const choices = liveTargets || targets;
  const selected = choices.find(t => t.id === value && t.kind === kind);
  const input = value.trim();
  const valid = !!repository && !!host && (kind === 'commit' ? /^[a-fA-F0-9]{40}$/.test(input) : kind === 'pr' ? !!selected || /^[1-9][0-9]*$/.test(input) : !!selected);
  const request = selected ? JSON.stringify({ repository, kind, ref: kind === 'pr' ? String(selected.pr) : selected.branch }) : (kind === 'pr' ? `PR #${input}` : input.toLowerCase());
  const workflow = host && `https://github.com/${host}/actions/workflows/10-analysis-discovery.yml`;
  const reset = (next: string) => { setValue(next); setHandoff(false); setSubmitted(undefined); setLaunchError(''); };
  const launch = async () => {
    setBusy(true); setLaunchError('');
    try {
      const result = await auth.api<{ url: string; run_id?: number }>('launch', { repository, kind, ref: selected ? kind === 'pr' ? String(selected.pr) : selected.branch : input });
      setSubmitted(result); onSubmitted({ kind, ref: selected ? kind === 'pr' ? String(selected.pr) : selected.branch : input });
      const current = targets.find(t => t.kind === kind && (kind === 'pr' ? t.pr === selected?.pr || String(t.pr) === input : kind === 'commit' ? t.head_sha.toLowerCase() === input.toLowerCase() : t.branch === selected?.branch));
      if (current) follow(current.id);
    } catch (e) { setLaunchError(e instanceof Error ? e.message : 'Launch failed.'); } finally { setBusy(false); }
  };
  const revisionLabel = kind === 'pr' ? selected?.label || `PR #${input}` : kind === 'commit' ? input : selected?.branch;
  return <Modal className="launch-modal" title={<div className="launch-title"><span>NEW ANALYSIS</span><strong>Analyze a revision</strong><p>Choose an exact source revision and run the repository's trusted scanner profile.</p></div>} open={open} onCancel={close} footer={null} width={760}>
    <div className="analysis-launcher">
      <section className="launch-section"><div className="launch-section-head"><span>1</span><div><h3>Project</h3><p>Scanner configuration and execution boundary</p></div></div>
        <div className="project-choice" role="group" aria-label="Analysis repository"><GithubOutlined/><div><small>CODEBASE</small><strong>{repository || 'Configuration unavailable'}</strong><p>Source is checked out read-only at the selected SHA.</p></div><Tag color="green">Configured</Tag></div>
        <div className="launch-meta"><span>Analysis host <Typography.Text code>{host || 'Unavailable'}</Typography.Text></span><span>Workflow ref <Typography.Text code>{workflowBranch || 'Unavailable'}</Typography.Text></span></div>
      </section>
      <section className="launch-section"><div className="launch-section-head"><span>2</span><div><h3>Revision</h3><p>Select the code developers expect this report to describe</p></div></div>
        <Segmented block aria-label="Revision type" value={kind} options={[{ label: <span><BranchesOutlined/> Branch</span>, value: 'branch' }, { label: 'Pull request', value: 'pr' }, { label: 'Commit SHA', value: 'commit' }]} onChange={next => { setKind(next); reset(''); }}/>
        {kind !== 'commit' && <Select className="revision-picker" aria-label="Available analysis targets" loading={!!auth.session && !liveTargets} showSearch optionFilterProp="label" placeholder={auth.session && !liveTargets ? 'Loading current targets…' : kind === 'branch' ? 'Choose a branch' : 'Choose an open PR'} value={selected?.id} options={choices.filter(t => t.kind === kind).map(t => ({ value: t.id, label: t.label }))} onChange={reset}/>}
        {kind !== 'branch' && <Input aria-label="Analysis target" value={selected ? String(selected.pr || '') : value} onChange={e => reset(e.target.value)} placeholder={kind === 'commit' ? 'Full 40-character commit SHA' : 'Or enter a PR number'}/>}
        {kind === 'commit' && input && !/^[a-fA-F0-9]{40}$/.test(input) && <Alert type="warning" title="Enter the full 40-character commit SHA."/>}
        {kind === 'pr' && input && !selected && !/^[1-9][0-9]*$/.test(input) && <Alert type="warning" title="Enter a positive PR number."/>}
        {(selected || (kind === 'commit' && valid)) && <div className="revision-preview"><div className="revision-summary"><CheckCircleOutlined/><div><small>READY TO ANALYZE</small><strong>{revisionLabel}</strong></div><Tag color="blue">Exact source</Tag></div><Descriptions column={{ xs: 1, sm: 2 }} size="small" items={[{ key: 'source', label: 'Source repository', children: selected?.source_repository || repository }, { key: 'head', label: 'Head commit', children: <Typography.Text copyable code>{selected?.head_sha || input}</Typography.Text> }, ...(selected?.pr ? [{ key: 'base', label: 'PR target', children: selected.base_branch || 'Unavailable' }] : []), { key: 'checked', label: 'Head last checked', children: selected?.checked_at ? new Date(selected.checked_at).toLocaleString() : kind === 'commit' ? 'Verified when submitted' : 'Unavailable' }]}/></div>}
        <p className="developer-note">{kind === 'commit' ? 'GitHub verifies that the commit belongs to this codebase before work is queued.' : 'The launcher resolves the latest head at submission. PR scans retain head repository, head SHA, base branch, and base SHA context.'}</p>
      </section>
      <section className="launch-section"><div className="launch-section-head"><span>3</span><div><h3>Scanner profile</h3><p>All configured channels run against the same resolved source</p></div></div>
        <div className="profile-summary"><SafetyCertificateOutlined/><div><strong>{channelCount || 'Configured'} channels</strong><p>{completedChannels} completed in the currently published report. Failures publish as explicit unavailable channels.</p></div></div>
        <div className="profile-tags"><Tag>Security</Tag><Tag>Code quality</Tag><Tag>Dependencies</Tag><Tag>Infrastructure</Tag><Tag>Reliability</Tag></div>
        <div className="queue-summary"><span><b>{queued}</b> queued</span><span><b>{scanning}</b> scanning</span><span>Latest report per active target</span></div>
      </section>
      <section className="launch-section run-section"><div className="launch-section-head"><span>4</span><div><h3>Run analysis</h3><p>Authenticate the developer and dispatch the trusted workflow</p></div></div>
        {auth.available ? auth.session ? <div className="direct-launch"><div><small>GITHUB IDENTITY</small><strong>Signed in as {auth.session.login}</strong><p>The request will be recorded in GitHub Actions with this exact revision.</p></div><Space wrap><Button onClick={auth.signOut}>Sign out</Button><Button size="large" icon={<PlayCircleOutlined/>} aria-label="Start analysis" type="primary" loading={busy} disabled={!valid || !liveTargets || !!submitted} onClick={launch}>Start analysis</Button></Space></div> : <div className="sign-in-callout"><div><GithubOutlined/><span><strong>Sign in to run scanners</strong><p>GitHub confirms repository access and records who launched the workflow.</p></span></div><Button type="primary" size="large" onClick={auth.signIn}>Sign in with GitHub</Button></div> : <Alert type="info" title="Direct launching needs administrator setup" description="Connect this instance to its authenticated launcher to start scans here."/>}
        {(launchError || auth.error) && <Alert type="error" title="Analysis launcher" description={launchError || auth.error}/>} {submitted && <div className="run-receipt"><div className="receipt-head"><CheckCircleOutlined/><div><strong>Analysis request submitted</strong><p>GitHub accepted the request. Completion is pending.</p></div><a href={submitted.url} target="_blank" rel="noreferrer">Track run {submitted.run_id || 'in GitHub'}</a></div><Steps size="small" current={0} items={[{ title: 'Submitted' }, { title: 'Queued' }, { title: 'Scanning' }, { title: 'Published' }]}/></div>}
        {!workflowBranch && <Alert type="warning" title="Launch configuration is unavailable. Refresh after the next publication."/>}
      </section>
      {!auth.session && <Collapse ghost className="manual-handoff" items={[{ key: 'fallback', label: 'Use the GitHub Actions fallback', children: <><ol><li>Copy the target: <Typography.Text copyable={{ text: request }} code>{request || 'Select a valid revision first'}</Typography.Text></li><li>Open Actions and keep the workflow branch at <strong>{workflowBranch || 'the configured default'}</strong>.</li><li>Paste the copied value into <strong>refresh_target</strong>, then run the workflow.</li></ol><Space wrap><Button disabled={!valid || !workflowBranch} href={valid && workflowBranch ? workflow : undefined} target="_blank" rel="noreferrer" onClick={() => setHandoff(true)}>Open GitHub Actions</Button>{handoff && <Button onClick={close}>Return to results</Button>}</Space>{handoff && <Alert type="info" showIcon title="Awaiting confirmation on GitHub" description="Opening Actions does not submit a scan. Confirm Run workflow in GitHub to queue it."/>}</>}]}/>}
      <p className="launch-footnote">Published results refresh every minute. Branches and open PRs retain only their latest report, so repeated scans do not accumulate site history.</p>
    </div>
  </Modal>;
}
