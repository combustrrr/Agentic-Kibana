import { useEffect, useState } from 'react';
import { Alert, Button, Descriptions, Input, Modal, Segmented, Select, Space, Typography } from 'antd';

type Target = { id: string; repository: string; source_repository: string; kind: string; branch: string; pr?: number; label: string; head_sha: string; base_branch?: string; checked_at: string };
type Auth = ReturnType<typeof import('./useLaunchAuth').useLaunchAuth>;
type Props = { onSubmitted: (request: { kind: string; ref: string }) => void; auth: Auth; open: boolean; close: () => void; repository?: string; host?: string; workflowBranch?: string; preferredBranch?: string; targets: Target[]; initial?: Target; follow: (target: string) => void };

export function AnalysisLauncher({ onSubmitted, auth, open, close, repository, host, workflowBranch, preferredBranch, targets, initial, follow }: Props) {
  // The parent mounts a new form for each launch, so it follows the currently viewed target.
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
      const sameTarget = data.targets.find(t => t.kind === initial?.kind &&
        (t.kind === 'pr' ? t.pr === initial?.pr : t.kind === 'commit' ? t.head_sha === initial?.head_sha : t.branch === initial?.branch));
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
  const valid = !!repository && !!host && (kind === 'commit'
    ? /^[a-fA-F0-9]{40}$/.test(input)
    : kind === 'pr' ? !!selected || /^[1-9][0-9]*$/.test(input) : !!selected);
  const request = selected ? JSON.stringify({ repository, kind, ref: kind === 'pr' ? String(selected.pr) : selected.branch }) : (kind === 'pr' ? `PR #${input}` : input.toLowerCase());
  const workflow = host && `https://github.com/${host}/actions/workflows/10-analysis-discovery.yml`;
  const reset = (next: string) => { setValue(next); setHandoff(false); setSubmitted(undefined); setLaunchError(''); };
  const launch = async () => {
    setBusy(true); setLaunchError('');
    try {
      const result = await auth.api<{ url: string; run_id?: number }>('launch', { repository, kind, ref: selected ? kind === 'pr' ? String(selected.pr) : selected.branch : input });
      setSubmitted(result);
      onSubmitted({ kind, ref: selected ? kind === 'pr' ? String(selected.pr) : selected.branch : input });
      const current = targets.find(t => t.kind === kind && (kind === 'pr' ? t.pr === selected?.pr || String(t.pr) === input : kind === 'commit' ? t.head_sha.toLowerCase() === input.toLowerCase() : t.branch === selected?.branch));
      if (current) follow(current.id);
    } catch (e) { setLaunchError(e instanceof Error ? e.message : 'Launch failed.'); }
    finally { setBusy(false); }
  };
  return <Modal title="Run source analysis" open={open} onCancel={close} footer={null} width={660}>
    <div className="analysis-launcher">
      <label htmlFor="analysis-repository">Codebase</label>
      <Select id="analysis-repository" aria-label="Analysis repository" value={repository} options={repository ? [{ value: repository, label: repository }] : []} placeholder="Repository configuration unavailable"/>
      <p>This instance runs the scanner profile configured for this repository. Another codebase needs its own repository configuration and scanner setup.</p>
      <label>Revision to analyze</label>
      <Segmented aria-label="Revision type" value={kind} options={[{ label: 'Branch', value: 'branch' }, { label: 'Pull request', value: 'pr' }, { label: 'Commit', value: 'commit' }]} onChange={next => { setKind(next); reset(''); }}/>
      {kind !== 'commit' && <Select aria-label="Available analysis targets" loading={!!auth.session && !liveTargets} showSearch optionFilterProp="label" placeholder={auth.session && !liveTargets ? 'Loading current targets…' : kind === 'branch' ? 'Choose a branch' : 'Choose an open PR'} value={selected?.id} options={choices.filter(t => t.kind === kind).map(t => ({ value: t.id, label: t.label }))} onChange={reset}/>}
      {kind !== 'branch' && <Input aria-label="Analysis target" value={selected ? String(selected.pr || '') : value} onChange={e => reset(e.target.value)} placeholder={kind === 'commit' ? 'Full 40-character commit SHA' : 'Or enter a PR number'}/>}
      {kind === 'commit' && input && !/^[a-fA-F0-9]{40}$/.test(input) && <Alert type="warning" title="Enter the full 40-character commit SHA."/>}
      {kind === 'pr' && input && !selected && !/^[1-9][0-9]*$/.test(input) && <Alert type="warning" title="Enter a positive PR number."/>}
      {selected && <Descriptions column={1} size="small" items={[
        { key: 'source', label: 'Source', children: selected.source_repository },
        { key: 'head', label: 'Last discovered head', children: <Typography.Text code>{selected.head_sha}</Typography.Text> },
        ...(selected.pr ? [{ key: 'base', label: 'PR target branch', children: selected.base_branch || 'Unavailable' }] : []),
        { key: 'checked', label: 'Head last checked', children: selected.checked_at ? new Date(selected.checked_at).toLocaleString() : 'Unavailable' },
      ]}/>}
      <p>{kind === 'commit' ? 'GitHub verifies this commit belongs to the configured codebase before scanning.' : 'GitHub resolves the latest head when you submit the request. A PR scan preserves its source repository and base context.'}</p>
      {auth.available ? auth.session ? <div className="direct-launch">
        <div><strong>Signed in as {auth.session.login}</strong><p>Select the revision above, then submit it to the configured scanner workflow.</p></div>
        <Space wrap><Button onClick={auth.signOut}>Sign out</Button><Button aria-label="Start analysis" type="primary" loading={busy} disabled={!valid || !liveTargets || !!submitted} onClick={launch}>Start analysis</Button></Space>
      </div> : <Button type="primary" onClick={auth.signIn}>Sign in with GitHub to start analysis</Button>
      : <Alert type="info" title="Direct launching needs administrator setup" description="Connect this instance to its authenticated launcher to start scans here. GitHub Actions remains available below."/>}
      {(launchError || auth.error) && <Alert type="error" title="Analysis launcher" description={launchError || auth.error}/>}
      {submitted && <Alert type="success" title="Analysis request submitted" description={<span>GitHub accepted the request. Discovery resolves the target and queues scanners; completion is not yet confirmed. <a href={submitted.url} target="_blank" rel="noreferrer">Track request {submitted.run_id || 'in GitHub'}</a></span>}/>}
      {!workflowBranch && <Alert type="warning" title="Launch configuration is not yet available. Refresh after the next publication."/>}
      {!auth.session && valid && workflowBranch && <>
        <ol><li>Copy the analysis target: <Typography.Text copyable={{ text: request }} code>{request}</Typography.Text></li>
          <li>Continue to GitHub, select <strong>Run workflow</strong>, and keep the workflow branch at <strong>{workflowBranch}</strong>.</li>
          <li>Paste the copied value into <strong>refresh_target</strong> and confirm <strong>Run workflow</strong>.</li></ol>
        <p>Scanner execution: <strong>{host}</strong>. GitHub requires permission to run workflows there.</p>
      </>}
      {!auth.session && <Space wrap><Button type="primary" disabled={!valid || !workflowBranch} href={valid && workflowBranch ? workflow : undefined} target="_blank" rel="noreferrer" onClick={() => { setHandoff(true); const current = targets.find(t => t.kind === kind && (kind === 'pr' ? t.pr === selected?.pr : t.branch === selected?.branch)); if (current) follow(current.id); }}>Open Run analysis in GitHub</Button>
        {handoff && <Button onClick={close}>Return to results</Button>}</Space>
      }{!auth.session && handoff && <Alert type="info" showIcon title="Awaiting confirmation on GitHub" description="Opening GitHub does not submit a scan. After you confirm Run workflow, the request is queued for an available analysis slot. The dashboard shows the run once the next status publication arrives."/>}
      <p>Results refresh every minute from published data; publication runs about every 10 minutes. Each active branch and open PR keeps its latest report. A manual commit or closed PR replaces the previous manual selection.</p>
    </div>
  </Modal>;
}
