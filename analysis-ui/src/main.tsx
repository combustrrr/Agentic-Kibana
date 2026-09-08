import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Alert, Button, ConfigProvider, Descriptions, Drawer, Empty, Grid, Input, Modal, Segmented, Progress, Select, Space, Statistic, Table, Tabs, Tag, Typography, theme } from 'antd';
import { CodeOutlined, GithubOutlined, SearchOutlined } from '@ant-design/icons';
import 'antd/dist/reset.css';
import './style.css';

type Target = { scan_run_id?: number; run_attempt?: number; tooling_sha?: string; id: string; label: string; repository: string; source_repository: string; head_sha: string; kind: string; branch: string; pr?: number; base_branch?: string; base_sha?: string; checked_at: string; status: string; report?: string; error?: string };
type Index = { metrics?: {site_bytes: number; site_limit_bytes: number}; schema_version: string; checked_at: string; targets: Target[]; preferred_branch: string; analysis_repository: string; discovery_error?: string; publication_error?: string };
type Finding = { id: string; severity: string; message: string; file: string; line: number; scanners: string[]; rules: string[]; page: number };
type Detail = Finding & { origins: { scanner_family: string; rule: string; file: string; start_line: number; raw_artifact: string; observation_id: string }[]; source: string | null; source_start: number; source_url: string | null };
type Channel = { channel: string; name: string; class: string; status: string; findings: number | null; observation_count: number; reason: string; workflow: string };
type Report = { tooling_sha?: string; producer_run_attempt?: number; analyzed_sha: string; generated_at: string; status: string; finding_count: number; observation_count: number; channels: Channel[]; severities: Record<string, number>; producer_runs: { id: string; url: string }[]; publication_gate: { satisfied: boolean } };
const states: Record<string, string> = { current: 'Up to date', partial: 'Partial analysis', queued: 'Queued', scanning: 'Scanning', stale: 'Newer revision pending', failed: 'Analysis failed' };
const ranks: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, UNKNOWN: 5 };
async function json<T>(path: string, signal?: AbortSignal): Promise<T> {
  const compressed = await fetch(`${path}.gz`, { signal, cache: 'no-store' });
  if (compressed.ok) {
    if (compressed.headers.get('content-encoding') === 'gzip') return compressed.json();
    if (!compressed.body) throw new Error('Empty report response');
    return new Response(compressed.body.pipeThrough(new DecompressionStream('gzip'))).json();
  }
  // Uncompressed local fixtures remain usable without a separate development server.
  const r = await fetch(path, { signal, cache: 'no-store' }); if (!r.ok) throw new Error(`Report unavailable (${r.status}). Try again after the next publication.`); return r.json();
}
function route() { const p = new URLSearchParams(location.hash.slice(1)); return { target: p.get('target') || '', tab: p.get('tab') || 'overview', issue: p.get('issue') || '' }; }
function navigate(target: string, tab: string, issue = '') { location.hash = new URLSearchParams({ target, tab, ...(issue ? { issue } : {}) }).toString(); }
function date(s?: string) { return s ? new Date(s).toLocaleString() : 'Unavailable'; }
const colors: Record<string, string> = { CRITICAL: 'red', HIGH: 'volcano', MEDIUM: 'gold', LOW: 'blue', INFO: 'default', current: 'green', partial: 'orange', failed: 'red', scanning: 'blue', COMPLETED: 'green', CONFIGURED_COMPLETE: 'green', POLICY_FINDINGS: 'orange', NOT_AVAILABLE: 'orange', FAILED: 'red' };
function Badge({ value }: { value: string }) { return <Tag className={`status-tag status-${value}`} color={colors[value]}>{states[value] || value.replaceAll('_', ' ')}</Tag>; }

function Evidence({ detail, source, error }: { detail?: Detail; source: string[]; error: string }) {
  return <div className="evidence-content">        {detail ? <><Badge value={detail.severity}/><h2>{detail.message}</h2><p className="path">{detail.file}:{detail.line}</p>
          {detail.source_url && <a href={detail.source_url} target="_blank" rel="noreferrer">Open exact source revision</a>}
          {source.length ? <pre className="source">{source.slice(Math.max(0, detail.line - 6), Math.max(0, detail.line - 6) + 16).map((line, i) => <div key={i} className={Math.max(1, detail.line - 5) + i === detail.line ? 'highlight' : ''}><span>{Math.max(1, detail.line - 5) + i}</span>{line}</div>)}</pre> : <p>Source preview unavailable or withheld. Use the immutable source link when available.</p>}
          <h3>Supporting observations</h3>{detail.origins.map(o => <div className="origin" key={o.observation_id}><strong>{o.scanner_family} | {o.rule}</strong><small>{o.file}:{o.start_line}</small><small>Artifact: {o.raw_artifact || 'Unavailable'}</small></div>)}
        </> : <Empty description={error || 'Issue evidence unavailable or loading...'}/>}</div>;
}

function App() {
  const screens = Grid.useBreakpoint();
  const [appearance, setAppearance] = useState(() => { try { return localStorage.getItem('analysis-theme') || 'dark'; } catch { return 'dark'; } });
  const [runOpen, setRunOpen] = useState(false);
  const [selection, setSelection] = useState('');
  const [refreshTick, setRefreshTick] = useState(0);
  const [lastRefresh, setLastRefresh] = useState('');
  useEffect(() => { document.documentElement.dataset.theme = appearance; try { localStorage.setItem('analysis-theme', appearance); } catch {} }, [appearance]);
  const [category, setCategory] = useState('');
  const [channelStatus, setChannelStatus] = useState('');
  const [directory, setDirectory] = useState('');
  const [index, setIndex] = useState<Index>(); const [error, setError] = useState(''); const [r, setRoute] = useState(route());
  const [report, setReport] = useState<Report>(); const [findings, setFindings] = useState<Finding[]>([]); const [detail, setDetail] = useState<Detail>(); const [source, setSource] = useState<string[]>([]);
  const [query, setQuery] = useState(''); const [severity, setSeverity] = useState(''); const [scanner, setScanner] = useState(''); const [page, setPage] = useState(0); const [loading, setLoading] = useState(false);
  useEffect(() => { const c = new AbortController(); const refresh = () => json<Index>('data/index.json', c.signal).then(value => { setIndex(value); setLastRefresh(new Date().toISOString()); }).catch(e => { if (e.name !== 'AbortError') setError(e.message); }); refresh(); const timer = window.setInterval(refresh, 60000); const change = () => setRoute(route()); window.addEventListener('hashchange', change); return () => { c.abort(); window.clearInterval(timer); window.removeEventListener('hashchange', change); }; }, [refreshTick]);
  const target = index?.targets.find(t => t.id === r.target) || (!r.target ? index?.targets.find(t => t.kind === 'branch' && t.branch === index.preferred_branch) || index?.targets[0] : undefined);
  useEffect(() => { setReport(undefined); setFindings([]); setDetail(undefined); setSource([]); setPage(0); setError(''); setLoading(false); if (!target?.report) return;
    const c = new AbortController(); setLoading(true); Promise.all([json<Report>(`data/${target.report}/report.json`, c.signal), json<Finding[]>(`data/${target.report}/findings.json`, c.signal)]).then(([a, b]) => { setReport(a); setFindings(b); }).catch(e => { if (e.name !== 'AbortError') setError(e.message); }).finally(() => { if (!c.signal.aborted) setLoading(false); }); return () => c.abort();
  }, [target?.id, target?.report]);
  useEffect(() => { setDetail(undefined); setSource([]); if (!r.issue || !target?.report) return; const f = findings.find(f => f.id === r.issue); if (!f) return; const c = new AbortController();
    json<Detail[]>(`data/${target.report}/details/${f.page}.json`, c.signal).then(async rows => { const d = rows.find(d => d.id === f.id); setDetail(d); if (d?.source) setSource(await json<string[]>(`data/${target.report}/${d.source}`, c.signal)); }).catch(e => { if (e.name !== 'AbortError') setError(e.message); }); return () => c.abort();
  }, [r.issue, findings, target?.report]);
  const filtered = useMemo(() => findings.filter(f => (!directory || (f.file.includes('/') ? f.file.slice(0, f.file.lastIndexOf('/')) : '(root)') === directory) && (!severity || f.severity === severity) && (!scanner || f.scanners.includes(scanner)) && `${f.message} ${f.file} ${f.rules.join(' ')}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => (ranks[a.severity] ?? 9) - (ranks[b.severity] ?? 9) || a.file.localeCompare(b.file)), [findings, query, severity, scanner, directory]);
  useEffect(() => setPage(0), [query, severity, scanner, directory]);
  const directories = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach(f => { const dir = f.file.includes('/') ? f.file.slice(0, f.file.lastIndexOf('/')) : '(root)'; counts.set(dir, (counts.get(dir) || 0) + 1); });
    return [...counts].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [findings]);
  const support = useMemo(() => [1, 2, 3].map(n => ({ n, count: findings.filter(f => n === 3 ? new Set(f.scanners).size >= 3 : new Set(f.scanners).size === n).length })), [findings]);
  useEffect(() => {
    if (!r.issue || !screens.lg) return;
    const close = (e: KeyboardEvent) => { if (e.key === 'Escape') navigate(target?.id || '', 'issues'); };
    window.addEventListener('keydown', close); return () => window.removeEventListener('keydown', close);
  }, [r.issue, screens.lg, target?.id]);
  const fresh = !!report && report.analyzed_sha === target?.head_sha;
  const completed = report?.channels.filter(c => ['COMPLETED', 'COMPLETED_OPTIONAL', 'CONFIGURED_COMPLETE', 'POLICY_FINDINGS'].includes(c.status)).length || 0;
  return <ConfigProvider theme={{ algorithm: appearance === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm, token: { colorPrimary: appearance === 'dark' ? '#7bd0ff' : '#1765ad', colorLink: appearance === 'dark' ? '#7bd0ff' : '#1765ad', colorLinkHover: appearance === 'dark' ? '#b3e5ff' : '#124c85', colorBgBase: appearance === 'dark' ? '#071523' : '#f4f7fa', colorBgContainer: appearance === 'dark' ? '#102131' : '#ffffff', colorText: appearance === 'dark' ? '#dce8f5' : '#202d3d', colorTextSecondary: appearance === 'dark' ? '#a6b8c9' : '#52657a', colorBorder: appearance === 'dark' ? '#304459' : '#c9d4df', borderRadius: 6, fontFamily: 'Segoe UI, sans-serif' }, components: { Button: { primaryColor: appearance === 'dark' ? '#071523' : '#ffffff' } } }}>
    <header className="topbar"><a className="brand" href="#"><CodeOutlined/> Code Analysis</a><Space wrap><Segmented aria-label="Color theme" value={appearance} options={[{label:'Dark',value:'dark'},{label:'Light',value:'light'}]} onChange={setAppearance}/><Button type="primary" onClick={() => { setSelection(target?.kind === 'commit' ? target.head_sha : target?.pr ? `PR #${target.pr}` : target?.branch || ''); setRunOpen(true); }}>Run analysis</Button><a href={`https://github.com/${index?.analysis_repository || 'combustrrr/Agentic-Kibana'}/actions`} target="_blank" rel="noreferrer"><GithubOutlined/> Workflows</a></Space></header>
    <Modal title="Run source analysis" open={runOpen} onCancel={() => setRunOpen(false)} footer={null}>
        <p>Select a branch or PR, or paste a full commit SHA or upstream GitHub URL. GitHub Actions runs the scanners with your repository permissions.</p>
        <Select className="run-target-select" aria-label="Available analysis targets" placeholder="Choose a discovered target" value={index?.targets.some(t => t.id === selection) ? selection : undefined} options={index?.targets.map(t => ({value:t.id,label:t.label}))} onChange={setSelection}/>
        <Input aria-label="Analysis target" value={selection} onChange={e => setSelection(e.target.value)} placeholder="Testing, PR #123, full commit SHA, or GitHub URL"/>
        <ol><li>Copy the target: <Typography.Text copyable={{text:selection}} code>{selection || 'Enter a target above'}</Typography.Text></li><li>Open GitHub Actions below and select <strong>Run workflow</strong>. Keep the workflow branch at the fork default, <strong>Testing</strong>.</li><li>Paste the target into <strong>refresh_target</strong>, then run the workflow.</li></ol>
        <Alert type="info" showIcon title="Results update automatically" description="The dashboard checks published reports every minute. Publication runs about every 10 minutes after analysis. Branch discovery runs hourly. One explicitly selected commit or closed PR is retained alongside active targets; a new manual selection replaces that slot."/>
        <Button type="primary" href={`https://github.com/${index?.analysis_repository || 'combustrrr/Agentic-Kibana'}/actions/workflows/10-analysis-discovery.yml`} target="_blank" rel="noreferrer">Open Run analysis in GitHub</Button>
      </Modal>
    <main>
      <section className="project">
        <div className="eyebrow">SOURCE REPOSITORY</div><h1>{target?.repository || 'Code quality dashboard'}</h1>
        <div className="target-row"><label htmlFor="target">Branch or pull request</label>
          <Select id="target" aria-label="Branch or pull request" showSearch optionFilterProp="label" value={target?.id} placeholder="Select a target" onChange={value => navigate(value, r.tab)} options={['branch', 'pr', 'commit'].map(kind => ({ label: kind === 'branch' ? 'Branches' : kind === 'pr' ? 'Pull requests' : 'Selected commit', options: index?.targets.filter(t => t.kind === kind).map(t => ({ value: t.id, label: t.label })) || [] }))}/>
          {target && <Badge value={target.status || 'queued'}/>}
        </div>
        {target?.pr && <p>Source {target.source_repository}:{target.branch} to {target.base_branch} | head analysis, not merge validation</p>}
        <Descriptions className="identity" size="small" column={{ xs: 1, sm: 1, md: 2 }} items={[
          { key: 'head', label: 'DISCOVERED HEAD', children: <code>{target?.head_sha || 'Unavailable'}</code> },
          { key: 'analyzed', label: 'ANALYZED COMMIT', children: <code>{report?.analyzed_sha || 'Not analyzed'}</code> },
          { key: 'checked', label: 'HEAD LAST CHECKED', children: date(target?.checked_at || index?.checked_at) },
          { key: 'time', label: 'ANALYSIS COMPLETED', children: date(report?.generated_at) }
        ]}/>
        <Space wrap className="runs">
          <span>Reports checked: {date(lastRefresh)}</span><Button size="small" onClick={() => setRefreshTick(t => t + 1)}>Refresh results</Button>
          {target?.scan_run_id && !report?.producer_runs.some(run => run.id === String(target.scan_run_id)) && <a href={`https://github.com/${index!.analysis_repository}/actions/runs/${target.scan_run_id}`} target="_blank" rel="noreferrer">Current scan #{target.scan_run_id}</a>}
          {index && <span>{index.targets.length} active targets | {index.targets.filter(t => t.status === 'queued').length} queued | {index.targets.filter(t => t.status === 'scanning').length} scanning</span>}
          {report?.tooling_sha && <span>Tooling <code title={report.tooling_sha}>{report.tooling_sha.slice(0, 12)}</code> | attempt {report.producer_run_attempt ?? 'Unavailable'}</span>}
          {report?.producer_runs.map(run => <a key={run.id} href={run.url} target="_blank" rel="noreferrer">Run #{run.id}</a>)}
        </Space>
      </section>
      {(error || index?.discovery_error || index?.publication_error || target?.error) && <Alert showIcon type="error" title="Report service error" description={error || index?.discovery_error || index?.publication_error || target?.error}/>}
      {report && (!fresh || report.status === 'partial') && <Alert showIcon type="warning" title={!fresh ? 'Newer head awaiting analysis' : 'Analysis is incomplete'} description={!fresh ? 'These findings belong to the older analyzed commit shown above.' : 'Available findings are shown. Unavailable scanners do not mean zero issues.'}/>}
      <Tabs activeKey={r.tab} onChange={tab => navigate(target?.id || '', tab)} items={['overview', 'issues', 'scanners', 'provenance'].map(tab => ({ key: tab, label: tab[0].toUpperCase() + tab.slice(1) + (tab === 'issues' && report ? ` (${report.finding_count.toLocaleString()})` : '') }))}/>
      {!report ? <div className="empty" role="status"><Empty description={loading ? 'Loading the selected report...' : r.target && !target ? 'Target no longer active' : 'No report available yet'}/></div> : <>
        {r.tab === 'overview' && <>
          <section className="metrics">{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <div key={s}><Statistic title={<Badge value={s}/>} value={report.severities[s] || 0}/><Button type="link" onClick={() => { setSeverity(s); navigate(target!.id, 'issues'); }}>View findings</Button></div>)}</section>
          <section className="summary"><div><h2>Reported issues</h2><p>{report.finding_count.toLocaleString()} findings from {report.observation_count.toLocaleString()} scanner observations.</p><p>Inspect the rule, exact source location, and evidence behind each finding.</p><Button type="primary" onClick={() => { setSeverity(''); setDirectory(''); setQuery(''); setScanner(''); navigate(target!.id, 'issues'); }}>Browse issues</Button></div>
            <div><h2>Scanner execution</h2><p>{completed} of {report.channels.length} channels completed.</p><Progress strokeColor="#7bd0ff" percent={Math.round(completed / Math.max(1, report.channels.length) * 100)} showInfo={false} aria-label={`${completed} of ${report.channels.length} channels completed`}/><p>Strict evidence gate: <strong>{report.publication_gate.satisfied ? 'Passed' : 'Not satisfied'}</strong></p><Button onClick={() => navigate(target!.id, 'scanners')}>Inspect every scanner</Button></div></section>
        </>}
        {r.tab === 'overview' && <section className="insights-grid">
          <article className="panel"><h2>Severity distribution</h2><p>Composition of the available findings at this revision.</p>{Object.keys(ranks).map(level => <div className="distribution" key={level}><Badge value={level}/><Progress strokeColor="#7bd0ff" percent={report.finding_count ? (report.severities[level] || 0) / report.finding_count * 100 : 0} showInfo={false}/><span>{(report.severities[level] || 0).toLocaleString()}</span></div>)}</article>
          <article className="panel"><h2>Scanner overlap</h2><p>Distinct scanner families supporting each canonical finding. This measures overlap, not confidence.</p>{support.map(({ n, count }) => <div className="support-row" key={n}><span>{n === 3 ? '3 or more scanners' : `${n} scanner${n === 1 ? '' : 's'}`}</span><strong>{count.toLocaleString()}</strong><Progress strokeColor="#7bd0ff" percent={report.finding_count ? count / report.finding_count * 100 : 0} showInfo={false}/></div>)}</article>
          <article className="panel"><h2>Directories with most findings</h2><p>Finding counts, without normalization by code size.</p>{directories.map(([dir, count]) => <div className="directory-row" key={dir}><Button type="link" onClick={() => { setDirectory(dir); setQuery(''); setSeverity(''); setScanner(''); navigate(target!.id, 'issues'); }}>{dir}</Button><strong>{count.toLocaleString()}</strong><Progress strokeColor="#7bd0ff" percent={count / Math.max(1, directories[0][1]) * 100} showInfo={false}/></div>)}</article>
          <article className="panel"><h2>Highest severity findings</h2><p>Open the original location and scanner observations.</p>{[...findings].sort((a,b) => (ranks[a.severity] ?? 9) - (ranks[b.severity] ?? 9)).slice(0, 4).map(f => <div className="priority-row" key={f.id}><Badge value={f.severity}/><Button type="link" onClick={() => navigate(target!.id, 'issues', f.id)}>{f.message}</Button><small>{f.file}:{f.line}</small></div>)}</article>
        </section>}
        {r.tab === 'provenance' && <section className="insights-grid">
          <article className="panel"><h2>Analysis identity</h2><Descriptions column={1} items={[
            {key:'source',label:'Source repository',children:target!.source_repository},
            {key:'sha',label:'Analyzed revision',children:<code>{report.analyzed_sha}</code>},
            {key:'tool',label:'Trusted tooling revision',children:<code>{report.tooling_sha || 'Unavailable'}</code>},
            {key:'base',label:'PR base revision',children:<code>{target!.base_sha || 'Not applicable'}</code>},
            {key:'attempt',label:'Producer attempt',children:report.producer_run_attempt ?? 'Unavailable'},
            {key:'schema',label:'Collection schema',children:index?.schema_version}
          ]}/></article>
          <article className="panel"><h2>Producing workflows</h2><p>These exact runs produced the displayed report.</p>{report.producer_runs.map(run => <div className="origin" key={run.id}><GithubOutlined/> <a href={run.url} target="_blank" rel="noreferrer">Run #{run.id}</a></div>)}<h3>Evidence gate</h3><Tag color={report.publication_gate.satisfied ? 'green' : 'orange'}>{report.publication_gate.satisfied ? 'Passed' : 'Not satisfied'}</Tag><p>The evidence gate and scanner completeness are separate. {completed} of {report.channels.length} channels completed.</p><p>Individual finding details identify their source observations and retained artifact paths.</p></article>
        </section>}
        {r.tab === 'scanners' && <><Alert showIcon type="info" title="Scanner execution and evidence" description="Execution failures are separate from code findings. Unavailable counts are unknown; completed policy findings can still require attention."/>
          <div className="filters"><Select aria-label="Scanner category" value={category} onChange={setCategory} options={[{value:'',label:'All categories'}, ...[...new Set(report.channels.map(c => c.class))].sort().map(c => ({value:c,label:c}))]}/><Select aria-label="Execution status" value={channelStatus} onChange={setChannelStatus} options={[{value:'',label:'All statuses'}, ...[...new Set(report.channels.map(c => c.status))].sort().map(c => ({value:c,label:c.replaceAll('_',' ')}))]}/><span>{report.channels.filter(c => (!category || c.class === category) && (!channelStatus || c.status === channelStatus)).length} channels</span></div>
          <Table<Channel> rowKey="channel" size="middle" dataSource={report.channels.filter(c => (!category || c.class === category) && (!channelStatus || c.status === channelStatus))} pagination={false} scroll={{ x: 850 }} columns={[
            { title: 'Scanner', key: 'scanner', width: 210, render: (_, c) => <><strong>{c.name}</strong><small>{c.class}</small></> },
            { title: 'Status', key: 'status', width: 200, render: (_, c) => <Badge value={c.status}/> },
            { title: 'Findings', key: 'findings', width: 110, render: (_, c) => c.findings === null ? 'Unavailable' : c.findings.toLocaleString() },
            { title: 'Workflow / evidence limitations', key: 'reason', render: (_, c) => <>{c.reason || 'Retained evidence available'}<small>Scanner definition: {c.workflow}</small></> }
          ]}/></>}
        {r.tab === 'issues' && <>
          {directory && <Tag closable onClose={() => setDirectory('')}>Directory: {directory}</Tag>}
          <div className="filters"><Input aria-label="Search issues" prefix={<SearchOutlined/>} placeholder="Search message, file, or rule" allowClear value={query} onChange={e => setQuery(e.target.value)}/>
            <Select aria-label="Severity" value={severity} onChange={setSeverity} options={[{ value: '', label: 'All severities' }, ...Object.keys(ranks).map(s => ({ value: s, label: s }))]}/>
            <Select aria-label="Scanner" showSearch optionFilterProp="label" value={scanner} onChange={setScanner} options={[{ value: '', label: 'All scanners' }, ...[...new Set(findings.flatMap(f => f.scanners))].sort().map(s => ({ value: s, label: s }))]}/>
            <span>{filtered.length.toLocaleString()} results</span>
          </div>
          <div className={r.issue && screens.lg ? "findings-workspace split" : "findings-workspace"}><div className="findings-list"><Table<Finding> rowKey="id" size="middle" dataSource={filtered} scroll={{ x: r.issue && screens.lg ? undefined : 760 }} rowClassName={f => r.issue === f.id ? 'selected' : ''} locale={{ emptyText: 'No findings match these filters.' }} pagination={{ current: page + 1, pageSize: 50, showSizeChanger: false, onChange: p => setPage(p - 1), showTotal: total => `${total.toLocaleString()} findings` }} columns={r.issue && screens.lg ? [{title:'Findings',key:'compact',render:(_,f) => <><Badge value={f.severity}/><Button type="link" className="issue-link" onClick={() => navigate(target!.id, 'issues', f.id)}>{f.message}</Button><small>{f.file}:{f.line}</small><small>{f.scanners.join(', ')} | {f.rules.join(', ')}</small></>}] : [
            { title: 'Severity', key: 'severity', width: 120, render: (_, f) => <Badge value={f.severity}/> },
            { title: 'Issue and source', key: 'issue', render: (_, f) => <><Button type="link" className="issue-link" onClick={() => navigate(target!.id, 'issues', f.id)}>{f.message}</Button><small>{f.file}{f.line ? `:${f.line}` : ''}</small></> },
            { title: 'Scanner / rule', key: 'scanner', width: 240, render: (_, f) => <>{f.scanners.join(', ')}<small>{f.rules.join(', ')}</small></> }
          ]}/></div>
          {r.issue && screens.lg && <section className="evidence-panel" aria-label="Issue detail"><div className="pane-heading"><h2>Issue detail</h2><Button onClick={() => navigate(target!.id, 'issues')}>Close issue</Button></div><Evidence detail={detail} source={source} error={error}/></section>}
          </div>
        </>}
      </>}
      <Drawer title="Issue detail" open={!!r.issue && r.tab === 'issues' && !screens.lg} onClose={() => navigate(target?.id || '', 'issues')} size="min(850px, 100vw)" destroyOnHidden>
        <Evidence detail={detail} source={source} error={error}/>
      </Drawer>
      <footer>{index?.metrics && <span>Site data and UI: ~{(index.metrics.site_bytes / 1000000).toFixed(1)} MB / {(index.metrics.site_limit_bytes / 1000000).toFixed(0)} MB limit. </span>}Findings are scanner observations, not confirmed defects. Viewing this page never starts a scan.</footer>
    </main>
  </ConfigProvider>;
}
createRoot(document.getElementById('root')!).render(<App/>);
