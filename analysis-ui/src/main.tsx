import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Alert, Button, ConfigProvider, Descriptions, Drawer, Empty, Input, Progress, Select, Space, Statistic, Table, Tabs, Tag } from 'antd';
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
  const compressed = await fetch(`${path}.gz`, { signal });
  if (compressed.ok) {
    if (compressed.headers.get('content-encoding') === 'gzip') return compressed.json();
    if (!compressed.body) throw new Error('Empty report response');
    return new Response(compressed.body.pipeThrough(new DecompressionStream('gzip'))).json();
  }
  // Uncompressed local fixtures remain usable without a separate development server.
  const r = await fetch(path, { signal }); if (!r.ok) throw new Error(`Report unavailable (${r.status}). Try again after the next publication.`); return r.json();
}
function route() { const p = new URLSearchParams(location.hash.slice(1)); return { target: p.get('target') || '', tab: p.get('tab') || 'overview', issue: p.get('issue') || '' }; }
function navigate(target: string, tab: string, issue = '') { location.hash = new URLSearchParams({ target, tab, ...(issue ? { issue } : {}) }).toString(); }
function date(s?: string) { return s ? new Date(s).toLocaleString() : 'Unavailable'; }
const colors: Record<string, string> = { CRITICAL: 'red', HIGH: 'volcano', MEDIUM: 'gold', LOW: 'blue', INFO: 'default', current: 'green', partial: 'orange', failed: 'red', scanning: 'blue', COMPLETED: 'green', CONFIGURED_COMPLETE: 'green', POLICY_FINDINGS: 'orange', NOT_AVAILABLE: 'orange', FAILED: 'red' };
function Badge({ value }: { value: string }) { return <Tag color={colors[value]}>{states[value] || value.replaceAll('_', ' ')}</Tag>; }

function App() {
  const [index, setIndex] = useState<Index>(); const [error, setError] = useState(''); const [r, setRoute] = useState(route());
  const [report, setReport] = useState<Report>(); const [findings, setFindings] = useState<Finding[]>([]); const [detail, setDetail] = useState<Detail>(); const [source, setSource] = useState<string[]>([]);
  const [query, setQuery] = useState(''); const [severity, setSeverity] = useState(''); const [scanner, setScanner] = useState(''); const [page, setPage] = useState(0); const [loading, setLoading] = useState(false);
  useEffect(() => { const c = new AbortController(); const refresh = () => json<Index>('data/index.json', c.signal).then(setIndex).catch(e => { if (e.name !== 'AbortError') setError(e.message); }); refresh(); const timer = window.setInterval(refresh, 60000); const change = () => setRoute(route()); window.addEventListener('hashchange', change); return () => { c.abort(); window.clearInterval(timer); window.removeEventListener('hashchange', change); }; }, []);
  const target = index?.targets.find(t => t.id === r.target) || (!r.target ? index?.targets.find(t => t.kind === 'branch' && t.branch === index.preferred_branch) || index?.targets[0] : undefined);
  useEffect(() => { setReport(undefined); setFindings([]); setDetail(undefined); setSource([]); setPage(0); setError(''); setLoading(false); if (!target?.report) return;
    const c = new AbortController(); setLoading(true); Promise.all([json<Report>(`data/${target.report}/report.json`, c.signal), json<Finding[]>(`data/${target.report}/findings.json`, c.signal)]).then(([a, b]) => { setReport(a); setFindings(b); }).catch(e => { if (e.name !== 'AbortError') setError(e.message); }).finally(() => { if (!c.signal.aborted) setLoading(false); }); return () => c.abort();
  }, [target?.id, target?.report]);
  useEffect(() => { setDetail(undefined); setSource([]); if (!r.issue || !target?.report) return; const f = findings.find(f => f.id === r.issue); if (!f) return; const c = new AbortController();
    json<Detail[]>(`data/${target.report}/details/${f.page}.json`, c.signal).then(async rows => { const d = rows.find(d => d.id === f.id); setDetail(d); if (d?.source) setSource(await json<string[]>(`data/${target.report}/${d.source}`, c.signal)); }).catch(e => { if (e.name !== 'AbortError') setError(e.message); }); return () => c.abort();
  }, [r.issue, findings, target?.report]);
  const filtered = useMemo(() => findings.filter(f => (!severity || f.severity === severity) && (!scanner || f.scanners.includes(scanner)) && `${f.message} ${f.file} ${f.rules.join(' ')}`.toLowerCase().includes(query.toLowerCase())).sort((a, b) => (ranks[a.severity] ?? 9) - (ranks[b.severity] ?? 9) || a.file.localeCompare(b.file)), [findings, query, severity, scanner]);
  useEffect(() => setPage(0), [query, severity, scanner]);
  const fresh = !!report && report.analyzed_sha === target?.head_sha;
  const completed = report?.channels.filter(c => ['COMPLETED', 'COMPLETED_OPTIONAL', 'CONFIGURED_COMPLETE', 'POLICY_FINDINGS'].includes(c.status)).length || 0;
  return <ConfigProvider theme={{ token: { colorPrimary: '#1765ad', borderRadius: 6, fontFamily: 'Inter, Segoe UI, sans-serif' } }}>
    <header className="topbar"><a className="brand" href="#"><CodeOutlined/> Code Analysis</a><a href={`https://github.com/${index?.analysis_repository || 'combustrrr/Agentic-Kibana'}/actions`} target="_blank" rel="noreferrer"><GithubOutlined/> Workflows</a></header>
    <main>
      <section className="project">
        <div className="eyebrow">SOURCE REPOSITORY</div><h1>{target?.repository || 'Code quality dashboard'}</h1>
        <div className="target-row"><label htmlFor="target">Branch or pull request</label>
          <Select id="target" aria-label="Branch or pull request" showSearch optionFilterProp="label" value={target?.id} placeholder="Select a target" onChange={value => navigate(value, r.tab)} options={['branch', 'pr'].map(kind => ({ label: kind === 'branch' ? 'Branches' : 'Open pull requests', options: index?.targets.filter(t => t.kind === kind).map(t => ({ value: t.id, label: t.label })) || [] }))}/>
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
          {target?.scan_run_id && !report?.producer_runs.some(run => run.id === String(target.scan_run_id)) && <a href={`https://github.com/${index!.analysis_repository}/actions/runs/${target.scan_run_id}`} target="_blank" rel="noreferrer">Current scan #{target.scan_run_id}</a>}
          {index && <span>{index.targets.length} active targets | {index.targets.filter(t => t.status === 'queued').length} queued | {index.targets.filter(t => t.status === 'scanning').length} scanning</span>}
          {report?.tooling_sha && <span>Tooling <code title={report.tooling_sha}>{report.tooling_sha.slice(0, 12)}</code> | attempt {report.producer_run_attempt ?? 'Unavailable'}</span>}
          {report?.producer_runs.map(run => <a key={run.id} href={run.url} target="_blank" rel="noreferrer">Run #{run.id}</a>)}
        </Space>
      </section>
      {(error || index?.discovery_error || index?.publication_error || target?.error) && <Alert showIcon type="error" title="Report service error" description={error || index?.discovery_error || index?.publication_error || target?.error}/>}
      {report && (!fresh || report.status === 'partial') && <Alert showIcon type="warning" title={!fresh ? 'Newer head awaiting analysis' : 'Analysis is incomplete'} description={!fresh ? 'These findings belong to the older analyzed commit shown above.' : 'Available findings are shown. Unavailable scanners do not mean zero issues.'}/>}
      <Tabs activeKey={r.tab} onChange={tab => navigate(target?.id || '', tab)} items={['overview', 'issues', 'scanners'].map(tab => ({ key: tab, label: tab[0].toUpperCase() + tab.slice(1) + (tab === 'issues' && report ? ` (${report.finding_count.toLocaleString()})` : '') }))}/>
      {!report ? <div className="empty" role="status"><Empty description={loading ? 'Loading the selected report...' : r.target && !target ? 'Target no longer active' : 'No report available yet'}/></div> : <>
        {r.tab === 'overview' && <>
          <section className="metrics">{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => <div key={s}><Statistic title={<Badge value={s}/>} value={report.severities[s] || 0}/><Button type="link" onClick={() => { setSeverity(s); navigate(target!.id, 'issues'); }}>View findings</Button></div>)}</section>
          <section className="summary"><div><h2>Reported issues</h2><p>{report.finding_count.toLocaleString()} findings from {report.observation_count.toLocaleString()} scanner observations.</p><p>Inspect the rule, exact source location, and evidence behind each finding.</p><Button type="primary" onClick={() => { setSeverity(''); navigate(target!.id, 'issues'); }}>Browse issues</Button></div>
            <div><h2>Scanner execution</h2><p>{completed} of {report.channels.length} channels completed.</p><Progress percent={Math.round(completed / Math.max(1, report.channels.length) * 100)} showInfo={false} aria-label={`${completed} of ${report.channels.length} channels completed`}/><p>Strict evidence gate: <strong>{report.publication_gate.satisfied ? 'Passed' : 'Not satisfied'}</strong></p><Button onClick={() => navigate(target!.id, 'scanners')}>Inspect every scanner</Button></div></section>
        </>}
        {r.tab === 'scanners' && <><Alert showIcon type="info" title="Scanner execution and evidence" description="Execution failures are separate from code findings. Unavailable counts are unknown; completed policy findings can still require attention."/>
          <Table<Channel> rowKey="channel" size="middle" dataSource={report.channels} pagination={false} scroll={{ x: 850 }} columns={[
            { title: 'Scanner', key: 'scanner', width: 210, render: (_, c) => <><strong>{c.name}</strong><small>{c.class}</small></> },
            { title: 'Status', key: 'status', width: 200, render: (_, c) => <Badge value={c.status}/> },
            { title: 'Findings', key: 'findings', width: 110, render: (_, c) => c.findings === null ? 'Unavailable' : c.findings.toLocaleString() },
            { title: 'Workflow / evidence limitations', key: 'reason', render: (_, c) => <>{c.reason || 'Retained evidence available'}<small>Scanner definition: {c.workflow}</small></> }
          ]}/></>}
        {r.tab === 'issues' && <>
          <div className="filters"><Input aria-label="Search issues" prefix={<SearchOutlined/>} placeholder="Search message, file, or rule" allowClear value={query} onChange={e => setQuery(e.target.value)}/>
            <Select aria-label="Severity" value={severity} onChange={setSeverity} options={[{ value: '', label: 'All severities' }, ...Object.keys(ranks).map(s => ({ value: s, label: s }))]}/>
            <Select aria-label="Scanner" showSearch optionFilterProp="label" value={scanner} onChange={setScanner} options={[{ value: '', label: 'All scanners' }, ...[...new Set(findings.flatMap(f => f.scanners))].sort().map(s => ({ value: s, label: s }))]}/>
            <span>{filtered.length.toLocaleString()} results</span>
          </div>
          <Table<Finding> rowKey="id" size="middle" dataSource={filtered} scroll={{ x: 760 }} rowClassName={f => r.issue === f.id ? 'selected' : ''} locale={{ emptyText: 'No findings match these filters.' }} pagination={{ current: page + 1, pageSize: 50, showSizeChanger: false, onChange: p => setPage(p - 1), showTotal: total => `${total.toLocaleString()} findings` }} columns={[
            { title: 'Severity', key: 'severity', width: 120, render: (_, f) => <Badge value={f.severity}/> },
            { title: 'Issue and source', key: 'issue', render: (_, f) => <><Button type="link" className="issue-link" onClick={() => navigate(target!.id, 'issues', f.id)}>{f.message}</Button><small>{f.file}{f.line ? `:${f.line}` : ''}</small></> },
            { title: 'Scanner / rule', key: 'scanner', width: 240, render: (_, f) => <>{f.scanners.join(', ')}<small>{f.rules.join(', ')}</small></> }
          ]}/>
        </>}
      </>}
      <Drawer title="Issue detail" open={!!r.issue && r.tab === 'issues'} onClose={() => navigate(target?.id || '', 'issues')} size="min(850px, 100vw)" destroyOnHidden>
        {detail ? <><Badge value={detail.severity}/><h2>{detail.message}</h2><p className="path">{detail.file}:{detail.line}</p>
          {detail.source_url && <a href={detail.source_url} target="_blank" rel="noreferrer">Open exact source revision</a>}
          {source.length ? <pre className="source">{source.slice(Math.max(0, detail.line - 6), Math.max(0, detail.line - 6) + 16).map((line, i) => <div key={i} className={Math.max(1, detail.line - 5) + i === detail.line ? 'highlight' : ''}><span>{Math.max(1, detail.line - 5) + i}</span>{line}</div>)}</pre> : <p>Source preview unavailable or withheld. Use the immutable source link when available.</p>}
          <h3>Supporting observations</h3>{detail.origins.map(o => <div className="origin" key={o.observation_id}><strong>{o.scanner_family} | {o.rule}</strong><small>{o.file}:{o.start_line}</small><small>Artifact: {o.raw_artifact || 'Unavailable'}</small></div>)}
        </> : <Empty description={error || 'Loading issue evidence...'}/>}
      </Drawer>
      <footer>{index?.metrics && <span>Site data and UI: ~{(index.metrics.site_bytes / 1000000).toFixed(1)} MB / {(index.metrics.site_limit_bytes / 1000000).toFixed(0)} MB limit. </span>}Findings are scanner observations, not confirmed defects. Viewing this page never starts a scan.</footer>
    </main>
  </ConfigProvider>;
}
createRoot(document.getElementById('root')!).render(<App/>);
