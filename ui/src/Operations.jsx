import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, ArrowUpRight, CheckCircle2, Download, FileText, History, RefreshCw, Search, Server, ShieldCheck, WifiOff } from 'lucide-react';
import { api, query } from './api';
import { downloadCsv, percent } from './monitoring';

export function useHistoryReport(days) {
  const [state, setState] = useState({ report: null, loading: true, error: '' });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setState({ report: null, loading: true, error: '' });
    const end = Math.floor(Date.now() / 1000);
    query('/history/summary', { from_ts: end - days * 86400, to_ts: end })
      .then(report => { if (!cancelled) setState({ report, loading: false, error: '' }); })
      .catch(error => { if (!cancelled) setState({ report: null, loading: false, error: error.message }); });
    return () => { cancelled = true; };
  }, [days, revision]);
  return { ...state, reload: () => setRevision(value => value + 1) };
}

export function HealthStrip({ health, lastSync, t, language }) {
  return <div className={`health-strip health-${health}`} role={health === 'live' ? 'status' : 'alert'}>
    {health === 'live' ? <ShieldCheck /> : <AlertTriangle />}
    <strong>{t(`health_${health}`)}</strong>
    {health !== 'live' && <span>{t('healthUnsafeHelp')}</span>}
    <time>{t('lastSync')}: {lastSync ? new Date(lastSync * 1000).toLocaleTimeString(language === 'he' ? 'he-IL' : 'en-GB') : '—'}</time>
  </div>;
}

export function ReportMethod({ t, children }) {
  return <details className="report-method"><summary><FileText /><strong>{t('historyEstimate')}</strong><span>{t('methodDetails')}</span></summary><p>{t('historyEstimateHelp')}</p>{children}</details>;
}

export function OperationsOverview({ data, t, setRoute, health, children }) {
  const devices = (data.devices || []).filter(d => !d.ignored && !d.quarantined && !d.trashed_at);
  const issues = devices.filter(d => d.status !== 'online').sort((a, b) => Number(Boolean(b.critical)) - Number(Boolean(a.critical)) || Number(a.status !== 'offline') - Number(b.status !== 'offline'));
  const critical = issues.filter(d => d.critical).length;
  const groups = Object.values(devices.reduce((all, device) => {
    const key = device.category || '';
    const group = all[key] ||= { name: key, total: 0, online: 0, offline: 0, unstable: 0, other: 0 };
    group.total++;
    group[device.status === 'online' ? 'online' : device.status === 'offline' ? 'offline' : device.status === 'unstable' ? 'unstable' : 'other']++;
    return all;
  }, Object.create(null))).sort((a, b) => b.offline - a.offline || b.unstable - a.unstable || b.other - a.other || a.name.localeCompare(b.name));
  const online = devices.filter(d => d.status === 'online').length;
  const offline = devices.filter(device => device.status === 'offline').length;
  const unstable = devices.filter(device => device.status === 'unstable').length;
  const summary = data.viewer?.summary;
  const availability = summary?.series?.some(point => !point.inferred && point.availability_pct != null) ? summary.availability_24h : null;
  const preview = [...devices].sort((a, b) => Number(b.status === 'offline') - Number(a.status === 'offline') || Number(Boolean(b.critical)) - Number(Boolean(a.critical)) || (a.display_name || a.ip).localeCompare(b.display_name || b.ip)).slice(0, 3);
  return <>
    <section className={`aura-hero overview-command snapshot-${health}`} aria-label={t('overview')}>
      <div className="overview-command-heading"><div><h1>{t('overview')}</h1><span>{devices.length} {t('devices')} · {t('last24h')}</span></div><button className="button subtle" onClick={() => setRoute('viewer')}>{t('viewer')}<ArrowUpRight /></button></div>
      <section className="overview-metric-row" aria-label={t('status')}>
        <button className={`overview-metric metric-availability state-${availability == null ? 'unknown' : availability >= 99 ? 'online' : availability >= 60 ? 'warning' : 'offline'}`} onClick={() => setRoute('history')}><span>{t('availabilityEstimate')}<ShieldCheck /></span><strong>{percent(availability)}</strong><small>{t('last24h')}</small></button>
        <button className="overview-metric metric-online state-online" onClick={() => setRoute('devices/online')}><span>{t('online')}<Server /></span><strong>{online}</strong><small>{online} / {devices.length} {t('devices')}</small></button>
        <button className={`overview-metric metric-offline state-${offline ? 'offline' : unstable ? 'unstable' : 'online'}`} onClick={() => setRoute(offline ? 'devices/offline' : unstable ? 'devices/unstable' : 'devices/offline')}><span>{t('offline')}<WifiOff /></span><strong>{offline}</strong><small>{unstable} {t('unstable')} · {critical} {t('critical')}</small></button>
      </section>
      {health !== 'live' && <span className="aura-snapshot-note">{t('lastKnownSnapshot')}</span>}
    </section>
    <div className="ops-grid overview-analysis">
      {children}
      <section className="panel ops-incidents"><div className="section-heading"><h2>{t('priorityQueue')}</h2><span className="count-badge">{critical > 0 ? `${critical} ${t('critical')}` : issues.length}</span></div>
        <div className="ops-issue-list">{issues.slice(0, 1).map(device => <button className={`state-${device.status} ${device.critical ? 'critical' : ''}`} key={device.ip} onClick={() => setRoute(`devices/${encodeURIComponent(device.ip)}`)}><span><strong>{device.display_name || device.name || device.ip}</strong><small><bdi>{device.ip}</bdi> · {device.category || t('uncategorized')}</small></span><span className={`state-chip state-${device.status}`}>{device.critical && <AlertTriangle />}{t(device.status)}</span><ArrowUpRight /></button>)}</div>
        {!issues.length && <div className="ops-empty"><CheckCircle2 /><strong>{t(devices.length && health === 'live' ? 'noActiveIssues' : 'noMeasurements')}</strong></div>}
        {issues.length > 1 && <button className="text-action" onClick={() => setRoute('devices')}>{t('viewAll')} ({issues.length}) <ArrowUpRight /></button>}
      </section>
    </div>
    <section className="panel overview-inventory"><div className="section-heading"><h2>{t('devices')}</h2><button className="text-action" onClick={() => setRoute('devices')}>{t('viewAll')}<ArrowUpRight /></button></div><div className="overview-inventory-rows">{preview.map(device => <button className={`overview-device-row state-${device.status} ${device.critical ? 'critical' : ''}`} key={device.ip} onClick={() => setRoute(`devices/${encodeURIComponent(device.ip)}`)}><Server /><span><strong>{device.display_name || device.name || device.ip}</strong><small>{device.category || t('uncategorized')}</small></span><bdi>{device.ip}</bdi><span className="overview-device-state">{t(device.status)}</span><small>{t(device.approved || device.manual ? 'alwaysMonitored' : 'discoveredDevice')}</small><ArrowUpRight /></button>)}</div>{!devices.length && <p className="ops-empty">{t('noMeasurements')}</p>}</section>
    <details className="panel ops-categories aura-category-summary"><summary>{t('categories')}<Activity /></summary><div className="ops-category-list">{groups.map(group => <button key={group.name} onClick={() => setRoute(`devices/category:${encodeURIComponent(group.name)}`)}><span><strong>{group.name || t('uncategorized')}</strong><small><bdi dir="ltr">{group.online} / {group.total}</bdi> {t('online')}</small></span><div className="segmented-meter" aria-label={`${group.online} ${t('online')}, ${group.offline} ${t('offline')}`}><i style={{ flex: group.online }} /><i style={{ flex: group.offline }} /><i style={{ flex: group.unstable + group.other }} /></div><b>{group.offline ? `${group.offline} ${t('offline')}` : group.unstable + group.other ? `${group.unstable + group.other} ${t('requiresAttention')}` : t('online')}</b></button>)}</div>{!groups.length && <p className="ops-empty">{t('noMeasurements')}</p>}</details>
  </>;
}

export function ReportsPage({ t, language, setRoute }) {
  const [days, setDays] = useState(7);
  const [category, setCategory] = useState('*');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const { report, loading, error, reload } = useHistoryReport(days);
  const rows = useMemo(() => (report?.devices || []).filter(row => (category === '*' || row.category === category) && `${row.name} ${row.ip}`.toLowerCase().includes(search.toLowerCase())).sort((a, b) => b.offline_count - a.offline_count || a.name.localeCompare(b.name)), [report, category, search]);
  useEffect(() => setPage(0), [days, category, search]);
  const categories = [...new Set((report?.devices || []).map(row => row.category || ''))].sort();
  const locale = language === 'he' ? 'he-IL' : 'en-GB';
  const date = ts => ts ? new Date(ts * 1000).toLocaleString(locale) : '—';
  const exportReport = () => downloadCsv(`homeii-report-${days}d.csv`, [
    [t('reports'), `${days} ${t('days')}`], [t('reportFrom'), date(report.window?.from_ts)], [t('reportTo'), date(report.window?.to_ts)],
    [t('reportMethod'), t('historyEstimateHelp')],
    [t('name'), t('ip'), t('category'), t('availabilityEstimate'), t('historyCoverage'), t('disconnects'), t('recoveries')],
    ...rows.map(row => [row.name, row.ip, row.category, percent(row.availability_pct), percent(row.coverage_pct), row.offline_count, row.recovery_count]),
  ]);
  return <div className="page-stack reports-page">
    <div className="page-heading"><div><h1>{t('reports')}</h1></div><div className="report-actions"><button className="button" onClick={reload} disabled={loading}><RefreshCw className={loading ? 'spin' : ''} />{t('reloadReport')}</button><button className="button primary" onClick={exportReport} disabled={loading || !rows.length || Boolean(error)}><Download />{t('exportReport')}</button></div></div>
    <section className="panel report-controls"><label>{t('reportPeriod')}<select value={days} onChange={event => setDays(Number(event.target.value))}>{[1, 7, 30, 90, 365].map(value => <option key={value} value={value}>{value} {t('days')}</option>)}</select></label><label>{t('category')}<select value={category} onChange={event => setCategory(event.target.value)}><option value="*">{t('allCategories')}</option>{categories.map(value => <option key={value} value={value}>{value || t('uncategorized')}</option>)}</select></label><label>{t('searchDevices')}<input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder={t('nameOrIp')} /></label></section>
    <ReportMethod t={t}>{report?.window && <small>{date(report.window.from_ts)} — {date(report.window.to_ts)}</small>}</ReportMethod>
    {error && <div className="error-banner" role="alert">{t('reportLoadFailed')}: {error}</div>}
    {loading ? <div className="ops-empty" role="status"><RefreshCw className="spin" />{t('loadingReport')}</div> : report && <>
      <section className="report-summary"><div><span>{t('devicesInReport')}</span><strong>{rows.length}</strong></div><div><span>{t('disconnects')}</span><strong>{rows.reduce((total, row) => total + row.offline_count, 0)}</strong></div><div><span>{t('recoveries')}</span><strong>{rows.reduce((total, row) => total + row.recovery_count, 0)}</strong></div><div><span>{t('withoutHistory')}</span><strong>{rows.filter(row => row.availability_pct == null).length}</strong></div></section>
      <section className="panel report-table-panel"><div className="section-heading"><h2>{t('deviceReliability')}</h2></div><div className="table-scroll"><table className="report-table"><thead><tr>{['name', 'category', 'availabilityEstimate', 'historyCoverage', 'disconnects', 'recoveries'].map(key => <th scope="col" key={key}>{t(key)}</th>)}</tr></thead><tbody>{rows.slice(page * 20, (page + 1) * 20).map(row => <tr key={row.ip}><td><button className="report-device-link" onClick={() => setRoute(`devices/${encodeURIComponent(row.ip)}`)}><strong>{row.name}</strong><small><bdi>{row.ip}</bdi></small></button></td><td>{row.category || t('uncategorized')}</td><td><strong>{percent(row.availability_pct)}</strong></td><td><span className="coverage-value">{percent(row.coverage_pct)}</span></td><td className={row.offline_count ? 'danger-text' : ''}>{row.offline_count}</td><td>{row.recovery_count}</td></tr>)}</tbody></table></div>{!rows.length && <div className="ops-empty">{t('noReportRows')}</div>}<div className="table-pagination"><span>{rows.length ? page * 20 + 1 : 0}–{Math.min((page + 1) * 20, rows.length)} / {rows.length}</span><button className="button" disabled={!page} onClick={() => setPage(value => value - 1)}>{t('previousPage')}</button><button className="button" disabled={(page + 1) * 20 >= rows.length} onClick={() => setPage(value => value + 1)}>{t('nextPage')}</button></div></section>
    </>}
  </div>;
}

export function AuditLog({ t, language }) {
  const [records, setRecords] = useState([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(true);
  const [search, setSearch] = useState('');
  const [outcome, setOutcome] = useState('');
  const load = async () => {
    setBusy(true); setError('');
    try { setRecords((await api('/audit?limit=500')).records || []); }
    catch (error) { setError(error.message); }
    finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);
  const filtered = records.filter(record => (!outcome || record.outcome === outcome) && `${record.actor} ${record.action} ${record.target} ${record.client_ip}`.toLowerCase().includes(search.toLowerCase()));
  return <div className="audit-panel"><div className="settings-title"><History /><div><h2>{t('auditLog')}</h2><p>{t('auditLogHelp')}</p></div><button className="button settings-title-action" disabled={busy} onClick={load}><RefreshCw className={busy ? 'spin' : ''} />{t('refresh')}</button></div><div className="audit-filters"><label><Search />{t('searchAudit')}<input value={search} onChange={event => setSearch(event.target.value)} /></label><label>{t('outcome')}<select value={outcome} onChange={event => setOutcome(event.target.value)}><option value="">{t('all')}</option><option value="success">{t('success')}</option><option value="failed">{t('failed')}</option></select></label></div>{error && <div className="error-banner" role="alert">{error}</div>}<div className="audit-list" aria-busy={busy}>{filtered.map(record => <article key={record.id}><span className={`state-chip ${record.outcome === 'success' ? 'state-online' : 'state-offline'}`}>{t(record.outcome)}</span><div><strong>{record.actor}</strong><code>{record.action}</code><small>{record.target} · {record.client_ip}</small></div><time>{new Date(record.ts * 1000).toLocaleString(language === 'he' ? 'he-IL' : 'en-GB')}</time></article>)}</div>{!busy && !error && !filtered.length && <p className="ops-empty">{t('noReportRows')}</p>}<small>{t('auditLimit')}</small></div>;
}
