import { useEffect, useState } from 'react';
import { api } from './api';
import { Tools, UserManagement } from './App';
import { AuditLog } from './Operations';
import { translator } from './i18n';

export default function EngineOperations({ tab, language, user, l }) {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);
  const [days, setDays] = useState(1);
  const [page, setPage] = useState(0);
  const t = translator(language);
  useEffect(() => {
    if (tab !== 'reports') return;
    let cancelled = false;
    setBusy(true); setError('');
    (async () => {
      const all = [];
      for (let page=1; page<=100; page++) {
        const data = await api(`/engine/devices?page=${page}&limit=100`);
        if (cancelled) return;
        if (data.stale) throw new Error('Monitoring unavailable');
        all.push(...data.devices);
        if (all.length >= data.total) break;
      }
      if (!cancelled) setRows(all);
    })().catch(e => { if (!cancelled) setError(e.message); }).finally(() => { if (!cancelled) setBusy(false); });
    return () => { cancelled=true; };
  }, [tab]);
  if (tab === 'tools') return <Tools data={{devices:[]}} t={t}/>;
  if (tab === 'users') return <UserManagement t={t} currentUser={user}/>;
  if (tab === 'audit') return <AuditLog t={t} language={language}/>;
  const exportCsv = () => {
    const escape = v => '"'+String(v ?? '').replaceAll('"','""').replace(/^[=+@-]/,"'$&")+'"';
    const values = [['Name','IP','Status','Groups','Location','Critical','Latency ms','Loss %'], ...rows.map(d => [d.name,d.ip,d.status,d.groups.join(', '),d.location,d.critical,d.latency_ms,d.loss_percent])];
    const url = URL.createObjectURL(new Blob(['\uFEFF'+values.map(r=>r.map(escape).join(',')).join('\r\n')], {type:'text/csv;charset=utf-8'}));
    const a=document.createElement('a'); a.href=url;a.download='homeii-zabbix-inventory.csv';a.click();URL.revokeObjectURL(url);
  };
  return <section className="z-section"><h1>{l('דוחות וסטטיסטיקות','Reports and statistics')}</h1>
    <p>{l('מלאי מהמנוע הפעיל. בחר התקן להפקת דוח מדידות לתקופה.','Inventory from the active engine. Select a device for a period report.')}</p>
    {error && <p role="alert">{error}</p>}
    <div className="z-toolbar"><select aria-label={l('תקופת דוח','Report period')} value={days} onChange={e=>{setDays(Number(e.target.value));setReport(null);}}>{[1,7,30].map(n=><option key={n} value={n}>{n} {l('ימים','days')}</option>)}</select><button disabled={busy || !!error || !rows.length} onClick={exportCsv}>{l('ייצוא מלאי CSV','Export inventory CSV')}</button></div>
    <p>{busy ? l('טוען…','Loading…') : `${rows.length} ${l('התקנים','devices')}`}</p>
    {report && <section className="z-notice"><strong>{report.name}</strong><span>{l('בדיקות מוצלחות','Successful checks')}: {report.availability ?? '—'}% · {l('כיסוי מדידות','Coverage')}: {report.coverage}% · {report.samples} {l('בדיקות','checks')}{report.truncated ? l(' · נתונים חלקיים: הושגה מגבלת מדידות',' · Partial data: sample limit reached') : ''}</span></section>}
    <p className="z-muted">{l('אחוז ההצלחה מבוסס על מדידות שנשמרו בלבד. פערי מדידות אינם נחשבים לזמינות.','Success rate uses stored measurements only. Missing measurements do not count as availability.')}</p>
    <div className="z-table-wrap"><table><thead><tr>{[l('התקן','Device'),l('מצב','State'),l('מיקום','Location'),l('דוח','Report')].map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{rows.slice(page*50, (page+1)*50).map(d=><tr key={d.id}><td>{d.name}<small dir="ltr">{d.ip}</small></td><td>{d.status}</td><td>{d.location || '—'}</td><td><button disabled={busy} onClick={async()=>{setBusy(true);setError('');setReport(null);try{setReport({...await api(`/engine/hosts/${d.id}/history?days=${days}`),name:d.name});}catch(e){setError(e.message);}finally{setBusy(false);}}}>{l('הפק דוח','Generate report')}</button></td></tr>)}</tbody></table></div>
    <div className="z-pagination"><button disabled={!page} onClick={()=>setPage(page-1)}>{l('הקודם','Previous')}</button><span>{page+1} / {Math.max(1,Math.ceil(rows.length/50))}</span><button disabled={(page+1)*50>=rows.length} onClick={()=>setPage(page+1)}>{l('הבא','Next')}</button></div>
  </section>;
}
