import { useCallback, useEffect, useState } from 'react';
import { Activity, ArrowLeft, Bell, Check, ChevronLeft, ChevronRight, CircleHelp, Home, LogOut, Monitor, Plus, Radar, RefreshCw, Search, Server, Settings, ShieldCheck, X } from 'lucide-react';
import { api } from './api';
import { AuthScreen } from './App';
import './zabbix.css';

const labels = {
  online: ['תקין', 'Online'], offline: ['מנותק', 'Offline'], unknown: ['אין מדידה עדכנית', 'No fresh measurement'],
  paused: ['מושהה', 'Paused'], maintenance: ['בתחזוקה', 'Maintenance'],
};
const errors = {
  engine_unreachable: ['אין חיבור למנוע הניטור. בדוק את מצב התוסף ונסה שוב.', 'Cannot reach the monitoring engine. Check the add-on and retry.'],
  engine_request_rejected: ['המנוע דחה את הפעולה. בדוק הרשאות או חדש את החיבור.', 'The engine rejected the request. Check permissions or reconnect.'],
  engine_not_configured: ['מנוע הניטור עדיין לא הוגדר.', 'The monitoring engine is not configured yet.'],
  duplicate_address: ['הכתובת כבר משויכת להתקן מנוטר. חפש אותו ברשימת ההתקנים.', 'This address already belongs to a monitored device. Find it in the inventory.'],
  invalid_ip: ['יש להזין כתובת IP תקינה.', 'Enter a valid IP address.'],
  invalid_local_network: ['בחר רשת מקומית IPv4 עד 4,096 כתובות, למשל 192.168.1.0/24.', 'Enter a private IPv4 network of up to 4,096 addresses, such as 192.168.1.0/24.'],
  invalid_server_url: ['כתובת שרת לא תקינה.', 'Enter a valid server URL.'],
  credentials_required: ['יש להזין שם משתמש וסיסמה.', 'Enter a username and password.'],
  check_unavailable: ['אין בדיקת זמינות פעילה להתקן הזה.', 'This device has no active availability check.'],
  icmp_template_missing: ['פרופיל בדיקת הזמינות חסר במנוע.', 'The ICMP monitoring template is missing.'],
  unsupported_engine_version: ['נדרש Zabbix בגרסה 7.', 'Zabbix version 7 is required.'],
};

function Modal({ title, children, close, l }) {
  useEffect(() => {
    const previous = document.activeElement;
    const dialog = document.querySelector('.z-dialog');
    dialog?.querySelector('input,button')?.focus();
    const keyboard = event => {
      if (event.key === 'Escape') close();
      if (event.key === 'Tab') {
        const nodes = [...dialog.querySelectorAll('button:not(:disabled),input,select,a[href]')];
        if (!nodes.length) return;
        if (event.shiftKey && document.activeElement === nodes[0]) { event.preventDefault(); nodes.at(-1).focus(); }
        else if (!event.shiftKey && document.activeElement === nodes.at(-1)) { event.preventDefault(); nodes[0].focus(); }
      }
    };
    document.addEventListener('keydown', keyboard);
    return () => { document.removeEventListener('keydown', keyboard); previous?.focus(); };
  }, [close]);
  return <div className="z-overlay"><section className="z-dialog" role="dialog" aria-modal="true" aria-label={title}>
    <div className="z-dialog-head"><h2>{title}</h2><button onClick={close} aria-label={l('סגירה', 'Close')}><X size={20}/></button></div>{children}
  </section></div>;
}

export default function ZabbixWorkspace() {
  const [language, setLanguage] = useState(() => localStorage.getItem('homeii-engine-language') || 'he');
  const l = (he, en) => language === 'he' ? he : en;
  const [auth, setAuth] = useState(null);
  const [config, setConfig] = useState(null);
  const [tab, setTab] = useState('control');
  const [snapshot, setSnapshot] = useState(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [tick, setTick] = useState(Date.now());
  const [reload, setReload] = useState(0);
  const [modal, setModal] = useState(null);
  const [history, setHistory] = useState(null);
  const [discovery, setDiscovery] = useState(null);
  const [network, setNetwork] = useState('192.168.1.0/24');
  const [draft, setDraft] = useState({ ip: '', name: '', group: '', location: '', critical: false });
  const [connection, setConnection] = useState({ url: '', username: '', password: '' });
  const [haToken, setHaToken] = useState('');
  const admin = auth?.user?.role === 'admin';
  const operator = admin || auth?.user?.role === 'user';
  const canAcknowledge = admin || (operator && auth?.user?.can_manage_alerts);
  const explain = code => (errors[code] || ['הפעולה לא הושלמה. בדוק את החיבור ונסה שוב.', 'The request failed. Check the connection and retry.'])[language === 'he' ? 0 : 1];
  const close = useCallback(() => { setModal(null); setHistory(null); }, []);
  const loadSession = useCallback(async () => {
    try { setAuth(await api('/auth/session')); } catch { setAuth({ authenticated: false }); }
  }, []);
  useEffect(() => { loadSession(); }, [loadSession]);
  useEffect(() => {
    const expired = () => { setAuth({ authenticated: false }); setSnapshot(null); };
    addEventListener('homeii-session-expired', expired);
    return () => removeEventListener('homeii-session-expired', expired);
  }, []);
  useEffect(() => {
    document.documentElement.dir = language === 'he' ? 'rtl' : 'ltr';
    document.documentElement.lang = language;
    document.documentElement.dataset.theme = 'granite';
    localStorage.setItem('homeii-engine-language', language);
  }, [language]);
  useEffect(() => {
    if (!auth?.authenticated) return;
    let cancelled = false;
    const read = async () => {
      try { const value = await api('/engine/config'); if (!cancelled) setConfig(value); }
      catch (e) { if (!cancelled) setError(e.message); }
    };
    read();
    const timer = setInterval(read, 15000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [auth?.authenticated, reload]);
  useEffect(() => {
    if (!auth?.authenticated || !config?.configured) return;
    let cancelled = false, running = false;
    const read = async () => {
      if (running) return;
      running = true;
      try {
        const params = new URLSearchParams({ search, state: filter, page: String(page), limit: '50' });
        const value = await api(`/engine/devices?${params}`);
        if (!cancelled) { setSnapshot(value); setError(value.error || ''); }
      } catch (e) {
        if (!cancelled) { setError(e.message); setSnapshot(old => old && { ...old, stale: true }); }
      } finally { running = false; }
    };
    const initial = setTimeout(read, 200);
    const timer = setInterval(read, 15000);
    return () => { cancelled = true; clearTimeout(initial); clearInterval(timer); };
  }, [auth?.authenticated, config?.configured, search, filter, page, reload]);
  useEffect(() => { const timer = setInterval(() => setTick(Date.now()), 5000); return () => clearInterval(timer); }, []);
  useEffect(() => {
    if (!modal?.device) return;
    let cancelled = false;
    setHistory(null);
    const read = () => api(`/engine/hosts/${modal.device.id}/history`).then(value => { if (!cancelled) setHistory(value); })
      .catch(e => { if (!cancelled) setHistory({ error: e.message }); });
    read();
    const timer = setInterval(read, 30000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [modal]);
  const act = async (action, success) => {
    setBusy(true); setError(''); setNotice('');
    try { await action(); setNotice(success || ''); setReload(n => n + 1); return true; }
    catch (e) { setError(e.message); return false; }
    finally { setBusy(false); }
  };
  const post = (path, body = {}) => api(path, { method: 'POST', body: JSON.stringify(body) });
  const add = ip => { setDraft({ ip: ip || '', name: '', group: '', location: '', critical: false }); setModal({ add: true }); };
  const stale = Boolean(snapshot?.stale || (snapshot?.updated_at && tick/1000 - snapshot.updated_at > 45));
  const time = value => value ? new Date(value*1000).toLocaleString(language === 'he' ? 'he-IL' : 'en-GB') : '—';
  const stateName = state => (labels[state] || labels.unknown)[language === 'he' ? 0 : 1];
  const counts = snapshot?.counts || {};
  const events = snapshot?.events || [];
  const selected = modal?.device && (snapshot?.devices.find(d => d.id === modal.device.id) || { ...modal.device, status: 'unknown' });

  if (!auth) return <div className="z-loading">HOMEii</div>;
  if (!auth.authenticated) return <AuthScreen setupRequired={auth.setup_required} onAuthenticated={loadSession}/>;

  return <div className="z-workspace" dir={language === 'he' ? 'rtl' : 'ltr'}>
    <header className="z-top"><a className="z-brand" href="#/control"><Activity/><strong>HOMEii<span> NETWORK</span></strong></a>
      <div className="z-top-actions"><span className="z-local"><ShieldCheck size={15}/>{l('ניטור מקומי', 'Local monitoring')}</span>
        <button onClick={() => setLanguage(language === 'he' ? 'en' : 'he')}>{language === 'he' ? 'EN' : 'עברית'}</button>
        <button aria-label={l('יציאה', 'Sign out')} onClick={async () => { await post('/auth/logout'); setAuth({ authenticated: false }); }}><LogOut size={17}/></button>
      </div>
    </header>
    <div className="z-layout">
      <nav className="z-nav" aria-label={l('ניווט ראשי', 'Main navigation')}>
        {[[Monitor, 'control', l('חדר בקרה', 'Control room')], [Server, 'devices', l('התקנים', 'Devices')],
          [Bell, 'events', l('אירועים', 'Events')], ...(admin ? [[Settings, 'setup', l('הגדרה', 'Setup')]] : [])].map(([Icon, key, name]) =>
          <button className={tab === key ? 'selected' : ''} key={key} onClick={() => { setTab(key); setSearch(''); setFilter(''); setPage(1); }}><Icon size={19}/><span>{name}</span>{key === 'events' && counts.problems > 0 && <b>{counts.problems}</b>}</button>)}
        <div className="z-nav-foot"><span>HOMEii 8.0</span><small>{l('נתונים באתר שלך', 'Your data stays on site')}</small></div>
      </nav>
      <main className="z-main">
        {error && <div className="z-warning" role="alert"><CircleHelp size={20}/><span><strong>{stale ? l('הניטור אינו זמין', 'Monitoring unavailable') : l('נדרשת בדיקה', 'Attention required')}</strong>{explain(error)}</span><button onClick={() => setReload(n => n+1)}>{l('נסה שוב', 'Retry')}</button></div>}
        {stale && !error && <div className="z-warning" role="alert">{l('הנתונים אינם עדכניים. המצב האחרון אינו אישור לתקינות.', 'Data is stale. Last known state is not proof of availability.')}</div>}
        {notice && <div className="z-notice" role="status"><Check size={17}/>{notice}<button aria-label={l('סגירה', 'Dismiss')} onClick={() => setNotice('')}><X size={16}/></button></div>}

        {!config?.configured && <section className="z-welcome"><ShieldCheck size={36}/><p className="z-eyebrow">HOMEii NETWORK</p>
          <h1>{config?.local_bundle ? l('מכינים את מנוע הניטור המקומי', 'Preparing your local monitoring engine') : l('מחברים את הרשת לתמונה אחת ברורה', 'Bring your network into focus')}</h1>
          <p>{config?.local_bundle ? l('בהפעלה הראשונה מוקמים מסד הנתונים והמנוע באופן אוטומטי. העמוד יתעדכן כשהמערכת תהיה מוכנה.', 'The database and engine are initialized automatically on first start. This page updates when ready.') : l('התוסף המלא כולל מנוע מקומי. לחיבור לשרת קיים, הזן את פרטי החיבור בהגדרה.', 'The full add-on includes a local engine. To connect an existing server, enter its details in Setup.')}</p>
          {admin && <button onClick={() => setTab('setup')}>{l('הגדרת חיבור', 'Connection setup')}<ArrowLeft size={16}/></button>}
        </section>}

        {tab === 'setup' && admin ? <div className="z-settings">
          <div className="z-heading"><div><p className="z-eyebrow">HOMEii / SETUP</p><h1>{l('הגדרה פשוטה. ניטור רציף.', 'Simple setup. Continuous monitoring.')}</h1></div></div>
          <section className="z-section"><h2>{l('מנוע הניטור', 'Monitoring engine')}</h2><p>{config?.configured ? l('המנוע מחובר. אפשר להוסיף התקנים ידנית או להגדיר גילוי ברשת.', 'Engine connected. Add devices manually or enable network discovery.') : l('התוסף המקומי מתחבר אוטומטית; חיבור לשרת אחר הוא אפשרות מתקדמת.', 'The local add-on connects automatically; connecting another server is an advanced option.')}</p>
            <details><summary>{l('חיבור לשרת קיים', 'Connect an existing server')}</summary>
              <form onSubmit={async e => { e.preventDefault(); if (await act(() => post('/engine/connect', connection), l('המנוע חובר בהצלחה', 'Engine connected'))) setConnection({ url: '', username: '', password: '' }); }}>
                <label>{l('כתובת השרת', 'Server URL')}<input required type="url" value={connection.url} onChange={e => setConnection({ ...connection, url: e.target.value })} placeholder="http://192.168.1.10/zabbix" dir="ltr"/></label>
                <label>{l('שם משתמש', 'Username')}<input required autoComplete="off" value={connection.username} onChange={e => setConnection({ ...connection, username: e.target.value })}/></label>
                <label>{l('סיסמה', 'Password')}<input required type="password" autoComplete="new-password" value={connection.password} onChange={e => setConnection({ ...connection, password: e.target.value })}/></label>
                <button className="z-primary" disabled={busy}>{l('בדיקה וחיבור', 'Test and connect')}</button>
              </form>
            </details>
          </section>
          {config?.configured && <>
            <section className="z-section"><h2>{l('גילוי התקנים', 'Device discovery')}</h2><p>{l('התקנים שהתגלו ממתינים לאישור שלך. הם לא יוצרים התראות לפני שהוספת אותם לניטור.', 'Discovered devices await your approval. They do not generate alerts until added to monitoring.')}</p>
              <form className="z-inline" onSubmit={e => { e.preventDefault(); act(() => post('/engine/discovery', { network }), l('הגילוי הוגדר. התוצאות יופיעו לאחר סריקת המנוע.', 'Discovery configured. Results appear after the engine scans the network.')); }}>
                <label>{l('טווח רשת', 'Network range')}<input required value={network} onChange={e => setNetwork(e.target.value)} dir="ltr"/></label><button className="z-primary" disabled={busy}><Radar size={17}/>{l('הפעל גילוי', 'Enable discovery')}</button>
              </form>
              <button disabled={busy} onClick={() => act(async () => setDiscovery(await api('/engine/discovery')))}>{l('הצג תוצאות גילוי', 'Show discovered devices')}</button>
              {discovery && <><p>{discovery.devices.length} {l('התקנים ממתינים', 'devices awaiting approval')}</p>{discovery.devices.slice(0, 100).map(d => <div className="z-discovered" key={d.ip}><span><strong>{d.name}</strong><small dir="ltr">{d.ip}</small></span><small>{l('זוהה לפי כתובת; יש לוודא זהות', 'Address detected; verify identity')}</small><button disabled={busy} onClick={() => add(d.ip)}><Plus size={15}/>{l('הוסף לניטור', 'Add to monitoring')}</button></div>)}</>}
            </section>
            <section className="z-section"><h2>Home Assistant</h2><p>{l('צור מפתח חיבור והדבק אותו בשדה מפתח הגישה של האינטגרציה. המפתח מאפשר קריאת מצב בלבד.', 'Generate a connection key and paste it into the integration access-key field. It grants read-only status access.')}</p>
              <button disabled={busy} onClick={() => act(async () => setHaToken((await post('/engine/ha-token')).token))}>{l('צור מפתח חיבור חדש', 'Generate a new connection key')}</button>
              {haToken && <label>{l('מפתח חיבור — יצירת מפתח חדש מבטלת את הקודם', 'Connection key — generating another revokes the previous key')}<input readOnly value={haToken} onFocus={e => e.target.select()} dir="ltr"/></label>}
            </section>
          </>}
          <section className="z-section"><h2>{l('הגרסה הקודמת', 'Previous workspace')}</h2><p>{l('הנתונים הקיימים נשמרו בנפרד. נתוני הגרסה הקודמת אינם מצב הניטור החדש.', 'Existing data remains separate. Legacy data does not represent the new monitoring state.')}</p><a href="?legacy=1#/dashboard">{l('פתח את סביבת העבודה הקודמת', 'Open the previous workspace')}</a></section>
        </div> : config?.configured && <>
          <div className="z-heading"><div><p className="z-eyebrow">HOMEii / {tab === 'control' ? 'OPERATIONS' : tab.toUpperCase()}</p><h1>{tab === 'control' ? l('הרשת שלך. תמונה ברורה.', 'Your network. Clearly.') : tab === 'events' ? l('מה דורש טיפול', 'What needs attention') : l('כל ההתקנים, במקום אחד', 'Every device, in one place')}</h1>
            <p className={stale ? 'z-muted' : 'z-live'}>{snapshot && !stale ? <><i/>{l('הניטור פעיל', 'Monitoring live')}</> : l('ממתינים לנתונים עדכניים', 'Waiting for current data')}<span> · {time(snapshot?.updated_at)}</span></p></div>
            <div className="z-actions"><button aria-label={l('רענון', 'Refresh')} onClick={() => setReload(n => n+1)}><RefreshCw size={17}/></button>{admin && <button className="z-primary" onClick={() => add()}><Plus size={17}/>{l('הוסף התקן', 'Add device')}</button>}</div>
          </div>
          <div className="z-metrics">{[['total', l('התקנים', 'Devices')], ['online', l('תקינים', 'Online')], ['offline', l('מנותקים', 'Offline')], ['unknown', l('ללא מדידה', 'No measurement')]].map(([key, name]) =>
            <button key={key} className={`z-metric z-${key}`} onClick={() => { setTab('devices'); setFilter(key === 'total' ? '' : key); setPage(1); }}><span>{name}</span><strong>{stale || !snapshot ? '—' : counts[key] || 0}</strong><small>{l('הצג התקנים', 'View devices')}</small></button>)}</div>
          {(tab === 'control' || tab === 'events') && <section className="z-section z-events"><div className="z-section-title"><h2>{l('אירועים פעילים', 'Active incidents')}</h2><span>{events.length}{snapshot?.events_truncated ? '+' : ''}</span></div>
            {!events.length ? <div className="z-empty"><ShieldCheck size={25}/><span>{stale ? l('לא ניתן לאמת את מצב האירועים', 'Incident state cannot be verified') : l('אין אירועים פעילים במנוע', 'No active engine incidents')}</span></div> :
              [...events].sort((a,b) => b.severity-a.severity || b.since-a.since).slice(0, tab === 'control' ? 8 : 100).map(event => <div className={`z-event z-severity-${event.severity}`} key={event.id}>
                <span className="z-severity">{event.severity >= 4 ? l('קריטי', 'Critical') : l('לטיפול', 'Attention')}</span><div><strong>{event.name}</strong><small>{l('החל ב־', 'Since ')}{time(event.since)}{event.suppressed ? l(' · התראה מושתקת', ' · Suppressed') : ''}</small></div>
                {event.acknowledged ? <span className="z-muted">{l('בטיפול', 'Acknowledged')}</span> : canAcknowledge && <button disabled={busy || stale} onClick={() => act(() => post(`/engine/events/${event.id}/acknowledge`), l('האירוע סומן בטיפול', 'Incident acknowledged'))}>{l('בטיפול שלי', 'Acknowledge')}</button>}
              </div>)}
          </section>}
          {tab !== 'events' && <section className="z-section z-inventory"><div className="z-section-title"><h2>{tab === 'control' ? l('סדר העדיפויות ברשת', 'Network priorities') : l('מלאי התקנים', 'Device inventory')}</h2><span>{snapshot?.total || 0}</span></div>
            <div className="z-toolbar"><label className="z-search"><Search size={17}/><input aria-label={l('חיפוש התקן', 'Search devices')} placeholder={l('שם, כתובת, קבוצה או מיקום', 'Name, address, group or location')} value={search} onChange={e => { setSearch(e.target.value); setPage(1); }}/></label>
              <select aria-label={l('סינון מצב', 'Filter state')} value={filter} onChange={e => { setFilter(e.target.value); setPage(1); }}><option value="">{l('כל המצבים', 'All states')}</option>{Object.keys(labels).map(key => <option key={key} value={key}>{stateName(key)}</option>)}</select>
            </div>
            <div className="z-table-wrap"><table><thead><tr><th>{l('התקן', 'Device')}</th><th>{l('מצב', 'Status')}</th><th>{l('קבוצה', 'Group')}</th><th>{l('זמן תגובה', 'Response')}</th><th>{l('בדיקה אחרונה', 'Last check')}</th></tr></thead>
              <tbody>{(snapshot?.devices || []).map(device => <tr key={device.id}><td><button className="z-device-link" onClick={() => setModal({ device })}><span className={`z-dot z-dot-${stale ? 'unknown' : device.status}`}/><span><strong>{device.name}{device.critical && <b className="z-critical">!</b>}</strong><small dir="ltr">{device.ip}</small></span></button></td>
                <td><span className={`z-state z-state-${stale ? 'unknown' : device.status}`}>{stale ? l('מידע לא עדכני', 'Stale data') : stateName(device.status)}</span></td><td>{device.groups.join(', ') || '—'}</td><td dir="ltr">{!stale && device.latency_ms != null ? `${device.latency_ms} ms` : '—'}</td><td>{time(device.last_check)}</td></tr>)}</tbody>
            </table></div>
            {snapshot && !snapshot.devices.length && <div className="z-empty"><Server size={25}/>{l('אין התקנים בתצוגה. אפשר להוסיף ידנית או להפעיל גילוי בהגדרה.', 'No devices in this view. Add one manually or enable discovery in Setup.')}</div>}
            <div className="z-pagination"><span>{l('עמוד', 'Page')} {page} / {Math.max(1, Math.ceil((snapshot?.total || 0)/50))}</span><button disabled={page === 1} aria-label={l('הקודם', 'Previous')} onClick={() => setPage(page-1)}><ChevronLeft size={17}/></button><button disabled={page*50 >= (snapshot?.total || 0)} aria-label={l('הבא', 'Next')} onClick={() => setPage(page+1)}><ChevronRight size={17}/></button></div>
          </section>}
        </>}
        <footer className="z-footer"><Home size={14}/>{l('עובד ברשת המקומית · ללא תלות באינטרנט', 'Runs on your local network · No Internet dependency')}</footer>
      </main>
    </div>
    {modal?.add && <Modal title={l('הוסף התקן', 'Add device')} close={close} l={l}><p className="z-muted">{l('בדיקת זמינות תתחיל אוטומטית. אפשר להוסיף גם התקן שמנותק כרגע.', 'Availability checks start automatically. You can also add a device that is currently offline.')}</p>
      <form onSubmit={async e => { e.preventDefault(); if (await act(() => post('/engine/hosts', draft), l('ההתקן נוסף. ממתינים למדידה הראשונה.', 'Device added. Waiting for its first measurement.'))) close(); }}>
        {[['ip', l('כתובת IP', 'IP address')], ['name', l('שם ההתקן', 'Device name')], ['group', l('קבוצה', 'Group')], ['location', l('מיקום', 'Location')]].map(([key, label]) => <label key={key}>{label}<input required={key === 'ip'} maxLength={128} dir={key === 'ip' ? 'ltr' : undefined} value={draft[key]} onChange={e => setDraft({ ...draft, [key]: e.target.value })}/></label>)}
        <label className="z-checkbox"><input type="checkbox" checked={draft.critical} onChange={e => setDraft({ ...draft, critical: e.target.checked })}/>{l('התקן קריטי לחדר הבקרה', 'Critical control-room device')}</label>
        {error && <p role="alert" className="z-form-error">{explain(error)}</p>}<button className="z-primary" disabled={busy}>{busy ? l('שומר…', 'Saving…') : l('שמור והתחל ניטור', 'Save and monitor')}</button>
      </form>
    </Modal>}
    {selected && <Modal title={selected.name} close={close} l={l}>
      <div className="z-device-summary"><span dir="ltr">{selected.ip}</span><span className={`z-state z-state-${stale ? 'unknown' : selected.status}`}>{stale ? l('מידע לא עדכני', 'Stale data') : stateName(selected.status)}</span></div>
      <h3>{l('24 השעות האחרונות', 'Last 24 hours')}</h3>
      {history?.error ? <p role="alert">{explain(history.error)}</p> : !history ? <p>{l('טוען מדידות…', 'Loading measurements…')}</p> : <>
        <div className="z-history" aria-label={l('היסטוריית זמינות', 'Availability history')} dir="ltr">{history.series.map((bucket, index) => <span key={index} className={`z-bar-${bucket.status}`} title={`${time(bucket.start)} · ${stateName(bucket.status)} · ${bucket.samples}`}/>)}</div>
        <div className="z-history-axis"><span>{l('לפני 24 שעות', '24 hours ago')}</span><span>{l('עכשיו', 'Now')}</span></div>
        <div className="z-history-facts"><div><strong>{history.availability == null ? '—' : `${history.availability}%`}</strong><span>{l('בדיקות מוצלחות', 'Successful checks')}</span></div><div><strong>{history.coverage}%</strong><span>{l('כיסוי מדידות', 'Measurement coverage')}</span></div><div><strong>{history.samples}</strong><span>{l('בדיקות שנשמרו', 'Recorded checks')}</span></div></div>
        <p className="z-muted">{l('אפור = אין מדידות. אחוז ההצלחה מחושב רק מבדיקות שנשמרו; הוא אינו SLA.', 'Gray means missing measurements. Success rate uses recorded checks only; it is not an SLA.')}</p>
        {history.truncated && <p>{l('מוצגות המדידות האחרונות בלבד.', 'Only the latest measurements are included.')}</p>}
      </>}
      {operator && <button disabled={busy || stale} onClick={() => act(() => post(`/engine/hosts/${selected.id}/check`), l('הבדיקה נשלחה למנוע. התוצאה תתעדכן לאחר הביצוע.', 'Check queued. The result updates after execution.'))}><RefreshCw size={17}/>{l('בדוק עכשיו', 'Check now')}</button>}
    </Modal>}
  </div>;
}
