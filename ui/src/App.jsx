import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, Bell, Boxes, ChevronLeft, CircleGauge, Clock3, Command,
  Cpu, Gauge, Globe2, History, Languages, LayoutDashboard, Menu, Network, Pin,
  Play, Radar, RefreshCw, Route, Search, Server, Settings, ShieldAlert, Sparkles,
  Terminal, Wifi, WifiOff, Wrench, X, Zap, CheckCircle2, TrendingUp, Eye,
  UserCog, MonitorUp, Database, SlidersHorizontal, ArrowUpRight,
  Upload, Download, FileJson, FileSpreadsheet,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
  Bar, BarChart,
} from 'recharts'
import { api, query } from './api'
import { translator } from './i18n'

const navItems = [
  ['dashboard', LayoutDashboard], ['viewer', CircleGauge], ['devices', Server],
  ['alerts', Bell], ['history', History], ['tools', Wrench], ['settings', Settings],
]
const statusIcons = { online: Wifi, offline: WifiOff, unstable: Activity, new: Sparkles, critical: ShieldAlert, pinned: Pin, total: Boxes }
const statusOrder = ['offline', 'unstable', 'new', 'critical', 'online', 'total']

function useRoute() {
  const getRoute = () => (location.hash.replace('#/', '') || 'dashboard').split('/')
  const [[route, detail], setRoute] = useState(getRoute)
  useEffect(() => {
    const onChange = () => setRoute(getRoute())
    addEventListener('hashchange', onChange)
    return () => removeEventListener('hashchange', onChange)
  }, [])
  return [route, (next) => { location.hash = `#/${next}` }, detail || '']
}

function Logo() {
  return <div className="brand-lockup">
    <div className="brand-mark"><img src="./icons/homeii-192.png" alt="" /></div>
    <div><strong>HOME<span>ii</span></strong><small>NETWORK INTELLIGENCE</small></div>
  </div>
}

function StatusDot({ status }) { return <span className={`status-dot ${status}`} aria-label={status} /> }

function TimeAgo({ timestamp, language }) {
  if (!timestamp) return <span>—</span>
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - timestamp))
  const units = language === 'he'
    ? [[86400, 'ימים'], [3600, 'שעות'], [60, 'דקות'], [1, 'שניות']]
    : [[86400, 'days'], [3600, 'hours'], [60, 'minutes'], [1, 'seconds']]
  const [size, label] = units.find(([size]) => seconds >= size) || units.at(-1)
  return <span>{Math.floor(seconds / size)} {label}</span>
}

function KpiCard({ type, value, label, onClick }) {
  const Icon = statusIcons[type] || Gauge
  return <button className={`kpi-card tone-${type}`} onClick={onClick}>
    <div className="kpi-head"><span className="icon-box"><Icon size={18} /></span><span className="micro-label">{label}</span></div>
    <div className="kpi-value">{value ?? 0}</div>
    <div className="kpi-foot"><span className="pulse-line" /><ChevronLeft size={16} /></div>
  </button>
}

function Empty({ t }) { return <div className="empty"><Radar size={38} /><p>{t('noData')}</p></div> }

function AvailabilityStrip({ series = [], t }) {
  const values = series.length ? series.slice(-24) : Array.from({ length: 24 }, () => ({ availability_pct: 100 }))
  return <div className="availability-strip" title={t ? t('availability24h') : '24h availability'}>
    {values.map((item, index) => {
      const pct = Number(item.availability_pct ?? item.availability ?? 100)
      return <span key={index} className={pct >= 99 ? 'good' : pct >= 60 ? 'warn' : 'bad'} />
    })}
  </div>
}

function Dashboard({ data, t, setRoute, language }) {
  const { status, alerts, events, viewer } = data
  const chartData = viewer?.summary?.series?.map((point, index) => ({
    name: `${index}:00`, availability: Number(point.availability_pct || 0),
  })) || []
  const attention = (data.devices || []).filter((d) => ['offline', 'unstable', 'new'].includes(d.status)).slice(0, 5)
  return <div className="page-stack">
    <section className="hero-panel">
      <div><span className="eyebrow"><Zap size={14} /> {t('monitorLive')}</span><h1>{t('networkPulse')}</h1><p>{t('last24h')} · {status?.networks?.length || 0} {t('network')}</p></div>
      <div className={`health-orb ${status?.offline ? 'danger' : 'healthy'}`}><Activity size={32} /><strong>{status?.offline ? status.offline : 'OK'}</strong><small>{status?.offline ? t('offline') : t('systemHealthy')}</small></div>
    </section>
    <section className="kpi-grid">
      {statusOrder.map((type) => <KpiCard key={type} type={type} value={status?.[type]} label={t(type)} onClick={() => setRoute(`devices/${type === 'total' ? 'all' : type}`)} />)}
    </section>
    <section className="dashboard-grid">
      <article className="panel chart-panel wide">
        <div className="panel-title"><div><span className="eyebrow">{t('sla24h')}</span><h2>{t('uptimeTrend')}</h2></div><span className="score">{viewer?.summary?.availability_24h ?? 0}%</span></div>
        <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={chartData}><defs><linearGradient id="availability" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#27e6a4" stopOpacity=".52"/><stop offset=".58" stopColor="#27e6a4" stopOpacity=".13"/><stop offset="1" stopColor="#27e6a4" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="var(--chart-grid)" vertical={false}/><XAxis dataKey="name" stroke="var(--chart-axis)" tickLine={false}/><YAxis domain={[0,100]} hide/><Tooltip contentStyle={{background:'var(--chart-tooltip)',border:'1px solid var(--line-strong)',borderRadius:14,boxShadow:'0 18px 45px #000a'}}/><Area type="monotone" dataKey="availability" stroke="#27e6a4" strokeWidth={3} fill="url(#availability)" activeDot={{r:5,fill:'#27e6a4',stroke:'#07130f',strokeWidth:3}} /></AreaChart></ResponsiveContainer></div>
      </article>
      <article className="panel attention-panel">
        <div className="panel-title"><div><span className="eyebrow">{t('liveQueue')}</span><h2>{t('attention')}</h2></div><AlertTriangle size={21} /></div>
        <div className="compact-list">{attention.length ? attention.map((device) => <div className="compact-row" key={device.ip}><StatusDot status={device.status}/><div><strong>{device.display_name || device.name || device.ip}</strong><small>{device.ip} · {device.vendor || 'Unknown'}</small></div><TimeAgo timestamp={device.last_seen} language={language}/></div>) : <Empty t={t}/>}</div>
      </article>
      <article className="panel events-panel">
        <div className="panel-title"><div><span className="eyebrow">{t('systemLog')}</span><h2>{t('recentEvents')}</h2></div><Command size={21}/></div>
        <div className="event-grid">{(events || []).slice(0, 6).map((event, index) => <div className={`event-tile ${event.level}`} key={event.id || index}><span>{event.event_type || event.type}</span><strong>{event.message}</strong><TimeAgo timestamp={event.ts} language={language}/></div>)}</div>
      </article>
      <article className="panel alerts-mini">
        <div className="panel-title"><div><span className="eyebrow">{t('alertCenter')}</span><h2>{t('openAlerts')}</h2></div><span className="score danger-text">{(alerts || []).filter(a => a.status === 'open').length}</span></div>
        <AvailabilityStrip series={chartData.map(x => ({availability_pct:x.availability}))}/>
      </article>
    </section>
  </div>
}

function Viewer({ data, t }) {
  const categories = data.viewer?.categories || []
  const [selected, setSelected] = useState(null)
  const selectedDevices = selected ? (data.viewer?.devices?.[selected] || data.devices?.filter(device => (device.category || '') === selected) || []) : []
  return <div className="page-stack noc-page"><div className="page-heading"><div><span className="eyebrow">{t('liveOperations')}</span><h1>{t('viewer')}</h1><p>{t('selectCategory')}</p></div><div className="live-badge"><span className="live-dot"/>{t('monitorLive')}</div></div>
    <section className="category-grid">{categories.map((item) => <button className={`category-card ${item.offline ? 'has-alert' : ''} ${selected===item.category?'selected':''}`} key={item.category} onClick={()=>setSelected(selected===item.category?null:item.category)}>
      <div className="category-top"><span className="icon-box"><Cpu size={20}/></span><span className="availability-score">{item.availability_24h ?? 0}%</span></div>
      <h2>{item.category || t('uncategorized')}</h2><strong className="category-count">{item.total ?? item.count ?? 0}</strong>
      <div className="category-tags"><span>{item.online || 0} {t('online')}</span>{item.offline > 0 && <span className="danger-tag">{item.offline} {t('offline')}</span>}</div>
      <AvailabilityStrip series={item.series}/>
    </button>)}</section>
    {selected && <section className="panel category-detail"><div className="panel-title"><div><span className="eyebrow">{t('deviceHealth')}</span><h2>{selected}</h2></div><button className="icon-button" onClick={()=>setSelected(null)}><X size={17}/></button></div><div className="noc-device-grid">{selectedDevices.map(device=><article className={`noc-device state-${device.status}`} key={device.ip}><div><StatusDot status={device.status}/><strong>{device.display_name||device.name||device.ip}</strong></div><small>{device.ip} · {device.vendor||'—'}</small><AvailabilityStrip series={device.availability_series}/></article>)}</div></section>}
  </div>
}

function Devices({ data, t, language, refresh, initialFilter = '' }) {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const [editing, setEditing] = useState(null)
  const [pingState, setPingState] = useState('idle')
  const [notice, setNotice] = useState('')
  useEffect(()=>{if(initialFilter)setFilter(initialFilter)},[initialFilter])
  const devices = useMemo(() => (data.devices || []).filter((device) => {
    const text = `${device.display_name} ${device.name} ${device.ip} ${device.vendor} ${device.category} ${device.mac}`.toLowerCase()
    const matchesFilter = filter === 'all' || (filter === 'quarantined' ? device.quarantined : filter === 'critical' ? device.critical : filter === 'pinned' ? device.pinned : device.status === filter)
    return (!search || text.includes(search.toLowerCase())) && matchesFilter
  }), [data.devices, search, filter])
  const action = async (path) => { await api(path); await refresh();setNotice(t('actionCompleted'));setTimeout(()=>setNotice(''),2500) }
  const saveDevice = async () => { await query('/update',{ip:editing.ip,name:editing.display_name||editing.name||'',category:editing.category||'',tags:editing.tags_text??(editing.tags||[]).join(','),assigned_network:editing.assigned_network||'',scan_profile:editing.scan_profile||'normal',device_profile:editing.device_profile||'generic',maintenance:editing.maintenance?1:0,mute_alerts:editing.mute_alerts?1:0,pinned:editing.pinned?1:0,critical:editing.critical?1:0,notes:editing.notes||''});await refresh();setEditing(null);setNotice(t('deviceSaved'));setTimeout(()=>setNotice(''),2500) }
  const pingDevice = async () => { setPingState('running');try{const response=await api(`/ping_now/${encodeURIComponent(editing.ip)}`);setPingState(response.status==='online'||response.ok?'success':'failed')}catch{setPingState('failed')} }
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">{t('assetInventory')}</span><h1>{t('devices')}</h1><p>{devices.length} {t('of')} {data.devices?.length || 0}</p></div></div>{notice&&<div className="success-banner"><CheckCircle2/>{notice}</div>}
    <section className="toolbar panel"><div className="search-box"><Search size={18}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder={t('search')}/></div><div className="filter-pills">{['all','online','offline','unstable','new','critical','pinned','quarantined'].map(item=><button className={filter===item?'active':''} onClick={()=>setFilter(item)} key={item}>{t(item)}</button>)}</div></section>
    <section className="device-grid">{devices.map(device => <article className={`device-card state-${device.status}`} key={device.ip}>
      <div className="device-card-head"><div><StatusDot status={device.status}/><span>{t(device.status)}</span></div><button className="icon-button" onClick={()=>{setEditing({...device});setPingState('idle')}}><Settings size={17}/></button></div>
      <h2>{device.display_name || device.name || device.ip}</h2><p>{device.vendor || 'Unknown vendor'}</p><code>{device.ip}</code>
      <div className="device-meta"><span><Network size={14}/>{device.assigned_network || '—'}</span><span><Clock3 size={14}/><TimeAgo timestamp={device.last_seen} language={language}/></span></div>
      <AvailabilityStrip series={device.availability_series}/>
    </article>)}{!devices.length&&<Empty t={t}/>}</section>
    {editing && <div className="modal-backdrop" onMouseDown={e=>e.target===e.currentTarget&&setEditing(null)}><div className="modal-card device-editor"><button className="modal-close" onClick={()=>setEditing(null)}><X/></button><span className="eyebrow">{t('deviceControl')} · {editing.ip}</span><h1>{editing.display_name || editing.ip}</h1><div className="detail-grid"><label>{t('name')}<input value={editing.display_name||editing.name||''} onChange={e=>setEditing({...editing,display_name:e.target.value,name:e.target.value})}/></label><label>{t('category')}<input value={editing.category||''} onChange={e=>setEditing({...editing,category:e.target.value})}/></label><label>{t('network')}<select value={editing.assigned_network||''} onChange={e=>setEditing({...editing,assigned_network:e.target.value})}><option value="">—</option>{(data.settingsPayload?.networks||data.status?.networks||[]).map(network=><option value={network} key={network}>{network}</option>)}</select></label><label>{t('scanProfile')}<select value={editing.scan_profile||'normal'} onChange={e=>setEditing({...editing,scan_profile:e.target.value})}><option value="slow">{t('slow')}</option><option value="normal">{t('normal')}</option><option value="fast">{t('fast')}</option></select></label><label>{t('deviceProfile')}<select value={editing.device_profile||'generic'} onChange={e=>setEditing({...editing,device_profile:e.target.value})}><option value="generic">{t('generic')}</option><option value="iot">IoT</option><option value="mobile">{t('mobile')}</option><option value="infrastructure">{t('infrastructure')}</option></select></label><label>{t('tags')}<input value={editing.tags_text??(editing.tags||[]).join(', ')} onChange={e=>setEditing({...editing,tags_text:e.target.value})}/></label></div><div className="editor-toggles">{[['critical','critical'],['pinned','pinned'],['maintenance','maintenance'],['mute_alerts','muteAlerts']].map(([field,label])=><button type="button" className={editing[field]?'active':''} onClick={()=>setEditing({...editing,[field]:!editing[field]})} key={field}><span/><strong>{t(label)}</strong></button>)}</div><label className="notes-field">{t('notes')}<textarea value={editing.notes||''} onChange={e=>setEditing({...editing,notes:e.target.value})}/></label>{pingState!=='idle'&&<div className={`ping-feedback ${pingState}`}>{pingState==='running'?<RefreshCw className="spin"/>:pingState==='success'?<CheckCircle2/>:<AlertTriangle/>}<strong>{t(pingState==='running'?'pingRunning':pingState==='success'?'pingSuccess':'pingFailed')}</strong></div>}<div className="modal-actions"><button className="button danger" onClick={()=>action(`/${editing.quarantined?'restore':'remove'}/${encodeURIComponent(editing.ip)}`).then(()=>setEditing(null))}>{t(editing.quarantined?'restore':'quarantine')}</button><button className={`button ping-button ${pingState}`} onClick={pingDevice}>{t('ping')}</button><button className="button" onClick={()=>setEditing(null)}>{t('close')}</button><button className="button primary" onClick={saveDevice}>{t('saveChanges')}</button></div></div></div>}
  </div>
}

function Alerts({ data, t, language, refresh }) {
  const alerts = data.alerts || []
  const [filter,setFilter]=useState('open')
  const visible=alerts.filter(alert=>filter==='all'||alert.status===filter||alert.severity===filter)
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">{t('incidentCenter')}</span><h1>{t('alerts')}</h1><p>{alerts.filter(a=>a.status==='open').length} {t('openAlerts')}</p></div></div>
    <section className="toolbar panel"><div className="filter-pills">{['open','criticalSeverity','high','resolved','all'].map(item=>{const value=item==='criticalSeverity'?'critical':item;return <button className={filter===value?'active':''} onClick={()=>setFilter(value)} key={item}>{t(item)}</button>})}</div></section>
    <section className="alert-list">{visible.length ? visible.map(alert=><article className={`alert-card severity-${alert.severity}`} key={alert.id}><div className="alert-icon"><AlertTriangle/></div><div><span className="eyebrow">{t(alert.severity)} · {alert.ip}</span><h2>{alert.title}</h2><p>{alert.message}</p></div><div className="alert-side"><TimeAgo timestamp={alert.created_at} language={language}/>{alert.status==='open'&&<button className="button" onClick={async()=>{await api(`/resolve_alert/${alert.id}`);refresh()}}>{t('resolve')}</button>}</div></article>) : <Empty t={t}/>}</section>
  </div>
}

function HistoryPage({ history, t, language }) {
  const [days,setDays]=useState(14)
  const [report,setReport]=useState(history)
  useEffect(()=>{const toTs=Math.floor(Date.now()/1000);query('/history/summary',{from_ts:toTs-(days*86400),to_ts:toTs}).then(setReport).catch(()=>setReport(history))},[days,history])
  const normalized = (report?.daily_series || []).map((item,index)=>({name:item.label||item.date||new Date((item.ts||0)*1000).toLocaleDateString(language==='he'?'he-IL':'en-US',{day:'2-digit',month:'2-digit'})||index,availability:Number(item.availability_pct||0),disconnects:Number(item.disconnects||0)}))
  const summary = report?.summary || {}
  const rankings = report?.rankings || {}
  const formatDate = (ts) => new Date((ts||0)*1000).toLocaleString(language==='he'?'he-IL':'en-US',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'})
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">HISTORICAL INTELLIGENCE</span><h1>{t('history')}</h1><p>{t('uptimeTrend')}</p></div><div className="range-pills"><button className={days===7?'active':''} onClick={()=>setDays(7)}>{t('last7d')}</button><button className={days===14?'active':''} onClick={()=>setDays(14)}>{t('last14d')}</button><button className={days===30?'active':''} onClick={()=>setDays(30)}>{t('last30d')}</button></div></div>
    <section className="history-summary">{[['availability',`${summary.availability_pct??0}%`,TrendingUp],['disconnects',summary.disconnects||0,WifiOff],['recoveries',summary.recoveries||0,CheckCircle2],['affectedDevices',summary.devices_affected||0,AlertTriangle]].map(([key,value,Icon])=><article className="history-stat" key={key}><Icon/><span>{t(key)}</span><strong>{value}</strong></article>)}</section>
    <section className="history-grid"><article className="panel chart-panel wide"><div className="panel-title"><h2>{t('availability')}</h2><span className="score">{summary.availability_pct ?? 0}%</span></div><div className="chart-wrap tall"><ResponsiveContainer><AreaChart data={normalized}><defs><linearGradient id="historyAvailability" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#35d7ef" stopOpacity=".52"/><stop offset="1" stopColor="#35d7ef" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="var(--chart-grid)" vertical={false}/><XAxis dataKey="name" stroke="var(--chart-axis)" tickLine={false}/><YAxis domain={[0,100]} stroke="var(--chart-axis)" tickLine={false}/><Tooltip contentStyle={{background:'var(--chart-tooltip)',border:'1px solid var(--line-strong)',borderRadius:14}}/><Area dataKey="availability" stroke="#35d7ef" fill="url(#historyAvailability)" strokeWidth={3}/></AreaChart></ResponsiveContainer></div></article><article className="panel chart-panel"><div className="panel-title"><h2>{t('disconnects')}</h2><span className="score danger-text">{summary.disconnects||0}</span></div><div className="chart-wrap tall"><ResponsiveContainer><BarChart data={normalized}><CartesianGrid stroke="var(--chart-grid)" vertical={false}/><XAxis dataKey="name" hide/><YAxis hide/><Tooltip contentStyle={{background:'var(--chart-tooltip)',border:'1px solid var(--line-strong)',borderRadius:14}}/><Bar dataKey="disconnects" fill="#ff5c70" radius={[8,8,2,2]}/></BarChart></ResponsiveContainer></div></article></section>
    <section className="history-lower"><article className="panel ranking-panel"><div className="panel-title"><h2>{t('stableDevices')}</h2><CheckCircle2/></div><div className="rank-list">{(rankings.stable||[]).map((item,index)=><div key={item.ip}><b>{index+1}</b><span><strong>{item.name}</strong><small>{item.ip}</small></span><em>{item.availability_pct??item.value}%</em></div>)}</div></article><article className="panel ranking-panel"><div className="panel-title"><h2>{t('unstableDevices')}</h2><AlertTriangle/></div><div className="rank-list">{(rankings.unstable||[]).map((item,index)=><div key={item.ip}><b>{index+1}</b><span><strong>{item.name}</strong><small>{item.offline_count||0} {t('disconnects')}</small></span><em>{item.availability_pct}%</em></div>)}</div></article><article className="panel changes-panel"><div className="panel-title"><h2>{t('recentChanges')}</h2><History/></div><div className="change-list">{(report?.recent_changes||[]).slice(0,8).map((item,index)=><div key={`${item.ip}-${item.ts}-${index}`}><StatusDot status={item.new_status}/><span><strong>{item.name}</strong><small>{item.old_status} → {item.new_status}</small></span><time>{formatDate(item.ts)}</time></div>)}</div></article></section>
  </div>
}

function Tools({ data, t }) {
  const [target,setTarget]=useState(''); const [selected,setSelected]=useState('ping'); const [ports,setPorts]=useState('80,443,554,8000,8080,22'); const [result,setResult]=useState(null); const [running,setRunning]=useState(false)
  const run=async()=>{setRunning(true);setResult(null);try{setResult(await api('/tools/run',{method:'POST',body:JSON.stringify({target,tools:[selected],ports})}))}catch(error){setResult({ok:false,error:error.message})}finally{setRunning(false)}}
  const toolResult = result?.tools?.[selected]
  const status = result?.overall_status || (result?.error?'down':'idle')
  const resultItems = toolResult?.items || toolResult?.ports || toolResult?.hops || toolResult?.addresses || []
  const assessmentKey = !toolResult ? '' : selected === 'ping' ? (Number(toolResult.loss_pct) === 0 ? (Number(toolResult.latency_avg_ms) < 40 ? 'pingExcellent' : Number(toolResult.latency_avg_ms) < 100 ? 'pingGood' : 'pingSlow') : Number(toolResult.loss_pct) < 30 ? 'pingPacketLoss' : 'pingUnavailable') : selected === 'ports' ? (Number(toolResult.open_ports) ? 'portsFound' : 'noOpenPorts') : selected === 'trace' ? (toolResult.hop_count ? 'routeFound' : 'routeUnavailable') : selected === 'dns' ? (toolResult.reverse_host ? 'dnsResolved' : 'dnsNotResolved') : selected === 'speed' ? (toolResult.ok ? 'speedCompleted' : 'speedFailed') : selected === 'free_ips' ? 'freeIpsFound' : status
  return <div className="page-stack"><div className="page-heading"><div><span className="eyebrow">DIAGNOSTICS LAB</span><h1>{t('tools')}</h1><p>Ping · Trace · Ports · DNS · Speed · IP discovery</p></div><span className={`result-status ${status}`}>{running?t('scanning'):status}</span></div><section className="tools-layout"><article className="panel tool-console"><div className="target-row"><label>{t('target')}<input value={target} onChange={e=>setTarget(e.target.value)} placeholder="192.168.1.100" list="device-ips"/><datalist id="device-ips">{(data.devices||[]).map(d=><option value={d.ip} key={d.ip}>{d.display_name}</option>)}</datalist></label><button className="button primary" onClick={run} disabled={running||(!target&&!['speed','free_ips'].includes(selected))}><Play size={17}/>{running?t('scanning'):t('run')}</button></div>{selected==='ports'&&<label className="ports-field">{t('ports')}<input value={ports} onChange={e=>setPorts(e.target.value)} placeholder="80,443 or 1-1024"/></label>}<div className="tool-selector">{[['ping',Activity],['trace',Route],['ports',ShieldAlert],['dns',Globe2],['speed',Gauge],['free_ips',Network]].map(([key,Icon])=><button className={selected===key?'active':''} onClick={()=>{setSelected(key);setResult(null)}} key={key}><Icon/><span>{key==='free_ips'?t('freeIps'):t(key)}</span></button>)}</div></article><article className="panel diagnostic-result"><div className="terminal-head"><Terminal size={17}/><span>HOMEii diagnostics</span><i className={running?'running':''}/>{result&&<button onClick={()=>setResult(null)}>{t('clear')}</button>}</div>{!result?<div className="diagnostic-empty"><Activity/><strong>{t('diagnostics')}</strong><p>{t('run')} {selected==='free_ips'?t('freeIps'):t(selected)}</p></div>:result.error?<div className="diagnostic-error"><AlertTriangle/><strong>{result.error}</strong></div>:<div className="result-body"><div className="result-hero"><span className={`result-orb ${status}`}><CheckCircle2/></span><div><small>{t('result')}</small><h2>{selected==='free_ips'?t('freeIps'):t(selected)}</h2><p>{result.target}</p></div></div><div className={`result-assessment ${status}`}><strong>{t(assessmentKey)}</strong><p>{t(`${assessmentKey}Help`)}</p></div><details className="advanced-result"><summary>{t('advancedDetails')}</summary><div className="result-metrics">{Object.entries(toolResult||{}).filter(([,value])=>['string','number','boolean'].includes(typeof value)).slice(0,8).map(([key,value])=><div key={key}><span>{key.replaceAll('_',' ')}</span><strong>{String(value)}</strong></div>)}</div>{resultItems.length>0&&<div className="result-list">{resultItems.slice(0,50).map((item,index)=>{const value=typeof item==='string'?item:(item.ip||item.port||item.host||index+1);const detail=typeof item==='string'?t('ready'):(item.open===true?t('open'):item.open===false?t('closed'):(item.status||item.name||item.service||item.address||'—'));return <div key={index}><code>{value}</code><span>{detail}</span></div>})}</div>}</details></div>}</article></section></div>
}

function SettingsPage({ data, t, language, refresh, enableNotifications }) {
  const settings=data.settings||{}; const [form,setForm]=useState({language:settings.language||language,theme:settings.theme||'granite',auto_refresh:settings.auto_refresh||'30',history_retention_days:settings.history_retention_days||'30',alert_profile:settings.alert_profile||'normal',default_view:settings.default_view||'table',dashboard_style:settings.dashboard_style||'advanced',status_animation:settings.status_animation||'blink',discovery_mode:data.settingsPayload?.discovery_mode||'auto_manual',discovery_protocols:data.settingsPayload?.discovery_protocols||['ping','arp','dns','special','vendor']})
  const [section,setSection]=useState('general')
  const [transfer,setTransfer]=useState({type:'',message:''})
  const [networksText,setNetworksText]=useState('')
  const importRef=useRef(null)
  useEffect(()=>setForm(f=>({...f,language:settings.language||f.language,theme:settings.theme||f.theme,auto_refresh:settings.auto_refresh||f.auto_refresh,history_retention_days:settings.history_retention_days||f.history_retention_days,alert_profile:settings.alert_profile||f.alert_profile,default_view:settings.default_view||f.default_view,dashboard_style:settings.dashboard_style||f.dashboard_style,status_animation:settings.status_animation||f.status_animation,discovery_mode:data.settingsPayload?.discovery_mode||f.discovery_mode,discovery_protocols:data.settingsPayload?.discovery_protocols||f.discovery_protocols})),[settings,data.settingsPayload?.discovery_mode,data.settingsPayload?.discovery_protocols])
  useEffect(()=>setNetworksText((data.settingsPayload?.networks||data.status?.networks||[]).join('\n')),[data.settingsPayload?.networks,data.status?.networks])
  const saveForm=async(next=form)=>{await api('/save_settings',{method:'POST',body:JSON.stringify({...settings,...next,networks:data.settingsPayload?.networks||data.status?.networks||[],network_names:data.settingsPayload?.network_names||{}})});await refresh()}
  const save=()=>saveForm(form)
  const saveNetworks=async()=>{await api('/save_networks',{method:'POST',body:JSON.stringify({networks:networksText,network_names:data.settingsPayload?.network_names||{}})});await refresh();setTransfer({type:'success',message:t('networksSaved')})}
  const importFile=async(event)=>{const file=event.target.files?.[0];if(!file)return;const kind=file.name.toLowerCase().endsWith('.csv')?'devices':'settings';const body=new FormData();body.append('file',file);try{const result=await api(`/import/${kind}`,{method:'POST',body});await refresh();setTransfer({type:'success',message:kind==='devices'?`${t('imported')} ${result.imported||0}`:t('settingsImported')})}catch(error){setTransfer({type:'error',message:error.message})}finally{event.target.value=''}}
  const sections=[['general',SlidersHorizontal],['appearance',Eye],['discovery',Radar],['networks',Network],['notification',Bell],['system',Database],['dataManagement',FileJson]]
  return <div className="page-stack settings-page"><div className="page-heading"><div><span className="eyebrow">{t('systemConfiguration')}</span><h1>{t('settings')}</h1><p>{t('controlPlane')} · v{data.status?.version}</p></div></div>{transfer.message&&<div className={transfer.type==='error'?'error-banner':'success-banner'}>{transfer.type==='error'?<AlertTriangle/>:<CheckCircle2/>}{transfer.message}<button onClick={()=>setTransfer({type:'',message:''})}><X/></button></div>}<div className="settings-layout"><nav className="settings-nav">{sections.map(([key,Icon])=><button className={section===key?'active':''} onClick={()=>setSection(key)} key={key}><Icon/><span>{t(key)}</span><ChevronLeft/></button>)}</nav><section className="panel settings-content">
    {section==='general'&&<><div className="settings-title"><SlidersHorizontal/><div><h2>{t('general')}</h2><p>{t('generalHelp')}</p></div></div><div className="form-grid"><label>{t('autoRefresh')}<input type="number" min="10" max="3600" value={form.auto_refresh} onChange={e=>setForm({...form,auto_refresh:e.target.value})}/><small>10–3600 {t('seconds')}</small></label><label>{t('historyDays')}<input type="number" min="1" max="365" value={form.history_retention_days} onChange={e=>setForm({...form,history_retention_days:e.target.value})}/><small>1–365 {t('days')}</small></label><label>{t('alertProfile')}<select value={form.alert_profile} onChange={e=>setForm({...form,alert_profile:e.target.value})}><option value="quiet">{t('quiet')}</option><option value="normal">{t('normal')}</option><option value="strict">{t('strict')}</option></select><small>{t('alertProfileHelp')}</small></label><label>{t('defaultView')}<select value={form.default_view} onChange={e=>setForm({...form,default_view:e.target.value})}><option value="table">{t('table')}</option><option value="grid">{t('grid')}</option></select></label><label>{t('dashboardStyle')}<select value={form.dashboard_style} onChange={e=>setForm({...form,dashboard_style:e.target.value})}><option value="advanced">{t('advanced')}</option><option value="compact">{t('compact')}</option></select></label><label>{t('statusAnimation')}<select value={form.status_animation} onChange={e=>setForm({...form,status_animation:e.target.value})}><option value="blink">{t('blink')}</option><option value="static">{t('static')}</option></select></label></div></>}
    {section==='appearance'&&<><div className="settings-title"><Eye/><div><h2>{t('appearance')}</h2><p>{t('language')} · {t('theme')}</p></div></div><div className="choice-grid"><button className={form.language==='he'?'selected':''} onClick={()=>{const next={...form,language:'he'};setForm(next);saveForm(next)}}><Languages/><strong>עברית</strong><span>RTL</span></button><button className={form.language==='en'?'selected':''} onClick={()=>{const next={...form,language:'en'};setForm(next);saveForm(next)}}><Languages/><strong>English</strong><span>LTR</span></button><button className={['granite','dark'].includes(form.theme)?'selected':''} onClick={()=>{const next={...form,theme:'granite'};setForm(next);document.documentElement.dataset.theme='granite';saveForm(next)}}><MonitorUp/><strong>{t('granite')}</strong><span>Charcoal</span></button><button className={form.theme==='navy'?'selected':''} onClick={()=>{const next={...form,theme:'navy'};setForm(next);document.documentElement.dataset.theme='navy';saveForm(next)}}><MonitorUp/><strong>{t('navy')}</strong><span>Midnight</span></button><button className={form.theme==='light'?'selected':''} onClick={()=>{const next={...form,theme:'light'};setForm(next);document.documentElement.dataset.theme='light';saveForm(next)}}><MonitorUp/><strong>{t('light')}</strong><span>Porcelain</span></button></div></>}
    {section==='discovery'&&<><div className="settings-title"><Radar/><div><h2>{t('discovery')}</h2><p>{t('discoveryHelp')}</p></div></div><div className="form-grid"><label>{t('discoveryMode')}<select value={form.discovery_mode} onChange={e=>setForm({...form,discovery_mode:e.target.value})}><option value="auto_manual">{t('autoManual')}</option><option value="auto_only">{t('autoOnly')}</option><option value="manual_only">{t('manualOnly')}</option></select><small>{t('discoveryModeHelp')}</small></label></div><div className="protocol-grid">{['ping','arp','dns','special','vendor'].map(protocol=><button type="button" className={(form.discovery_protocols||[]).includes(protocol)?'active':''} onClick={()=>setForm({...form,discovery_protocols:(form.discovery_protocols||[]).includes(protocol)?form.discovery_protocols.filter(item=>item!==protocol):[...(form.discovery_protocols||[]),protocol]})} key={protocol}><span/><div><strong>{t(`protocol_${protocol}`)}</strong><small>{t(`protocol_${protocol}_help`)}</small></div></button>)}</div></>}    {section==='networks'&&<><div className="settings-title"><Network/><div><h2>{t('networks')}</h2><p>{t('networksHelp')}</p></div></div><label className="notes-field">{t('networkRanges')}<textarea value={networksText} onChange={e=>setNetworksText(e.target.value)} placeholder={'192.168.1.0/24\n10.0.0.0/24'}/><small>{t('oneNetworkPerLine')}</small></label><div className="settings-actions inline"><button className="button primary" onClick={saveNetworks}>{t('saveNetworks')}</button></div><div className="network-list">{(data.settingsPayload?.networks||data.status?.networks||[]).map((network,index)=><div key={network}><span className="icon-box"><Network/></span><div><strong>{data.settingsPayload?.network_names?.[network]||`${t('network')} ${index+1}`}</strong><code>{network}</code></div><span className="healthy-label">{t('monitorLive')}</span></div>)}</div></>}
    {section==='notification'&&<><div className="settings-title"><Bell/><div><h2>{t('notification')}</h2><p>PWA · browser alerts</p></div></div><div className="notification-card"><Bell/><div><strong>{t('enableNotifications')}</strong><p>{t('openAlerts')} · {t('offline')} · {t('recoveries')}</p></div><button className="button" onClick={enableNotifications}>{t('enableNotifications')}</button></div></>}
    {section==='system'&&<><div className="settings-title"><DatabaseIcon/><div><h2>{t('system')}</h2><p>{t('systemWorkers')}</p></div></div><dl className="system-dl"><div><dt>{t('version')}</dt><dd>{data.status?.version}</dd></div><div><dt>{t('database')}</dt><dd className={data.status?.db_ok?'healthy-label':'danger-text'}>{data.status?.db_ok?t('ready'):t('unavailable')}</dd></div><div><dt>{t('networks')}</dt><dd>{data.status?.networks?.length||0}</dd></div><div><dt>PWA</dt><dd>{'serviceWorker' in navigator?t('ready'):t('unavailable')}</dd></div></dl></>}
    {section==='dataManagement'&&<><div className="settings-title"><FileJson/><div><h2>{t('dataManagement')}</h2><p>{t('dataManagementHelp')}</p></div></div><div className="transfer-grid"><a className="transfer-card" href="./api/export/devices.csv" download><FileSpreadsheet/><div><strong>{t('exportDevices')}</strong><span>CSV · Excel</span></div><Download/></a><a className="transfer-card" href="./api/export/settings.json" download><FileJson/><div><strong>{t('exportSettings')}</strong><span>JSON</span></div><Download/></a><button className="transfer-card" onClick={()=>importRef.current?.click()}><Upload/><div><strong>{t('importData')}</strong><span>CSV / JSON</span></div><ArrowUpRight/></button><input ref={importRef} className="visually-hidden" type="file" accept=".csv,.json,text/csv,application/json" onChange={importFile}/></div></>}
    <div className="settings-actions"><button className="button primary" onClick={save}>{t('save')}</button></div>
  </section></div></div>
}

function DatabaseIcon(){return <div className="db-icon"><span/><span/><span/></div>}

export default function App() {
  const [route,setRoute,routeDetail]=useRoute(); const [data,setData]=useState({}); const [loading,setLoading]=useState(true); const [error,setError]=useState(''); const [menuOpen,setMenuOpen]=useState(false)
  const [workspaceMode,setWorkspaceMode]=useState(()=>localStorage.getItem('homeii-workspace-mode')||'admin')
  const notificationReady=useRef(false)
  const language=data.settings?.language||'he'; const t=useMemo(()=>translator(language),[language])
  const showAlertNotifications=async(alerts=[])=>{if(!('Notification' in window)||Notification.permission!=='granted')return;const open=alerts.filter(a=>a.status==='open');const ids=open.map(a=>String(a.id));const previous=JSON.parse(localStorage.getItem('homeii-notified-alerts')||'null');localStorage.setItem('homeii-notified-alerts',JSON.stringify(ids));if(!notificationReady.current||!previous){notificationReady.current=true;return}const fresh=open.filter(a=>!previous.includes(String(a.id)));if(!fresh.length)return;const registration=await navigator.serviceWorker?.ready;fresh.slice(0,3).forEach(alert=>registration?.showNotification(alert.title||'HOMEii Network Alert',{body:alert.message||alert.ip||'',icon:'./icons/homeii-192.png',badge:'./icons/homeii-192.png',tag:`homeii-alert-${alert.id}`,data:{route:'#/alerts'}}))}
  const enableNotifications=async()=>{if(!('Notification' in window)){setError(t('notificationsUnsupported'));return}const permission=await Notification.requestPermission();if(permission==='granted'){notificationReady.current=true;setError('')}else setError(t('notificationsDenied'))}
  const refresh=async()=>{try{setError('');const [status,devices,alerts,events,settingsPayload,viewer,history]=await Promise.all([api('/status'),api('/devices'),api('/alerts?limit=100'),api('/events?limit=100'),api('/settings'),api('/viewer/categories'),api('/history/summary')]);const alertItems=alerts.alerts||[];setData({status,devices:devices.devices||[],alerts:alertItems,events:events.events||[],settings:settingsPayload.settings||{},settingsPayload,viewer,history});showAlertNotifications(alertItems)}catch(e){setError(e.message)}finally{setLoading(false)}}
  useEffect(()=>{refresh()},[])
  useEffect(()=>{const interval=Math.max(10,Number(data.settings?.auto_refresh||30))*1000;const id=setInterval(refresh,interval);return()=>clearInterval(id)},[data.settings?.auto_refresh])
  useEffect(()=>{document.documentElement.lang=language;document.documentElement.dir=language==='he'?'rtl':'ltr';document.documentElement.dataset.theme=data.settings?.theme||'dark'},[language,data.settings?.theme])
  const pages={dashboard:<Dashboard data={data} t={t} setRoute={setRoute} language={language}/>,viewer:<Viewer data={data} t={t}/>,devices:<Devices data={data} t={t} language={language} refresh={refresh} initialFilter={routeDetail}/>,alerts:<Alerts data={data} t={t} language={language} refresh={refresh}/>,history:<HistoryPage history={data.history} t={t} language={language}/>,tools:<Tools data={data} t={t}/>,settings:<SettingsPage data={data} t={t} language={language} refresh={refresh} enableNotifications={enableNotifications}/>}
  const allowed={admin:navItems,user:navItems.filter(([key])=>!['tools','settings'].includes(key)),noc:navItems.filter(([key])=>key==='viewer')}[workspaceMode]||navItems
  const changeMode=(mode)=>{setWorkspaceMode(mode);localStorage.setItem('homeii-workspace-mode',mode);if(mode==='noc')setRoute('viewer');if(mode==='user'&&['tools','settings'].includes(route))setRoute('dashboard')}
  return <div className={`app-shell mode-${workspaceMode}`}><aside className={menuOpen?'open':''}><Logo/><div className="mode-switch">{[['admin',UserCog],['user',Eye],['noc',MonitorUp]].map(([mode,Icon])=><button className={workspaceMode===mode?'active':''} onClick={()=>changeMode(mode)} title={t(`${mode}Mode`)} key={mode}><Icon/><span>{t(`${mode}Mode`)}</span></button>)}</div><nav>{allowed.map(([key,Icon])=><button key={key} className={route===key?'active':''} onClick={()=>{setRoute(key);setMenuOpen(false)}}><Icon/><span>{t(key)}</span>{route===key&&<i/>}</button>)}</nav><div className="sidebar-health"><span className="live-dot"/><div><strong>{t('monitorLive')}</strong><small>v{data.status?.version||'6.2.0'}</small></div></div></aside><div className="main-shell"><header><button className="mobile-menu icon-button" onClick={()=>setMenuOpen(!menuOpen)}><Menu/></button><div><span className="eyebrow">HOMEii / {t(route)}</span><h2>{new Date().toLocaleDateString(language==='he'?'he-IL':'en-US',{weekday:'long',day:'numeric',month:'long'})}</h2></div><div className="header-actions"><button className="button subtle" onClick={refresh}><RefreshCw className={loading?'spin':''}/><span>{t('refresh')}</span></button>{workspaceMode==='admin'&&<button className="button primary" onClick={async()=>{await api('/scan?mode=manual');refresh()}}><Radar/><span>{t('scanNow')}</span></button>}</div></header>{error&&<div className="error-banner"><AlertTriangle/>{error}<button onClick={()=>setError('')}><X/></button></div>}<main>{loading&&!data.status?<div className="loading-screen"><Logo/><div className="loader"/></div>:pages[route]||pages.dashboard}</main></div>{menuOpen&&<button className="scrim" onClick={()=>setMenuOpen(false)}/>}</div>
}
