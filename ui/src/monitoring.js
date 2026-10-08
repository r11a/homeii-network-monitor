// Shared presentation rules: missing evidence must never become a green state.
export function deviceMonitoringKey(device) {
  if (device.ignored || device.quarantined || device.trashed_at) return 'monitorPaused';
  return device.approved || device.manual ? 'alwaysMonitored' : 'discoveredDevice';
}

export function monitoringHealth(status, lastSync, connectionFailed, now = Date.now() / 1000, refreshSeconds = 30) {
  if (connectionFailed) return 'disconnected';
  if (!status || !lastSync) return 'unknown';
  if (now - lastSync > Math.max(45, Number(refreshSeconds) * 2 + 15)) return 'stale';
  if (status.monitoring_stale || Object.values(status.workers || {}).some(worker => worker.last_error || worker.alive === false)) return 'degraded';
  return 'live';
}

export function percent(value) {
  return value == null || !Number.isFinite(Number(value)) ? '—' : `${Number(value).toFixed(1)}%`;
}

export function csvText(rows) {
  // Excel formula injection applies to quoted cells too.
  return '\uFEFF' + rows.map(row => row.map(value => {
    let text = String(value ?? '');
    if (/^[\s]*[=+@-]/.test(text) || /^[\t\r\n]/.test(text)) text = "'" + text;
    return '"' + text.replaceAll('"', '""') + '"';
  }).join(',')).join('\r\n');
}

export function downloadCsv(name, rows) {
  const url = URL.createObjectURL(new Blob([csvText(rows)], { type: 'text/csv;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
