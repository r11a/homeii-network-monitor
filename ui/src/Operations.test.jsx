import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ReportsPage } from './Operations';
import { csvText, deviceMonitoringKey, monitoringHealth } from './monitoring';
import * as monitoring from './monitoring';
import { query } from './api';
import { translator } from './i18n';

vi.mock('./api', () => ({ query: vi.fn(), api: vi.fn() }));
const t = translator('en');
const report = { window: { from_ts: 1, to_ts: 100 }, devices: [
  { ip: '192.0.2.1', name: 'Gate camera', category: 'Cameras', availability_pct: 95, coverage_pct: 70, offline_count: 2, recovery_count: 1 },
  { ip: '192.0.2.2', name: 'Core router', category: 'Network', availability_pct: null, coverage_pct: 0, offline_count: 0, recovery_count: 0 },
] };
beforeEach(() => { query.mockReset().mockResolvedValue(report); });

describe('operational data integrity', () => {
  it('distinguishes retained monitoring from discovery and suspended devices', () => {
    expect(deviceMonitoringKey({ manual: true, status: 'offline' })).toBe('alwaysMonitored');
    expect(deviceMonitoringKey({ approved: true })).toBe('alwaysMonitored');
    expect(deviceMonitoringKey({ status: 'online' })).toBe('discoveredDevice');
    for (const flag of ['ignored', 'quarantined', 'trashed_at']) {
      expect(deviceMonitoringKey({ manual: true, [flag]: 1 })).toBe('monitorPaused');
    }
  });
  it('distinguishes unknown, stale, disconnected and degraded states', () => {
    expect(monitoringHealth(null, 0, false, 100)).toBe('unknown');
    expect(monitoringHealth({}, 90, false, 100)).toBe('live');
    expect(monitoringHealth({}, 1, false, 100)).toBe('stale');
    expect(monitoringHealth({}, 90, true, 100)).toBe('disconnected');
    expect(monitoringHealth({ workers: { monitor: { last_error: 'failed' } } }, 90, false, 100)).toBe('degraded');
    expect(monitoringHealth({ workers: { monitor: { alive: false } } }, 90, false, 100)).toBe('degraded');
  });
  it('escapes CSV fields and neutralizes spreadsheet formulas', () => {
    expect(csvText([['=cmd()', '+1', '@SUM(A1)', '-1', '  =1', 'a,"b', 'עברית']])).toBe('\uFEFF"\'=cmd()","\'+1","\'@SUM(A1)","\'-1","\'  =1","a,""b","עברית"');
  });
  it('filters reports without presenting missing history as 100%', async () => {
    const user = userEvent.setup();
    render(<ReportsPage t={t} language="en" setRoute={vi.fn()} />);
    await screen.findByText('Gate camera');
    expect(within(screen.getByText('Core router').closest('tr')).getByText('—')).toBeTruthy();
    await user.selectOptions(screen.getByLabelText(t('category')), 'Cameras');
    expect(screen.queryByText('Core router')).toBeNull();
    expect(screen.getByText('Gate camera')).toBeTruthy();
  });
  it('does not display or export an old period after a failed request', async () => {
    const user = userEvent.setup();
    render(<ReportsPage t={t} language="en" setRoute={vi.fn()} />);
    await screen.findByText('Gate camera');
    query.mockRejectedValueOnce(new Error('server unavailable'));
    await user.selectOptions(screen.getByLabelText(t('reportPeriod')), '30');
    await screen.findByRole('alert');
    expect(screen.queryByText('Gate camera')).toBeNull();
    expect(screen.getByRole('button', { name: t('exportReport') }).disabled).toBe(true);
  });
  it('exports exactly the filtered rows with the report period and method', async () => {
    const download = vi.spyOn(monitoring, 'downloadCsv').mockImplementation(() => {});
    const user = userEvent.setup();
    render(<ReportsPage t={t} language="en" setRoute={vi.fn()} />);
    await screen.findByText('Gate camera');
    await user.selectOptions(screen.getByLabelText(t('category')), 'Cameras');
    await user.click(screen.getByRole('button', { name: t('exportReport') }));
    const [filename, rows] = download.mock.calls[0];
    expect(filename).toBe('homeii-report-7d.csv');
    expect(rows[3]).toEqual([t('reportMethod'), t('historyEstimateHelp')]);
    expect(rows.slice(5)).toEqual([['Gate camera', '192.0.2.1', 'Cameras', '95.0%', '70.0%', 2, 1]]);
  });
  it('ignores a late response for a previous period', async () => {
    let finish;
    query.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const user = userEvent.setup();
    render(<ReportsPage t={t} language="en" setRoute={vi.fn()} />);
    await user.selectOptions(screen.getByLabelText(t('reportPeriod')), '30');
    await screen.findByText('Gate camera');
    await act(async () => finish({ devices: [{ ...report.devices[0], name: 'Obsolete response' }] }));
    expect(screen.queryByText('Obsolete response')).toBeNull();
    await waitFor(() => expect(screen.getByText('Gate camera')).toBeTruthy());
  });
});
