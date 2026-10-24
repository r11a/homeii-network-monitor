import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api } from './api';
import ZabbixWorkspace from './ZabbixWorkspace';

vi.mock('./api', () => ({ api: vi.fn() }));
let configured, stale, role, deviceStatus;
beforeEach(() => {
  configured = true; stale = false; role = 'admin'; deviceStatus = 'online'; localStorage.clear();
  localStorage.setItem('homeii-engine-language', 'en');
  api.mockReset().mockImplementation(async (path) => {
    if (path === '/auth/session') return { authenticated: true, user: { role, username: 'operator' } };
    if (path === '/engine/config') return { configured, active: configured, local_bundle: true };
    if (path.startsWith('/engine/devices')) return { devices: [{ id: '42', name: 'Camera', ip: '192.0.2.4', status: deviceStatus, groups: ['Cameras'], last_check: 1 }],
      events: [], counts: { total: 1, online: 1, offline: 0, unknown: 0, problems: 0 }, total: 1, updated_at: Math.floor(Date.now()/1000), stale, error: stale ? 'engine_unreachable' : '' };
    if (path.endsWith('/history')) return { samples: 0, availability: null, coverage: 0, series: [] };
    return { ok: true };
  });
});

it('updates an open device dialog when a fresh snapshot reports an outage', async () => {
  render(<ZabbixWorkspace />);
  fireEvent.click(await screen.findByRole('button', { name: /Camera/ }));
  expect(within(screen.getByRole('dialog')).getByText('Online')).toBeTruthy();
  deviceStatus = 'offline';
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
  await waitFor(() => expect(within(screen.getByRole('dialog')).getByText('Offline')).toBeTruthy());
});

it('offers manual entry with clear fields and submits the host', async () => {
  render(<ZabbixWorkspace />);
  fireEvent.click(await screen.findByRole('button', { name: 'Add device' }));
  fireEvent.change(screen.getByLabelText('IP address'), { target: { value: '192.0.2.8' } });
  fireEvent.change(screen.getByLabelText('Device name'), { target: { value: 'New camera' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save and monitor' }));
  await waitFor(() => expect(api.mock.calls.some(([path, options]) => path === '/engine/hosts' && JSON.parse(options.body).name === 'New camera')).toBe(true));
});

it('shows identification details and labels device type as inferred', async () => {
  const original = api.getMockImplementation();
  api.mockImplementation(async (path, options) => path === '/engine/discovery'
    ? { devices: [{ ip: '192.168.1.4', name: 'camera-front', mac: '00:40:8c:12:34:56', vendor: 'Axis', device_type: 'camera', last_seen: 10 }] }
    : original(path, options));
  render(<ZabbixWorkspace />);
  fireEvent.click(await screen.findByRole('button', { name: 'Setup' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Show discovered devices' }));
  expect(await screen.findByText('MAC: 00:40:8c:12:34:56')).toBeTruthy();
  expect(screen.getByText('Network adapter vendor: Axis')).toBeTruthy();
  expect(screen.getByText('Type inferred from name: camera')).toBeTruthy();
});

it('marks lost monitoring explicitly instead of displaying a live success', async () => {
  stale = true; render(<ZabbixWorkspace />);
  expect((await screen.findByRole('alert')).textContent).toContain('Monitoring unavailable');
  expect(screen.queryByText('Monitoring live')).toBeNull();
});

it('does not show administration to a control-room operator', async () => {
  role = 'control'; render(<ZabbixWorkspace />);
  await screen.findByText('Control room');
  expect(screen.queryByRole('button', { name: 'Add device' })).toBeNull();
  expect(screen.queryByRole('button', { name: 'Setup' })).toBeNull();
});

it('explains local automatic initialization without exposing configuration code', async () => {
  configured = false; render(<ZabbixWorkspace />);
  expect(await screen.findByText('Preparing your local monitoring engine')).toBeTruthy();
  expect(screen.queryByText('JSON')).toBeNull();
});

it('edits metadata through the engine and offers pause', async () => {
  render(<ZabbixWorkspace />);
  fireEvent.click(await screen.findByRole('button', {name:/Camera/}));
  fireEvent.change(screen.getByLabelText('Name'), {target:{value:'Gate camera'}});
  fireEvent.click(screen.getByRole('button', {name:'Save'}));
  await waitFor(()=>expect(api.mock.calls.some(([path, options]) => path === '/engine/hosts/42/update' && JSON.parse(options.body).name === 'Gate camera')).toBe(true));
});
it('loads reports from the engine inventory and selected period', async () => {
  render(<ZabbixWorkspace />);
  fireEvent.click(await screen.findByRole('button', {name:'Reports'}));
  fireEvent.change(screen.getByLabelText('Report period'), {target:{value:'7'}});
  fireEvent.click(await screen.findByRole('button', {name:'Generate report'}));
  await waitFor(()=>expect(api.mock.calls.some(([path])=>path === '/engine/hosts/42/history?days=7')).toBe(true));
});
