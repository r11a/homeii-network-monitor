import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { api } from './api';
import ZabbixWorkspace from './ZabbixWorkspace';

vi.mock('./api', () => ({ api: vi.fn() }));
let configured, stale, role;
beforeEach(() => {
  configured = true; stale = false; role = 'admin'; localStorage.clear();
  localStorage.setItem('homeii-engine-language', 'en');
  api.mockReset().mockImplementation(async (path) => {
    if (path === '/auth/session') return { authenticated: true, user: { role, username: 'operator' } };
    if (path === '/engine/config') return { configured, active: configured, local_bundle: true };
    if (path.startsWith('/engine/devices')) return { devices: [{ id: '42', name: 'Camera', ip: '192.0.2.4', status: 'online', groups: ['Cameras'], last_check: 1 }],
      events: [], counts: { total: 1, online: 1, offline: 0, unknown: 0, problems: 0 }, total: 1, updated_at: Math.floor(Date.now()/1000), stale, error: stale ? 'engine_unreachable' : '' };
    if (path.endsWith('/history')) return { samples: 0, availability: null, coverage: 0, series: [] };
    return { ok: true };
  });
});

it('offers manual entry with clear fields and submits the host', async () => {
  render(<ZabbixWorkspace />);
  fireEvent.click(await screen.findByRole('button', { name: 'Add device' }));
  fireEvent.change(screen.getByLabelText('IP address'), { target: { value: '192.0.2.8' } });
  fireEvent.change(screen.getByLabelText('Device name'), { target: { value: 'New camera' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save and monitor' }));
  await waitFor(() => expect(api.mock.calls.some(([path, options]) => path === '/engine/hosts' && JSON.parse(options.body).name === 'New camera')).toBe(true));
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
