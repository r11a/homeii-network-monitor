import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';
import { api } from './api';
import { translator } from './i18n';

vi.mock('./api', () => ({ api: vi.fn(), query: vi.fn(async () => ({ ok: true })) }));
const t = translator('en');
let inventory, errorLog, role;
const device = { ip: '127.0.0.1', name: 'Test device', display_name: 'Test device', category: 'Tests', status: 'online', approved: true, tags: [], first_seen: 1, last_seen: 1 };
async function respond(path, options = {}) {
  if (path === '/auth/session') return { authenticated: true, user: { id: 1, username: 'test', role } };
  if (path === '/status') return { total: inventory.length, online: inventory.length, offline: 0, networks: ['127.0.0.0/8'], workers: {}, version: 'test' };
  if (path === '/devices') return { devices: inventory };
  if (path === '/settings') return { settings: { language: 'en', theme: 'granite', default_view: 'table' }, networks: ['127.0.0.0/8'] };
  if (path === '/viewer/categories') return { categories: [{ category: 'Tests', total: 1, online: 1, series: [] }, { category: '', total: 0, series: [] }], devices: {}, summary: { series: [], availability_24h: 100 } };
  if (path === '/labels') return { categories: [{ id: 1, kind: 'category', name: 'Tests', color: '#123456', icon: 'boxes' }], tags: [] };
  if (path.startsWith('/alerts')) return { alerts: [] };
  if (path.startsWith('/events')) return { events: [] };
  if (path.startsWith('/admin/users')) return { users: [] };
  if (path === '/add_manual') {
    const draft = JSON.parse(options.body);
    if (draft.ip === 'invalid') throw new Error('invalid_ip');
    if (inventory.some(item => item.ip === draft.ip)) throw new Error('device_identity_conflict');
    const saved = { ...device, ...draft, display_name: draft.name, status: 'offline' };
    inventory.push(saved);
    return { ok: true, device: saved };
  }
  return {};
}
beforeEach(() => {
  localStorage.clear();
  inventory = [{ ...device }];
  role = 'admin';
  api.mockReset().mockImplementation(respond);
  errorLog = vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  expect(errorLog.mock.calls.map(args => args.join(' ')).join('\n')).not.toMatch(/ReferenceError|TypeError|Maximum update depth|page render failed|not defined/);
});
async function open(route) {
  window.history.replaceState({}, '', `/#/${route}`);
  render(<App />);
  await screen.findByRole('button', { name: route === 'settings' ? t('backToApplication') : t('refresh'), exact: true });
  await waitFor(() => expect(document.documentElement.lang).toBe('en'));
  return userEvent.setup();
}
describe('application routes', () => {
  it.each(['dashboard', 'viewer', 'devices', 'alerts', 'history', 'reports', 'tools'])('renders %s', async route => {
    await open(route);
    expect(document.querySelector('main')?.textContent.length).toBeGreaterThan(0);
    expect(document.querySelector('.page-recovery')).toBeNull();
  });
  it.each(['general', 'devices', 'labels', 'appearance', 'discovery', 'networks', 'notification', 'operationsManagement', 'users', 'auditLog', 'system', 'dataManagement'])('opens settings section %s', async section => {
    const user = await open('settings');
    await user.click(within(document.querySelector('.settings-nav')).getByRole('button', { name: t(section), exact: true }));
    expect(document.querySelector(`.section-${section}`)).not.toBeNull();
    expect(document.querySelector('.page-recovery')).toBeNull();
  });
  it.each(['user', 'viewer', 'control'])('renders restricted workspace for %s', async accountRole => {
    role = accountRole;
    window.history.replaceState({}, '', '/#/viewer');
    render(<App />);
    await screen.findByRole('button', { name: t('customizeControlRoom') });
    expect(document.querySelector('.page-recovery')).toBeNull();
  });
});
describe('device onboarding', () => {
  it.each(['devices', 'settings'])('adds consecutive devices from %s, preserving inputs on errors', async route => {
    const user = await open(route);
    if (route === 'settings') await user.click(within(document.querySelector('.settings-nav')).getByRole('button', { name: t('devices'), exact: true }));
    await user.click(screen.getByRole('button', { name: t('addDevice'), exact: true }));
    const dialog = screen.getByRole('dialog', { name: t('addDevice') });
    const ip = within(dialog).getByLabelText(t('ip'), { exact: true });
    const name = within(dialog).getByLabelText(t('name'), { exact: true });
    const category = within(dialog).getByLabelText(t('category'), { exact: true });
    const submit = within(dialog).getByRole('button', { name: t('addAndMonitor') });
    for (const suffix of ['2', '3']) {
      await user.type(ip, `127.0.0.${suffix}`);
      await user.type(name, `Device ${suffix}`);
      if (route === 'settings') await user.selectOptions(category, 'Tests');
      else await user.type(category, 'Tests');
      if (route === 'settings') await user.selectOptions(within(dialog).getByLabelText(t('scanProfile')), 'fast');
      await user.click(submit);
      await waitFor(() => expect(ip.value).toBe(''));
      expect(name.value).toBe('');
      expect(category.value).toBe('');
      expect(document.activeElement).toBe(ip);
      expect(within(dialog).getByText(t('rapidAddOffline'), { exact: false })).toBeTruthy();
      expect(inventory.at(-1).category).toBe('Tests');
      if (route === 'settings') expect(inventory.at(-1).scan_profile).toBe('fast');
    }
    expect(api.mock.calls.filter(([path]) => path === '/add_manual')).toHaveLength(2);
    expect(api.mock.calls.some(([path]) => path === '/devices/preflight' || path.startsWith('/ping_now'))).toBe(false);
    await user.type(ip, 'invalid');
    await user.type(name, 'Keep this name');
    await user.click(submit);
    await within(dialog).findByRole('alert');
    expect(ip.value).toBe('invalid');
    expect(name.value).toBe('Keep this name');
    expect(document.querySelector('.page-recovery')).toBeNull();
  });
});
describe('control center', () => {
  it('opens customization, saves selection, and opens uncategorized detail', async () => {
    const user = await open('viewer');
    await user.click(screen.getByRole('button', { name: t('customizeControlRoom') }));
    const dialog = screen.getByRole('dialog', { name: t('customizeControlRoom') });
    await user.selectOptions(within(dialog).getByLabelText(t('controlLayout')), 'stacked');
    await user.click(within(dialog).getByRole('checkbox', { name: 'Tests', exact: true }));
    await user.click(within(dialog).getAllByRole('button', { name: t('close'), exact: true }).at(-1));
    expect(document.querySelector('.control-board.layout-stacked')).not.toBeNull();
    const preferences = JSON.parse(localStorage.getItem('homeii-control-room-1'));
    expect(preferences.hiddenCategories).toContain('Tests');
    await user.click(within(document.querySelector('.category-grid')).getByRole('button'));
    expect(screen.getByRole('dialog', { name: t('uncategorized') })).toBeTruthy();
  });
});

describe('secondary forms and navigation', () => {
  it('shows user creation failures inside the dialog and keeps the draft', async () => {
    api.mockImplementation((path, options) => path === '/admin/users' && options?.method === 'POST' ? Promise.reject(new Error('username_exists')) : respond(path, options));
    const user = await open('settings');
    await user.click(within(document.querySelector('.settings-nav')).getByRole('button', { name: t('users'), exact: true }));
    await user.click(screen.getByRole('button', { name: t('addUser'), exact: true }));
    const dialog = screen.getByRole('dialog', { name: t('addUser') });
    await user.type(within(dialog).getByLabelText(t('username')), 'existing');
    await user.type(within(dialog).getByLabelText(t('password')), 'test-password-only');
    await user.click(within(dialog).getByRole('button', { name: t('addUser') }));
    expect((await within(dialog).findByRole('alert')).textContent).toContain('username_exists');
    expect(within(dialog).getByLabelText(t('username')).value).toBe('existing');
  });
  it('resets a user password through the existing update API', async () => {
    api.mockImplementation((path, options) => path === '/admin/users' ? Promise.resolve({ users: [{ id: 2, username: 'operator', role: 'user', active: true }] }) : respond(path, options));
    const user = await open('settings');
    await user.click(within(document.querySelector('.settings-nav')).getByRole('button', { name: t('users'), exact: true }));
    await user.click(await screen.findByRole('button', { name: `${t('resetPassword')} operator` }));
    const dialog = screen.getByRole('dialog', { name: t('resetPassword') });
    await user.type(within(dialog).getByLabelText(t('password')), 'test-new-password');
    await user.click(within(dialog).getByRole('button', { name: t('save') }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    const call = api.mock.calls.find(([path, options]) => path === '/admin/users/2' && options.method === 'PATCH');
    expect(JSON.parse(call[1].body).password).toBe('test-new-password');
  });
  it('opens an uncategorized category link and filters the inventory', async () => {
    inventory.push({ ...device, ip: '127.0.0.2', display_name: 'Uncategorized monitor', category: '' });
    const user = await open('dashboard');
    await user.click(within(document.querySelector('.ops-category-list')).getByRole('button', { name: new RegExp(t('uncategorized')) }));
    await waitFor(() => expect(document.querySelector('.device-toolbar select').value).toBe('__uncategorized__'));
    expect(screen.getByText('Uncategorized monitor', { exact: true })).toBeTruthy();
    expect(screen.queryByText('Test device', { exact: true })).toBeNull();
  });
  it.each([['users', 'addUser'], ['notification', 'addRule']])('opens and closes the %s dialog', async (section, action) => {
    const user = await open('settings');
    await user.click(within(document.querySelector('.settings-nav')).getByRole('button', { name: t(section), exact: true }));
    await user.click(screen.getByRole('button', { name: t(action), exact: true }));
    expect(document.querySelector('.modal-card')).not.toBeNull();
    await user.click(document.querySelector('.modal-card .modal-close'));
    expect(document.querySelector('.modal-card')).toBeNull();
  });
  it('opens device details and the clone form', async () => {
    const user = await open('devices/127.0.0.1');
    await waitFor(() => expect(document.querySelector('.device-editor')).not.toBeNull());
    await user.click(document.querySelector('.device-editor summary'));
    await user.click(within(document.querySelector('.device-editor')).getByRole('button', { name: t('cloneDevice'), exact: true }));
    expect(screen.getByLabelText(t('newIp'))).toBeTruthy();
    await user.click(within(document.querySelector('.manual-device-modal')).getByRole('button', { name: t('cancel'), exact: true }));
    expect(document.querySelector('.device-editor')).not.toBeNull();
  });
  it('opens category editing', async () => {
    const user = await open('settings');
    await user.click(within(document.querySelector('.settings-nav')).getByRole('button', { name: t('labels'), exact: true }));
    await user.click(within(screen.getByText('Tests', { exact: true }).closest('article')).getAllByRole('button')[0]);
    expect(screen.getByLabelText(t('name'), { exact: true }).value).toBe('Tests');
  });
  it('opens settings before initial refresh finishes', async () => {
    let finish;
    api.mockImplementation((path, options) => path === '/settings' ? new Promise(resolve => { finish = resolve; }) : respond(path, options));
    window.history.replaceState({}, '', '/#/settings');
    render(<App />);
    await screen.findByRole('heading', { name: translator('he')('settings'), exact: true });
    finish({ settings: { language: 'en' } });
    await screen.findByRole('heading', { name: t('settings'), exact: true });
    expect(document.querySelector('.page-recovery')).toBeNull();
  });
  it('returns from settings and opens it again through navigation', async () => {
    const user = await open('settings');
    await user.click(screen.getByRole('button', { name: t('backToApplication') }));
    await user.click(screen.getByRole('button', { name: t('settings'), exact: true }));
    await screen.findByRole('heading', { name: t('settings'), exact: true });
    expect(document.querySelector('.page-recovery')).toBeNull();
  });
});
