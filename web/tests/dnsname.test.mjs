import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';

test('dnsname: domain validation mirrors the server', async () => {
  const env = setupEnv();
  const d = await env.import('lib/dnsname.js');
  for (const ok of ['hestia.home', 'Hestia.HOME.', 'robot', 'a-b.c1.lan']) assert.equal(d.validateDomain(ok), '', ok);
  for (const bad of ['', '  ', '*.home', 'a..b', '.home', '-a.home', 'a-.home', 'a b.home', 'яндекс.рф', 'a_b.home', 'a'.repeat(64) + '.home', 'a.'.repeat(130) + 'x']) {
    assert.notEqual(d.validateDomain(bad), '', JSON.stringify(bad));
  }
  assert.equal(d.normalizeDomain(' Hestia.HOME. '), 'hestia.home');
  env.dispose();
});

test('dnsname: status texts and the fixing action', async () => {
  const env = setupEnv();
  const { statusInfo, NAME_STATUS } = await env.import('lib/dnsname.js');
  assert.equal(statusInfo('ok').action, null);
  assert.equal(statusInfo('ip_changed').action.plan, 'update_ip');
  assert.equal(statusInfo('ip_changed').action.label, 'Обновить запись');
  assert.equal(statusInfo('missing').action.label, 'Восстановить');
  assert.equal(statusInfo('changed').action.plan, 'update_ip');
  // Login and certificate problems are fixed in the connection, not by a plan.
  for (const s of ['auth_failed', 'cert_changed']) {
    assert.equal(statusInfo(s).action.plan, null);
    assert.equal(statusInfo(s).action.label, 'Изменить подключение');
  }
  assert.equal(statusInfo('unreachable').action, null);
  for (const k of Object.keys(NAME_STATUS)) assert.ok(NAME_STATUS[k].label && NAME_STATUS[k].cls, k);
  assert.equal(statusInfo('weird').label, 'weird');
  env.dispose();
});

test('dnsname: the state of the block', async () => {
  const env = setupEnv();
  const { blockState, suggestedDomain } = await env.import('lib/dnsname.js');
  assert.equal(blockState(null).state, 'loading');
  assert.equal(blockState({ candidates: [], integration: null, name: null }).state, 'hidden');
  const found = blockState({ candidates: [{ host: '10.10.10.15', endpoints: [] }], integration: null, name: null });
  assert.deepEqual([found.state, found.host], ['found', '10.10.10.15']);
  assert.equal(blockState({ candidates: [], integration: { id: 1 }, name: null }).state, 'connected');
  assert.equal(blockState({ candidates: [{ host: 'x' }], integration: { id: 1 }, name: { domain: 'hestia.home' } }).state, 'named');
  assert.equal(suggestedDomain({ default_domain: 'hestia.lan' }), 'hestia.lan');
  assert.equal(suggestedDomain(null), 'hestia.home');
  env.dispose();
});

test('dnsname: endpoints, plan view, AdGuard mark in the services table', async () => {
  const env = setupEnv();
  const d = await env.import('lib/dnsname.js');
  const ch = d.endpointChoices({ endpoints: [{ url: 'https://10.10.10.15', scheme: 'https', port: 443 }, { url: 'http://10.10.10.15:9091', scheme: 'http', port: 9091 }] });
  assert.deepEqual(ch.map((c) => c.label), ['HTTPS, порт 443', 'HTTP, порт 9091']);
  assert.deepEqual(d.endpointChoices(null), []);

  assert.equal(d.planView(null).canApply, false);
  assert.equal(d.planView({ action: 'add', actions: [{ id: 'add' }], conflicts: [] }).canApply, true);
  const conflict = d.planView({ action: 'add', actions: [], conflicts: [{ domain: 'hestia.home' }] });
  assert.deepEqual([conflict.canApply, conflict.needsReplace], [false, true]);
  assert.equal(d.planView({ action: 'replace', actions: [{ id: 'update' }], conflicts: [] }).canApply, true);
  assert.equal(d.planView({ action: 'add', noop: true, actions: [{ id: 'verify-dns' }], conflicts: [] }).noop, true);

  const dns = { integration: { base_url: 'https://10.10.10.15' }, name: { domain: 'hestia.home', status: 'ip_changed' } };
  assert.equal(d.adguardMark({ rule: 'adguard', ip: '10.10.10.20' }, dns), null);
  assert.equal(d.adguardMark({ rule: 'gitea', ip: '10.10.10.15' }, dns), null);
  assert.equal(d.adguardMark({ rule: 'adguard', ip: '10.10.10.15' }, null), null);
  const m = d.adguardMark({ rule: 'adguard', ip: '10.10.10.15' }, dns);
  assert.equal(m.text, 'подключён · hestia.home');
  assert.equal(m.status.label, 'Адрес изменился');
  assert.equal(d.adguardMark({ rule: 'adguard', ip: '10.10.10.15' }, { integration: { base_url: 'http://10.10.10.15:3000' }, name: null }).text, 'подключён');
  env.dispose();
});

test('dnsname: connection problems and the address line', async () => {
  const env = setupEnv({
    'POST /api/v1/dns/adguard': () => [409, { error: 'Сертификат AdGuard изменился', code: 'cert_changed', fingerprint: 'AA:BB' }],
  });
  const { api } = await env.import('lib/api.js');
  const d = await env.import('lib/dnsname.js');
  // The error body travels with the ApiError, and a 409 does not sign the user out.
  const e = await api.connectAdguard({ url: 'https://10.10.10.15' }).catch((x) => x);
  assert.equal(e.status, 409);
  assert.equal(e.data.code, 'cert_changed');
  const p = d.connectProblem(e);
  assert.deepEqual([p.kind, p.fingerprint], ['cert', 'AA:BB']);
  assert.equal(d.connectProblem({ message: 'x', data: { code: 'auth_failed' } }).kind, 'auth');
  assert.equal(d.connectProblem(new Error('нет связи')).kind, 'other');

  assert.equal(d.addressLine({ configured_url: 'http://hestia.home', fallback_url: 'http://10.10.10.5' }), 'Адрес: http://hestia.home (запасной: http://10.10.10.5)');
  assert.equal(d.addressLine({ configured_url: 'http://10.10.10.5' }), 'Адрес: http://10.10.10.5');
  assert.equal(d.addressLine({}), '');
  env.dispose();
});

test('api: dns calls use the documented routes', async () => {
  const env = setupEnv({
    'GET /api/v1/dns': () => [200, { candidates: [] }],
    'POST /api/v1/dns/adguard/probe': () => [200, {}],
    'POST /api/v1/dns/plan': () => [200, {}],
    'POST /api/v1/dns/apply': () => [202, { job_id: 'j1' }],
    'PUT /api/v1/dns/adguard': () => [200, {}],
    'DELETE /api/v1/dns/adguard': () => [204],
  });
  const { api } = await env.import('lib/api.js');
  await api.dns();
  await api.probeAdguard('http://10.10.10.2:3000');
  await api.dnsPlan('add', 'hestia.home');
  const r = await api.dnsApply('p1', 'h1');
  await api.updateAdguard({ url: 'u' });
  await api.disconnectAdguard();
  assert.equal(r.job_id, 'j1');
  assert.deepEqual(env.calls.map((c) => c.key), [
    'GET /api/v1/dns', 'POST /api/v1/dns/adguard/probe', 'POST /api/v1/dns/plan', 'POST /api/v1/dns/apply', 'PUT /api/v1/dns/adguard', 'DELETE /api/v1/dns/adguard',
  ]);
  assert.deepEqual(env.calls[1].body, { url: 'http://10.10.10.2:3000' });
  assert.deepEqual(env.calls[2].body, { action: 'add', domain: 'hestia.home' });
  assert.deepEqual(env.calls[3].body, { plan_id: 'p1', hash: 'h1' });
  env.dispose();
});
