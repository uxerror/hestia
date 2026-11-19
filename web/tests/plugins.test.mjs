import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';

test('plugins: routes', async () => {
  const env = setupEnv();
  const { parseHash } = await env.import('lib/router.js');
  assert.deepEqual(parseHash('#/plugins'), { name: 'plugins' });
  assert.deepEqual(parseHash('#/plugins/'), { name: 'plugins' });
  assert.deepEqual(parseHash('#/plugins/hestia-hello'), { name: 'plugin', id: 'hestia-hello' });
  assert.deepEqual(parseHash('#/plugins/a%20b?x=1'), { name: 'plugin', id: 'a b' });
  env.dispose();
});

test('plugins: permission, state, status and trust labels', async () => {
  const env = setupEnv();
  const p = await env.import('lib/plugins.js');
  assert.equal(p.permissionLabel('targets.read'), 'Видеть выбранные серверы (имя, адрес, ОС)');
  assert.equal(p.permissionLabel('targets.exec'), 'Выполнять команды от root на выбранных серверах');
  assert.equal(p.permissionLabel('deploy.docker'), 'Разворачивать Docker-контейнеры');
  assert.equal(p.permissionLabel('net.outbound'), 'Сетевые подключения напрямую');
  assert.equal(p.permissionLabel('inventory.read'), 'Читать карту сети');
  assert.equal(p.permissionLabel('x.y'), 'x.y');
  assert.deepEqual(
    p.permissionList({ permissions: ['targets.read', 'deploy.docker'], update: { from: 'v0.1.0', to: 'v0.2.0', new_permissions: ['deploy.docker'] } }).map((x) => [x.id, x.isNew]),
    [['targets.read', false], ['deploy.docker', true]],
  );
  assert.deepEqual(p.permissionList({ permissions: ['net.outbound'], update: null }).map((x) => x.isNew), [false]);
  assert.deepEqual(p.permissionList(null), []);

  assert.equal(p.stateInfo('connected').label, 'Работает');
  assert.equal(p.stateInfo('unresponsive').label, 'Не отвечает');
  assert.equal(p.stateInfo('disabled').label, 'Отключён');
  assert.equal(p.stateInfo('disconnected').label, 'Не подключён');
  assert.equal(p.stateInfo('weird').label, 'weird');
  for (const k of Object.keys(p.PLUGIN_STATE)) assert.ok(p.PLUGIN_STATE[k].cls, k);

  assert.equal(p.instanceStatusInfo('ok').cls, 'badge-success');
  assert.equal(p.instanceStatusInfo('degraded').cls, 'badge-warning');
  assert.equal(p.instanceStatusInfo('down').cls, 'badge-error');
  assert.equal(p.instanceStatusInfo('unknown').label, 'Неизвестно');
  assert.equal(p.instanceStatusInfo('').label, 'Неизвестно');

  assert.equal(p.unitInfo(null), null);
  assert.equal(p.unitInfo({ active: 'active' }).cls, 'badge-success');
  assert.deepEqual(p.unitInfo({ active: 'failed', error: 'exit 1' }), { label: 'Служба упала', cls: 'badge-error', error: 'exit 1' });
  assert.equal(p.unitInfo({ active: 'inactive' }).label, 'Служба: inactive');

  assert.equal(p.trustInfo('official').label, 'Официальный');
  assert.equal(p.trustInfo('new').cls, 'badge-warning');
  assert.equal(p.trustInfo('pinned').cls, 'badge-info');
  assert.equal(p.authorBadge({ official: true }).label, 'Официальный');
  assert.equal(p.authorBadge({ official: false }).label, 'Сторонний');
  assert.equal(p.authorBadge(null).label, 'Сторонний');

  assert.equal(p.sourceLabel('catalog'), 'Из каталога');
  assert.equal(p.sourceLabel('file'), 'Из файла');
  assert.equal(p.sourceLabel('dev'), 'Режим разработки');
  assert.equal(p.sourceLabel('url:https://x/y.hpkg'), 'По ссылке https://x/y.hpkg');
  assert.equal(p.capabilityText({ type: 'http.service', name: '' }), 'http.service');
  assert.equal(p.capabilityText({ type: 'db', name: 'pg' }), 'db (pg)');
  env.dispose();
});

test('plugins: fingerprint display', async () => {
  const env = setupEnv();
  const p = await env.import('lib/plugins.js');
  assert.equal(p.fingerprintDisplay('AB12CD34EF56'), 'ab12 cd34 ef56');
  assert.equal(p.fingerprintDisplay('ab:12:cd:34:e'), 'ab12 cd34 e');
  assert.equal(p.fingerprintDisplay('ab12 cd34'), 'ab12 cd34');
  assert.equal(p.fingerprintDisplay(''), '');
  assert.equal(p.fingerprintDisplay(null), '');
  assert.equal(p.shortFingerprint('0123456789abcdef0123'), '0123 4567 89ab cdef …');
  assert.equal(p.shortFingerprint('0123 4567'), '0123 4567');
  env.dispose();
});

test('plugins: only http/https endpoints become links', async () => {
  const env = setupEnv();
  const p = await env.import('lib/plugins.js');
  assert.equal(p.safeUrl('http://10.0.0.5:8080'), 'http://10.0.0.5:8080/');
  assert.equal(p.safeUrl(' https://hello.home/x?a=1 '), 'https://hello.home/x?a=1');
  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'ftp://x', '//evil.com', '/relative', 'not a url', '', null, 42, { url: 'http://x' }]) {
    assert.equal(p.safeUrl(bad), '', String(bad));
  }
  env.dispose();
});

test('plugins: plan view, install gate, job id, instance name', async () => {
  const env = setupEnv();
  const p = await env.import('lib/plugins.js');
  assert.deepEqual(p.planView(null), { danger: false, canApply: false });
  const safe = { danger: false, plan: { actions: [{ title: 'a', risk: 'info' }, { title: 'b', risk: 'change' }], warnings: [] } };
  assert.deepEqual(p.planView(safe), { danger: false, canApply: true });
  const danger = { danger: true, plan: { actions: [{ title: 'a', risk: 'danger' }] } };
  assert.deepEqual(p.planView(danger), { danger: true, canApply: false });
  assert.deepEqual(p.planView(danger, true), { danger: true, canApply: true });
  // A danger action without the flag still needs the confirmation.
  assert.equal(p.planView({ plan: { actions: [{ risk: 'danger' }] } }).canApply, false);
  assert.equal(p.riskInfo('danger').alert, 'alert-error');
  assert.equal(p.riskInfo('change').alert, 'alert-warning');
  assert.equal(p.riskInfo('info').alert, '');
  assert.equal(p.riskInfo('weird'), p.RISK.info);

  assert.equal(p.canInstall(null, true), false);
  assert.equal(p.canInstall({ author: { trust: 'official' } }, false), true);
  assert.equal(p.canInstall({ author: { trust: 'pinned' } }, false), true);
  assert.equal(p.canInstall({ author: { trust: 'new' } }, false), false);
  assert.equal(p.canInstall({ author: { trust: 'new' } }, true), true);

  assert.equal(p.jobIdOf({ job: { id: 'j1' } }), 'j1');
  assert.equal(p.jobIdOf({ job_id: 'j2' }), 'j2');
  assert.equal(p.jobIdOf(null), '');

  assert.equal(p.suggestedInstanceName('Hestia Hello', []), 'Hestia Hello 1');
  assert.equal(p.suggestedInstanceName('Hestia Hello', [{ name: 'Hestia Hello 1' }]), 'Hestia Hello 2');
  assert.equal(p.suggestedInstanceName('H', [{ name: 'H 2' }]), 'H 3');
  env.dispose();
});

test('plugins: errors of plan/apply and of plugin removal', async () => {
  const env = setupEnv();
  const p = await env.import('lib/plugins.js');
  const { ApiError } = await env.import('lib/api.js');
  const f = p.planError(new ApiError(422, 'Проверьте поля формы', { error: 'Проверьте поля формы', fields: [{ field: 'port', msg: 'занят' }] }));
  assert.deepEqual(f, { kind: 'fields', message: 'Проверьте поля формы', fields: { port: 'занят' } });
  // 422 without fields is a plain error (a broken package, etc.).
  assert.equal(p.planError(new ApiError(422, 'плохо', { error: 'плохо' })).kind, 'other');
  assert.deepEqual(p.planError(new ApiError(409, 'Состояние изменилось, проверьте план ещё раз')), { kind: 'stale', message: p.STALE_PLAN });
  assert.equal(p.planError(new ApiError(410, 'gone')).kind, 'expired');
  assert.equal(p.planError(new ApiError(410, 'gone')).message, p.EXPIRED_PLAN);
  assert.deepEqual(p.planError(new ApiError(500, 'упало')), { kind: 'other', message: 'упало' });

  assert.equal(p.removeBlocked(new ApiError(500, 'x')), null);
  assert.deepEqual(p.removeBlocked(new ApiError(409, 'Сначала удалите экземпляры', { instances: ['Hello 1', 'Hello 2'] })), { message: 'Сначала удалите экземпляры', instances: ['Hello 1', 'Hello 2'] });
  assert.deepEqual(p.removeBlocked(new ApiError(409, 'x', null)).instances, []);
  env.dispose();
});

test('plugins: package upload is multipart with the field "file"', async () => {
  const env = setupEnv();
  const { uploadPackage } = await env.import('lib/plugins.js');
  const { ApiError } = await env.import('lib/api.js');
  let seen;
  const ok = async (u, init) => {
    seen = { u, init };
    return new Response(JSON.stringify({ upload_id: 'u1', preview: { id: 'hestia-hello' } }));
  };
  const file = new File([new Uint8Array([1, 2, 3])], 'hello.hpkg');
  const r = await uploadPackage(file, ok);
  assert.equal(r.upload_id, 'u1');
  assert.equal(seen.u, '/api/v1/plugins/packages');
  assert.equal(seen.init.method, 'POST');
  assert.equal(seen.init.credentials, 'same-origin');
  assert.ok(seen.init.body instanceof FormData);
  assert.equal(seen.init.body.get('file').name, 'hello.hpkg');
  // No manual Content-Type: the browser sets the multipart boundary.
  assert.equal(seen.init.headers['Content-Type'], undefined);
  const fail = async () => new Response(JSON.stringify({ error: 'Ключ автора изменился' }), { status: 409 });
  await assert.rejects(uploadPackage(file, fail), (e) => e instanceof ApiError && e.status === 409 && e.message === 'Ключ автора изменился' && e.data.error === 'Ключ автора изменился');
  await assert.rejects(uploadPackage(file, async () => { throw new TypeError('x'); }), /Нет связи/);
  env.dispose();
});

test('api: plugin calls', async () => {
  const env = setupEnv({
    'GET /api/v1/plugins': () => [200, { available: true, reason: '', plugins: [] }],
    'GET /api/v1/plugins/hestia-hello?unit=1': () => [200, { id: 'hestia-hello', unit: { active: 'active' } }],
    'GET /api/v1/plugins/hestia-hello': () => [200, { id: 'hestia-hello' }],
    'POST /api/v1/plugins/hestia-hello/enable': () => [202, { job: { id: 'j1' } }],
    'POST /api/v1/plugins/hestia-hello/disable': () => [202, { job: { id: 'j2' } }],
    'DELETE /api/v1/plugins/hestia-hello': () => [409, { error: 'Сначала удалите экземпляры', instances: ['Hello 1'] }],
    'POST /api/v1/plugins/packages/fetch': () => [200, { upload_id: 'u', preview: {} }],
    'POST /api/v1/plugins/install': () => [202, { job: { id: 'j3' } }],
    'GET /api/v1/plugins/hestia-hello/instances': () => [200, { instances: [{ id: 5 }] }],
    'GET /api/v1/plugins/instances/5?status=refresh': () => [200, { id: 5, status: 'ok' }],
    'POST /api/v1/plugins/hestia-hello/instances/plan': () => [200, { plan_id: 'p1', hash: 'h' }],
    'POST /api/v1/plugins/instances/5/plan': () => [200, { plan_id: 'p2', hash: 'h' }],
    'POST /api/v1/plugins/plans/p1/apply': () => [409, { error: 'Состояние изменилось, проверьте план ещё раз' }],
    'GET /api/v1/plugins/targets': () => [200, { targets: [] }],
    'GET /api/v1/plugins/catalog': () => [200, { plugins: [{ id: 'hestia-hello' }], error: '' }],
    'POST /api/v1/plugins/catalog/refresh': () => [200, { plugins: [], error: 'подпись каталога неверна: каталог не показывается' }],
    'POST /api/v1/plugins/packages/catalog': () => [200, { upload_id: 'u2', preview: { id: 'hestia-hello' } }],
  });
  const { api } = await env.import('lib/api.js');
  assert.equal((await api.plugins()).available, true);
  assert.equal((await api.plugin('hestia-hello', true)).unit.active, 'active');
  assert.equal((await api.plugin('hestia-hello')).id, 'hestia-hello');
  assert.equal((await api.enablePlugin('hestia-hello')).job.id, 'j1');
  assert.equal((await api.disablePlugin('hestia-hello')).job.id, 'j2');
  await assert.rejects(api.removePlugin('hestia-hello'), (e) => e.status === 409 && e.data.instances[0] === 'Hello 1');
  await api.fetchPluginPackage('https://x/y.hpkg');
  assert.deepEqual(env.calls.at(-1).body, { url: 'https://x/y.hpkg' });
  await api.installPlugin('u', 1);
  assert.deepEqual(env.calls.at(-1).body, { upload_id: 'u', trust_author: true });
  assert.equal((await api.pluginInstances('hestia-hello')).instances[0].id, 5);
  assert.equal((await api.pluginInstance(5, true)).status, 'ok');
  await api.planCreateInstance('hestia-hello', 'Hello 1', { port: 80 });
  assert.deepEqual(env.calls.at(-1).body, { name: 'Hello 1', config: { port: 80 } });
  await api.planUpdateInstance(5, { port: 81 });
  assert.deepEqual(env.calls.at(-1).body, { action: 'update', config: { port: 81 } });
  await api.planRemoveInstance(5);
  assert.deepEqual(env.calls.at(-1).body, { action: 'remove' });
  assert.equal((await api.pluginCatalog()).plugins[0].id, 'hestia-hello');
  assert.match((await api.refreshPluginCatalog()).error, /подпись/);
  assert.equal((await api.fetchCatalogPackage('hestia-hello')).upload_id, 'u2');
  assert.deepEqual(env.calls.at(-1).body, { id: 'hestia-hello' });
  await assert.rejects(api.applyPluginPlan('p1', 'h', false), (e) => e.status === 409);
  assert.deepEqual(env.calls.at(-1).body, { hash: 'h', confirm_danger: false });
  assert.deepEqual((await api.pluginTargets()).targets, []);
  env.dispose();
});

test('plugins: catalog actions and status line', async () => {
  const env = setupEnv();
  const p = await env.import('lib/plugins.js');
  assert.deepEqual(p.catalogAction({ id: 'a', version: 'v0.2.0', compatible: true, installed: '', update: false }), { kind: 'install', label: 'Установить' });
  assert.deepEqual(p.catalogAction({ version: 'v0.2.0', compatible: true, installed: 'v0.1.0', update: true }), { kind: 'update', label: 'Обновить до v0.2.0' });
  assert.deepEqual(p.catalogAction({ version: 'v0.2.0', compatible: true, installed: 'v0.2.0', update: false }), { kind: 'installed', label: 'Установлен v0.2.0' });
  assert.equal(p.catalogAction({ compatible: false, reason: 'плагину нужна Hestia v9.0.0' }).kind, 'incompatible');
  assert.equal(p.catalogAction({ compatible: false }).label, 'Нужна более новая Hestia');
  assert.equal(p.catalogAction(null).kind, 'none');

  const now = Date.parse('2026-11-19T12:00:00Z');
  assert.deepEqual(p.catalogStatus({ fetched_at: null, error: '' }, now), { text: 'Каталог ещё не загружен', error: '' });
  assert.equal(p.catalogStatus({ fetched_at: '2026-11-19T11:59:40Z' }, now).text, 'Проверен только что');
  assert.equal(p.catalogStatus({ fetched_at: '2026-11-19T11:30:00Z' }, now).text, 'Проверен 30 мин назад');
  assert.equal(p.catalogStatus({ fetched_at: '2026-11-19T07:00:00Z' }, now).text, 'Проверен 5 ч назад');
  assert.equal(p.catalogStatus({ fetched_at: '2026-11-15T12:00:00Z' }, now).text, 'Проверен 4 дн назад');
  assert.deepEqual(p.catalogStatus({ fetched_at: '2026-11-19T11:30:00Z', error: 'нет сети' }, now).error, 'нет сети');
  assert.deepEqual(p.catalogStatus(null), { text: '', error: '' });
  env.dispose();
});
