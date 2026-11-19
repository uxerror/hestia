import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';

const lib = async () => {
  const env = setupEnv();
  const m = await env.import('lib/schemaform.js');
  env.dispose();
  return m;
};

// The schema of hestia-hello plus one field of every other type.
const FIELDS = [
  { name: 'target', type: 'target', label: 'Где запустить', required: true, filter: { docker_capable: true } },
  { name: 'port', type: 'int', label: 'Порт', default: 8080, min: 1, max: 65535 },
  { name: 'message', type: 'string', label: 'Приветствие', default: 'Привет от Hestia', max_len: 200 },
  { name: 'notes', type: 'text', label: 'Заметки', advanced: true },
  { name: 'tls', type: 'bool', label: 'TLS', default: true },
  { name: 'debug', type: 'bool', label: 'Отладка', advanced: true },
  { name: 'mode', type: 'enum', label: 'Режим', default: 'a', options: [{ value: 'a', label: 'А' }, { value: 'b', label: 'Б' }] },
  { name: 'password', type: 'secret', label: 'Пароль', required: true },
];

const TARGETS = [
  { id: 'ssh:1', kind: 'ssh', name: 'srv', address: '10.0.0.5', os: 'debian', docker_capable: true, available: true, reason: '' },
  { id: 'ssh:2', kind: 'ssh', name: 'alpine', address: '10.0.0.6', os: 'alpine', docker_capable: false, available: true, reason: '' },
  { id: 'lxc:2:pve1:120', kind: 'lxc', name: 'ct120', address: '10.0.0.7', docker_capable: true, available: false, reason: 'Узел недоступен' },
  { id: 'lxc:2:pve1:121', kind: 'lxc', name: 'ct121', address: '', docker_capable: true, available: false, reason: '' },
];

test('schemaform: fields, presets and the advanced split', async () => {
  const s = await lib();
  assert.deepEqual(s.fieldsOf(null), []);
  assert.deepEqual(s.fieldsOf({ fields: [{ name: 'a', type: 'string' }, null, { type: 'int' }] }).map((f) => f.name), ['a']);
  assert.deepEqual(s.presetsOf({ presets: [{ name: 'p', label: 'P', values: {} }, {}] }).map((p) => p.name), ['p']);
  assert.deepEqual(s.presetsOf({}), []);
  const { basic, advanced } = s.splitAdvanced(FIELDS);
  assert.deepEqual(basic.map((f) => f.name), ['target', 'port', 'message', 'tls', 'mode', 'password']);
  assert.deepEqual(advanced.map((f) => f.name), ['notes', 'debug']);
  assert.deepEqual(s.splitAdvanced(undefined), { basic: [], advanced: [] });
  // An error in an advanced field opens «Подробнее».
  assert.equal(s.advancedNeedsOpen(FIELDS, { notes: 'x' }), true);
  assert.equal(s.advancedNeedsOpen(FIELDS, { port: 'x' }), false);
  assert.equal(s.advancedNeedsOpen(FIELDS, null), false);
});

test('schemaform: initial values come from defaults for every type', async () => {
  const s = await lib();
  assert.deepEqual(s.initialValues(FIELDS), {
    target: '',
    port: 8080,
    message: 'Привет от Hestia',
    notes: '',
    tls: true,
    debug: false,
    mode: 'a',
    password: '',
  });
  assert.equal(s.initialValues([{ name: 'n', type: 'int' }]).n, '');
  assert.equal(s.initialValues([{ name: 'n', type: 'int', default: '12' }]).n, 12);
  assert.equal(s.initialValues([{ name: 'b', type: 'bool', default: 'true' }]).b, true);
});

test('schemaform: editing starts from the config; secrets start empty and are tracked as set', async () => {
  const s = await lib();
  const config = { target: 'ssh:1', port: 9000, message: 'hi', tls: false, mode: 'b', password: { secret: 'password', set: true } };
  const v = s.initialValues(FIELDS, config);
  assert.deepEqual(v, { target: 'ssh:1', port: 9000, message: 'hi', notes: '', tls: false, debug: false, mode: 'b', password: '' });
  // A field missing from the config is empty, not its default.
  assert.equal(s.initialValues([{ name: 'm', type: 'string', default: 'x' }], {}).m, '');
  assert.deepEqual(s.secretsSetOf(FIELDS, config), ['password']);
  assert.deepEqual(s.secretsSetOf(FIELDS, { password: { secret: 'password', set: false } }), []);
  assert.deepEqual(s.secretsSetOf(FIELDS, null), []);
});

test('schemaform: presets apply known non-secret fields and keep the rest', async () => {
  const s = await lib();
  const v0 = s.initialValues(FIELDS);
  const v = s.applyPreset({ ...v0, target: 'ssh:1', password: 'p' }, { name: 'big', label: 'Большой', values: { port: '9090', tls: false, mode: 'b', unknown: 1, password: 'leak', target: 'ssh:2' } }, FIELDS);
  assert.equal(v.port, 9090);
  assert.equal(v.tls, false);
  assert.equal(v.mode, 'b');
  assert.equal(v.message, 'Привет от Hestia');
  assert.equal(v.target, 'ssh:1');
  assert.equal(v.password, 'p');
  assert.equal('unknown' in v, false);
  // The original object is not mutated; an empty preset changes nothing.
  assert.equal(v0.port, 8080);
  assert.deepEqual(s.applyPreset(v0, { name: 'default', label: 'По умолчанию', values: {} }, FIELDS), v0);
  assert.deepEqual(s.applyPreset(v0, null, FIELDS), v0);
});

test('schemaform: target candidates: availability and the docker filter', async () => {
  const s = await lib();
  const opts = s.targetOptions(FIELDS[0], TARGETS);
  assert.deepEqual(
    opts.map((o) => [o.id, o.label, o.disabled, o.reason]),
    [
      ['ssh:1', 'srv (10.0.0.5)', false, ''],
      ['ssh:2', 'alpine (10.0.0.6)', true, s.DOCKER_REASON],
      ['lxc:2:pve1:120', 'ct120 (10.0.0.7)', true, 'Узел недоступен'],
      ['lxc:2:pve1:121', 'ct121', true, 'Недоступна'],
    ],
  );
  assert.equal(s.DOCKER_REASON, 'Нужен Debian/Ubuntu с root или sudo');
  // Without the filter a non-docker target is fine.
  const plain = s.targetOptions({ name: 't', type: 'target' }, TARGETS);
  assert.equal(plain.find((o) => o.id === 'ssh:2').disabled, false);
  assert.deepEqual(s.targetOptions(FIELDS[0], null), []);
});

test('schemaform: validation: required for every type', async () => {
  const s = await lib();
  const empty = { target: '', port: '', message: '', notes: '', tls: false, debug: false, mode: '', password: '' };
  const req = FIELDS.map((f) => ({ ...f, required: true }));
  const e = s.validate(req, empty, { targets: TARGETS });
  // bool cannot be "missing": false is a value.
  assert.deepEqual(Object.keys(e).sort(), ['message', 'mode', 'notes', 'password', 'port', 'target']);
  for (const k of Object.keys(e)) assert.equal(e[k], 'Обязательное поле', k);
  // Whitespace-only and null count as empty; NaN from a number input too.
  assert.equal(s.validateField({ name: 'x', type: 'string', required: true }, '   '), 'Обязательное поле');
  assert.equal(s.validateField({ name: 'x', type: 'int', required: true }, null), 'Обязательное поле');
  assert.equal(s.validateField({ name: 'x', type: 'int', required: true }, NaN), 'Обязательное поле');
  // Optional empty fields are fine.
  assert.deepEqual(s.validate(FIELDS.filter((f) => !f.required), { port: '', message: '', notes: '', mode: '' }), {});
});

test('schemaform: validation: int min, max and integer', async () => {
  const s = await lib();
  const f = FIELDS[1];
  assert.equal(s.validateField(f, 8080), '');
  assert.equal(s.validateField(f, '8080'), '');
  assert.equal(s.validateField(f, 1), '');
  assert.equal(s.validateField(f, 65535), '');
  assert.equal(s.validateField(f, 0), 'Не меньше 1');
  assert.equal(s.validateField(f, -5), 'Не меньше 1');
  assert.equal(s.validateField(f, 65536), 'Не больше 65535');
  assert.equal(s.validateField(f, 1.5), 'Введите целое число');
  assert.equal(s.validateField(f, '12abc'), 'Введите целое число');
  assert.equal(s.validateField({ name: 'n', type: 'int' }, -100), '');
});

test('schemaform: validation: max_len counts characters, pattern matches the whole value, string is one line', async () => {
  const s = await lib();
  const f = { name: 'm', type: 'string', max_len: 5 };
  assert.equal(s.validateField(f, 'ёжики'), ''); // 5 runes, more bytes
  assert.equal(s.validateField(f, 'ёжики!'), 'Не длиннее 5 символов');
  assert.equal(s.validateField({ name: 't', type: 'text', max_len: 3 }, 'abcd'), 'Не длиннее 3 символов');
  assert.equal(s.validateField({ name: 'm', type: 'string' }, 'a\nb'), 'Только одна строка');
  assert.equal(s.validateField({ name: 't', type: 'text' }, 'a\nb'), '');
  const p = { name: 'h', type: 'string', pattern: '[a-z]+' };
  assert.equal(s.validateField(p, 'abc'), '');
  assert.equal(s.validateField(p, 'abc1'), 'Значение не подходит по формату'); // anchored like the server
  assert.equal(s.validateField({ ...p, pattern: 'a|b' }, 'ab'), 'Значение не подходит по формату');
  assert.equal(s.validateField({ ...p, pattern: 'a|b' }, 'b'), '');
  assert.equal(s.validateField({ name: 't', type: 'text', pattern: '\\d+' }, '12'), '');
  // An empty optional value is not checked against the pattern; a broken pattern is left to the server.
  assert.equal(s.validateField(p, ''), '');
  assert.equal(s.validateField({ ...p, pattern: '(' }, 'x'), '');
});

test('schemaform: validation: enum membership', async () => {
  const s = await lib();
  const f = FIELDS[6];
  assert.equal(s.validateField(f, 'a'), '');
  assert.equal(s.validateField(f, 'b'), '');
  assert.equal(s.validateField(f, 'c'), 'Выберите значение из списка');
  assert.equal(s.validateField({ ...f, options: undefined }, 'a'), 'Выберите значение из списка');
});

test('schemaform: validation: target availability and filter', async () => {
  const s = await lib();
  const f = FIELDS[0];
  assert.equal(s.validateField(f, 'ssh:1', { targets: TARGETS }), '');
  assert.equal(s.validateField(f, 'ssh:2', { targets: TARGETS }), s.DOCKER_REASON);
  assert.equal(s.validateField(f, 'lxc:2:pve1:120', { targets: TARGETS }), 'Узел недоступен');
  assert.equal(s.validateField(f, 'ssh:99', { targets: TARGETS }), 'Выберите сервер из списка');
  // Candidates not loaded yet: only "required" is checked here.
  assert.equal(s.validateField(f, 'ssh:99'), '');
  assert.equal(s.validateField(f, ''), 'Обязательное поле');
});

test('schemaform: validation: secret keep or replace', async () => {
  const s = await lib();
  const f = FIELDS[7];
  // Required and never set: must be entered.
  assert.equal(s.validateField(f, ''), 'Обязательное поле');
  // Required and already set: empty means keep.
  assert.equal(s.validateField(f, '', { secretsSet: ['password'] }), '');
  assert.equal(s.validateField(f, 'new'), '');
  assert.equal(s.validateField({ ...f, required: false }, ''), '');
  // bool never fails.
  assert.equal(s.validateField(FIELDS[4], false), '');
  assert.equal(s.validateField({ ...FIELDS[4], required: true }, undefined), '');
  // Unknown types pass (the server decides).
  assert.equal(s.validateField({ name: 'x', type: 'weird' }, 'v'), '');
});

test('schemaform: the whole form validates to a field map', async () => {
  const s = await lib();
  const v = { ...s.initialValues(FIELDS), target: 'ssh:2', port: 0, password: 'x' };
  assert.deepEqual(s.validate(FIELDS, v, { targets: TARGETS }), { target: s.DOCKER_REASON, port: 'Не меньше 1' });
  assert.deepEqual(s.validate(FIELDS, { ...v, target: 'ssh:1', port: 80 }, { targets: TARGETS }), {});
});

test('schemaform: form values → request config', async () => {
  const s = await lib();
  const v = { target: 'ssh:1', port: '8081', message: '  hi  ', notes: ' multi\nline ', tls: true, debug: false, mode: 'b', password: 's3cret' };
  assert.deepEqual(s.toConfig(FIELDS, v), { target: 'ssh:1', port: 8081, message: 'hi', notes: ' multi\nline ', tls: true, debug: false, mode: 'b', password: 's3cret' });
  // An empty secret is omitted (keep the stored one); empty optional fields too; bools are always sent.
  const kept = s.toConfig(FIELDS, { target: 'ssh:1', port: '', message: '', notes: '', tls: 'true', debug: undefined, mode: '', password: '' });
  assert.deepEqual(kept, { target: 'ssh:1', tls: true, debug: false });
  assert.equal('password' in kept, false);
  assert.equal(typeof s.toConfig(FIELDS, { port: 42 }).port, 'number');
  // The secret value is sent as is (no trimming).
  assert.equal(s.toConfig(FIELDS, { password: ' p ' }).password, ' p ');
});

test('schemaform: server field errors → map', async () => {
  const s = await lib();
  assert.deepEqual(s.serverErrors({ error: 'Проверьте поля формы', fields: [{ field: 'port', msg: 'занят' }, { field: 'port', msg: 'второе' }, { field: 'x' }, null] }), { port: 'занят', x: 'Неверное значение' });
  assert.deepEqual(s.serverErrors(null), {});
});
