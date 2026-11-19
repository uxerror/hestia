// Pure logic of the form built from a plugin schema (manifest.schema):
// initial values, presets, client validation, the request config and the
// target candidates. The server validates again; its 422 errors win.

export const FIELD_TYPES = ['string', 'text', 'int', 'bool', 'enum', 'secret', 'target'];

export const DOCKER_REASON = 'Нужен Debian/Ubuntu с root или sudo';

const isBlank = (v) => v === undefined || v === null || (typeof v === 'string' && v.trim() === '') || (typeof v === 'number' && Number.isNaN(v));

// A config value of a secret field: {"secret": "...", "set": true}.
const isSecretRef = (v) => v !== null && typeof v === 'object' && 'secret' in v;

export function fieldsOf(schema) {
  return Array.isArray(schema?.fields) ? schema.fields.filter((f) => f && f.name) : [];
}

export function presetsOf(schema) {
  return Array.isArray(schema?.presets) ? schema.presets.filter((p) => p && p.name) : [];
}

// Basic fields are shown, advanced ones go under «Подробнее».
export function splitAdvanced(fields) {
  const basic = [];
  const advanced = [];
  for (const f of fields || []) (f.advanced ? advanced : basic).push(f);
  return { basic, advanced };
}

// A value as the form control holds it: ints as numbers (or '' when empty),
// bools as booleans, everything else as strings.
function formValue(f, v) {
  if (f.type === 'bool') return v === true || v === 'true';
  if (f.type === 'secret') return '';
  if (isBlank(v)) return '';
  if (f.type === 'int') {
    const n = Number(v);
    return Number.isFinite(n) ? n : String(v);
  }
  return String(v);
}

// Form values for a new instance (defaults) or for editing (the stored config).
// Secret fields always start empty: empty means "keep" when the secret is set.
export function initialValues(fields, config = null) {
  const out = {};
  for (const f of fields || []) {
    const v = config && Object.prototype.hasOwnProperty.call(config, f.name) ? config[f.name] : config ? undefined : f.default;
    out[f.name] = formValue(f, isSecretRef(v) ? '' : v);
  }
  return out;
}

// Names of secret fields that already have a stored value.
export function secretsSetOf(fields, config) {
  const out = [];
  for (const f of fields || []) {
    if (f.type !== 'secret') continue;
    const v = config?.[f.name];
    if (isSecretRef(v) && v.set) out.push(f.name);
  }
  return out;
}

// Applies a preset: known fields take the preset values, the others keep theirs.
export function applyPreset(values, preset, fields) {
  const out = { ...values };
  const byName = new Map((fields || []).map((f) => [f.name, f]));
  for (const [k, v] of Object.entries(preset?.values || {})) {
    const f = byName.get(k);
    // Presets never set secrets or targets (the server rejects such manifests).
    if (!f || f.type === 'secret' || f.type === 'target') continue;
    out[k] = formValue(f, v);
  }
  return out;
}

// Advanced fields that need attention (an error or a required empty value)
// open «Подробнее» by themselves.
export function advancedNeedsOpen(fields, errors) {
  return (fields || []).some((f) => f.advanced && errors?.[f.name]);
}

// Target candidates of a field: unavailable ones and ones the filter rejects
// are disabled with the reason.
export function targetOptions(field, targets) {
  const needDocker = !!field?.filter?.docker_capable;
  return (targets || []).map((t) => {
    let reason = '';
    if (!t.available) reason = t.reason || 'Недоступна';
    else if (needDocker && !t.docker_capable) reason = DOCKER_REASON;
    const label = t.address && t.address !== t.name ? `${t.name} (${t.address})` : String(t.name || t.id);
    return { id: t.id, label, kind: t.kind, os: t.os || '', disabled: !!reason, reason };
  });
}

// Runs of a string, so "ё" and emoji count as one character (like the server's runes).
const runeLen = (s) => [...String(s)].length;

// The pattern matches the whole value, as on the server (^(?:pattern)$).
function patternError(f, s) {
  if (!f.pattern) return '';
  let re = null;
  for (const flags of ['u', '']) {
    try {
      re = new RegExp('^(?:' + f.pattern + ')$', flags);
      break;
    } catch {
      re = null;
    }
  }
  if (!re) return ''; // the client cannot check it; the server will
  return re.test(s) ? '' : 'Значение не подходит по формату';
}

// Checks one field; returns the message or ''.
export function validateField(f, value, { secretsSet = [], targets = null } = {}) {
  const blank = isBlank(value);
  if (f.type === 'bool') return '';
  if (f.type === 'secret') {
    if (blank) return f.required && !secretsSet.includes(f.name) ? 'Обязательное поле' : '';
  } else if (blank) {
    return f.required ? 'Обязательное поле' : '';
  }
  switch (f.type) {
    case 'string':
    case 'text': {
      const s = String(value);
      if (typeof f.max_len === 'number' && f.max_len > 0 && runeLen(s) > f.max_len) return `Не длиннее ${f.max_len} символов`;
      if (f.type === 'string' && /[\r\n]/.test(s)) return 'Только одна строка';
      return patternError(f, s);
    }
    case 'secret':
      return '';
    case 'int': {
      const n = typeof value === 'number' ? value : /^\s*-?\d+\s*$/.test(String(value)) ? Number(value) : NaN;
      if (!Number.isInteger(n)) return 'Введите целое число';
      if (typeof f.min === 'number' && n < f.min) return `Не меньше ${f.min}`;
      if (typeof f.max === 'number' && n > f.max) return `Не больше ${f.max}`;
      return '';
    }
    case 'enum':
      return (f.options || []).some((o) => String(o.value) === String(value)) ? '' : 'Выберите значение из списка';
    case 'target': {
      if (!targets) return ''; // candidates not loaded yet: the server checks
      const o = targetOptions(f, targets).find((t) => t.id === value);
      if (!o) return 'Выберите сервер из списка';
      return o.disabled ? o.reason : '';
    }
    default:
      return '';
  }
}

// Client validation of the whole form → {field: message} (empty when fine).
export function validate(fields, values, opts = {}) {
  const errors = {};
  for (const f of fields || []) {
    const msg = validateField(f, values?.[f.name], opts);
    if (msg) errors[f.name] = msg;
  }
  return errors;
}

// Form values → the config of a plan request: int as a number, bool as a
// boolean, enum by its option value (numbers stay numbers), an empty secret is
// omitted (keep the stored one), empty optional fields are omitted.
export function toConfig(fields, values) {
  const out = {};
  for (const f of fields || []) {
    const v = values?.[f.name];
    if (f.type === 'bool') {
      out[f.name] = v === true || v === 'true';
      continue;
    }
    if (isBlank(v)) continue;
    if (f.type === 'int') out[f.name] = Number(v);
    else if (f.type === 'enum') {
      const o = (f.options || []).find((x) => String(x.value) === String(v));
      out[f.name] = o ? o.value : v;
    } else if (f.type === 'text' || f.type === 'secret') out[f.name] = String(v);
    else out[f.name] = String(v).trim();
  }
  return out;
}

// Server field errors ({fields: [{field, msg}]}) → {field: message}.
export function serverErrors(data) {
  const out = {};
  for (const f of data?.fields || []) if (f && f.field && !out[f.field]) out[f.field] = f.msg || 'Неверное значение';
  return out;
}
