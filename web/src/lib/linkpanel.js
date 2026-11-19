// Logic of the link panels («Новая связь», panel of a link, «Связи» of an instance): texts,
// the request of a plan, the choice of the second side and the mapping of errors.
import { planError } from './plugins.js';

export const LINK_STATUS = {
  ok: { label: 'Работает', cls: 'badge-success' },
  degraded: { label: 'Работает с проблемами', cls: 'badge-warning' },
  down: { label: 'Не работает', cls: 'badge-error' },
  unknown: { label: 'Не проверена', cls: 'badge-ghost' },
  orphaned: { label: 'Осиротела', cls: 'badge-error' },
  failed: { label: 'Ошибка', cls: 'badge-error' },
};

export function linkStatusInfo(status) {
  return LINK_STATUS[status] || { label: status || 'Не проверена', cls: 'badge-ghost' };
}

export const KIND_LABEL = { service: 'Сервис ↔ сервис', device: 'Сервис → устройство' };

// A side of a link as text: «Hestia Hello 1 · web».
export const endText = (e) => (e ? `${e.name || 'экземпляр ' + e.instance} · ${e.port}` : '');
export const deviceText = (d) => (d ? (d.host_ip && d.host_ip !== d.name ? `${d.name} (${d.host_ip})` : d.name || d.ref) : '');

// {provider, consumer} texts of a link of GET /graph.
export function linkSides(link) {
  return {
    provider: endText(link?.provider),
    consumer: link?.kind === 'device' ? deviceText(link.device) : endText(link?.consumer),
    consumerLabel: link?.kind === 'device' ? 'Устройство' : 'Потребитель',
  };
}

export function removeAction(link) {
  return link?.status === 'orphaned'
    ? { label: 'Удалить запись', confirm: 'Убрать запись о связи? Настройки на сторонах не будут тронуты.' }
    : { label: 'Удалить', confirm: 'Удалить связь? Hestia уберёт её настройки на обеих сторонах.' };
}

// The body of POST /plugins/links/plan. own = {instance, port, dir}, peer =
// {kind: 'port', instance, port} | {kind: 'device', ref}. Returns null when it is incomplete.
export function newLinkRequest(own, peer, config = {}) {
  if (!own || !peer) return null;
  if (peer.kind === 'device') {
    if (own.dir !== 'provides' || !peer.ref) return null;
    return { kind: 'device', provider: { instance: own.instance, port: own.port }, device: { ref: peer.ref }, config };
  }
  if (peer.kind !== 'port' || !peer.instance || !peer.port) return null;
  const me = { instance: own.instance, port: own.port };
  const other = { instance: peer.instance, port: peer.port };
  return own.dir === 'provides' ? { kind: 'service', provider: me, consumer: other, config } : { kind: 'service', provider: other, consumer: me, config };
}

// Candidates of GET /plugins/links/candidates → options of the «second side» list.
// value: «p|<instance>|<port>» or «d|<ref>».
export function candidateOptions(cands) {
  const out = [];
  for (const c of cands?.ports || []) {
    out.push({
      value: `p|${c.instance}|${c.port}`,
      label: `${c.name} · ${c.label || c.port}${c.plugin_name ? ` (${c.plugin_name})` : ''}`,
      disabled: !c.available,
      reason: c.available ? '' : c.reason || 'недоступно',
      group: 'Сервисы',
    });
  }
  for (const c of cands?.devices || []) {
    out.push({
      value: `d|${c.device}`,
      label: c.address && c.address !== c.name ? `${c.name} (${c.address})` : c.name,
      disabled: !c.available,
      reason: c.available ? '' : c.reason || 'недоступно',
      group: 'Устройства',
    });
  }
  return out;
}

export function parseChoice(value) {
  const s = String(value || '');
  if (s.startsWith('d|')) return { kind: 'device', ref: s.slice(2) };
  const m = /^p\|(\d+)\|(.+)$/.exec(s);
  return m ? { kind: 'port', instance: Number(m[1]), port: m[2] } : null;
}

// The port of the provider whose link_schema configures the link.
export function providerPort(plugin, port) {
  return (plugin?.provides || plugin?.manifest?.provides || []).find((p) => (p.name || '') === port || (!p.name && p.type?.replace(/[.-]/g, '_') === port)) || null;
}

// The plugin of the provider side and the port, for the form.
export function providerSide(own, peer) {
  if (!own || !peer) return null;
  if (peer.kind === 'device' || own.dir === 'provides') return { instance: own.instance, port: own.port };
  return { instance: peer.instance, port: peer.port };
}

// Errors of a link plan: field errors for the link_schema form (names without prefix);
// errors about the sides (provider, consumer, device) become the message.
const SIDE_FIELDS = /^(provider|consumer|device)(\.|$)/;
export function linkPlanError(e) {
  const pe = planError(e);
  if (pe.kind !== 'fields') return { ...pe, side: false };
  const fields = {};
  let side = false;
  for (const [k, v] of Object.entries(pe.fields)) {
    if (SIDE_FIELDS.test(k)) side = true;
    else fields[k] = v;
  }
  return { ...pe, fields, side };
}
