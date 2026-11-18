// Pure helpers for the network map: host classification, filters and the
// graph (router → Proxmox nodes / device groups → guests). No DOM, no network.

export const CATEGORY_LABEL = {
  infra: 'Инфраструктура',
  network: 'Сеть',
  storage: 'Хранилища',
  media: 'Медиа',
  dev: 'Разработка',
  monitoring: 'Мониторинг',
  home: 'Умный дом',
  db: 'Базы данных',
  remote: 'Удалённый доступ',
  other: 'Прочее',
};

export const CATEGORY_ORDER = ['infra', 'network', 'storage', 'media', 'dev', 'monitoring', 'home', 'db', 'remote', 'other'];

// Groups of devices that are not tied to a node: shown as an intermediate
// box under the router.
export const GROUP_LABEL = {
  network: 'Сетевое оборудование',
  server: 'Серверы и хранилища',
  client: 'Компьютеры и телефоны',
  unknown: 'Неизвестные',
};
const GROUP_ORDER = ['proxmox', 'network', 'server', 'client', 'unknown'];

// Services typical for a desktop (Windows file sharing, RDP): not a server by themselves.
const CLIENT_RULES = new Set(['smb', 'rdp', 'nomachine']);

export const PVE_GUEST_HINT = 'вероятно гость Proxmox';

// A MAC from the Proxmox VE range (BC:24:11) on a host that is not in the inventory.
export function probableGuest(h) {
  return !h.link && String(h.mac || '').replace(/[^0-9a-f]/gi, '').toLowerCase().startsWith('bc2411');
}

// Rules that say nothing about what a device is.
const GENERIC_RULES = new Set(['port', 'http', 'https', 'web-server', 'banner', 'ssh']);
const NETWORK_RULES = new Set(['mikrotik', 'tplink', 'adguard', 'npm', 'dns', 'socks', 'openvpn', 'wireguard']);

export function ipToInt(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return ((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3];
}

// Whether the address is inside "10.10.10.0/24".
export function inCidr(ip, cidr) {
  const a = ipToInt(ip);
  const [base, bitsStr] = String(cidr || '').split('/');
  const b = ipToInt(base);
  const bits = Number(bitsStr);
  if (a === null || b === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const size = 2 ** (32 - bits);
  return Math.floor(a / size) === Math.floor(b / size);
}

export function compareIP(a, b) {
  const x = ipToInt(a);
  const y = ipToInt(b);
  if (x === null || y === null) return String(a).localeCompare(String(b));
  return x - y;
}

// The most telling name of a host: the inventory name, then PTR, certificate, title, address.
export function hostName(h) {
  const by = (src) => (h.names || []).find((n) => n.source === src)?.name;
  return h.link?.name || by('inventory') || by('ptr') || by('cert') || by('title') || h.ip;
}

// alive | down (not answering) | stopped (a stopped guest or node).
export function hostStatus(h) {
  if (h.link?.kind === 'guest' && h.link.status && h.link.status !== 'running') return 'stopped';
  if (h.link?.kind === 'node' && h.link.status === 'offline') return 'stopped';
  if (!h.alive) return 'down';
  return 'alive';
}

export const STATUS_LABEL = { alive: 'отвечает', down: 'не отвечает', stopped: 'остановлен' };

const realServices = (h) => (h.services || []).filter((s) => !GENERIC_RULES.has(s.rule));

// node | guest | network | server | client | unknown
export function classify(h) {
  if (h.link?.kind === 'node') return 'node';
  if (h.link?.kind === 'guest') return 'guest';
  const svcs = h.services || [];
  if (svcs.some((s) => NETWORK_RULES.has(s.rule))) return 'network';
  if (probableGuest(h)) return 'server';
  if (realServices(h).some((s) => !CLIENT_RULES.has(s.rule)) || svcs.some((s) => s.rule === 'ssh')) return 'server';
  if (h.random_mac || svcs.some((s) => CLIENT_RULES.has(s.rule))) return 'client';
  if (svcs.length === 0 && h.mac) return 'client';
  return 'unknown';
}

// Distinct service categories of a host (for the icons), most telling first.
export function hostCategories(h) {
  const seen = new Set();
  for (const s of h.services || []) if (!GENERIC_RULES.has(s.rule) || s.rule === 'ssh') seen.add(s.category);
  return CATEGORY_ORDER.filter((c) => seen.has(c));
}

export function defaultFilters() {
  return { clients: true, stopped: false, query: '' };
}

function matches(h, q) {
  if (!q) return true;
  const hay = [h.ip, h.mac, h.vendor, hostName(h), ...(h.names || []).map((n) => n.name), ...(h.services || []).flatMap((s) => [s.name, s.title, s.version, s.rule])]
    .filter(Boolean)
    .join('\n')
    .toLowerCase();
  return hay.includes(q);
}

export function filterHosts(hosts, f = defaultFilters()) {
  const q = (f.query || '').trim().toLowerCase();
  return (hosts || []).filter((h) => {
    if (!f.clients && classify(h) === 'client') return false;
    if (!f.stopped && hostStatus(h) !== 'alive') return false;
    return matches(h, q);
  });
}

const nodeOf = (h) => ({
  id: 'h:' + h.ip,
  type: 'host',
  position: { x: 0, y: 0 },
  data: {
    ip: h.ip,
    label: hostName(h),
    kind: classify(h),
    status: hostStatus(h),
    categories: hostCategories(h),
    vendor: h.vendor || '',
    hint: probableGuest(h) ? PVE_GUEST_HINT : '',
    router: false,
  },
});

// Builds the graph for the filtered hosts. view = the answer of GET /network.
// Returns { nodes, edges, counts } where nodes have no positions yet (see layout.js).
export function buildGraph(view, filters = defaultFilters()) {
  const all = view?.hosts || [];
  const shown = filterHosts(all, filters);
  const subnets = (view?.subnets || []).filter((s) => !s.error);
  const nodes = [];
  const edges = [];
  const edge = (a, b) => edges.push({ id: `e:${a}>${b}`, source: a, target: b });
  const byIP = new Map(shown.map((h) => [h.ip, h]));
  const placed = new Set();

  // One root per subnet: its router if it is among the hosts, else a plain network box.
  const roots = subnets.map((s) => {
    let router = null;
    if (s.gateway && inCidr(s.gateway, s.cidr)) router = byIP.get(s.gateway) || null;
    if (!router) {
      router = shown.find((h) => inCidr(h.ip, s.cidr) && (h.services || []).some((x) => x.rule === 'mikrotik') && h.ip.endsWith('.1')) || null;
    }
    let id;
    if (router) {
      const n = nodeOf(router);
      n.data.router = true;
      n.data.kind = 'router';
      nodes.push(n);
      placed.add(router.ip);
      id = n.id;
    } else {
      id = 'n:' + s.cidr;
      nodes.push({ id, type: 'net', position: { x: 0, y: 0 }, data: { label: s.cidr, kind: 'net', status: 'alive', categories: [] } });
    }
    return { cidr: s.cidr, id };
  });
  // Hosts outside every listed subnet hang under a "Прочее" box.
  let otherRoot = null;
  const rootFor = (ip) => {
    const r = roots.find((x) => inCidr(ip, x.cidr));
    if (r) return r;
    if (!otherRoot) {
      otherRoot = { cidr: '', id: 'n:other' };
      nodes.push({ id: otherRoot.id, type: 'net', position: { x: 0, y: 0 }, data: { label: 'Вне подсетей', kind: 'net', status: 'alive', categories: [] } });
    }
    return otherRoot;
  };

  const rest = shown.filter((h) => !placed.has(h.ip)).sort((a, b) => compareIP(a.ip, b.ip));
  const groups = new Map(); // group id → group node
  // A group box is a container: hosts are its children (parentId), the edge goes root → group.
  const groupFor = (rootId, key, label, kind) => {
    const gid = `g:${rootId}:${key}`;
    if (!groups.has(gid)) {
      const g = { id: gid, type: 'group', position: { x: 0, y: 0 }, data: { label, kind, count: 0 } };
      groups.set(gid, g);
      nodes.push(g);
      edge(rootId, gid);
    }
    return groups.get(gid);
  };
  const addChild = (h, g) => {
    const n = nodeOf(h);
    n.parentId = g.id;
    n.extent = 'parent';
    n.data.group = g.data.kind;
    nodes.push(n);
    g.data.count++;
    return n;
  };
  const pveGroup = (h) => groupFor(rootFor(h.ip).id, `pve:${h.link.target_id}|${h.link.node}`, `${h.link.node} (Proxmox)`, 'proxmox');
  // A Proxmox node and its guests share one box (the node card is its header).
  for (const h of rest) if (classify(h) === 'node') addChild(h, pveGroup(h)).data.header = true;
  for (const h of rest) {
    const kind = classify(h);
    if (kind === 'node') continue;
    if (kind === 'guest') addChild(h, pveGroup(h));
    else addChild(h, groupFor(rootFor(h.ip).id, kind, GROUP_LABEL[kind], kind));
  }
  // Roots first, then the boxes, then their hosts (a parent must precede its children).
  const rank = (n) => (n.parentId ? 100 : n.type === 'group' ? 1 + GROUP_ORDER.indexOf(n.data.kind) : 0);
  nodes.sort((a, b) => rank(a) - rank(b));

  const counts = {
    total: all.length,
    shown: shown.length,
    alive: all.filter((h) => hostStatus(h) === 'alive').length,
  };
  return { nodes, edges, counts };
}

// Host for the side panel by graph node id ("h:10.10.10.5").
export function hostByNodeId(view, id) {
  if (!id || !id.startsWith('h:')) return null;
  return (view?.hosts || []).find((h) => h.ip === id.slice(2)) || null;
}

// What the side panel shows about a host's link to the Proxmox inventory.
export function linkText(link) {
  if (!link) return '';
  if (link.kind === 'node') return `Узел ${link.node} (${link.target})`;
  const t = link.guest_type === 'lxc' ? 'LXC' : link.guest_type === 'qemu' ? 'VM' : 'Гость';
  return `${t} ${link.vmid} «${link.name}» на ${link.node} (${link.target})`;
}

// Hash of the "Системы" page that shows the linked guest or node.
export function linkHref(link) {
  if (!link || !link.target_id) return '';
  return `#/targets/${link.target_id}/${encodeURIComponent(link.node)}`;
}

// "в 14:05, через 5 ч 59 мин".
export function untilText(iso, now = Date.now()) {
  const t = Date.parse(iso || '');
  if (Number.isNaN(t)) return '';
  const sec = Math.round((t - now) / 1000);
  if (sec <= 0) return 'сейчас';
  if (sec < 60) return `через ${sec} с`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `через ${m} мин`;
  const h = Math.floor(m / 60);
  return `через ${h} ч ${m % 60} мин`;
}
