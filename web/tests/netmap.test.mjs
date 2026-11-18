import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';

const T0 = '2026-11-18T10:00:00Z';
const svc = (rule, name, category, port, extra = {}) => ({ port, proto: 'http', rule, name, category, ...extra });
const host = (ip, o = {}) => ({
  ip, mac: '', vendor: '', random_mac: false, names: [], first_seen: T0, last_seen: T0, alive: true, source: 'scan',
  ports: [], services: [], link: null, no_response: false, ...o,
});
const node = (ip, name, extra = {}) => host(ip, { link: { kind: 'node', target_id: 1, target: 'home', node: name, name, status: 'online' }, services: [svc('proxmox-ve', 'Proxmox VE', 'infra', 8006, { url: `https://${ip}:8006/` })], ...extra });
const guest = (ip, vmid, name, status = 'running', extra = {}) =>
  host(ip, { link: { kind: 'guest', target_id: 1, target: 'home', node: 'pve1', vmid, name, guest_type: 'lxc', status }, alive: status === 'running', ...extra });

function sampleView() {
  return {
    subnets: [
      { cidr: '10.10.10.0/24', source: 'proxmox', label: 'home · pve1 · vmbr0', gateway: '10.10.10.1' },
      { cidr: '10.20.0.0/16', source: 'proxmox', label: 'x', error: 'подсеть больше /22 — не сканируется' },
    ],
    hosts: [
      host('10.10.10.1', { names: [{ name: 'router.lan', source: 'ptr' }], services: [svc('mikrotik', 'MikroTik RouterOS', 'infra', 80)] }),
      node('10.10.10.10', 'pve1'),
      node('10.10.10.11', 'pve2'),
      guest('10.10.10.33', 100, 'semaphore', 'running', { services: [svc('semaphore', 'Semaphore UI', 'dev', 3000)] }),
      guest('10.10.10.34', 101, 'old-vm', 'stopped'),
      guest('10.10.10.35', 102, 'quiet', 'running', { alive: false, no_response: true }),
      host('10.10.10.15', { services: [svc('adguard', 'AdGuard Home', 'network', 9091)] }),
      host('10.10.10.36', { services: [svc('hpe-ilo', 'HPE iLO', 'infra', 443)], ports: [22, 443] }),
      host('10.10.10.77', { mac: 'da:a1:19:00:00:77', random_mac: true }),
      host('10.10.10.78', { mac: '3c:22:fb:00:00:78', vendor: 'Apple, Inc.' }),
      host('10.10.10.90', { ports: [4242], services: [svc('port', 'Открытый порт 4242', 'other', 4242)] }),
    ],
  };
}

test('netmap: classification of hosts', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const v = sampleView();
  const by = (ip) => v.hosts.find((h) => h.ip === ip);
  assert.equal(m.classify(by('10.10.10.10')), 'node');
  assert.equal(m.classify(by('10.10.10.33')), 'guest');
  assert.equal(m.classify(by('10.10.10.15')), 'network');
  assert.equal(m.classify(by('10.10.10.1')), 'network');
  assert.equal(m.classify(by('10.10.10.36')), 'server');
  assert.equal(m.classify(by('10.10.10.77')), 'client');
  assert.equal(m.classify(by('10.10.10.78')), 'client');
  assert.equal(m.classify(by('10.10.10.90')), 'unknown');
  assert.equal(m.hostStatus(by('10.10.10.33')), 'alive');
  assert.equal(m.hostStatus(by('10.10.10.34')), 'stopped');
  assert.equal(m.hostStatus(by('10.10.10.35')), 'down');
  env.dispose();
});

test('netmap: names, addresses and CIDR helpers', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  assert.equal(m.hostName({ ip: '10.0.0.5', names: [{ name: 'a.lan', source: 'ptr' }, { name: 'a-cert', source: 'cert' }], link: null }), 'a.lan');
  assert.equal(m.hostName({ ip: '10.0.0.5', names: [], link: { name: 'web' } }), 'web');
  assert.equal(m.hostName({ ip: '10.0.0.5', names: [] }), '10.0.0.5');
  assert.ok(m.inCidr('10.10.10.200', '10.10.10.0/24'));
  assert.ok(!m.inCidr('10.10.11.1', '10.10.10.0/24'));
  assert.ok(m.inCidr('10.10.9.7', '10.10.8.0/22'));
  assert.ok(!m.inCidr('nope', '10.10.8.0/22'));
  assert.ok(m.compareIP('10.10.10.9', '10.10.10.10') < 0);
  assert.equal(m.untilText('2026-11-18T16:00:00Z', Date.parse('2026-11-18T10:01:00Z')), 'через 5 ч 59 мин');
  assert.equal(m.untilText('2026-11-18T10:00:30Z', Date.parse('2026-11-18T10:00:00Z')), 'через 30 с');
  assert.equal(m.untilText('2026-11-18T09:00:00Z', Date.parse('2026-11-18T10:00:00Z')), 'сейчас');
  const g = { kind: 'guest', target_id: 7, target: 'home', node: 'pve 1', vmid: 100, name: 'web', guest_type: 'lxc' };
  assert.equal(m.linkHref(g), '#/targets/7/pve%201');
  assert.equal(m.linkText(g), 'LXC 100 «web» на pve 1 (home)');
  assert.equal(m.linkText({ kind: 'node', node: 'pve1', target: 'home' }), 'Узел pve1 (home)');
  assert.equal(m.linkHref(null), '');
  env.dispose();
});

test('netmap: graph — router, nodes, guests under their node, device groups', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const g = m.buildGraph(sampleView(), { clients: true, stopped: true, query: '' });
  const ids = g.nodes.map((n) => n.id);
  const has = (a, b) => g.edges.some((e) => e.source === a && e.target === b);

  // The router (the gateway of the subnet) is the root; the /16 without scan is not a root.
  const router = g.nodes.find((n) => n.data.router);
  assert.equal(router.id, 'h:10.10.10.1');
  assert.equal(router.data.kind, 'router');
  assert.ok(!ids.some((i) => i.startsWith('n:')));
  // Nodes and device groups hang under the router; hosts are children of their box.
  const grp = (kind) => g.nodes.find((n) => n.type === 'group' && n.data.kind === kind);
  const pve1 = g.nodes.find((n) => n.type === 'group' && n.data.label === 'pve1 (Proxmox)');
  const pve2 = g.nodes.find((n) => n.type === 'group' && n.data.label === 'pve2 (Proxmox)');
  assert.ok(has('h:10.10.10.1', pve1.id) && has('h:10.10.10.1', pve2.id));
  const parent = (ip) => g.nodes.find((n) => n.id === 'h:' + ip).parentId;
  assert.equal(parent('10.10.10.10'), pve1.id);
  assert.equal(parent('10.10.10.33'), pve1.id);
  assert.equal(parent('10.10.10.34'), pve1.id);
  assert.equal(parent('10.10.10.11'), pve2.id);
  assert.equal(g.nodes.find((n) => n.id === 'h:10.10.10.10').data.header, true);
  assert.deepEqual(['network', 'server', 'client', 'unknown'].map((k) => grp(k)?.data.count), [1, 1, 2, 1]);
  assert.equal(grp('network').data.label, 'Сетевое оборудование');
  assert.equal(grp('server').data.label, 'Серверы и хранилища');
  assert.equal(grp('client').data.label, 'Компьютеры и телефоны');
  assert.equal(grp('unknown').data.label, 'Неизвестные');
  assert.ok(has('h:10.10.10.1', grp('network').id));
  assert.equal(parent('10.10.10.36'), grp('server').id);
  assert.equal(parent('10.10.10.77'), grp('client').id);
  assert.equal(parent('10.10.10.90'), grp('unknown').id);
  // Boxes have one parent (the router); the router none; hosts are tied by parentId, not edges.
  for (const n of g.nodes) {
    const parents = g.edges.filter((e) => e.target === n.id).length;
    assert.equal(parents, n.type === 'group' ? 1 : 0, n.id);
  }
  // A parent always comes before its children.
  for (const n of g.nodes) if (n.parentId) assert.ok(ids.indexOf(n.parentId) < ids.indexOf(n.id));
  for (const e of g.edges) assert.ok(ids.includes(e.source) && ids.includes(e.target));
  assert.deepEqual(g.counts, { total: 11, shown: 11, alive: 9 });
  // Card data: name, ip, status, category icons.
  const card = g.nodes.find((n) => n.id === 'h:10.10.10.33').data;
  assert.equal(card.label, 'semaphore');
  assert.equal(card.status, 'alive');
  assert.deepEqual(card.categories, ['dev']);
  env.dispose();
});

test('netmap: filters — clients, stopped, search', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const v = sampleView();
  const ips = (f) => m.filterHosts(v.hosts, f).map((h) => h.ip);
  const d = m.defaultFilters();
  assert.deepEqual(d, { clients: true, stopped: false, query: '' });
  // Default: clients shown, stopped and silent hidden.
  assert.ok(ips(d).includes('10.10.10.77'));
  assert.ok(!ips(d).includes('10.10.10.34') && !ips(d).includes('10.10.10.35'));
  assert.ok(!ips({ ...d, clients: false }).includes('10.10.10.77') && !ips({ ...d, clients: false }).includes('10.10.10.78'));
  assert.ok(ips({ ...d, stopped: true }).includes('10.10.10.34'));
  // Search over name, address, vendor and service names.
  assert.deepEqual(ips({ ...d, query: 'semaphore' }), ['10.10.10.33']);
  assert.deepEqual(ips({ ...d, query: '10.10.10.15' }), ['10.10.10.15']);
  assert.deepEqual(ips({ ...d, query: 'apple' }), ['10.10.10.78']);
  assert.deepEqual(ips({ ...d, query: 'adguard' }), ['10.10.10.15']);
  assert.deepEqual(ips({ ...d, query: 'нет такого' }), []);
  // A guest whose node is filtered out still gets its Proxmox box (without the node card).
  const g = m.buildGraph(v, { ...d, query: 'semaphore' });
  const box = g.nodes.find((n) => n.type === 'group');
  assert.equal(box.data.label, 'pve1 (Proxmox)');
  assert.equal(g.nodes.find((n) => n.id === 'h:10.10.10.33').parentId, box.id);
  assert.equal(g.counts.shown, 1);
  env.dispose();
});

test('netmap: no router found — a plain subnet box; hosts outside every subnet', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const v = {
    subnets: [{ cidr: '10.10.20.0/24', source: 'manual', label: 'вручную' }],
    hosts: [host('10.10.20.5', { services: [svc('ssh', 'SSH', 'remote', 22, { proto: 'ssh' })] }), host('10.99.0.5', { mac: 'aa:bb:cc:dd:ee:ff' })],
  };
  const g = m.buildGraph(v, m.defaultFilters());
  const root = g.nodes.find((n) => n.id === 'n:10.10.20.0/24');
  assert.equal(root.type, 'net');
  assert.ok(g.nodes.some((n) => n.id === 'n:other'));
  assert.ok(g.edges.some((e) => e.source === 'n:10.10.20.0/24' && e.target.startsWith('g:')));
  assert.equal(m.buildGraph({ subnets: [], hosts: [] }).nodes.length, 0);
  assert.equal(m.hostByNodeId(v, 'h:10.10.20.5').ip, '10.10.20.5');
  assert.equal(m.hostByNodeId(v, 'g:x'), null);
  env.dispose();
});

function flatScan() {
  const hosts = [
    host('10.10.10.1', { mac: '48:8f:5a:00:00:01', vendor: 'MikroTik', services: [svc('mikrotik', 'MikroTik RouterOS', 'infra', 80)] }),
    host('10.10.10.2', { mac: '48:8f:5a:00:00:02', vendor: 'MikroTik', services: [svc('mikrotik', 'MikroTik RouterOS', 'infra', 80)] }),
    host('10.10.10.3', { mac: '50:c7:bf:00:00:03', vendor: 'TP-Link', services: [svc('tplink', 'TP-Link', 'network', 80)] }),
    host('10.10.10.200', { mac: '3c:22:fb:00:00:c8', vendor: 'Apple, Inc.' }),
    host('10.10.10.210', { mac: '00:11:22:00:00:d2', services: [svc('smb', 'Samba / SMB', 'storage', 445)] }),
    host('10.10.10.220', { ports: [4242], services: [svc('port', 'Открытый порт 4242', 'other', 4242)] }),
    host('10.10.10.221', { ports: [4343], services: [svc('port', 'Открытый порт 4343', 'other', 4343)] }),
    host('10.10.10.150', { mac: '00:11:32:00:00:96', vendor: 'Synology', services: [svc('synology', 'Synology DSM', 'storage', 5000)] }),
  ];
  for (let i = 0; i < 5; i++) hosts.push(host(`10.10.10.${40 + i}`, { mac: `94:57:a5:00:00:${i}0`, services: [svc('hpe-ilo', 'HPE iLO', 'infra', 443)] }));
  for (let i = 0; i < 4; i++) hosts.push(host(`10.10.10.${230 + i}`, { mac: `da:a1:19:00:00:${i}0`, random_mac: true }));
  for (let i = 0; i < 30; i++) {
    const ssh = svc('ssh', 'SSH', 'remote', 22);
    hosts.push(host(`10.10.10.${60 + i}`, { mac: `bc:24:11:00:00:${String(i).padStart(2, '0')}`, vendor: '', services: i % 3 ? [ssh] : [ssh, svc('gitea', 'Gitea', 'dev', 3000), svc('grafana', 'Grafana', 'monitoring', 3001), svc('postgres', 'PostgreSQL', 'db', 5432), svc('redis', 'Redis', 'db', 6379), svc('jellyfin', 'Jellyfin', 'media', 8096)] }));
  }
  return { subnets: [{ cidr: '10.10.10.0/24', source: 'scan', label: 'lan', gateway: '10.10.10.1' }], hosts };
}

function pveScan(nodes = 3, per = 15) {
  const hosts = [host('10.10.10.1', { services: [svc('mikrotik', 'MikroTik RouterOS', 'infra', 80)] })];
  for (let n = 0; n < nodes; n++) {
    hosts.push(node(`10.10.10.${10 + n}`, `pve${n + 1}`, { link: { kind: 'node', target_id: 1, target: 'home', node: `pve${n + 1}`, name: `pve${n + 1}`, status: 'online' } }));
    for (let i = 0; i < per; i++) {
      hosts.push(host(`10.10.${20 + n}.${i + 1}`.replace(/^10\.10\.2\d/, '10.10.10').replace(/\.\d+$/, `.${100 + n * 20 + i}`), {
        link: { kind: 'guest', target_id: 1, target: 'home', node: `pve${n + 1}`, vmid: 100 + n * 100 + i, name: `vm${n}-${i}`, guest_type: 'lxc', status: 'running' },
      }));
    }
  }
  return { subnets: [{ cidr: '10.10.10.0/24', source: 'proxmox', label: 'x', gateway: '10.10.10.1' }], hosts };
}

const ALL = { clients: true, stopped: true, query: '' };

function checkLayout(placed, l) {
  const rects = l.absoluteRects(placed);
  // Cards (hosts) never overlap each other.
  const cards = rects.filter((r) => r.type === 'host' || r.type === 'net');
  for (let i = 0; i < cards.length; i++)
    for (let j = i + 1; j < cards.length; j++) {
      const a = cards[i], b = cards[j];
      const apart = a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y;
      assert.ok(apart, `${a.id} overlaps ${b.id}`);
    }
  // Boxes do not overlap each other; children lie inside their box.
  const boxes = rects.filter((r) => r.type === 'group');
  for (let i = 0; i < boxes.length; i++)
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      assert.ok(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y, `${a.id} overlaps ${b.id}`);
    }
  for (const c of rects.filter((r) => r.parentId)) {
    const p = boxes.find((b) => b.id === c.parentId);
    assert.ok(c.x >= p.x && c.y >= p.y && c.x + c.w <= p.x + p.w && c.y + c.h <= p.y + p.h, `${c.id} outside ${p.id}`);
  }
  const x0 = Math.min(...rects.map((r) => r.x)), x1 = Math.max(...rects.map((r) => r.x + r.w));
  const y0 = Math.min(...rects.map((r) => r.y)), y1 = Math.max(...rects.map((r) => r.y + r.h));
  return { rects, aspect: (x1 - x0) / (y1 - y0), boxes };
}

// Most cards standing in one visual row (same y inside one box).
function widestRow(rects) {
  const rows = new Map();
  for (const r of rects.filter((x) => x.type === 'host')) {
    const k = `${r.parentId}|${r.y}`;
    rows.set(k, (rows.get(k) || 0) + 1);
  }
  return Math.max(...rows.values());
}

test('layout: 47 hosts without inventory — groups by role, no long row, sane shape', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const l = await env.import('lib/layout.js');
  const view = flatScan();
  assert.equal(view.hosts.length, 47);
  const g = m.buildGraph(view, ALL);
  const kinds = Object.fromEntries(g.nodes.filter((n) => n.type === 'group').map((n) => [n.data.kind, n.data.count]));
  // router is its own node; 2nd MikroTik + TP-Link = network; iLO, Synology and 30 guests = servers.
  assert.deepEqual(kinds, { network: 2, server: 36, client: 6, unknown: 2 });
  assert.equal(g.nodes.filter((n) => n.data.router).length, 1);
  // Probable Proxmox guests are marked.
  assert.equal(g.nodes.find((n) => n.id === 'h:10.10.10.60').data.hint, 'вероятно гость Proxmox');
  assert.equal(m.classify(view.hosts.find((h) => h.ip === '10.10.10.60')), 'server');
  const placed = l.layoutGraph(g.nodes, g.edges);
  const { rects, aspect } = checkLayout(placed, l);
  assert.equal(placed.length, g.nodes.length);
  assert.ok(widestRow(rects) <= 6, 'row too wide: ' + widestRow(rects));
  assert.ok(aspect >= 0.6 && aspect <= 2.5, 'aspect ' + aspect);
  assert.deepEqual(l.layoutGraph(g.nodes, g.edges), placed); // deterministic
  // The router is above every box.
  const top = rects.find((r) => r.id === 'h:10.10.10.1');
  for (const b of rects.filter((r) => r.type === 'group')) assert.ok(top.y + top.h <= b.y);
  env.dispose();
});

test('layout: 3 Proxmox nodes × 15 guests — a box per node, grid up to 6 columns', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const l = await env.import('lib/layout.js');
  const g = m.buildGraph(pveScan(3, 15), ALL);
  const groups = g.nodes.filter((n) => n.type === 'group');
  assert.equal(groups.length, 3);
  assert.deepEqual(groups.map((x) => x.data.label), ['pve1 (Proxmox)', 'pve2 (Proxmox)', 'pve3 (Proxmox)']);
  for (const x of groups) assert.equal(x.data.count, 16); // node + 15 guests
  const placed = l.layoutGraph(g.nodes, g.edges);
  const { rects, aspect } = checkLayout(placed, l);
  assert.ok(widestRow(rects) <= 6);
  assert.ok(aspect >= 0.6 && aspect <= 2.5, 'aspect ' + aspect);
  // The node card is the header of its box: above all its guests.
  for (const x of groups) {
    const kids = rects.filter((r) => r.parentId === x.id);
    const head = kids.find((r) => r.id === 'h:10.10.10.' + (9 + Number(x.data.label.match(/\d+/)[0])));
    assert.ok(head);
    for (const k of kids) if (k !== head) assert.ok(k.y >= head.y + head.h);
  }
  env.dispose();
});

test('layout: small and empty inputs, boxes wrap into rows', async () => {
  const env = setupEnv();
  const m = await env.import('lib/netmap.js');
  const l = await env.import('lib/layout.js');
  assert.equal(l.layoutGraph([], [{ id: 'e', source: 'a', target: 'b' }]).length, 0);
  const g = m.buildGraph(sampleView(), ALL);
  const placed = l.layoutGraph(g.nodes, g.edges);
  const { boxes } = checkLayout(placed, l);
  assert.ok(boxes.length >= 5);
  assert.ok(new Set(boxes.map((b) => b.y)).size >= 2, 'more than 3 boxes must wrap into rows');
  for (const n of placed) assert.ok(Number.isFinite(n.position.x) && Number.isFinite(n.position.y));
  env.dispose();
});

test('services: rows, filters and grouping by category', async () => {
  const env = setupEnv();
  const s = await env.import('lib/services.js');
  const v = sampleView();
  v.hosts[0].names.push({ name: 'router.home', source: 'cert' }, { name: 'Router UI', source: 'title' });
  const rows = s.serviceRows(v.hosts);
  assert.equal(rows.length, 7);
  const r = rows.find((x) => x.key === '10.10.10.1:80');
  assert.deepEqual({ host: r.host, dns: r.dns, name: r.name, category: r.category }, { host: 'router.lan', dns: ['router.lan', 'router.home'], name: 'MikroTik RouterOS', category: 'infra' });
  assert.equal(rows.find((x) => x.port === 8006 && x.ip === '10.10.10.10').url, 'https://10.10.10.10:8006/');

  // Open ports without a service are hidden by default; silent hosts can be hidden.
  assert.equal(s.filterServices(rows, {}).length, 6);
  assert.equal(s.filterServices(rows, { unknown: true }).length, 7);
  assert.ok(!s.filterServices(rows, { dead: false }).some((x) => !x.alive));
  assert.deepEqual(s.filterServices(rows, { category: 'dev' }).map((x) => x.name), ['Semaphore UI']);
  assert.deepEqual(s.filterServices(rows, { query: 'router.home' }).map((x) => x.key), ['10.10.10.1:80']);
  assert.deepEqual(s.filterServices(rows, { query: 'Умный' }), []);
  assert.deepEqual(s.filterServices(rows, { query: 'инфраструктура' }).length, 4);

  const groups = s.groupByCategory(s.filterServices(rows, {}));
  assert.deepEqual(groups.map((x) => x.category), ['infra', 'network', 'dev']);
  assert.equal(groups[0].label, 'Инфраструктура');
  // Inside a group: by service name, then address.
  assert.deepEqual(groups[0].rows.map((x) => x.name), ['HPE iLO', 'MikroTik RouterOS', 'Proxmox VE', 'Proxmox VE']);
  assert.deepEqual(groups[0].rows.filter((x) => x.name === 'Proxmox VE').map((x) => x.ip), ['10.10.10.10', '10.10.10.11']);
  assert.deepEqual(s.categoriesOf(rows).map((c) => c.value), ['infra', 'network', 'dev', 'other']);
  assert.deepEqual(s.serviceRows(undefined), []);
  env.dispose();
});

test('router: map and services routes; API helpers use the right calls', async () => {
  const env = setupEnv({
    'GET /api/v1/network': () => [200, { hosts: [] }],
    'POST /api/v1/network/scan': () => [202, { job: { id: 'j1' } }],
    'DELETE /api/v1/network/scan': () => [204, null],
    'PUT /api/v1/network/settings': (b) => [200, b],
    'DELETE /api/v1/network/hosts/10.10.10.5': () => [204, null],
  });
  const { parseHash } = await env.import('lib/router.js');
  assert.deepEqual(parseHash('#/map'), { name: 'map' });
  assert.deepEqual(parseHash('#/services'), { name: 'services' });
  const { api } = await env.import('lib/api.js');
  await api.network();
  assert.equal((await api.scanNetwork()).job.id, 'j1');
  await api.cancelScan();
  assert.deepEqual(await api.networkSettings({ extra_subnets: ['10.10.30.0/24'], exclude: [] }), { extra_subnets: ['10.10.30.0/24'], exclude: [] });
  await api.forgetHost('10.10.10.5');
  assert.deepEqual(env.calls.map((c) => c.key), [
    'GET /api/v1/network', 'POST /api/v1/network/scan', 'DELETE /api/v1/network/scan', 'PUT /api/v1/network/settings', 'DELETE /api/v1/network/hosts/10.10.10.5',
  ]);
  env.dispose();
});
