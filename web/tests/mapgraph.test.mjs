import test from 'node:test';
import assert from 'node:assert/strict';
import { setupEnv } from './env.mjs';

import { sampleView, sampleGraph } from './fixtures.mjs';

test('mapgraph: composite hosts, instances, controller and «Без хоста»', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const g = m.buildMapGraph(sampleView(), sampleGraph());
  const by = (id) => g.nodes.find((n) => n.id === id);
  // hello stands on its guest: the host card became a composite node with the instance inside
  assert.equal(by('h:10.10.10.33').type, 'chost');
  assert.equal(by('h:10.10.10.33').data.instances, 1);
  assert.equal(by('i:1').parentId, 'h:10.10.10.33');
  assert.equal(by('i:1').type, 'inst');
  assert.equal(by('i:1').data.containers.length, 1);
  // instances without a target go to the controller's host
  assert.equal(by('i:2').parentId, 'h:10.10.10.30');
  assert.equal(by('i:3').parentId, 'h:10.10.10.30');
  assert.equal(by('h:10.10.10.30').data.controller, true);
  // a host without instances stays a plain card
  assert.equal(by('h:10.10.10.34').type, 'host');
  assert.equal(g.nodes.some((n) => n.id === m.NOHOST_ID), false);
  // an unclosed required requires is open (red), a closed one is not
  assert.equal(by('i:3').data.requires[0].open, true);
  assert.equal(by('i:2').data.requires[0].open, false);
  // parents precede children
  const idx = new Map(g.nodes.map((n, i) => [n.id, i]));
  for (const n of g.nodes) if (n.parentId) assert.ok(idx.get(n.parentId) < idx.get(n.id), n.id);
  env.dispose();
});

test('mapgraph: without a controller host instances go to «Без хоста»', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const gr = sampleGraph();
  gr.controller_ip = '';
  const g = m.buildMapGraph(sampleView(), gr);
  const box = g.nodes.find((n) => n.id === m.NOHOST_ID);
  assert.equal(box.type, 'group');
  assert.equal(box.data.kind, 'nohost');
  assert.equal(box.data.count, 2);
  assert.equal(g.nodes.find((n) => n.id === 'i:2').parentId, m.NOHOST_ID);
  // an instance on an address that is not on the map is «Без хоста» too
  gr.instances[0].host_ip = '10.10.10.250';
  assert.equal(m.buildMapGraph(sampleView(), gr).nodes.find((n) => n.id === 'i:1').parentId, m.NOHOST_ID);
  env.dispose();
});

test('mapgraph: link edges — service solid, device dashed, ports on the border', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const g = m.buildMapGraph(sampleView(), sampleGraph());
  const by = (id) => g.linkEdges.find((e) => e.id === id);
  // hello (host .33) → probe (controller host .30): leaves from the port on the border of the host
  const svc = by('l:10');
  assert.equal(svc.source, 'h:10.10.10.33');
  assert.equal(svc.sourceHandle, 'out:1:web');
  assert.equal(svc.target, 'i:2');
  assert.equal(svc.targetHandle, 'r:target');
  assert.equal(svc.data.dashed, false);
  assert.equal(svc.data.label, 'http.service');
  assert.equal(svc.data.color, 'var(--color-success)');
  // hello → device: dashed, to the host card, colour of the status
  const dev = by('l:11');
  assert.equal(dev.target, 'h:10.10.10.34');
  assert.equal(dev.targetHandle, 'dev');
  assert.equal(dev.data.dashed, true);
  assert.equal(dev.data.color, 'var(--color-warning)');
  assert.equal(dev.data.detail, 'нет строки');
  // inside one host the edge goes between the instance cards
  const gr = sampleGraph();
  gr.instances[1].host_ip = '10.10.10.33';
  gr.instances[1].controller = false;
  const g2 = m.buildMapGraph(sampleView(), gr);
  const inner = g2.linkEdges.find((e) => e.id === 'l:10');
  assert.equal(inner.source, 'i:1');
  assert.equal(inner.sourceHandle, 'p:web');
  // the tree edges stay separate from the links
  assert.ok(g.edges.every((e) => e.id.startsWith('e:')));
  env.dispose();
});

test('mapgraph: a link to a hidden host is not drawn; no graph = the plain map', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const v = sampleView();
  const plain = m.buildMapGraph(v, null);
  assert.equal(plain.linkEdges.length, 0);
  assert.ok(plain.nodes.every((n) => n.type !== 'chost' && n.type !== 'inst'));
  const gr = sampleGraph();
  const q = m.buildMapGraph(v, gr, { clients: true, stopped: false, query: 'device-ct' });
  // the search keeps only the device host; the device link target exists, its provider does not
  assert.equal(q.linkEdges.length, 0);
  // the search also looks into instance names
  const byName = m.buildMapGraph(v, gr, { clients: true, stopped: false, query: 'hello 1' });
  assert.ok(byName.nodes.some((n) => n.id === 'i:1'));
  assert.ok(!byName.nodes.some((n) => n.id === 'i:2'));
  env.dispose();
});

test('mapgraph: stopped hosts with instances stay on the map', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const v = sampleView();
  v.hosts[2].link.status = 'stopped';
  v.hosts[2].alive = false;
  const g = m.buildMapGraph(v, sampleGraph());
  assert.ok(g.nodes.some((n) => n.id === 'h:10.10.10.33' && n.type === 'chost'));
  const plain = m.buildMapGraph(v, null);
  assert.ok(!plain.nodes.some((n) => n.id === 'h:10.10.10.33'));
  env.dispose();
});

test('mapgraph: node id parsing and lookups', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  assert.deepEqual(m.parseNodeId('h:10.10.10.5'), { kind: 'host', id: '10.10.10.5' });
  assert.deepEqual(m.parseNodeId('i:7'), { kind: 'instance', id: 7 });
  assert.deepEqual(m.parseNodeId('l:3'), { kind: 'link', id: 3 });
  assert.equal(m.parseNodeId('g:x'), null);
  const gr = sampleGraph();
  assert.equal(m.instanceById(gr, 2).name, 'Probe 1');
  assert.equal(m.linksOfInstance(gr, 1).length, 2);
  assert.equal(m.linksOfInstance(gr, 3).length, 0);
  env.dispose();
});

test('layout: composite host sizes, instance cards and ports exported to the border', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const l = await env.import('lib/layout.js');
  const g = m.buildMapGraph(sampleView(), sampleGraph());
  const placed = l.layoutGraph(g.nodes, g.edges);
  const by = (id) => placed.find((n) => n.id === id);
  const hello = by('h:10.10.10.33');
  assert.ok(hello.width >= l.INST.w, 'the composite is wider than an instance');
  assert.ok(hello.height > l.CARD.h, 'and taller than a plain card');
  const inst = by('i:1');
  assert.ok(inst.position.y >= l.CARD.h, 'the instance is below the host header');
  assert.deepEqual(hello.data.exports.map((e) => [e.instance, e.port]), [[1, 'web']]);
  assert.equal(hello.data.exports[0].y, inst.position.y + l.portY(0));
  // everything stays inside its parent and nothing overlaps among the cards of a box
  const rects = l.absoluteRects(placed);
  const byId = new Map(rects.map((r) => [r.id, r]));
  for (const n of placed) {
    if (!n.parentId) continue;
    const r = byId.get(n.id);
    const p = byId.get(n.parentId);
    assert.ok(r.x >= p.x && r.y >= p.y && r.x + r.w <= p.x + p.w + 1 && r.y + r.h <= p.y + p.h + 1, `${n.id} inside ${n.parentId}`);
  }
  const siblings = rects.filter((r) => r.parentId === 'h:10.10.10.30');
  assert.equal(siblings.length, 2);
  const [a, b] = siblings;
  assert.ok(a.y + a.h <= b.y || b.y + b.h <= a.y, 'instances of one host do not overlap');
  // parents before children
  const idx = new Map(placed.map((n, i) => [n.id, i]));
  for (const n of placed) if (n.parentId) assert.ok(idx.get(n.parentId) < idx.get(n.id));
  env.dispose();
});

test('layout: «Без хоста» box holds instance cards', async () => {
  const env = setupEnv();
  const m = await env.import('lib/mapgraph.js');
  const l = await env.import('lib/layout.js');
  const gr = sampleGraph();
  gr.controller_ip = '';
  const g = m.buildMapGraph(sampleView(), gr);
  const placed = l.layoutGraph(g.nodes, g.edges);
  const box = placed.find((n) => n.id === m.NOHOST_ID);
  assert.ok(box.width >= l.INST.w && box.height > 0);
  const rects = l.absoluteRects(placed);
  const b = rects.find((r) => r.id === m.NOHOST_ID);
  for (const r of rects.filter((x) => x.parentId === m.NOHOST_ID)) assert.ok(r.x >= b.x && r.x + r.w <= b.x + b.w + 1 && r.y + r.h <= b.y + b.h + 1);
  env.dispose();
});

test('layout: instanceSize grows with ports and containers (capped)', async () => {
  const env = setupEnv();
  const l = await env.import('lib/layout.js');
  const base = l.instanceSize({ provides: [], requires: [], containers: [] });
  const ports = l.instanceSize({ provides: [{}, {}], requires: [{}], containers: [] });
  assert.equal(ports.h - base.h, 2 * l.INST.row);
  const few = l.instanceSize({ provides: [], requires: [], containers: [{}, {}] });
  const many = l.instanceSize({ provides: [], requires: [], containers: new Array(20).fill({}) });
  assert.ok(many.h > few.h);
  assert.equal(many.h, base.h + 6 + (l.INST.maxCont + 1) * l.INST.cont);
  assert.equal(l.containerRows(new Array(20)), l.INST.maxCont + 1);
  env.dispose();
});
