// Shared fixtures of the map tests: GET /network and GET /graph of a small home lab.
const T0 = '2026-11-18T10:00:00Z';
export const host = (ip, o = {}) => ({
  ip, mac: '', vendor: '', random_mac: false, names: [], first_seen: T0, last_seen: T0, alive: true, source: 'scan',
  ports: [], services: [], link: null, no_response: false, ref: '', ...o,
});
export const guest = (ip, vmid, name, ref = '') =>
  host(ip, { ref, link: { kind: 'guest', target_id: 1, target: 'home', node: 'pve1', vmid, name, guest_type: 'lxc', status: 'running' } });

const pweb = (o = {}) => ({ name: 'web', type: 'http.service', label: 'Веб-страница', client: true, multi: true, linked: 0, linkable: true, ...o });
const preq = (o = {}) => ({ name: 'target', type: 'http.service', label: 'Что проверять', multi: false, linked: 0, linkable: true, ...o });

export function sampleView() {
  return {
    subnets: [{ cidr: '10.10.10.0/24', source: 'proxmox', label: 'x', gateway: '10.10.10.1' }],
    hosts: [
      host('10.10.10.1', { services: [{ port: 80, proto: 'http', rule: 'mikrotik', name: 'MikroTik', category: 'infra' }] }),
      guest('10.10.10.30', 900, 'hestia'),
      guest('10.10.10.33', 901, 'hello-ct'),
      guest('10.10.10.34', 902, 'device-ct'),
    ],
  };
}

export function sampleGraph() {
  const hosts = [
    { ...sampleView().hosts[0], ref: '' },
    { ...sampleView().hosts[1], ref: 'lxc:1:pve1:900' },
    { ...sampleView().hosts[2], ref: 'lxc:1:pve1:901' },
    { ...sampleView().hosts[3], ref: 'lxc:1:pve1:902' },
  ];
  return {
    hosts,
    controller_ip: '10.10.10.30',
    instances: [
      { id: 1, plugin_id: 'hestia-hello', plugin_name: 'Hestia Hello', name: 'Hello 1', icon_url: '', status: 'ok', detail: '', host_ref: 'lxc:1:pve1:901', host_ip: '10.10.10.33', controller: false,
        provides: [pweb({ linked: 2 })], requires: [], containers: [{ name: 'whoami', image: 'traefik/whoami', state: 'running', ports: [] }] },
      { id: 2, plugin_id: 'hestia-probe', plugin_name: 'Hestia Probe', name: 'Probe 1', icon_url: '', status: 'ok', detail: '', host_ref: '', host_ip: '', controller: true,
        provides: [], requires: [preq({ linked: 1 })], containers: [] },
      { id: 3, plugin_id: 'hestia-probe', plugin_name: 'Hestia Probe', name: 'Probe 2', icon_url: '', status: 'degraded', detail: 'Не подключён к сервису', host_ref: '', host_ip: '', controller: true,
        provides: [], requires: [preq()], containers: [] },
    ],
    links: [
      { id: 10, kind: 'service', type: 'http.service', provider: { instance: 1, port: 'web', name: 'Hello 1', plugin_id: 'hestia-hello' },
        consumer: { instance: 2, port: 'target', name: 'Probe 1', plugin_id: 'hestia-probe' }, device: null, status: 'ok', detail: '' },
      { id: 11, kind: 'device', type: 'http.service', provider: { instance: 1, port: 'web', name: 'Hello 1', plugin_id: 'hestia-hello' },
        consumer: null, device: { ref: 'lxc:1:pve1:902', name: 'device-ct', host_ip: '10.10.10.34' }, status: 'degraded', detail: 'нет строки' },
    ],
    positions: {},
  };
}

