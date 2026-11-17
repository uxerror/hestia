// Hash routes: #/install, #/handoff/<token>, #/wizard, #/wizard/proxmox, #/wizard/server, #/targets, #/targets/<id>[/<node>], #/jobs, #/jobs/<id>, #/update/offer?…
export function parseHash(hash) {
  const parts = (hash || '').split('?')[0].replace(/^#\/?/, '').split('/').filter(Boolean);
  if (parts[0] === 'jobs') return parts[1] ? { name: 'job', id: decodeURIComponent(parts[1]) } : { name: 'jobs' };
  if (parts[0] === 'update' && parts[1] === 'offer') return { name: 'update-offer', hash: hash || '' };
  if (parts[0] === 'install') return { name: 'install' };
  if (parts[0] === 'handoff') return { name: 'handoff', token: parts[1] ? decodeURIComponent(parts[1]) : '' };
  if (parts[0] === 'targets') {
    const id = Number(parts[1]);
    if (!parts[1] || !Number.isInteger(id) || id <= 0) return { name: 'targets' };
    return { name: 'guests', id, node: parts[2] ? decodeURIComponent(parts[2]) : '' };
  }
  if (parts[0] === 'wizard') {
    if (parts[1] === 'proxmox' || parts[1] === 'server') return { name: 'connect', kind: parts[1] };
    return parts[1] === 'next' ? { name: 'next', kind: parts[2] || '' } : { name: 'wizard' };
  }
  return { name: 'wizard' };
}
