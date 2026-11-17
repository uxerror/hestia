// Hash routes: #/wizard, #/wizard/proxmox, #/wizard/server, #/targets, #/jobs, #/jobs/<id>
export function parseHash(hash) {
  const parts = (hash || '').replace(/^#\/?/, '').split('/').filter(Boolean);
  if (parts[0] === 'jobs') return parts[1] ? { name: 'job', id: decodeURIComponent(parts[1]) } : { name: 'jobs' };
  if (parts[0] === 'targets') return { name: 'targets' };
  if (parts[0] === 'wizard') {
    if (parts[1] === 'proxmox' || parts[1] === 'server') return { name: 'connect', kind: parts[1] };
    return parts[1] === 'next' ? { name: 'next', kind: parts[2] || '' } : { name: 'wizard' };
  }
  return { name: 'wizard' };
}
