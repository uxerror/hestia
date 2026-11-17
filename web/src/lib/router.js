// Hash routes: #/wizard, #/wizard/next, #/jobs, #/jobs/<id>
export function parseHash(hash) {
  const parts = (hash || '').replace(/^#\/?/, '').split('/').filter(Boolean);
  if (parts[0] === 'jobs') return parts[1] ? { name: 'job', id: decodeURIComponent(parts[1]) } : { name: 'jobs' };
  if (parts[0] === 'wizard') return parts[1] === 'next' ? { name: 'next', kind: parts[2] || '' } : { name: 'wizard' };
  return { name: 'wizard' };
}
