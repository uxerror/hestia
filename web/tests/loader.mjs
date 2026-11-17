// Node module hooks for the frontend tests.
//  - `*.svelte.js` files are compiled with the real Svelte compiler (runes -> plain JS),
//    exactly as vite-plugin-svelte does for the browser bundle.
//  - `?fresh=N` is propagated through every import under src/, so each test gets its own
//    copy of the whole module graph (separate singletons: player, auth, downloads, api cache).
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compileModule } from 'svelte/compiler';

let srcRoot = '';
let loaderURL = '';

export function initialize(data) {
  srcRoot = data.srcRoot;
  loaderURL = data.loaderURL;
}

const isSrc = (url) => url.startsWith('file:') && fileURLToPath(url.split('?')[0]).startsWith(srcRoot);
const freshOf = (url) => /[?&]fresh=(\d+)/.exec(url)?.[1];

export async function resolve(specifier, context, nextResolve) {
  let ctx = context;
  // Bare imports (svelte, esm-env...) from a src copy that has no node_modules next to it.
  if (!specifier.startsWith('.') && !specifier.startsWith('/') && !specifier.startsWith('file:') && !specifier.startsWith('node:') && context.parentURL && isSrc(context.parentURL)) {
    ctx = { ...context, parentURL: loaderURL };
  }
  const r = await nextResolve(specifier, ctx);
  const fresh = context.parentURL && freshOf(context.parentURL);
  if (fresh && isSrc(r.url) && !r.url.includes('?')) return { ...r, url: r.url + '?fresh=' + fresh };
  return r;
}

export async function load(url, context, nextLoad) {
  if (isSrc(url)) {
    const file = fileURLToPath(url.split('?')[0]);
    if (file.endsWith('.svelte.js')) {
      const out = compileModule(fs.readFileSync(file, 'utf8'), { filename: file, generate: 'client' });
      return { format: 'module', source: out.js.code, shortCircuit: true };
    }
    if (file.endsWith('.js')) {
      return { format: 'module', source: fs.readFileSync(file, 'utf8'), shortCircuit: true };
    }
  }
  return nextLoad(url, context);
}
