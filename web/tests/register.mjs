// Registers the module hooks that let node:test import the app's real source files.
import { register } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
// HESTIA_WEB_SRC points the suite at another copy of src/ (e.g. a pre-fix snapshot).
const srcRoot = path.resolve(process.env.HESTIA_WEB_SRC || path.join(here, '..', 'src'));
register('./loader.mjs', { parentURL: import.meta.url, data: { srcRoot, loaderURL: import.meta.url } });
