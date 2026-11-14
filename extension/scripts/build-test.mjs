// Writes a copy of dist/ that talks to another native host, so the real-extension test lane can
// register its own host (dev.phantab.bridge_test_<pid>) and never touch the owner's registration.
// Usage: npm run build:test -- --host <name> [--out <dir>]   (default out: dist-test)
// The copy keeps the manifest key, so its extension ID is the same as the real build's.
import { cpSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const DEFAULT = "const HOST = 'dev.phantab.bridge';";
const { values } = parseArgs({ options: { host: { type: 'string' }, out: { type: 'string', default: 'dist-test' } } });
const fail = message => { console.error(`build:test: ${message}`); process.exit(2); };

// Chrome's rule for native host names; anything else fails only later, as "host not found".
if (!values.host || !/^[a-z0-9_]+(\.[a-z0-9_]+)*$/.test(values.host)) fail('--host <name> is required: lowercase letters, digits, _ and dots, e.g. dev.phantab.bridge_test_1234.');
const worker = readFileSync('dist/background.js', 'utf8');
// Exactly one match, so a reworded constant breaks this build instead of shipping the owner's host name.
if (worker.split(DEFAULT).length !== 2) fail(`dist/background.js must contain exactly one ${DEFAULT}`);

rmSync(values.out, { recursive: true, force: true });
cpSync('dist', values.out, { recursive: true });
writeFileSync(`${values.out}/background.js`, worker.replace(DEFAULT, `const HOST = '${values.host}';`));
console.log(`build:test: ${values.out}/ talks to native host ${values.host}`);
