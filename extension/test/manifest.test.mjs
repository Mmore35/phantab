import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');
const manifest = JSON.parse(read('../manifest.json'));

// What a generic build never holds: a folder on the machine that built it (a drive path, a user's home
// in any of its generic forms) or an email address. A shipped file names no person and no machine.
const local = /(?<![\w-])[A-Za-z]:[\\/]|\\Users\\|\/Users\/|\/home\/|[\w.+-]+@[\w-]+\.[a-z]{2,}/i;

// Chrome's ID for an unpacked extension with a key: sha256 of the key's DER, first 32 hex digits mapped 0-f to a-p.
const idOf = key => [...createHash('sha256').update(Buffer.from(key, 'base64')).digest('hex').slice(0, 32)]
  .map(h => String.fromCharCode(97 + parseInt(h, 16))).join('');

test('extension-id.txt is the ID of the manifest key, on one line with nothing around it', () => {
  const id = read('../extension-id.txt');
  assert.match(id, /^[a-p]{32}$/);
  assert.equal(id, idOf(manifest.key));
});

test('the key is a public RSA-2048 SPKI key', () => {
  const key = createPublicKey({ key: Buffer.from(manifest.key, 'base64'), format: 'der', type: 'spki' });
  assert.equal(key.asymmetricKeyType, 'rsa');
  assert.equal(key.asymmetricKeyDetails.modulusLength, 2048);
});

test('the README states the same ID', () => {
  assert.ok(read('../README.md').includes(read('../extension-id.txt')));
});

test('the manifest keeps the bridge permissions and is generic', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.name, 'phantab bridge');
  assert.equal(manifest.minimum_chrome_version, '125');
  assert.deepEqual(manifest.permissions, ['debugger', 'tabs', 'nativeMessaging', 'alarms', 'storage', 'scripting']);
  assert.deepEqual(manifest.host_permissions, ['<all_urls>']);
  assert.deepEqual(manifest.background, { service_worker: 'background.js', type: 'module' });
  assert.equal(manifest.action.default_title, 'phantab bridge: no agent working');
  // Generic: every text Chrome shows speaks of phantab, and nothing in the manifest names a person or a
  // machine's folder. The one web address is the project's page.
  for (const text of [manifest.name, manifest.description, manifest.action.default_title]) {
    assert.match(text, /\bphantab\b/, text);
  }
  assert.doesNotMatch(JSON.stringify(manifest), local);
  assert.match(manifest.homepage_url, /^https:\/\/github\.com\/[\w.-]+\/phantab$/);
  const { homepage_url: _homepage, ...rest } = manifest;
  assert.doesNotMatch(JSON.stringify(rest), /\bhttps?:\/\//i);
});

test('the built folder is loadable: the worker and the manifest sit side by side', () => {
  assert.deepEqual(JSON.parse(read('../dist/manifest.json')), manifest);
  assert.match(read('../dist/background.js'), /'dev\.phantab\.bridge'/);
  assert.doesNotMatch(read('../dist/background.js'), local);
});

// THREAT-MODEL SR-18: no web page or other extension can reach the bridge. Pages get no content script
// or exposed resource, and nothing listens for external messages.
test('nothing outside the extension can message it', () => {
  for (const key of ['content_scripts', 'externally_connectable', 'web_accessible_resources']) {
    assert.equal(key in manifest, false, key);
  }
  const sources = ['background.ts', 'cdp-methods.ts'].map(f => read(`../src/${f}`)).join('\n');
  assert.doesNotMatch(sources, /onMessageExternal|onConnectExternal/);
});

// THREAT-MODEL SR-57: the shipped folder is first-party compiled code and the manifest, nothing else.
test('the built folder holds only our compiled files, importing only each other', () => {
  const files = readdirSync(new URL('../dist/', import.meta.url)).sort();
  assert.deepEqual(files, ['background.js', 'cdp-methods.js', 'manifest.json']);
  for (const js of files.filter(f => f.endsWith('.js'))) {
    const specifiers = [...read(`../dist/${js}`).matchAll(/\bimport\b[^'"]*['"]([^'"]+)['"]/g)].map(m => m[1]);
    for (const s of specifiers) assert.match(s, /^\.\/[a-z-]+\.js$/, `${js} imports ${s}`);
  }
  assert.equal(JSON.parse(read('../package.json')).dependencies, undefined, 'no runtime packages');
});

// THREAT-MODEL SR-20, L1: the relayed CDP methods are exact names, none of them banned. The service reads
// the same file (crates/phantab/src/cdp_methods.rs), one quoted name per line.
test('the CDP allow-list is exact names and bans the dangerous domains', () => {
  const source = read('../src/cdp-methods.ts');
  const quoted = [...source.matchAll(/'([^']*)'/g)].map(m => m[1]);
  const lines = source.split('\n').filter(l => l.includes("'"));
  assert.deepEqual(lines, quoted.map(m => `  '${m}',`), 'one quoted name per line, nothing else quoted');
  assert.ok(quoted.length > 0);
  for (const m of quoted) {
    assert.match(m, /^(DOM|Emulation|Input|Page|Runtime|Target)\.[a-z][A-Za-z]+$/, m);
    assert.doesNotMatch(m, /^(Network|Storage|Fetch|Browser|Security)\./, m);
    assert.ok(!['Target.createBrowserContext', 'Page.setDownloadBehavior', 'Target.createTarget', 'Target.closeTarget'].includes(m), m);
  }
  assert.deepEqual([...new Set(quoted)].sort(), quoted, 'sorted, no duplicates');
});
