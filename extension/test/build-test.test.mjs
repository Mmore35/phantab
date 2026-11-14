import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startWorker } from './fake-chrome.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const buildTest = (...args) => spawnSync(process.execPath, ['scripts/build-test.mjs', ...args], { cwd: root, encoding: 'utf8' });

test('the default build talks to dev.phantab.bridge', async () => {
  assert.match(readFileSync(join(root, 'dist/background.js'), 'utf8'), /^const HOST = 'dev\.phantab\.bridge';$/m);
  const fake = await startWorker();
  assert.deepEqual(fake.callsOf('runtime.connectNative'), [['dev.phantab.bridge']]);
});

test('build:test writes a copy that talks to the test host, and leaves dist alone', async t => {
  const out = mkdtempSync(join(tmpdir(), 'phantab-ext-'));
  t.after(() => rmSync(out, { recursive: true, force: true }));
  const host = `dev.phantab.bridge_test_${process.pid}`;
  const run = buildTest('--host', host, '--out', out);
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8')), JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')));
  const worker = readFileSync(join(out, 'background.js'), 'utf8');
  assert.ok(worker.includes(`const HOST = '${host}';`));
  assert.ok(!worker.includes("'dev.phantab.bridge'"));
  assert.match(readFileSync(join(root, 'dist/background.js'), 'utf8'), /^const HOST = 'dev\.phantab\.bridge';$/m);
  const fake = await startWorker({ worker: pathToFileURL(join(out, 'background.js')).href });
  assert.deepEqual(fake.callsOf('runtime.connectNative'), [[host]]);
});

test('build:test refuses a missing or invalid host name', () => {
  for (const args of [[], ['--host', 'Dev.Phantab'], ['--host', 'dev..phantab'], ['--host', "x';alert(1);'"]]) {
    const run = buildTest(...args, '--out', join(tmpdir(), 'phantab-ext-never'));
    assert.equal(run.status, 2, `${args.join(' ')}: ${run.stderr}`);
    assert.match(run.stderr, /--host <name> is required/);
  }
});
