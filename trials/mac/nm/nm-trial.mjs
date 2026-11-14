// Native messaging trial: branded Chrome on a throwaway profile, extension loaded through
// CDP Extensions.loadUnpacked (branded Chrome 137+ ignores --load-extension), host manifest in
// <user-data-dir>/NativeMessagingHosts. Pipe transport: fd 3 = to Chrome, fd 4 = from Chrome.
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHROME, sleep } from '../cdp.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const LOG = '/tmp/phantab-mac/nm-host.log';
rmSync(LOG, { force: true });
const dir = mkdtempSync(join(tmpdir(), 'phantab-nm-'));
const proc = spawn(CHROME, [`--user-data-dir=${dir}`, '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
  '--no-first-run', '--no-default-browser-check', 'about:blank'], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
let id = 0, buf = '';
const pending = new Map();
proc.stdio[4].on('data', (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\0')) >= 0) {
    const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); }
  }
});
const send = (method, params = {}, sessionId) => new Promise((res, rej) => {
  const msg = { id: ++id, method, params, ...(sessionId ? { sessionId } : {}) };
  pending.set(msg.id, { res, rej });
  proc.stdio[3].write(JSON.stringify(msg) + '\0');
});
const out = {};
try {
  const { id: extId } = await send('Extensions.loadUnpacked', { path: join(here, 'extension') });
  out.extensionId = extId;
  const nmDir = join(dir, 'NativeMessagingHosts');
  mkdirSync(nmDir, { recursive: true });
  writeFileSync(join(nmDir, 'dev.phantab.trial.json'), JSON.stringify({
    name: 'dev.phantab.trial', description: 'trial', path: process.env.NM_HOST || join(here, 'host.sh'), type: 'stdio',
    allowed_origins: [`chrome-extension://${extId}/`],
  }));
  let sw;
  for (let i = 0; i < 50 && !sw; i++) {
    sw = (await send('Target.getTargets')).targetInfos.find((t) => t.type === 'service_worker' && t.url.includes(extId));
    if (!sw) await sleep(200);
  }
  const { sessionId } = await send('Target.attachToTarget', { targetId: sw.targetId, flatten: true });
  const ping = async (name) => (await send('Runtime.evaluate', { expression: `ping(${JSON.stringify(name)})`, awaitPromise: true, returnByValue: true }, sessionId)).result.value;
  out.trialHost = await ping('dev.phantab.trial');
  await sleep(500);
  out.hostLog = existsSync(LOG) ? readFileSync(LOG, 'utf8') : '(host never ran)';
  // Is the default-profile directory read too? A host that exists there but does not allow this
  // origin answers "forbidden" (found, not launched); one Chrome cannot see answers "not found".
  // Name a host installed in the default profile's directory on this machine as the first argument.
  out.defaultDirHost = process.argv[2] ? await ping(process.argv[2]) : '(no host named)';
  out.missingHost = await ping('dev.phantab.does_not_exist');
} finally {
  await send('Browser.close').catch(() => {});
  await sleep(1000);
  proc.kill();
  for (const f of ['Preferences', 'Secure Preferences']) {
    const pf = join(dir, 'Default', f);
    if (!existsSync(pf)) { out[f] = 'absent'; continue; }
    const j = JSON.parse(readFileSync(pf, 'utf8'));
    const st = j.extensions?.settings?.[out.extensionId];
    out[f] = st ? { hasExtension: true, path: st.path, location: st.location } : { hasExtension: false };
  }
  rmSync(dir, { recursive: true, force: true });
}
console.log(JSON.stringify(out, null, 2));
