// Does a minimized page keep full-rate timers past Chrome's 5-minute intensive throttling,
// with focus emulation vs without? Also prints power assertions the test Chrome holds.
import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { launch, sleep } from './cdp.mjs';

const MINUTES = Number(process.argv[2] || 6);
const PAGE = 'data:text/html,' + encodeURIComponent('<title>long</title><script>window.ticks=0;setInterval(()=>ticks++,100)</script>');
const chrome = await launch();
const { cdp, pid } = chrome;
const pages = [];
for (const focus of [false, true]) {
  const { targetId } = await cdp.send('Target.createTarget', { url: PAGE, newWindow: true, windowState: 'minimized' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
  if (focus) await cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true }, sessionId);
  pages.push({ focus, sessionId });
}
const ticks = async (p) => (await cdp.send('Runtime.evaluate', { expression: 'ticks', returnByValue: true }, p.sessionId)).result.value;
const assertions = () => execFileSync('pmset', ['-g', 'assertions'], { encoding: 'utf8' })
  .split('\n').filter((l) => l.includes(`pid ${pid}(`) || l.includes('Google Chrome')).join('\n') || '(none from test Chrome)';
console.log('power assertions:', assertions());
for (let m = 0; m <= MINUTES; m++) {
  const a = await Promise.all(pages.map(ticks));
  await sleep(10000);
  const b = await Promise.all(pages.map(ticks));
  console.log(JSON.stringify({ minute: m, perTenSeconds: pages.map((p, i) => ({ focus: p.focus, ticks: b[i] - a[i] })) }));
  if (m < MINUTES) await sleep(50000);
}
console.log('power assertions:', assertions());
await cdp.send('Browser.close').catch(() => {});
await sleep(1000);
rmSync(chrome.dir, { recursive: true, force: true });
