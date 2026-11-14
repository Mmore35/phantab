// What the user sees, for an UNLOCKED session (the trial ran with the screen locked, so this was
// not observed). Takes screenshots to /tmp/phantab-mac/observe: needs Screen Recording for the
// app running it, and briefly opens Mission Control on the user's screen.
// Usage: node --experimental-websocket observe.mjs
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { launch, sleep } from './cdp.mjs';

const HELPER = process.env.MACHELPER || '/tmp/phantab-mac/bin/machelper';
const helper = (...a) => execFileSync(HELPER, a, { encoding: 'utf8' }).trim();
const OUT = '/tmp/phantab-mac/observe';
if (helper('locked') === '1') { console.log('screen is locked: nothing to observe'); process.exit(1); }
mkdirSync(OUT, { recursive: true });
const shot = (name) => execFileSync('screencapture', ['-x', `${OUT}/${name}.png`]);
const missionControl = async (name) => {
  execFileSync('open', ['-b', 'com.apple.exposelauncher']); await sleep(1500); shot(name);
  execFileSync('open', ['-b', 'com.apple.exposelauncher']); await sleep(1000);
};
const chrome = await launch();
const { cdp } = chrome;
const PAGE = 'data:text/html,<title>PHANTAB-OBSERVE</title><h1>agent window</h1>';
const report = {};
try {
  for (const [name, create, after] of [
    ['create-minimized', { windowState: 'minimized' }, null],
    ['minimized-later', {}, { windowState: 'minimized' }],
    ['offscreen', {}, { left: -10000, top: 10000, width: 1280, height: 900 }],
  ]) {
    const front = helper('front');
    const { targetId } = await cdp.send('Target.createTarget', { url: PAGE, newWindow: true, ...create });
    await sleep(300);
    const frontAfterCreate = helper('front');
    const { windowId } = await cdp.send('Browser.getWindowForTarget', { targetId });
    if (after) await cdp.send('Browser.setWindowBounds', { windowId, bounds: after });
    await sleep(1500);
    shot(`${name}-desktop`);
    await missionControl(`${name}-mission-control`);
    report[name] = { front, frontAfterCreate, stoleFocus: front !== frontAfterCreate, chromePid: chrome.pid };
    await cdp.send('Target.closeTarget', { targetId });
  }
} finally {
  await cdp.send('Browser.close').catch(() => {});
  await sleep(1000);
  rmSync(chrome.dir, { recursive: true, force: true });
}
console.log(JSON.stringify(report, null, 2), `\nscreenshots in ${OUT}`);
