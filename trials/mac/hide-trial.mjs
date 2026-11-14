// Mac feasibility trial: for each hiding method x keepalive variant, does the page keep rendering,
// is the window visible, and does showing restore it intact? Prints one JSON object per run.
// Usage: node --experimental-websocket hide-trial.mjs [method...]   (cgwin helper in $CGWIN)
import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { launch, sleep, pngInfo } from './cdp.mjs';

const CGWIN = process.env.CGWIN || '/tmp/phantab-mac/bin/cgwin';
const HELPER = process.env.MACHELPER || '/tmp/phantab-mac/bin/machelper';
const helper = (...a) => execFileSync(HELPER, a.map(String), { encoding: 'utf8' }).trim();
const PAGE = 'data:text/html,' + encodeURIComponent(`<title>PHANTAB-TRIAL</title>
<body style="margin:0;font:32px sans-serif"><div style="height:200px"></div><input id=i style="font-size:32px">
<div id=s></div><script>
window.ticks=0;window.rafs=0;setInterval(()=>ticks++,100);(function f(){rafs++;requestAnimationFrame(f)})();
setInterval(()=>{s.textContent='ticks '+ticks+' rafs '+rafs+' '+document.visibilityState},100);
</script>`);

// Each method: hide(win) and show(win). win = {cdp, windowId, targetId}.
const setB = (w, bounds) => w.cdp.send('Browser.setWindowBounds', { windowId: w.windowId, bounds });
const waitState = async (w, state) => {
  for (let i = 0; i < 40; i++) {
    if ((await w.cdp.send('Browser.getWindowBounds', { windowId: w.windowId })).bounds.windowState === state) return;
    await sleep(100);
  }
};
const onScreen = async (w) => { await setB(w, { windowState: 'normal' }); await waitState(w, 'normal'); await setB(w, { left: 0, top: 30, width: 1280, height: 900 }); };
const maximize = async (w) => { await setB(w, { windowState: 'maximized' }); await waitState(w, 'maximized'); };
const METHODS = {
  visible: { hide: async () => {}, show: maximize },
  minimized: { hide: (w) => setB(w, { windowState: 'minimized' }), show: async (w) => { await onScreen(w); await maximize(w); } },
  'create-minimized': { create: { windowState: 'minimized' }, hide: async () => {}, show: async (w) => { await onScreen(w); await maximize(w); } },
  offscreen: { hide: (w) => setB(w, { left: -10000, top: 10000, width: 1280, height: 900 }), show: async (w) => { await onScreen(w); await maximize(w); } },
  'offscreen-far-right': { hide: (w) => setB(w, { left: 20000, top: 20000, width: 1280, height: 900 }), show: async (w) => { await onScreen(w); await maximize(w); } },
  'create-offscreen': { create: { left: -10000, top: 10000, width: 1280, height: 900 }, hide: async () => {}, show: async (w) => { await onScreen(w); await maximize(w); } },
  tiny: { hide: (w) => setB(w, { left: 0, top: 30, width: 1, height: 1 }), show: async (w) => { await onScreen(w); await maximize(w); } },
  'sls-alpha0': { hide: (w) => { w.slsResult = helper('sls-alpha', w.cgId, 0); }, show: async (w) => { helper('sls-alpha', w.cgId, 1); await maximize(w); } },
  'sls-order-out': { hide: (w) => { w.slsResult = helper('sls-order-out', w.cgId); }, show: maximize },
};
const VARIANTS = { none: [false, false], focus: [false, true], cast: [true, false], 'cast+focus': [true, true] };

const cgwin = (pid) => execFileSync(CGWIN, [String(pid)], { encoding: 'utf8' }).trim().split('\n')
  .filter(Boolean).map((l) => JSON.parse(l)).filter((w) => w.layer === 0 && w.w > 0);

async function run(chrome, method, variant) {
  const { cdp, pid } = chrome;
  const [cast, focus] = VARIANTS[variant];
  const before = new Set(cgwin(pid).map((x) => x.id));
  const frontBefore = helper('front');
  const { targetId } = await cdp.send('Target.createTarget', { url: PAGE, newWindow: true, ...(METHODS[method].create || {}) });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const s = (m, p, t) => cdp.send(m, p, sessionId, t);
  const { windowId } = await cdp.send('Browser.getWindowForTarget', { targetId });
  const w = { cdp, windowId, targetId };
  await s('Page.enable');
  await s('Runtime.enable');
  await sleep(500);
  const created = (await cdp.send('Browser.getWindowBounds', { windowId })).bounds;
  const mine = cgwin(pid).filter((x) => !before.has(x.id) && x.w > 100);
  w.cgId = mine[0]?.id;
  const r0 = { created, frontAfterCreate: helper('front'), frontBefore };
  // Before hiding: red. While hidden: green. The screenshot must come back green.
  await s('Runtime.evaluate', { expression: "document.documentElement.style.background='rgb(255,0,0)'" });
  await s('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  if (focus) await s('Emulation.setFocusEmulationEnabled', { enabled: true });
  let frames = 0;
  const off = cdp.on((m) => {
    if (m.method === 'Page.screencastFrame' && m.sessionId === sessionId) {
      frames++;
      s('Page.screencastFrameAck', { sessionId: m.params.sessionId }).catch(() => {});
    }
  });
  if (cast) await s('Page.startScreencast', { format: 'jpeg', quality: 1, maxWidth: 16, maxHeight: 16, everyNthFrame: 60 });
  const r = { method, variant, ...r0 };
  try {
    await METHODS[method].hide(w);
  } catch (e) { r.hideError = e.message; }
  await sleep(3000);
  r.cdpBounds = (await cdp.send('Browser.getWindowBounds', { windowId })).bounds;
  r.slsResult = w.slsResult;
  r.osWindows = cgwin(pid).filter((x) => !before.has(x.id) && x.w > 100).map(({ id, onscreen, x, y, w: ww, h, alpha }) => ({ id, onscreen, x, y, w: ww, h, alpha, isNew: !before.has(id) }));
  const ev = async (e) => (await s('Runtime.evaluate', { expression: e, returnByValue: true })).result.value;
  const t0 = await ev('({t:ticks,r:rafs,v:document.visibilityState,f:document.hasFocus()})');
  // Type while hidden, then change the page, then screenshot: the image must show the change.
  await s('Runtime.evaluate', { expression: 'i.focus()' });
  await s('Input.insertText', { text: 'typed-while-hidden' });
  await ev("document.documentElement.style.background='rgb(0,255,0)';1");
  await sleep(3000);
  const t1 = await ev('({t:ticks,r:rafs,v:document.visibilityState,f:document.hasFocus()})');
  r.timersPer3s = t1.t - t0.t; r.rafPer3s = t1.r - t0.r; r.visibility = t1.v; r.hasFocus = t1.f;
  const st = Date.now();
  try {
    const shot = await s('Page.captureScreenshot', { format: 'png' }, 8000);
    const info = pngInfo(shot.data);
    r.shot = { ms: Date.now() - st, w: info.width, h: info.height, current: info.rgb[1] > 150 && info.rgb[0] < 120, rgb: info.rgb };
  } catch (e) { r.shot = { error: e.message, ms: Date.now() - st }; }
  r.castFrames = frames;
  if (cast) await s('Page.stopScreencast').catch(() => {});
  off();
  // Show: the user takes over. Overrides off, window restored and maximized.
  await s('Emulation.setFocusEmulationEnabled', { enabled: false });
  await s('Emulation.clearDeviceMetricsOverride');
  try { await METHODS[method].show(w); } catch (e) { r.showError = e.message; }
  await cdp.send('Target.activateTarget', { targetId });
  r.activate = helper('activate', pid);
  await sleep(1500);
  r.shown = {
    cdp: (await cdp.send('Browser.getWindowBounds', { windowId })).bounds,
    os: cgwin(pid).filter((x) => !before.has(x.id) && x.w > 100).map(({ onscreen, x, y, w: ww, h }) => ({ onscreen, x, y, w: ww, h })),
    input: await ev('i.value'),
    vis: await ev('document.visibilityState'),
    front: helper('front'),
  };
  await cdp.send('Target.closeTarget', { targetId });
  await sleep(300);
  return r;
}

const chrome = await launch();
const methods = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(METHODS);
try {
  for (const m of methods) for (const v of Object.keys(VARIANTS)) {
    try { console.log(JSON.stringify(await run(chrome, m, v))); } catch (e) { console.log(JSON.stringify({ method: m, variant: v, error: e.message })); }
  }
} finally {
  await chrome.cdp.send('Browser.close').catch(() => {});
  await sleep(1000);
  rmSync(chrome.dir, { recursive: true, force: true });
}
