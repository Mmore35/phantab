import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startWorker, loadWorker, settle, EXTENSION_ID } from './fake-chrome.mjs';

const IDLE = { text: '', title: 'phantab bridge: no agent working' };

test('CDP events are forwarded with their tab and session', async () => {
  const fake = await startWorker();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.loadEventFired', { timestamp: 1 });
  fake.chrome.debugger.onEvent.fire({ tabId: 5, sessionId: 'S1' }, 'Page.domContentEventFired', { type: 'log' });
  assert.deepEqual(fake.posted(), [
    { event: 'cdp', tabId: 5, method: 'Page.loadEventFired', params: { timestamp: 1 } },
    { event: 'cdp', tabId: 5, sessionId: 'S1', method: 'Page.domContentEventFired', params: { type: 'log' } },
  ]);
});

test('screencast frames of a kept-rendering tab are acked, not forwarded', async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  await fake.op('keepRendering', { tabId: 5 });
  const before = fake.posted().length;
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.screencastFrame', { data: 'AAAA', sessionId: 42, metadata: {} });
  await settle();
  assert.equal(fake.posted().length, before);
  assert.deepEqual(fake.callsOf('debugger.sendCommand').at(-1), [{ tabId: 5 }, 'Page.screencastFrameAck', { sessionId: 42 }]);

  // Another tab's frames, or this one's after detach, belong to the service.
  fake.chrome.debugger.onEvent.fire({ tabId: 6 }, 'Page.screencastFrame', { sessionId: 1 });
  await fake.op('detach', { tabId: 5 });
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.screencastFrame', { sessionId: 43 });
  assert.deepEqual(fake.posted().filter(m => m.event === 'cdp').map(m => [m.tabId, m.params.sessionId]), [[6, 1], [5, 43]]);
  assert.equal(fake.callsOf('debugger.sendCommand').filter(c => c[1] === 'Page.screencastFrameAck').length, 1);
});

test('a failed ack is swallowed', async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  await fake.op('keepRendering', { tabId: 5 });
  fake.overrides['debugger.sendCommand'] = async () => { throw Error('Detached while handling command.'); };
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.screencastFrame', { sessionId: 1 });
  await settle();
});

test('the detach event comes 200 ms later and says whether the tab is still open', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }], start: false });
  await loadWorker();
  await fake.op('attach', { tabId: 5 });
  await fake.op('attach', { tabId: 6 });
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  fake.chrome.debugger.onDetach.fire({ tabId: 6 }, 'target_closed');
  t.mock.timers.tick(199);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event), []);
  t.mock.timers.tick(1);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event), [
    { event: 'detach', tabId: 5, reason: 'target_closed', tabOpen: true, foreign: null },
    { event: 'detach', tabId: 6, reason: 'target_closed', tabOpen: false, foreign: null },
  ]);
});

test('a detach names the foreign extension frame that navigated within 1 s before it', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }], start: false });
  await loadWorker();
  await fake.op('attach', { tabId: 5 });
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameStartedNavigating', { url: 'chrome-extension://otherext/menu.html?field=1#x' });
  t.mock.timers.tick(1000);
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  t.mock.timers.tick(200);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event === 'detach'), [
    { event: 'detach', tabId: 5, reason: 'target_closed', tabOpen: true, foreign: { id: 'otherext', url: 'chrome-extension://otherext/menu.html' } },
  ]);
});

test('a foreign navigation more than 1 s before the detach is not blamed, and is forgotten after it', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }], start: false });
  await loadWorker();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameRequestedNavigation', { url: 'chrome-extension://otherext/menu.html' });
  t.mock.timers.tick(1001);
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  t.mock.timers.tick(200);
  await settle();
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  t.mock.timers.tick(200);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event === 'detach').map(m => m.foreign), [null, null]);
});

test("the inserting script's stack names an extension whose frame URL hides its ID", async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }], start: false });
  await loadWorker();
  const on = (method, params) => fake.chrome.debugger.onEvent.fire({ tabId: 5 }, method, params);
  on('Page.frameAttached', { frameId: 'F', stack: { callFrames: [
    { url: 'https://site.test/app.js' },
    { url: `chrome-extension://${EXTENSION_ID}/own.js` },
    { url: 'chrome-extension://realid/content.js' },
  ] } });
  on('Page.frameStartedNavigating', { url: 'chrome-extension://dynamicuuid/menu.html' });
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  t.mock.timers.tick(200);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event === 'detach')[0].foreign, { id: 'realid', url: 'chrome-extension://dynamicuuid/menu.html' });
});

test('own frames, web frames and a frame that never navigated are not blamed', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }, { id: 6, windowId: 1 }], start: false });
  await loadWorker();
  const on = (tabId, method, params) => fake.chrome.debugger.onEvent.fire({ tabId }, method, params);
  on(5, 'Page.frameStartedNavigating', { url: `chrome-extension://${EXTENSION_ID}/viewer.html` });
  on(5, 'Page.frameStartedNavigating', { url: 'https://site.test/' });
  on(5, 'Page.frameStartedNavigating', {});
  on(5, 'Page.frameAttached', { frameId: 'F' });
  on(6, 'Page.frameAttached', { stack: { callFrames: [{ url: 'chrome-extension://realid/content.js' }] } });
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  fake.chrome.debugger.onDetach.fire({ tabId: 6 }, 'target_closed');
  t.mock.timers.tick(200);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event === 'detach').map(m => m.foreign), [null, null]);
});

test('attach and tab removal forget a recorded foreign frame', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }], start: false });
  await loadWorker();
  const nav = () => fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameStartedNavigating', { url: 'chrome-extension://otherext/menu.html' });
  const detach = async () => { fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed'); t.mock.timers.tick(200); await settle(); };
  nav();
  await fake.op('attach', { tabId: 5 });
  await detach();
  nav();
  fake.chrome.tabs.onRemoved.fire(5);
  await detach();
  assert.deepEqual(fake.posted().filter(m => m.event === 'detach').map(m => m.foreign), [null, null]);
});

test('a removed tab is reported', async () => {
  const fake = await startWorker();
  fake.chrome.tabs.onRemoved.fire(5, { windowId: 1, isWindowClosing: false });
  assert.deepEqual(fake.posted(), [{ event: 'removed', tabId: 5 }]);
});

test("the toolbar button detaches every agent and reports canceled_by_user", async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  await fake.op('keepRendering', { tabId: 5 });
  await fake.op('attach', { tabId: 6 });
  fake.chrome.action.onClicked.fire({ id: 1 });
  await settle(); // each tab's window is read first: one closing keeps its session for that close
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 5 }], [{ tabId: 6 }]]);
  assert.deepEqual(fake.posted().filter(m => m.event), [
    { event: 'detach', tabId: 5, reason: 'canceled_by_user' },
    { event: 'detach', tabId: 6, reason: 'canceled_by_user' },
  ]);
  assert.deepEqual(fake.badge(), IDLE);
  // Casting stopped with it: frames go to the service again.
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.screencastFrame', { sessionId: 1 });
  assert.equal(fake.posted().at(-1).method, 'Page.screencastFrame');
  // Nothing attached: a second click posts nothing.
  const count = fake.posted().length;
  fake.chrome.action.onClicked.fire({ id: 1 });
  assert.equal(fake.posted().length, count);
});

test('a fresh worker closes only the unshown agent windows an earlier worker left', async () => {
  const fake = await startWorker({
    windows: [{ id: 10 }, { id: 11 }, { id: 12 }],
    tabs: [{ id: 20, windowId: 10 }, { id: 21, windowId: 11 }, { id: 22, windowId: 12 }],
    session: { windows: { 10: false, 11: true } },
  });
  // Closed without its beforeunload (closeHiddenWindow); this worker attached nothing, so the tab is attached for it,
  // with the Page domain on so a fallback's dialog would be answered.
  assert.deepEqual(fake.callsOf('debugger.attach'), [[{ tabId: 20 }, '1.3']]);
  assert.deepEqual(fake.callsOf('debugger.sendCommand'), [[{ tabId: 20 }, 'Page.enable'], [{ tabId: 20 }, 'Target.closeTarget', { targetId: 'target-20' }]]);
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.deepEqual([...fake.state.windows.keys()], [11, 12]);
  assert.deepEqual(fake.state.session.windows, { 11: true });
  assert.deepEqual(fake.badge(), IDLE);
});

test('a dropped service link closes unshown agent windows and detaches every tab', async () => {
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }] });
  const hidden = (await fake.op('createWindow', { url: 'about:blank' })).result.windowId;
  const shown = (await fake.op('createWindow', { url: 'about:blank' })).result.windowId;
  await fake.op('markShown', { windowId: shown, shown: true });
  await fake.op('attach', { tabId: 5 });
  await fake.op('attach', { tabId: 6 });
  await fake.op('keepRendering', { tabId: 5 });
  fake.port.disconnect();
  await settle();
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 5 }], [{ tabId: 6 }]]);
  assert.equal(fake.callsOf('debugger.sendCommand').filter(([, method]) => method === 'Target.closeTarget').length, 1, 'the hidden tab closed');
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.equal(fake.state.windows.has(hidden), false);
  assert.equal(fake.state.windows.has(shown), true);
  assert.deepEqual(fake.state.session.windows, { [shown]: true });
  assert.deepEqual(fake.badge(), IDLE);
});

test('a dialog in a hidden agent window is answered at once and still reported; others are left for the owner', async () => {
  // A hidden window left from before is closed at start, so this one is made the way the service makes it.
  const fake = await startWorker({
    windows: [{ id: 1 }, { id: 3 }],
    tabs: [{ id: 6, windowId: 1 }, { id: 7, windowId: 3 }],
    session: { windows: { 3: true } },
  });
  const { result: { tabId: hidden } } = await fake.op('createWindow', { url: 'about:blank' });
  await fake.op('attach', { tabId: hidden });
  const answers = () => fake.callsOf('debugger.sendCommand').filter(c => c[1] === 'Page.handleJavaScriptDialog');
  for (const [type, accept] of [['beforeunload', true], ['alert', true], ['confirm', false], ['prompt', false]]) {
    fake.chrome.debugger.onEvent.fire({ tabId: hidden }, 'Page.javascriptDialogOpening', { type, message: 'm' });
    await settle();
    assert.deepEqual(answers().at(-1), [{ tabId: hidden }, 'Page.handleJavaScriptDialog', { accept }], type);
  }
  fake.chrome.debugger.onEvent.fire({ tabId: hidden, sessionId: 'S1' }, 'Page.javascriptDialogOpening', { type: 'alert' });
  await settle();
  assert.deepEqual(answers().at(-1)[0], { tabId: hidden, sessionId: 'S1' }, 'answered on the session that opened it');
  assert.equal(fake.posted().filter(m => m.method === 'Page.javascriptDialogOpening').length, 5, 'the service still hears of each');

  const before = answers().length;
  fake.chrome.debugger.onEvent.fire({ tabId: 6 }, 'Page.javascriptDialogOpening', { type: 'beforeunload' });
  fake.chrome.debugger.onEvent.fire({ tabId: 7 }, 'Page.javascriptDialogOpening', { type: 'beforeunload' });
  fake.chrome.debugger.onEvent.fire({ tabId: 99 }, 'Page.javascriptDialogOpening', { type: 'alert' });
  await settle();
  assert.equal(answers().length, before, "the owner's window, a shown agent window and a gone tab are left alone");
});

test("the agent's answer for a hidden tab's next dialog is used once; other tabs refuse one", async () => {
  const fake = await startWorker({ windows: [{ id: 1 }], tabs: [{ id: 6, windowId: 1 }] });
  const { result: { tabId: hidden, windowId } } = await fake.op('createWindow', { url: 'about:blank' });
  await fake.op('attach', { tabId: hidden });
  const answers = () => fake.callsOf('debugger.sendCommand').filter(c => c[1] === 'Page.handleJavaScriptDialog').map(c => c[2]);
  const open = async type => { fake.chrome.debugger.onEvent.fire({ tabId: hidden }, 'Page.javascriptDialogOpening', { type, message: 'm' }); await settle(); };
  assert.deepEqual((await fake.op('answerNextDialog', { tabId: hidden, accept: true, promptText: 'Ada' })).result, {});
  await open('prompt');
  await open('prompt');
  assert.deepEqual(answers(), [{ accept: true, promptText: 'Ada' }, { accept: false }], 'once, then the usual answer');
  await fake.op('answerNextDialog', { tabId: hidden, accept: true });
  await fake.op('markShown', { windowId, shown: true });
  await fake.op('markShown', { windowId, shown: false });
  await open('confirm');
  assert.deepEqual(answers().at(-1), { accept: false }, 'showing the window drops the answer');
  const refused = await fake.op('answerNextDialog', { tabId: 6, accept: true });
  assert.match(refused.error, /not in a hidden agent window; its dialogs are the owner's to answer/);
});

test('hiding and showing a window changes whether its dialogs are answered, with one storage read', async () => {
  const fake = await startWorker();
  const { result: { windowId, tabId } } = await fake.op('createWindow', { url: 'about:blank' });
  await fake.op('attach', { tabId });
  const answered = async () => {
    const before = fake.callsOf('debugger.sendCommand').length;
    fake.chrome.debugger.onEvent.fire({ tabId }, 'Page.javascriptDialogOpening', { type: 'beforeunload' });
    await settle(20);
    return fake.callsOf('debugger.sendCommand').length > before;
  };
  assert.equal(await answered(), true, 'a new agent window is hidden');
  await fake.op('markShown', { windowId, shown: true });
  assert.equal(await answered(), false, 'shown to the owner, its dialogs are his');
  await fake.op('markShown', { windowId, shown: false });
  assert.equal(await answered(), true);
  assert.equal(fake.callsOf('storage.session.get').length, 1, 'later reads come from memory');
});

// perf-data-3: the welcome names the events the service reads (phantab_cdp::EVENTS); only those cross.
const READ = ['Page.frameNavigated', 'Page.javascriptDialogOpening', 'Runtime.executionContextCreated'];

test('after a welcome with events, only those are forwarded', async () => {
  const fake = await startWorker();
  fake.port.receive({ welcome: true, events: READ });
  await settle();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.domContentEventFired', { type: 'log' });
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.windowOpen', {});
  fake.chrome.debugger.onEvent.fire({ tabId: 5, sessionId: 'S1' }, 'Runtime.executionContextCreated', { context: { id: 1 } });
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.loadEventFired', {});
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameNavigated', { frame: { id: 'F' } });
  assert.deepEqual(fake.posted(), [
    { event: 'cdp', tabId: 5, sessionId: 'S1', method: 'Runtime.executionContextCreated', params: { context: { id: 1 } } },
    { event: 'cdp', tabId: 5, method: 'Page.frameNavigated', params: { frame: { id: 'F' } } },
  ]);
});

test('a welcome without a usable events list forwards every event', async () => {
  for (const welcome of [{ welcome: true }, { welcome: true, events: 'Page.frameNavigated' }, { welcome: true, events: [] },
    { welcome: true, events: ['Page.frameNavigated', 7] }, { welcome: true, events: null }]) {
    const fake = await startWorker();
    fake.port.receive(welcome);
    await settle();
    fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.domContentEventFired', { type: 'log' });
    assert.deepEqual(fake.posted().map(m => m.method), ['Page.domContentEventFired'], JSON.stringify(welcome));
  }
});

test('the extension\'s own event handling does not depend on the list', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 10000 });
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }], start: false });
  await loadWorker();
  fake.port.receive({ welcome: true, events: ['Page.frameNavigated'] });
  await settle();
  // A kept-rendering tab's screencast frames are still acked.
  await fake.op('attach', { tabId: 5 });
  await fake.op('keepRendering', { tabId: 5 });
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.screencastFrame', { data: 'AAAA', sessionId: 42, metadata: {} });
  await settle();
  assert.deepEqual(fake.callsOf('debugger.sendCommand').at(-1), [{ tabId: 5 }, 'Page.screencastFrameAck', { sessionId: 42 }]);
  // A foreign extension frame, unlisted, is still seen and named on the detach.
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameStartedNavigating', { url: 'chrome-extension://otherext/menu.html' });
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  t.mock.timers.tick(200);
  await settle();
  assert.deepEqual(fake.posted().filter(m => m.event), [
    { event: 'detach', tabId: 5, reason: 'target_closed', tabOpen: true, foreign: { id: 'otherext', url: 'chrome-extension://otherext/menu.html' } },
  ]);
});

test('a hidden window\'s dialog is answered whether or not the list names it', async () => {
  const fake = await startWorker();
  fake.port.receive({ welcome: true, events: ['Page.frameNavigated'] });
  await settle();
  const { result: { tabId } } = await fake.op('createWindow', { url: 'about:blank' });
  await fake.op('attach', { tabId });
  fake.chrome.debugger.onEvent.fire({ tabId }, 'Page.javascriptDialogOpening', { type: 'alert', message: 'm' });
  await settle(20);
  assert.deepEqual(fake.callsOf('debugger.sendCommand').at(-1), [{ tabId }, 'Page.handleJavaScriptDialog', { accept: true }]);
  assert.deepEqual(fake.posted().filter(m => m.event === 'cdp'), []);
});

test('a reconnect forwards every event until the new welcome, and an old port\'s welcome is ignored', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ start: false });
  await loadWorker();
  const old = fake.port;
  old.receive({ welcome: true, events: READ });
  await settle();
  old.disconnect();
  await settle();
  t.mock.timers.tick(1000);
  assert.equal(fake.ports.length, 2);
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.domContentEventFired', {});
  old.receive({ welcome: true, events: READ });
  await settle();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.windowOpen', {});
  fake.port.receive({ welcome: true, events: READ });
  await settle();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.domContentEventFired', {});
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameNavigated', {});
  assert.deepEqual(fake.posted().map(m => m.method), ['Page.domContentEventFired', 'Page.windowOpen', 'Page.frameNavigated']);
});

test('a fast retry after a stable link forwards every event until its own welcome', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ start: false });
  await loadWorker();
  fake.port.receive({ welcome: true, events: READ });
  await settle();
  t.mock.timers.tick(10000);
  fake.port.disconnect();
  await settle();
  t.mock.timers.tick(100);
  assert.equal(fake.ports.length, 2, 'the stable link is retried after 100 ms');
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.domContentEventFired', {});
  fake.port.receive({ welcome: true, events: READ });
  await settle();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.windowOpen', {});
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameNavigated', {});
  assert.deepEqual(fake.posted().map(m => m.method), ['Page.domContentEventFired', 'Page.frameNavigated']);
});

test('only a port\'s first welcome sets the list: a later one, even one without events, changes nothing', async () => {
  const fake = await startWorker();
  fake.port.receive({ welcome: true, events: ['Page.frameNavigated'] });
  fake.port.receive({ welcome: true });
  fake.port.receive({ welcome: true, events: ['Page.domContentEventFired'] });
  await settle();
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.domContentEventFired', {});
  fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameNavigated', {});
  assert.deepEqual(fake.posted().map(m => m.method), ['Page.frameNavigated']);
});

// THREAT-MODEL SR-90: a developer-tools event crosses only for a tab the service is recording, on that
// tab's own target, on a connection whose welcome declared devTools; an ...ExtraInfo event never does.
const CONSOLE = ['Runtime.consoleAPICalled', 'Runtime.exceptionThrown', 'Log.entryAdded'];
const NETWORK = ['Network.requestWillBeSent', 'Network.responseReceived', 'Network.loadingFinished', 'Network.loadingFailed'];
const EXTRA = ['Network.requestWillBeSentExtraInfo', 'Network.responseReceivedExtraInfo', 'Network.anythingExtraInfo'];
const fireAll = (fake, source, methods) => { for (const m of methods) fake.chrome.debugger.onEvent.fire(source, m, { m }); };
const cdpPosted = fake => fake.posted().filter(m => m.event === 'cdp').map(m => m.sessionId ? `${m.tabId}/${m.sessionId} ${m.method}` : `${m.tabId} ${m.method}`);

test('developer-tools events cross only for a recording tab, on its own target, and never an ExtraInfo one', async () => {
  const fake = await startWorker();
  fake.port.receive({ welcome: true, events: ['Page.frameNavigated'], devTools: true });
  await settle();
  await fake.op('attach', { tabId: 5 });
  await fake.op('attach', { tabId: 6 });
  // Not recording yet: nothing crosses.
  fireAll(fake, { tabId: 5 }, [...CONSOLE, ...NETWORK, ...EXTRA]);
  assert.deepEqual(cdpPosted(fake), []);
  // The console recording, started on tab 5's own target, lets only its console events through.
  await fake.op('send', { tabId: 5, method: 'Log.enable' });
  fireAll(fake, { tabId: 5 }, [...CONSOLE, ...NETWORK, ...EXTRA]);
  fireAll(fake, { tabId: 5, sessionId: 'S1' }, CONSOLE);
  fireAll(fake, { tabId: 6 }, CONSOLE);
  assert.deepEqual(cdpPosted(fake), CONSOLE.map(m => `5 ${m}`));
  // A recording started on a child session marks nothing.
  await fake.op('send', { tabId: 6, sessionId: 'S2', method: 'Network.enable' });
  fireAll(fake, { tabId: 6 }, NETWORK);
  assert.equal(cdpPosted(fake).length, CONSOLE.length);
  // The network recording adds the network's, still never an ExtraInfo one.
  await fake.op('send', { tabId: 5, method: 'Network.enable', params: { maxPostDataSize: 0 } });
  fireAll(fake, { tabId: 5 }, [...NETWORK, ...EXTRA]);
  assert.deepEqual(cdpPosted(fake).slice(CONSOLE.length), NETWORK.map(m => `5 ${m}`));
});

test('an ExtraInfo event is dropped whatever the welcome lists, and with no welcome at all', async () => {
  for (const welcome of [null, { welcome: true }, { welcome: true, events: [...EXTRA, 'Page.frameNavigated'], devTools: true }]) {
    const fake = await startWorker();
    if (welcome) fake.port.receive(welcome);
    await settle();
    fireAll(fake, { tabId: 5 }, EXTRA);
    fireAll(fake, { tabId: 5, sessionId: 'S1' }, EXTRA);
    fake.chrome.debugger.onEvent.fire({ tabId: 5 }, 'Page.frameNavigated', {});
    assert.deepEqual(cdpPosted(fake), ['5 Page.frameNavigated'], JSON.stringify(welcome));
  }
});

test('without devTools, developer-tools events are dropped even with no list', async () => {
  for (const welcome of [null, { welcome: true }, { welcome: true, events: CONSOLE }]) {
    const fake = await startWorker();
    if (welcome) fake.port.receive(welcome);
    await settle();
    await fake.op('attach', { tabId: 5 });
    await fake.op('send', { tabId: 5, method: 'Log.enable' }); // refused: not declared
    fireAll(fake, { tabId: 5 }, [...CONSOLE, ...NETWORK]);
    assert.deepEqual(cdpPosted(fake), [], JSON.stringify(welcome));
  }
});

test('a recording ends with a failed start, a detach, a removed tab, the toolbar button and a new connection', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ start: false });
  await loadWorker();
  const declare = async () => { fake.port.receive({ welcome: true, devTools: true }); await settle(); };
  const record = async tabId => { await fake.op('attach', { tabId }); await fake.op('send', { tabId, method: 'Log.enable' }); };
  const crosses = tabId => {
    const before = cdpPosted(fake).length;
    fake.chrome.debugger.onEvent.fire({ tabId }, 'Runtime.consoleAPICalled', {});
    return cdpPosted(fake).length > before;
  };
  await declare();
  fake.overrides['debugger.sendCommand'] = async () => { throw Error('Log.enable failed'); };
  await record(5);
  delete fake.overrides['debugger.sendCommand'];
  assert.equal(crosses(5), false, 'a failed start');
  await record(5);
  assert.equal(crosses(5), true);
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  assert.equal(crosses(5), false, 'a detach');
  await record(5);
  fake.chrome.tabs.onRemoved.fire(5, { windowId: 1, isWindowClosing: false });
  assert.equal(crosses(5), false, 'a removed tab');
  await record(6);
  fake.chrome.action.onClicked.fire({ id: 1 });
  await settle();
  assert.equal(crosses(6), false, 'the toolbar button');
  await record(7);
  await fake.op('detach', { tabId: 7 });
  await fake.op('attach', { tabId: 7 });
  assert.equal(crosses(7), false, 'a detach op and a new attach');
  await record(8);
  fake.port.disconnect();
  await settle();
  t.mock.timers.tick(1000);
  await declare();
  await fake.op('attach', { tabId: 8 });
  assert.equal(crosses(8), false, 'a new connection');
});
