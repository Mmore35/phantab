import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startWorker, settle } from './fake-chrome.mjs';

// Sends op and advances the mocked clock in small steps until the reply arrives.
async function opWithClock(t, fake, op, args, { step = 10, limit = 5000 } = {}) {
  const port = fake.port, from = port.sent.length, id = ++fake.seq;
  port.receive({ id, op, args });
  for (let elapsed = 0; ; elapsed += step) {
    await settle();
    const reply = port.sent.slice(from).find(m => m.id === id);
    if (reply) return { reply, elapsed };
    if (elapsed >= limit) throw Error(`no reply to ${op} in ${limit} ms`);
    t.mock.timers.tick(step);
  }
}

// Every worker reads the one global chrome, so a keepMinimized watch still running from an earlier test
// would act on the next test's windows. Each test that makes a minimized window mocks the clock, which
// ends such a watch with the test.
async function minimizedAgentWindow(t) {
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }] });
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { result } = await fake.op('createWindow', { url: 'about:blank', left: 0, top: 0, width: 1280, height: 900, state: 'minimized' });
  fake.calls.length = 0;
  return { fake, ...result };
}

test('createWindow with state minimized creates the window inactive, without the bounds Chrome refuses with minimized, then minimizes it', async t => {
  const fake = await startWorker();
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 }); // the 2 s keepMinimized watch must not outlive the test
  const reply = await fake.op('createWindow', { url: 'about:blank', left: 10, top: 20, width: 800, height: 600, state: 'minimized' }, 1);
  assert.deepEqual(fake.callsOf('windows.create'), [[{ url: 'about:blank', focused: false }]]);
  const [w] = [...fake.state.windows.values()];
  const [tab] = [...fake.state.tabs.values()];
  assert.deepEqual(fake.callsOf('windows.update'), [[w.id, { state: 'minimized' }]]);
  assert.deepEqual(reply, { id: 1, result: { windowId: w.id, tabId: tab.id } });
  assert.equal(w.state, 'minimized');
  assert.equal(w.focused, false);
  assert.deepEqual(fake.state.session.windows, { [w.id]: false });
});

test('createWindow answers only once the window reads minimized (macOS animates it)', async t => {
  const fake = await startWorker();
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  fake.state.stateLag = { minimized: 300 };
  const { reply, elapsed } = await opWithClock(t, fake, 'createWindow', { url: 'about:blank', state: 'minimized' });
  assert.ok(reply.result.windowId !== undefined);
  assert.equal(fake.state.windows.get(reply.result.windowId).state, 'minimized');
  assert.ok(elapsed >= 300 && elapsed <= 400, `answered after ${elapsed} ms`);
});

test('createWindow takes no other state', async () => {
  const fake = await startWorker();
  assert.deepEqual(await fake.op('createWindow', { url: 'about:blank', state: 'maximized' }, 1), { id: 1, error: `createWindow takes no state "maximized"; only 'minimized'.` });
  assert.deepEqual(fake.callsOf('windows.create'), []);
});

test("maximized from minimized restores to normal, waits for it, then maximizes with focus", async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.stateLag = { normal: 120 };
  const { reply, elapsed } = await opWithClock(t, fake, 'windowState', { windowId, state: 'maximized' });
  // The fake throws like Chrome on maximize from minimized, so a result proves the wait.
  assert.deepEqual(reply.result, { state: 'maximized' });
  assert.ok(elapsed >= 120 && elapsed <= 200, `waited ${elapsed} ms`);
  const updates = fake.callsOf('windows.update');
  assert.deepEqual(updates, [[windowId, { state: 'normal' }], [windowId, { state: 'maximized', focused: true }]]);
  // Polled every 50 ms: the first read, then 50, 100, 150.
  assert.ok(fake.callsOf('windows.get').length >= 4);
  assert.deepEqual(fake.state.session.windows, { [windowId]: false }, 'shown-tracking stays with markShown');
});

test('maximized from normal maximizes at once', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.windows.get(windowId).state = 'normal';
  const { reply } = await opWithClock(t, fake, 'windowState', { windowId, state: 'maximized' });
  assert.deepEqual(reply.result, { state: 'maximized' });
  assert.deepEqual(fake.callsOf('windows.update'), [[windowId, { state: 'maximized', focused: true }]]);
});

test('a restore that never lands gives up after 2 s and leaves the refusal to Chrome', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.stateLag = { normal: Infinity };
  const { reply, elapsed } = await opWithClock(t, fake, 'windowState', { windowId, state: 'maximized' });
  assert.equal(reply.error, 'To maximize a minimized or fullscreen window, restore it to normal state first.');
  assert.ok(elapsed >= 2000 && elapsed <= 2100, `gave up after ${elapsed} ms`);
});

test('normal restores with focus; minimized minimizes without it; both answer the state read back', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.stateLag = { normal: 60, minimized: 60 };
  assert.deepEqual((await opWithClock(t, fake, 'windowState', { windowId, state: 'normal' })).reply.result, { state: 'normal' });
  assert.deepEqual((await opWithClock(t, fake, 'windowState', { windowId, state: 'minimized' })).reply.result, { state: 'minimized' });
  assert.deepEqual(fake.callsOf('windows.update'), [[windowId, { state: 'normal', focused: true }], [windowId, { state: 'minimized' }]]);
});

test('the read-back reports what Chrome says after 2 s, even when it differs', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.stateLag = { normal: Infinity };
  const { reply, elapsed } = await opWithClock(t, fake, 'windowState', { windowId, state: 'normal' });
  assert.deepEqual(reply.result, { state: 'minimized' });
  assert.ok(elapsed >= 2000 && elapsed <= 2100);
});

test('windowState leaves the owner\'s windows, unknown windows and unknown states alone', async t => {
  const fake = await startWorker({ windows: [{ id: 1 }] });
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 }); // the 2 s keepMinimized watch must not outlive the test
  const { result: { windowId } } = await fake.op('createWindow', { url: 'about:blank', state: 'minimized' });
  fake.calls.length = 0;
  assert.deepEqual(await fake.op('windowState', { windowId: 1, state: 'maximized' }, 1), { id: 1, error: 'Window 1 is not an agent window; its state is left alone.' });
  assert.deepEqual(await fake.op('windowState', { windowId: 99, state: 'normal' }, 2), { id: 2, error: 'Window 99 is not an agent window; its state is left alone.' });
  assert.deepEqual(await fake.op('windowState', { windowId, state: 'fullscreen' }, 3), { id: 3, error: 'Unknown window state: fullscreen' });
  assert.deepEqual(await fake.op('windowState', { windowId }, 4), { id: 4, error: 'Unknown window state: undefined' });
  assert.deepEqual(fake.callsOf('windows.update'), []);
  await settle();
});

test('a shown agent window is still an agent window for windowState', async t => {
  const fake = await startWorker();
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 }); // the 2 s keepMinimized watch must not outlive the test
  const { result: { windowId } } = await fake.op('createWindow', { url: 'about:blank', state: 'minimized' });
  await fake.op('markShown', { windowId, shown: true });
  assert.deepEqual(await fake.op('windowState', { windowId, state: 'minimized' }, 1), { id: 1, result: { state: 'minimized' } });
});

// Chrome restores the window a new tab lands in (macOS lane 4: a popup left the agent window normal).
async function tabLands(t, fake, windowId, id, { restore = true, ms = 2500 } = {}) {
  const tab = { id, windowId, active: true };
  fake.state.tabs.set(id, { ...tab });
  if (restore) fake.state.windows.get(windowId).state = 'normal';
  fake.chrome.tabs.onCreated.fire(tab);
  for (let elapsed = 0; elapsed < ms; elapsed += 10) { await settle(); t.mock.timers.tick(10); }
  await settle();
}

test('a tab landing in a minimized agent window minimizes it again, and the watch ends after 2 s', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  await tabLands(t, fake, windowId, 900);
  assert.equal(fake.state.windows.get(windowId).state, 'minimized');
  assert.deepEqual(fake.callsOf('windows.update'), [[windowId, { state: 'minimized' }]]);
  assert.equal(fake.state.tabs.get(900).muted, true);

  // A restore after the watch has ended is not undone: the watch is per tab, not forever.
  fake.calls.length = 0;
  fake.state.windows.get(windowId).state = 'normal';
  for (let i = 0; i < 50; i++) { await settle(); t.mock.timers.tick(10); }
  assert.deepEqual(fake.callsOf('windows.update'), []);
});

test('a minimize that settles slowly is not asked for again while it settles', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.stateLag = { minimized: 300 };
  await tabLands(t, fake, windowId, 900);
  assert.equal(fake.state.windows.get(windowId).state, 'minimized');
  assert.deepEqual(fake.callsOf('windows.update'), [[windowId, { state: 'minimized' }]]);
});

test('a shown agent window, and a hidden one that was never minimized, are left as they are', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  await opWithClock(t, fake, 'windowState', { windowId, state: 'maximized' });
  await fake.op('markShown', { windowId, shown: true });
  fake.calls.length = 0;
  await tabLands(t, fake, windowId, 900);
  assert.deepEqual(fake.callsOf('windows.update'), []);

  // Hidden through the OS (Windows): created without a state, its normal state is how it is hidden.
  const { result } = await fake.op('createWindow', { url: 'about:blank', left: 0, top: 0, width: 800, height: 600 });
  fake.calls.length = 0;
  await tabLands(t, fake, result.windowId, 901, { restore: false });
  assert.deepEqual(fake.callsOf('windows.update'), []);
  assert.equal(fake.state.tabs.get(901).muted, true);
});

test('showing the window stops a running watch at once', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  const tab = { id: 900, windowId, active: true };
  fake.state.tabs.set(900, { ...tab });
  fake.chrome.tabs.onCreated.fire(tab);
  await settle();
  await opWithClock(t, fake, 'windowState', { windowId, state: 'normal' });
  fake.calls.length = 0;
  for (let i = 0; i < 250; i++) { await settle(); t.mock.timers.tick(10); }
  assert.deepEqual(fake.callsOf('windows.update'), []);
  assert.equal(fake.state.windows.get(windowId).state, 'normal');
});

test('a minimized agent window restored soon after it was made is minimized again', async t => {
  const { fake, windowId } = await minimizedAgentWindow(t);
  fake.state.windows.get(windowId).state = 'normal';
  for (let i = 0; i < 50; i++) { await settle(); t.mock.timers.tick(10); }
  assert.equal(fake.state.windows.get(windowId).state, 'minimized');
  assert.deepEqual(fake.callsOf('windows.update'), [[windowId, { state: 'minimized' }]]);
});

// macOS lane 4, window server: Chrome restores a minimized window to show a dialog in it, and the
// "Delete it?" and "Saved" dialogs left the agent window on the owner's screen.
test('a dialog answered in a minimized agent window minimizes it again', async t => {
  const { fake, windowId, tabId } = await minimizedAgentWindow(t);
  for (let i = 0; i < 250; i++) { await settle(); t.mock.timers.tick(10); } // the creation watch is over
  await fake.op('attach', { tabId });
  fake.calls.length = 0;
  fake.chrome.debugger.onEvent.fire({ tabId }, 'Page.javascriptDialogOpening', { type: 'confirm', message: 'Delete it?' });
  await settle();
  fake.state.windows.get(windowId).state = 'normal';
  for (let i = 0; i < 50; i++) { await settle(); t.mock.timers.tick(10); }
  assert.deepEqual(fake.callsOf('debugger.sendCommand').map(c => c[1]), ['Page.handleJavaScriptDialog']);
  assert.equal(fake.state.windows.get(windowId).state, 'minimized');
  assert.deepEqual(fake.callsOf('windows.update'), [[windowId, { state: 'minimized' }]]);
  for (let i = 0; i < 250; i++) { await settle(); t.mock.timers.tick(10); } // and its watch ends too
});
