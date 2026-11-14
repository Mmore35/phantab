import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startWorker, loadWorker, settle } from './fake-chrome.mjs';

const closes = fake => fake.callsOf('debugger.sendCommand').filter(([, method]) => method === 'Target.closeTarget');
// Moves the mocked clock on in small steps, letting the worker's polls run between them.
async function advance(t, ms, step = 10) {
  for (let i = 0; i < ms; i += step) { t.mock.timers.tick(step); await settle(); }
}
// Calls whose first argument is one of these tabs.
const onTabs = (fake, name, ids) => fake.calls.map((c, i) => ({ ...c, i })).filter(c => c.name === name && ids.includes(c.args[0]?.tabId));

// A hidden agent window with the agent's tab attached and a tab its page opened (a popup), as the service leaves it.
async function hiddenWindow() {
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }], tabs: [{ id: 5, windowId: 1 }] });
  const { windowId, tabId } = (await fake.op('createWindow', { url: 'about:blank' })).result;
  await fake.op('attach', { tabId });
  fake.state.tabs.set(900, { id: 900, windowId });
  fake.calls.length = 0;
  return { fake, windowId, tabId };
}

// chrome.windows.remove runs the page's beforeunload, and on macOS Chrome restores the minimized window to
// draw its "Leave site?". Target.closeTarget closes without it.
test('closeTab closes a hidden agent window tab by tab through Target.closeTarget, never chrome.windows.remove', async () => {
  const { fake, windowId, tabId } = await hiddenWindow();
  assert.deepEqual((await fake.op('closeTab', { tabId }, 1)), { id: 1, result: {} });
  // Chrome takes closeTarget only for the tab it is sent to, so the popup is attached for its own close.
  assert.deepEqual(closes(fake), [
    [{ tabId }, 'Target.closeTarget', { targetId: `target-${tabId}` }],
    [{ tabId: 900 }, 'Target.closeTarget', { targetId: 'target-900' }],
  ]);
  assert.deepEqual(fake.callsOf('debugger.attach'), [[{ tabId: 900 }, '1.3']], 'the agent tab is already attached');
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.deepEqual(fake.callsOf('tabs.remove'), []);
  assert.equal(fake.state.tabs.has(900), false, 'the tab its page opened went with it');
  assert.equal(fake.state.windows.has(windowId), false, 'the window went with its last tab');
});

test('a tab no debugger may attach to goes with the window through chrome.windows.remove, after the others closed', async () => {
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.overrides['debugger.attach'] = async ({ tabId: id }) => { if (id === 900) throw Error('Cannot access a chrome-extension:// URL of different extension'); };
  assert.deepEqual((await fake.op('closeTab', { tabId }, 1)), { id: 1, result: {} });
  assert.deepEqual(closes(fake), [[{ tabId }, 'Target.closeTarget', { targetId: `target-${tabId}` }]]);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  assert.equal(fake.state.tabs.has(900), false);
});

// A popup whose close is refused goes with the fallback, which may raise its "Leave site?": the session
// attached for its close is what answers it, so it is kept, and the tab's close ends it.
test('a tab attached only for its close keeps that session through the fallback when its close is refused', async () => {
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.beforeunload.add(900);
  fake.state.refuseClose.add(900);
  assert.deepEqual((await fake.op('closeTab', { tabId }, 1)), { id: 1, result: {} });
  await settle();
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  assert.deepEqual(fake.callsOf('debugger.detach'), [], "the popup's session was kept");
  assert.deepEqual(fake.state.unanswered, [], 'its "Leave site?" was answered');
  assert.equal(fake.state.windows.has(windowId), false);
});

// With no fallback to follow, a session attached for a close is detached again, never left behind.
test('a tab attached only for its close is detached again when chrome.windows.remove fails', async () => {
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.refuseClose.add(900);
  fake.overrides['windows.remove'] = async () => { throw Error('Cannot close the window.'); };
  assert.deepEqual(await fake.op('closeTab', { tabId }, 1), { id: 1, error: 'Cannot close the window.' }, 'the window is still open, and closeTab says so');
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 900 }]], 'only the popup, which this close attached');
  assert.equal(fake.state.windows.has(windowId), true);
  assert.equal(fake.badge().text, '', 'and the badge no longer counts it');
});

// Dialogs the owner can see are the owner's: a shown agent window and the owner's own windows close as before.
test('closeTab in a shown agent window or an owner window removes only the tab, the old way', async () => {
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }], tabs: [{ id: 5, windowId: 1 }] });
  const shown = (await fake.op('createWindow', { url: 'about:blank' })).result;
  await fake.op('markShown', { windowId: shown.windowId, shown: true });
  await fake.op('attach', { tabId: shown.tabId });
  await fake.op('attach', { tabId: 5 });
  fake.calls.length = 0;
  await fake.op('closeTab', { tabId: shown.tabId });
  await fake.op('closeTab', { tabId: 5 });
  assert.deepEqual(fake.callsOf('tabs.remove'), [[shown.tabId], [5]]);
  assert.deepEqual(closes(fake), []);
  assert.deepEqual(fake.callsOf('debugger.getTargets'), []);
  assert.deepEqual(fake.callsOf('windows.remove'), []);
});

// cleanup (a dropped service link, a worker start) detached every tab and then called chrome.windows.remove:
// the hidden page's "Leave site?" then had no session left to answer it, and the window came back on screen.
// Its other tabs are detached first, so a service that reconnects meanwhile can attach them again.
test('a dropped service link detaches the owner tabs, then closes a hidden window through Target.closeTarget', async () => {
  const { fake, windowId, tabId } = await hiddenWindow();
  await fake.op('attach', { tabId: 5 });
  fake.calls.length = 0;
  fake.port.disconnect();
  await settle();
  const at = (name, method, id) => fake.calls.findIndex(c => c.name === name && c.args[0].tabId === id && (method === undefined || c.args[1] === method));
  const closed = at('debugger.sendCommand', 'Target.closeTarget', tabId);
  assert.ok(closed >= 0, 'the agent tab was closed through its own session');
  assert.equal(at('debugger.detach', undefined, tabId), -1, 'the agent tab is never detached: its session ends with its tab');
  assert.ok(at('debugger.sendCommand', 'Target.closeTarget', 900) >= 0, 'the popup was closed too');
  const detached = at('debugger.detach', undefined, 5);
  assert.ok(detached >= 0 && detached < closed, 'the owner tab is detached before the closes');
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.equal(fake.state.windows.has(windowId), false);
  assert.equal(fake.state.windows.has(1), true, 'the owner window is left alone');
  assert.deepEqual(fake.state.session.windows, {});
  assert.deepEqual([...fake.state.attached.keys()], [], 'every session ended');
});


// MAC.md: CDP stalls around a macOS minimize. A close still running when cleanup's wait ended used to be
// cut by cleanup's detach, and its fallback then raised a "Leave site?" with no session left to answer it.
test('a close that outlasts cleanup keeps its tabs attached, and ends without chrome.windows.remove', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  await fake.op('attach', { tabId: 5 });
  fake.state.sendLag['Target.closeTarget'] = 2500; // a detach first fails it, like Chrome
  fake.calls.length = 0;
  fake.port.disconnect();
  await settle();
  await advance(t, 2000);
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 5 }]], 'only the owner tab is detached, before the wait');
  assert.equal(fake.state.session.windows[windowId], false, 'kept while the window is open, so its dialogs are still answered');
  await advance(t, 5000);
  assert.deepEqual(onTabs(fake, 'debugger.detach', [tabId, 900]), [], "the extension cut none of the window's sessions");
  assert.deepEqual(fake.callsOf('windows.remove'), [], 'both closes landed, late');
  assert.equal(fake.state.windows.has(windowId), false);
  assert.deepEqual(fake.state.session.windows, {}, 'the record went with the window');
});

test('a close that never replies still ends, through chrome.windows.remove with its sessions attached', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.sendLag['Target.closeTarget'] = Infinity;
  fake.port.disconnect();
  await settle();
  // The closes, sent at once, wait 2 s for their replies, then the tabs get 2 s to go.
  await advance(t, 3990);
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  await advance(t, 20);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  const removed = fake.calls.findIndex(c => c.name === 'windows.remove');
  assert.ok(onTabs(fake, 'debugger.detach', [tabId, 900]).every(c => c.i > removed), 'no session of the window was cut before its fallback');
  assert.equal(fake.state.windows.has(windowId), false);
});

// Without the deadline, a close that replies but never lands holds closeHiddenWindow for good.
test('a close that replies but never lands falls back to chrome.windows.remove 2 s later', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.closeLag = Infinity;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 1990);
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.equal(fake.port.sent.find(m => m.id === 99), undefined);
  await advance(t, 30);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, result: {} });
  assert.deepEqual(onTabs(fake, 'debugger.detach', [tabId, 900]), [], 'their sessions were kept for the fallback');
});

test('a worker start waits at most 2 s for a hung close before it connects', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ windows: [{ id: 10 }], tabs: [{ id: 20, windowId: 10 }], session: { windows: { 10: false } }, start: false });
  fake.state.sendLag['Target.closeTarget'] = Infinity;
  await loadWorker();
  assert.deepEqual(fake.callsOf('runtime.connectNative'), []);
  await advance(t, 1990);
  assert.deepEqual(fake.callsOf('runtime.connectNative'), []);
  await advance(t, 10);
  assert.deepEqual(fake.callsOf('runtime.connectNative'), [['dev.phantab.bridge']]);
  assert.deepEqual(fake.state.session.windows, { 10: false }, 'kept while the window is open');
  assert.deepEqual(fake.callsOf('debugger.detach'), [], 'its tab, attached for the close, is the close\'s');
});

// A service that connects during cleanup's wait is the new owner of what it attaches and records. The
// owner tabs were detached before the wait: detached after it, a service back within it (its reconnect timer
// starts at 1 s) found them taken ("Another debugger is already attached").
test('a service that reconnects during the wait attaches the owner tabs again, keeps them, and the windows it made', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId } = await hiddenWindow();
  fake.state.tabs.set(6, { id: 6, windowId: 1 });
  await fake.op('attach', { tabId: 5 });
  await fake.op('attach', { tabId: 6 });
  fake.state.sendLag['Target.closeTarget'] = Infinity;
  fake.calls.length = 0;
  fake.port.disconnect();
  await settle();
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 5 }], [{ tabId: 6 }]], 'at once');
  await advance(t, 1000); // the reconnect timer
  assert.equal(fake.ports.length, 2);
  assert.deepEqual(await fake.op('attach', { tabId: 5 }, 1), { id: 1, result: {} });
  const made = (await fake.op('createWindow', { url: 'about:blank' })).result.windowId;
  await advance(t, 1000);
  assert.equal(fake.callsOf('debugger.detach').length, 2, "the new service's attach is not cut");
  assert.ok(fake.state.attached.has(5));
  assert.deepEqual(await fake.op('send', { tabId: 5, method: 'Page.enable' }, 2), { id: 2, result: {} });
  assert.deepEqual(fake.state.session.windows, { [windowId]: false, [made]: false }, 'the new hidden window stays recorded');
});

// A second close of the same window (cleanup during closeTab) waits for the first: its attach of the popup
// would be refused ("Another debugger is already attached"), and its detach would then cut the first's session.
test('a second close of a window still closing waits for the first and cuts none of its sessions', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.closeLag = Infinity;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  fake.port.disconnect();
  await settle();
  await advance(t, 2100);
  assert.deepEqual(onTabs(fake, 'debugger.attach', [900]).length, 1, 'the popup was attached once');
  assert.deepEqual(onTabs(fake, 'debugger.detach', [tabId, 900]), []);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]], 'one fallback, with its sessions attached');
  assert.equal(fake.state.windows.has(windowId), false);
});

// A popup attached only for its close has the Page domain turned on for it, so a "Leave site?" its
// fallback raises is answered like any other dialog in a hidden window, never left on screen.
test("a popup's beforeunload raised by the fallback is answered, with no session cut before it", async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.beforeunload.add(900);
  fake.state.closeLag = Infinity; // both closes reply but never land, so the fallback runs
  fake.port.disconnect();
  await settle();
  await advance(t, 2100);
  const removed = fake.calls.findIndex(c => c.name === 'windows.remove');
  assert.ok(removed >= 0, 'the fallback ran');
  assert.ok(onTabs(fake, 'debugger.detach', [tabId, 900]).every(c => c.i > removed), 'no session of the window was cut before its fallback');
  assert.deepEqual(fake.state.unanswered, [], 'no "Leave site?" was left for nobody');
  assert.deepEqual(onTabs(fake, 'debugger.sendCommand', [900]).filter(c => c.args[1] === 'Page.handleJavaScriptDialog').map(c => c.args[2]), [{ accept: true }]);
  assert.equal(fake.state.windows.has(windowId), false, 'the answered dialog let the window close');
  assert.deepEqual(fake.state.session.windows, {});
});

// chrome.windows.remove resolves before its "Leave site?" is answered. A cleanup in that gap used to start
// a second close: its attach of the popup was refused, and its detach then cut the first close's session,
// so the dialog was never answered and the window and its record were left behind.
test('a cleanup while a fallback dialog is being answered leaves the first close alone', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.beforeunload.add(900);
  fake.state.closeLag = Infinity; // the closes reply but never land, so the fallback runs at 2 s
  fake.state.sendLag['Page.handleJavaScriptDialog'] = 5000;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 2200);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, result: {} });
  fake.port.disconnect();
  await settle();
  await advance(t, 6000);
  assert.equal(onTabs(fake, 'debugger.attach', [900]).length, 1, 'the popup was attached once');
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]], 'one fallback');
  assert.deepEqual(fake.callsOf('debugger.detach'), [], 'no session was cut');
  assert.deepEqual(fake.state.unanswered, []);
  assert.equal(fake.state.windows.has(windowId), false, 'the answered dialog let the window close');
  assert.deepEqual(fake.state.session.windows, {}, 'and its record went with it');
});

// The service gives an op 15 s (bridge.rs). Closed one after another, at 2 s for Page.enable and 2 s for
// closeTarget each, three stalled popups took 16 s.
test('a window of stalled tabs closes in parallel, well within the service\'s 15 s', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.tabs.set(901, { id: 901, windowId });
  fake.state.tabs.set(902, { id: 902, windowId });
  fake.state.sendLag['Page.enable'] = Infinity;
  fake.state.sendLag['Target.closeTarget'] = Infinity;
  fake.overrides['windows.remove'] = () => new Promise(() => {}); // and the fallback never answers
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 2010);
  assert.deepEqual(closes(fake).map(([{ tabId: id }]) => id).sort(), [tabId, 900, 901, 902].sort(), 'every close sent by 2 s');
  await advance(t, 5990); // the closes count as sent at 4 s, the tabs get 2 s, chrome.windows.remove 2 s
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, result: {} }, 'replied by 8 s');
});

// Page.enable stalls with CDP (a macOS minimize); the close does not wait for it past 2 s.
test("a popup's close waits at most 2 s for its Page.enable", async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.sendLag['Page.enable'] = Infinity;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 1990);
  assert.deepEqual(onTabs(fake, 'debugger.sendCommand', [900]).map(c => c.args[1]), ['Page.enable']);
  await advance(t, 20);
  assert.deepEqual(onTabs(fake, 'debugger.sendCommand', [900]).map(c => c.args[1]), ['Page.enable', 'Target.closeTarget']);
  await advance(t, 50);
  assert.equal(fake.state.windows.has(windowId), false);
  assert.deepEqual(fake.callsOf('windows.remove'), []);
});

// SR-22: the badge's click takes the agents' control away at once. It used to detach every session, so a
// close running then lost them: the popup's Target.closeTarget failed ("not attached") and the fallback's
// "Leave site?" was left for nobody. A window already closing now finishes its close quietly: its sessions
// are held for that close, and the service can no longer use them.
test("the badge's click during a hidden close takes the tabs from the service, and the close still answers its dialogs", async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  await fake.op('send', { tabId, method: 'Page.enable' }); // the service turns the Page domain on
  fake.state.beforeunload.add(tabId);
  fake.state.beforeunload.add(900);
  fake.state.closeLag = Infinity; // the closes reply but never land, so the fallback raises both dialogs
  fake.state.sendLag['Page.enable'] = 1500; // the popup's, stalled
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 500);
  const from = fake.port.sent.length, at = fake.calls.length;
  fake.chrome.action.onClicked.fire({ id: 1 });
  await settle();
  assert.deepEqual(fake.port.sent.slice(from), [{ event: 'detach', tabId, reason: 'canceled_by_user' }]);
  const refused = { error: `Debugger is not attached to the tab with id: ${tabId}.` };
  assert.deepEqual(await fake.op('send', { tabId, method: 'Page.enable' }, 2), { id: 2, ...refused }, 'the service lost the tab at the click');
  assert.deepEqual(await fake.op('keepRendering', { tabId }, 3), { id: 3, ...refused });
  assert.deepEqual(await fake.op('detach', { tabId }, 4), { id: 4, ...refused });
  assert.deepEqual(onTabs(fake, 'debugger.detach', [tabId, 900]), [], 'the closing window keeps its sessions');
  assert.equal(fake.badge().text, 'PT', 'still counted while they are held');
  await advance(t, 4000);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]], 'the fallback ran');
  assert.deepEqual(fake.state.unanswered, [], 'both "Leave site?" dialogs were answered');
  assert.equal(fake.state.windows.has(windowId), false, 'the window is gone');
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, result: {} });
  assert.deepEqual(fake.calls.slice(at).filter(c => c.name === 'debugger.sendCommand' && c.args[0].tabId === tabId).map(c => c.args[1]),
    ['Page.handleJavaScriptDialog'], "only the extension's own answer reached the agent's tab");
  assert.deepEqual(fake.port.sent.slice(from).filter(m => m.event === 'cdp' || m.event === 'detach'),
    [{ event: 'detach', tabId, reason: 'canceled_by_user' }], 'and none of its events went to the service');
  assert.equal(fake.badge().text, '', 'the held sessions ended with their tabs');
});

// After a Cancel the service may still close its tab: the extension attaches again only for that quiet close.
// A second click during it keeps that session for the close, so no "Leave site?" is left behind.
test('a second click while a canceled tab is being closed leaves no dialog', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.chrome.action.onClicked.fire({ id: 1 });
  await settle();
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId }]], 'no close was running: detached at once');
  fake.state.beforeunload.add(tabId);
  fake.state.beforeunload.add(900);
  fake.state.closeLag = Infinity;
  fake.state.sendLag['Page.enable'] = 1500;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 500);
  assert.equal(onTabs(fake, 'debugger.attach', [tabId]).length, 1, 'attached again, only for its close');
  fake.chrome.action.onClicked.fire({ id: 1 });
  await settle();
  assert.equal(fake.callsOf('debugger.detach').length, 1, 'the close keeps its sessions');
  await advance(t, 4000);
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
  assert.deepEqual(fake.state.unanswered, []);
  assert.equal(fake.state.windows.has(windowId), false);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, result: {} });
  assert.equal(fake.badge().text, '');
});

// After a cleanup, the dropped service's tabs in a window still closing are held for that close, not the
// next service's: a click reports only the tabs the current service attached.
test("a click after a reconnect reports only the new service's tabs", async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.closeLag = Infinity;
  fake.port.disconnect();
  await settle();
  await advance(t, 1000); // the reconnect timer
  assert.equal(fake.ports.length, 2);
  await fake.op('attach', { tabId: 5 });
  assert.deepEqual(await fake.op('send', { tabId, method: 'Page.enable' }, 2), { id: 2, error: `Debugger is not attached to the tab with id: ${tabId}.` }, "not the new service's");
  const from = fake.port.sent.length;
  fake.chrome.action.onClicked.fire({ id: 1 });
  await settle();
  assert.deepEqual(fake.port.sent.slice(from), [{ event: 'detach', tabId: 5, reason: 'canceled_by_user' }]);
  await advance(t, 1500);
  assert.equal(fake.state.windows.has(windowId), false, 'the close still finished');
});

// cleanup reads the windows and tabs before it detaches. A tab Chrome detached meanwhile and a service that
// connected meanwhile attached again is that service's: only the attachments cleanup began with are touched.
test('cleanup leaves alone a tab a new service attached during its reads', async () => {
  const { fake } = await hiddenWindow();
  await fake.op('attach', { tabId: 5 });
  let raced = false;
  fake.overrides['tabs.query'] = async (q = {}) => {
    if (q.windowId === undefined && !raced) {
      raced = true;
      fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'canceled_by_user');
      fake.chrome.runtime.onStartup.fire(); // connects at once
      assert.deepEqual(await fake.op('attach', { tabId: 5 }, 1), { id: 1, result: {} });
    }
    return [...fake.state.tabs.values()].filter(t => q.windowId === undefined || t.windowId === q.windowId).map(t => ({ ...t }));
  };
  fake.calls.length = 0;
  fake.port.disconnect();
  await settle(20);
  assert.ok(raced, 'the attach landed during cleanup');
  assert.deepEqual(onTabs(fake, 'debugger.detach', [5]), []);
  assert.deepEqual(await fake.op('send', { tabId: 5, method: 'Page.enable' }, 2), { id: 2, result: {} });
});

// A popup attach stalled past 4 s is given up on. When it lands after its window's close ended (here the
// fallback failed), its session is cut at once, never left with the badge on.
test('a popup attach that lands after its close gave up is detached at once', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, tabId } = await hiddenWindow();
  fake.overrides['debugger.attach'] = ({ tabId: id }) => new Promise(resolve => setTimeout(() => { fake.state.attached.set(id, new Set()); resolve(); }, 6000));
  fake.overrides['windows.remove'] = async () => { throw Error('Cannot close the window.'); };
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 5000);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, error: 'Cannot close the window.' });
  await advance(t, 1100);
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 900 }]], 'cut as it landed');
  assert.equal(fake.state.attached.has(900), false);
  assert.equal(fake.badge().text, '');
});

// The fallback can ask "Leave site?": a window the owner was shown meanwhile is his, and is left open.
test('a window shown while it closes is left open for the owner, never removed', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.state.closeLag = Infinity;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 1000);
  await fake.op('markShown', { windowId, shown: true });
  await advance(t, 1100);
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, error: `Window ${windowId} was shown while it closed: left open for the owner.` });
  assert.equal(fake.state.windows.has(windowId), true);
  assert.equal(onTabs(fake, 'debugger.detach', [900]).length, 1, "the popup's session, held for the close, ended with it");
  assert.ok(fake.state.attached.has(tabId), "the agent's tab is still the service's");
});

test('no close is sent after 4 s, even to a tab ready only then', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const { fake, windowId, tabId } = await hiddenWindow();
  fake.overrides['debugger.attach'] = ({ tabId: id }) => new Promise(resolve => setTimeout(() => { fake.state.attached.set(id, new Set()); resolve(); }, 3000));
  fake.state.sendLag['Page.enable'] = Infinity; // its wait ends at 4 s, when no close may be sent any more
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 10000);
  assert.deepEqual(closes(fake).map(([{ tabId: id }]) => id), [tabId], "the popup's close was never sent");
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]], 'it went with the fallback');
  assert.equal(fake.state.windows.has(windowId), false);
});

for (const [name, what] of [['debugger.getTargets', 'target'], ['tabs.query', 'tab']]) {
  test(`a ${what} list that cannot be read leaves the window to chrome.windows.remove`, async () => {
    const { fake, windowId, tabId } = await hiddenWindow();
    fake.overrides[name] = async () => { throw Error('Browser is shutting down.'); };
    assert.deepEqual(await fake.op('closeTab', { tabId }, 1), { id: 1, result: {} });
    assert.deepEqual(closes(fake), []);
    assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]]);
    assert.equal(fake.state.windows.has(windowId), false);
  });
}

// A window shown while its tabs wait for their close (here a stalled Page.enable) is the owner's: no close
// is sent to it, and the sessions attached for that close end with it.
test('a window shown before its tabs are closed gets no close, and is left open', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }], tabs: [{ id: 5, windowId: 1 }] });
  const { windowId, tabId } = (await fake.op('createWindow', { url: 'about:blank' })).result;
  fake.state.tabs.set(900, { id: 900, windowId });
  fake.state.sendLag['Page.enable'] = Infinity;
  fake.calls.length = 0;
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle();
  await advance(t, 500);
  assert.equal(onTabs(fake, 'debugger.attach', [tabId, 900]).length, 2, 'both attached for the close');
  await fake.op('markShown', { windowId, shown: true });
  await advance(t, 2000);
  assert.deepEqual(closes(fake), [], 'no close was sent');
  assert.deepEqual(fake.callsOf('windows.remove'), []);
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, error: `Window ${windowId} was shown while it closed: left open for the owner.` });
  assert.ok(fake.state.windows.has(windowId) && fake.state.tabs.has(tabId) && fake.state.tabs.has(900), 'the window and its tabs are left open');
  assert.deepEqual(onTabs(fake, 'debugger.detach', [tabId, 900]).map(c => c.args[0].tabId).sort(), [tabId, 900].sort(), 'its holds were released');
  assert.equal(fake.badge().text, '');
});

// A record already gone means the window went (windows.onRemoved), not that the owner was shown it.
test('a window gone with its record before the fallback is reported closed, not shown', async () => {
  const { fake, windowId, tabId } = await hiddenWindow();
  let gone = false;
  fake.overrides['tabs.query'] = async () => {
    if (!gone) {
      gone = true;
      await fake.chrome.tabs.remove(tabId);
      await fake.chrome.tabs.remove(900);
      await settle();
    }
    throw Error('Browser is shutting down.');
  };
  fake.port.receive({ id: 99, op: 'closeTab', args: { tabId } });
  await settle(30);
  assert.deepEqual(fake.state.session.windows, {}, 'its record went with it');
  assert.deepEqual(fake.callsOf('windows.remove'), [[windowId]], 'the fallback found it gone');
  assert.deepEqual(fake.port.sent.find(m => m.id === 99), { id: 99, result: {} });
});
