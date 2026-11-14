import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startWorker, settle } from './fake-chrome.mjs';

const WORKING = { text: 'PT', title: 'phantab: agents working, click to stop' };
const IDLE = { text: '', title: 'phantab bridge: no agent working' };

test('ping answers an empty result', async () => {
  const fake = await startWorker();
  assert.deepEqual(await fake.op('ping', {}, 7), { id: 7, result: {} });
});

test('an unknown op, or one only on the prototype, is an error', async () => {
  const fake = await startWorker();
  assert.deepEqual(await fake.op('nope', {}, 1), { id: 1, error: 'Unknown bridge operation: nope' });
  assert.deepEqual(await fake.op('toString', {}, 2), { id: 2, error: 'Unknown bridge operation: toString' });
  assert.deepEqual(await fake.op(undefined, {}, 3), { id: 3, error: 'Unknown bridge operation: undefined' });
});

test('a failing chrome call answers its message as the error', async () => {
  const fake = await startWorker();
  fake.overrides['debugger.attach'] = async () => { throw Error('Another debugger is already attached to the tab with id: 5.'); };
  assert.deepEqual(await fake.op('attach', { tabId: 5 }, 1), { id: 1, error: 'Another debugger is already attached to the tab with id: 5.' });
  assert.deepEqual(fake.badge(), IDLE);
  fake.overrides['debugger.attach'] = async () => { throw 'plain'; };
  assert.deepEqual(await fake.op('attach', { tabId: 5 }, 2), { id: 2, error: 'plain' });
});

test('attach and detach call chrome.debugger and keep the badge', async () => {
  const fake = await startWorker();
  assert.deepEqual(await fake.op('attach', { tabId: 5 }, 1), { id: 1, result: {} });
  assert.deepEqual(fake.callsOf('debugger.attach'), [[{ tabId: 5 }, '1.3']]);
  assert.deepEqual(fake.badge(), WORKING);
  await fake.op('attach', { tabId: 6 });
  assert.deepEqual(await fake.op('detach', { tabId: 5 }, 3), { id: 3, result: {} });
  assert.deepEqual(fake.callsOf('debugger.detach'), [[{ tabId: 5 }]]);
  assert.deepEqual(fake.badge(), WORKING);
  await fake.op('detach', { tabId: 6 });
  assert.deepEqual(fake.badge(), IDLE);
});

test("Chrome's own detach drops the tab from the badge", async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  fake.chrome.debugger.onDetach.fire({ tabId: 5 }, 'target_closed');
  assert.deepEqual(fake.badge(), IDLE);
});

test('send targets the tab, or the child session when given, and answers the result', async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  fake.state.sendResults.set('Runtime.callFunctionOn', { result: { value: 2 } });
  assert.deepEqual(await fake.op('send', { tabId: 5, method: 'Runtime.callFunctionOn', params: { functionDeclaration: '() => 1+1' } }, 1), { id: 1, result: { result: { value: 2 } } });
  await fake.op('send', { tabId: 5, sessionId: 'S1', method: 'Page.enable' });
  assert.deepEqual(fake.callsOf('debugger.sendCommand'), [
    [{ tabId: 5 }, 'Runtime.callFunctionOn', { functionDeclaration: '() => 1+1' }],
    [{ tabId: 5, sessionId: 'S1' }, 'Page.enable', undefined],
  ]);
  // A command with no result still answers an object.
  assert.deepEqual(await fake.op('send', { tabId: 5, method: 'Page.enable' }, 3), { id: 3, result: {} });
});

// THREAT-MODEL SR-20, L4: an agent that reached the bridge still cannot read cookies, storage or the
// network, nor run browser-wide commands; nothing outside the list reaches chrome.debugger.
test('send refuses every CDP method outside the allow-list, before chrome.debugger sees it', async () => {
  const fake = await startWorker();
  const refused = ['Network.getAllCookies', 'Storage.getCookies', 'Network.enable', 'Fetch.enable', 'Browser.close',
    'Security.disable', 'Target.createBrowserContext', 'Page.setDownloadBehavior', 'Runtime.evaluate', 'Nope.nope', '', undefined, 7];
  let id = 10;
  for (const method of refused) {
    assert.deepEqual(await fake.op('send', { tabId: 5, method, params: {} }, ++id), { id, error: 'CDP method not allowed: ' + method });
  }
  // A listed method still never gets universal access.
  for (const grant of [true, 1, 'yes']) {
    const params = { frameId: 'F', worldName: 'phantab', grantUniveralAccess: grant };
    assert.deepEqual(await fake.op('send', { tabId: 5, method: 'Page.createIsolatedWorld', params }, ++id),
      { id, error: 'CDP method not allowed: Page.createIsolatedWorld with grantUniveralAccess' });
  }
  assert.deepEqual(fake.callsOf('debugger.sendCommand'), []);
});

test('send relays an isolated world asked for without universal access', async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  const asked = [
    { frameId: 'F', worldName: 'phantab' },
    { frameId: 'F', worldName: 'phantab', grantUniveralAccess: false },
    { frameId: 'F', worldName: 'phantab', grantUniveralAccess: null },
    { frameId: 'F', worldName: 'phantab', grantUniveralAccess: undefined },
  ];
  let id = 10;
  for (const params of asked) {
    const answer = await fake.op('send', { tabId: 5, method: 'Page.createIsolatedWorld', params }, ++id);
    assert.equal(answer.error, undefined, JSON.stringify(params));
  }
  assert.deepEqual(fake.callsOf('debugger.sendCommand'), asked.map(p => [{ tabId: 5 }, 'Page.createIsolatedWorld', p]));
});

test('keepRendering starts a tiny screencast', async () => {
  const fake = await startWorker();
  await fake.op('attach', { tabId: 5 });
  assert.deepEqual(await fake.op('keepRendering', { tabId: 5 }, 1), { id: 1, result: {} });
  assert.deepEqual(fake.callsOf('debugger.sendCommand'), [[{ tabId: 5 }, 'Page.startScreencast', { format: 'jpeg', quality: 1, maxWidth: 32, maxHeight: 32, everyNthFrame: 60 }]]);
});

test('createWindow opens an unfocused window at the given place and records it as a hidden agent window', async () => {
  const fake = await startWorker();
  const reply = await fake.op('createWindow', { url: 'about:blank', left: 10, top: 20, width: 800, height: 600 }, 1);
  assert.deepEqual(fake.callsOf('windows.create'), [[{ url: 'about:blank', focused: false, left: 10, top: 20, width: 800, height: 600 }]]);
  const [w] = [...fake.state.windows.values()];
  const [t] = [...fake.state.tabs.values()];
  assert.deepEqual(reply, { id: 1, result: { windowId: w.id, tabId: t.id } });
  assert.deepEqual(fake.state.session.windows, { [w.id]: false });
  assert.ok(!('state' in fake.callsOf('windows.create')[0][0]), 'never minimized');
});

test('createTab opens in the last-focused window when it is a normal owner window', async () => {
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }, { id: 2 }] });
  const reply = await fake.op('createTab', { url: 'https://a.test/' }, 1);
  assert.deepEqual(fake.callsOf('tabs.create'), [[{ windowId: 1, url: 'https://a.test/', active: true }]]);
  assert.deepEqual(fake.callsOf('windows.update'), [[1, { focused: true }]]);
  assert.equal(reply.result.windowId, 1);
  assert.equal(typeof reply.result.tabId, 'number');
});

test('createTab skips agent, incognito and non-normal windows', async () => {
  const fake = await startWorker({ windows: [
    { id: 1, lastFocused: true },
    { id: 2, incognito: true },
    { id: 3, type: 'popup' },
    { id: 4 },
  ], session: { windows: { 1: true } } });
  // Window 1 is an agent window even while shown to the owner.
  await fake.op('createTab', { url: 'https://a.test/' });
  assert.deepEqual(fake.callsOf('tabs.create'), [[{ windowId: 4, url: 'https://a.test/', active: true }]]);
  assert.deepEqual(fake.callsOf('windows.update'), [[4, { focused: true }]]);
});

test('createTab opens a focused new window when the owner has none', async () => {
  const fake = await startWorker({ windows: [{ id: 2, incognito: true }] });
  const reply = await fake.op('createTab', { url: 'https://a.test/' }, 1);
  assert.deepEqual(fake.callsOf('tabs.create'), []);
  assert.deepEqual(fake.callsOf('windows.create'), [[{ url: 'https://a.test/', focused: true }]]);
  const w = [...fake.state.windows.values()].at(-1);
  const t = [...fake.state.tabs.values()].at(-1);
  assert.deepEqual(reply, { id: 1, result: { windowId: w.id, tabId: t.id } });
  // An owner window is never recorded as an agent window.
  assert.deepEqual(fake.state.session.windows, {});
});

test('tabs and tab answer the tab summary', async () => {
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1, title: 'A', url: 'https://a.test/', active: true }, { id: 6, windowId: 2 }] });
  assert.deepEqual(await fake.op('tabs', {}, 1), { id: 1, result: [
    { tabId: 5, windowId: 1, title: 'A', url: 'https://a.test/' },
    { tabId: 6, windowId: 2, title: 'Tab 6', url: 'https://example.test/6' },
  ] });
  assert.deepEqual(fake.callsOf('tabs.query'), [[{}]]);
  assert.deepEqual(await fake.op('tab', { tabId: 5 }, 2), { id: 2, result: { tabId: 5, windowId: 1, title: 'A', url: 'https://a.test/' } });
  assert.deepEqual(await fake.op('tab', { tabId: 9 }, 3), { id: 3, error: 'No tab with id: 9.' });
});

test('closeTab removes the tab', async () => {
  const fake = await startWorker({ tabs: [{ id: 5, windowId: 1 }] });
  assert.deepEqual(await fake.op('closeTab', { tabId: 5 }, 1), { id: 1, result: {} });
  assert.deepEqual(fake.callsOf('tabs.remove'), [[5]]);
});

test('focus activates the tab and focuses its window', async () => {
  const fake = await startWorker({ windows: [{ id: 3 }], tabs: [{ id: 5, windowId: 3 }] });
  assert.deepEqual(await fake.op('focus', { tabId: 5 }, 1), { id: 1, result: {} });
  assert.deepEqual(fake.callsOf('tabs.update'), [[5, { active: true }]]);
  assert.deepEqual(fake.callsOf('windows.update'), [[3, { focused: true }]]);
});

test('markShown ignores windows it did not create', async () => {
  const fake = await startWorker({ windows: [{ id: 3 }], tabs: [{ id: 5, windowId: 3 }] });
  const writes = fake.callsOf('storage.session.set').length;
  assert.deepEqual(await fake.op('markShown', { windowId: 3, shown: true }, 1), { id: 1, result: {} });
  assert.equal(fake.callsOf('storage.session.set').length, writes);
  assert.deepEqual(fake.callsOf('scripting.executeScript'), []);
});

test('markShown records the state, and a shown window gets its frames back', async () => {
  const fake = await startWorker();
  const { result: { windowId, tabId } } = await fake.op('createWindow', { url: 'about:blank' });
  assert.deepEqual(await fake.op('markShown', { windowId, shown: true }, 1), { id: 1, result: {} });
  assert.deepEqual(fake.state.session.windows, { [windowId]: true });
  const injections = fake.callsOf('scripting.executeScript').map(([i]) => i);
  assert.equal(injections.length, 1);
  assert.deepEqual(injections[0].target, { tabId, allFrames: true });

  // The injected function stops the guard, and does nothing where there is none.
  const stopped = [];
  globalThis.phantabForeignFrames = { stop: () => stopped.push(true) };
  try { injections[0].func(); } finally { delete globalThis.phantabForeignFrames; }
  assert.deepEqual(stopped, [true]);
  assert.doesNotThrow(() => injections[0].func());

  await fake.op('markShown', { windowId, shown: false });
  assert.deepEqual(fake.state.session.windows, { [windowId]: false });
  assert.equal(fake.callsOf('scripting.executeScript').length, 1, 'hiding injects nothing');
  // Truthy, not just true, counts as shown.
  await fake.op('markShown', { windowId, shown: 1 });
  assert.deepEqual(fake.state.session.windows, { [windowId]: true });
});

test('a hidden agent window is muted, and has its sound back once shown', async () => {
  const fake = await startWorker();
  const { result: { windowId, tabId } } = await fake.op('createWindow', { url: 'about:blank' });
  assert.equal(fake.state.tabs.get(tabId).muted, true);
  await fake.op('markShown', { windowId, shown: true });
  await settle();
  assert.equal(fake.state.tabs.get(tabId).muted, false);
  await fake.op('markShown', { windowId, shown: false });
  await settle();
  assert.equal(fake.state.tabs.get(tabId).muted, true);
});

test('a tab a hidden page opens is muted and the agent tab made active again', async () => {
  const fake = await startWorker({ windows: [{ id: 1 }], tabs: [{ id: 5, windowId: 1 }] });
  const { result: { windowId, tabId } } = await fake.op('createWindow', { url: 'about:blank' });
  await fake.op('attach', { tabId });
  const opened = { id: 900, windowId, active: true, openerTabId: tabId };
  fake.state.tabs.set(900, { ...opened });
  fake.chrome.tabs.onCreated.fire(opened);
  await settle();
  assert.equal(fake.state.tabs.get(900).muted, true);
  assert.deepEqual(fake.callsOf('tabs.update').filter(([id]) => id === tabId).at(-1), [tabId, { active: true }]);

  // A tab opened in the background leaves the active tab as it is.
  const behind = { id: 901, windowId, active: false, openerTabId: tabId };
  fake.state.tabs.set(901, { ...behind });
  const updates = fake.callsOf('tabs.update').length;
  fake.chrome.tabs.onCreated.fire(behind);
  await settle();
  assert.deepEqual(fake.callsOf('tabs.update').slice(updates), [[901, { muted: true }]]);

  // The owner's windows, and an agent window shown to the owner, are left alone.
  await fake.op('markShown', { windowId, shown: true });
  await settle();
  const before = fake.callsOf('tabs.update').length;
  for (const tab of [{ id: 902, windowId: 1, active: true, openerTabId: 5 }, { id: 903, windowId, active: true, openerTabId: tabId }]) {
    fake.state.tabs.set(tab.id, { ...tab });
    fake.chrome.tabs.onCreated.fire(tab);
  }
  await settle();
  assert.deepEqual(fake.callsOf('tabs.update').slice(before), []);
});

test('a closed window leaves the agent-window record', async () => {
  const fake = await startWorker();
  const { result: { windowId } } = await fake.op('createWindow', { url: 'about:blank' });
  fake.chrome.windows.onRemoved.fire(windowId);
  await settle();
  assert.deepEqual(fake.state.session.windows, {});
});
