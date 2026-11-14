// A small fake of the chrome.* surface the worker uses. It records every call in `calls`,
// keeps just enough state (tabs, windows, session storage) for the ops to be meaningful,
// and lets a test fire the events Chrome would.
import { setImmediate as tick } from 'node:timers/promises';

export const EXTENSION_ID = 'ownextensionidownextensionidaaaa';
export const WORKER = new URL('../dist/background.js', import.meta.url).href;
let generation = 0;

class FakeEvent {
  listeners = [];
  addListener(f) { this.listeners.push(f); }
  fire(...args) { return this.listeners.map(f => f(...args)); }
}

class FakePort {
  sent = [];
  onMessage = new FakeEvent();
  onDisconnect = new FakeEvent();
  disconnected = false;
  constructor(name) { this.name = name; }
  postMessage(message) {
    if (this.disconnected) throw Error('Attempting to use a disconnected port object');
    // Native messaging serialises as JSON: undefined fields vanish on the way.
    this.sent.push(JSON.parse(JSON.stringify(message)));
  }
  /** The service sends a message to the extension. */
  receive(message) { this.onMessage.fire(message); }
  /** The host exits or the service closes the link. */
  disconnect() { this.disconnected = true; this.onDisconnect.fire(this); }
}

/** Lets microtasks and promise chains in the worker run to completion. */
export async function settle(rounds = 5) { for (let i = 0; i < rounds; i++) await tick(); }

/**
 * Builds a fake chrome, installs it as the global, and starts a fresh copy of the worker
 * (a new module URL each time, so module state never leaks between tests).
 */
export async function startWorker({ windows = [], tabs = [], session = {}, connectFailures = 0, start = true, worker = WORKER, files = {} } = {}) {
  const calls = [];
  const record = (name, ...args) => { calls.push({ name, args }); };
  const state = {
    windows: new Map(windows.map(w => [w.id, { type: 'normal', incognito: false, focused: false, state: 'normal', ...w }])),
    tabs: new Map(tabs.map(t => [t.id, { title: `Tab ${t.id}`, url: `https://example.test/${t.id}`, ...t }])),
    session: structuredClone(session),
    lastFocused: windows.find(w => w.lastFocused)?.id,
    nextId: 1000,
    connectFailures,
    executeResults: [],
    stateLag: {},
    sendResults: new Map(),
    // Debugger sessions by tabId, each with the rejects of its commands still waiting for a reply.
    attached: new Map(),
    // How long a command takes to reply, by method (Infinity: never). A detach fails it first, like Chrome.
    sendLag: {},
    // How long after closeTarget replies its tab closes (Infinity: never).
    closeLag: 0,
    // Tabs whose Target.closeTarget Chrome refuses.
    refuseClose: new Set(),
    // Tabs whose page has a beforeunload, the sessions with the Page domain on, the "Leave site?"
    // dialogs waiting for an answer, and those nobody could answer (no session with Page on).
    beforeunload: new Set(),
    pageEnabled: new Set(),
    dialogs: new Set(),
    unanswered: [],
  };
  const ports = [];
  const overrides = {};
  const call = (name, impl) => async (...args) => {
    record(name, ...args);
    if (overrides[name]) return overrides[name](...args);
    return impl(...args);
  };
  const windowInfo = w => ({ ...w, tabs: [...state.tabs.values()].filter(t => t.windowId === w.id) });
  const noTab = id => Error(`No tab with id: ${id}.`);
  const notAttached = id => Error(`Debugger is not attached to the tab with id: ${id}.`);
  const endSession = tabId => {
    const pending = state.attached.get(tabId);
    state.attached.delete(tabId);
    state.pageEnabled.delete(tabId);
    for (const fail of pending ?? []) fail(Error('Detached while handling command.'));
  };
  // Like Chrome: a closing tab's debugger detaches (target_closed), then the tab and, with its last tab,
  // the window are removed, each with its event.
  const closeTab = tabId => {
    const t = state.tabs.get(tabId);
    if (!t) return;
    state.tabs.delete(tabId);
    const last = ![...state.tabs.values()].some(o => o.windowId === t.windowId);
    if (last) state.windows.delete(t.windowId);
    if (state.attached.has(tabId)) chrome.debugger.onDetach.fire({ tabId }, 'target_closed');
    chrome.tabs.onRemoved.fire(tabId, { windowId: t.windowId, isWindowClosing: last });
    if (last) chrome.windows.onRemoved.fire(t.windowId);
  };

  const chrome = {
    runtime: {
      id: EXTENSION_ID,
      lastError: undefined,
      getManifest: () => ({ version: '0.1.0' }),
      getURL: path => `chrome-extension://${EXTENSION_ID}/${path}`,
      connectNative(host) {
        record('runtime.connectNative', host);
        if (state.connectFailures > 0) { state.connectFailures--; throw Error('Specified native messaging host not found.'); }
        const port = new FakePort(host);
        ports.push(port);
        return port;
      },
      onStartup: new FakeEvent(),
    },
    debugger: {
      // Like Chrome: one debugger per tab, and commands only on an attached tab.
      attach: call('debugger.attach', async ({ tabId }) => {
        if (state.attached.has(tabId)) throw Error(`Another debugger is already attached to the tab with id: ${tabId}.`);
        state.attached.set(tabId, new Set());
      }),
      // The extension's own detach fires no onDetach, and fails the commands still waiting.
      detach: call('debugger.detach', async ({ tabId }) => {
        if (!state.attached.has(tabId)) throw notAttached(tabId);
        endSession(tabId);
      }),
      // Like Chrome: Target.closeTarget closes only the tab it is sent to, and a window goes with its last tab.
      sendCommand: call('debugger.sendCommand', async (target, method, params) => {
        const pending = state.attached.get(target.tabId);
        if (!pending) throw notAttached(target.tabId);
        const lag = state.sendLag[method] ?? 0;
        if (lag) {
          await new Promise((resolve, reject) => {
            pending.add(reject);
            if (lag !== Infinity) setTimeout(() => { pending.delete(reject); resolve(); }, lag);
          });
        }
        if (method === 'Page.enable') state.pageEnabled.add(target.tabId);
        if (method === 'Page.handleJavaScriptDialog' && state.dialogs.delete(target.tabId) && params?.accept) closeTab(target.tabId);
        if (method !== 'Target.closeTarget') return state.sendResults.get(method);
        if (params?.targetId !== `target-${target.tabId}` || state.refuseClose.has(target.tabId)) throw Error('{"code":-32000,"message":"Not allowed"}');
        if (state.closeLag === 0) closeTab(target.tabId);
        else if (state.closeLag !== Infinity) setTimeout(() => closeTab(target.tabId), state.closeLag);
        return { success: true };
      }),
      getTargets: call('debugger.getTargets', async () => [...state.tabs.values()].map(t => ({ id: `target-${t.id}`, tabId: t.id, type: 'page', attached: state.attached.has(t.id), url: t.url, title: t.title }))),
      onEvent: new FakeEvent(),
      // A test firing it is Chrome detaching the tab: the session ends there too.
      onDetach: new class extends FakeEvent { fire(source, reason) { endSession(source.tabId); return super.fire(source, reason); } }(),
    },
    tabs: {
      get: call('tabs.get', async id => { const t = state.tabs.get(id); if (!t) throw noTab(id); return { ...t }; }),
      query: call('tabs.query', async (q = {}) => [...state.tabs.values()].filter(t => q.windowId === undefined || t.windowId === q.windowId).map(t => ({ ...t }))),
      create: call('tabs.create', async ({ windowId, url }) => { const t = { id: state.nextId++, windowId, url, title: '' }; state.tabs.set(t.id, t); return { ...t }; }),
      // Like Chrome: the tab closes with its events, and its window with its last tab.
      remove: call('tabs.remove', async id => { if (!state.tabs.has(id)) throw noTab(id); closeTab(id); }),
      update: call('tabs.update', async (id, info = {}) => { const t = state.tabs.get(id); if (!t) throw noTab(id); if ('muted' in info) t.muted = info.muted; return { ...t, active: true }; }),
      onCreated: new FakeEvent(),
      onRemoved: new FakeEvent(),
    },
    windows: {
      create: call('windows.create', async ({ url, focused, state: windowState = 'normal', ...bounds }) => {
        if (windowState !== 'normal' && Object.keys(bounds).some(k => bounds[k] !== undefined)) throw Error("The 'minimized', 'maximized' and 'fullscreen' states cannot be combined with 'left', 'top', 'width' or 'height'.");
        // Like Chrome on macOS: a window created minimized lands normal, on screen. With focused: false
        // ShowInactive drops the state; unset, focused is true and the activation cancels the miniaturize.
        const shown = windowState === 'minimized' ? 'normal' : windowState;
        const w = { id: state.nextId++, type: 'normal', incognito: false, focused: focused ?? true, state: shown };
        state.windows.set(w.id, w);
        const t = { id: state.nextId++, windowId: w.id, url, title: '' };
        state.tabs.set(t.id, t);
        return windowInfo(w);
      }),
      getLastFocused: call('windows.getLastFocused', async () => {
        const w = state.windows.get(state.lastFocused);
        if (!w) throw Error('No last-focused window');
        return windowInfo(w);
      }),
      getAll: call('windows.getAll', async () => [...state.windows.values()].map(windowInfo)),
      get: call('windows.get', async id => { const w = state.windows.get(id); if (!w) throw Error(`No window with id: ${id}.`); return windowInfo(w); }),
      // Like Chrome: no maximize straight from minimized, and a state change lands stateLag[state] ms
      // after the call resolves (Infinity: never).
      update: call('windows.update', async (id, { state: wanted, ...info }) => {
        const w = state.windows.get(id); if (!w) throw Error(`No window with id: ${id}.`);
        if (wanted === 'maximized' && ['minimized', 'fullscreen'].includes(w.state)) throw Error('To maximize a minimized or fullscreen window, restore it to normal state first.');
        Object.assign(w, info);
        const lag = state.stateLag[wanted] ?? 0;
        if (wanted && lag === 0) w.state = wanted;
        else if (wanted && lag !== Infinity) setTimeout(() => { w.state = wanted; }, lag);
        return windowInfo(w);
      }),
      // Like Chrome: it answers at once, and a page with a beforeunload then raises "Leave site?", which keeps
      // its tab and window open until answered. A session with the Page domain on hears of it.
      remove: call('windows.remove', async id => {
        if (!state.windows.has(id)) throw Error(`No window with id: ${id}.`);
        for (const [tid, tab] of state.tabs) {
          if (tab.windowId !== id) continue;
          if (!state.beforeunload.has(tid)) { closeTab(tid); continue; }
          state.dialogs.add(tid);
          if (state.pageEnabled.has(tid)) queueMicrotask(() => chrome.debugger.onEvent.fire({ tabId: tid }, 'Page.javascriptDialogOpening', { type: 'beforeunload', message: '' }));
          else state.unanswered.push(tid);
        }
        if (state.windows.has(id) && ![...state.tabs.values()].some(t => t.windowId === id)) {
          state.windows.delete(id);
          chrome.windows.onRemoved.fire(id);
        }
      }),
      onRemoved: new FakeEvent(),
    },
    storage: {
      session: {
        // Like Chrome: a key or an array of keys; missing keys are left out.
        get: call('storage.session.get', async keys => Object.fromEntries([keys].flat().filter(k => k in state.session).map(k => [k, structuredClone(state.session[k])]))),
        set: call('storage.session.set', async items => { Object.assign(state.session, structuredClone(items)); }),
      },
    },
    alarms: {
      create: call('alarms.create', async () => {}),
      onAlarm: new FakeEvent(),
    },
    action: {
      setBadgeText: call('action.setBadgeText', async () => {}),
      setTitle: call('action.setTitle', async () => {}),
      onClicked: new FakeEvent(),
    },
    scripting: {
      executeScript: call('scripting.executeScript', async () => state.executeResults),
    },
  };

  const fake = {
    chrome, calls, state, ports, overrides,
    get port() { return ports.at(-1); },
    callsOf: name => calls.filter(c => c.name === name).map(c => c.args),
    /** The badge and title the worker set last. */
    badge() {
      return { text: fake.callsOf('action.setBadgeText').at(-1)?.[0].text, title: fake.callsOf('action.setTitle').at(-1)?.[0].title };
    },
    /** Every message the extension posted on the current port after the hello. */
    posted: () => fake.port.sent.slice(1),
    /** Sends op to the worker and waits for its reply. */
    async op(op, args, id = ++fake.seq) {
      const port = fake.port, from = port.sent.length;
      port.receive({ id, op, args });
      await settle();
      return port.sent.slice(from).find(m => m.id === id);
    },
    seq: 0,
  };
  globalThis.chrome = chrome;
  // The extension's own files (`files`: path -> text), as fetch serves them from chrome.runtime.getURL. A missing
  // one fails like Chrome's net::ERR_FILE_NOT_FOUND.
  globalThis.fetch = async url => {
    record('fetch', String(url));
    const path = String(url).replace(`chrome-extension://${EXTENSION_ID}/`, '');
    if (!(path in files)) throw new TypeError('Failed to fetch');
    return new Response(files[path]);
  };
  if (start) {
    await import(`${worker}?worker=${++generation}`);
    await settle();
  }
  return fake;
}

/** Imports another fresh worker on the already-installed fake (for tests that mock timers first). */
export async function loadWorker() {
  await import(`${WORKER}?worker=${++generation}`);
  await settle();
}
