// phantab bridge: relays the local phantab service's requests to
// chrome.debugger/tabs/windows in this profile. The native host (the phantab binary
// in host mode) pipes these messages to the service; nothing here is reachable
// from web pages.
import { CDP_METHODS, DEVTOOLS_EVENTS, DEVTOOLS_METHODS } from './cdp-methods.js';

const HOST = 'dev.phantab.bridge';
const PROTOCOL = 1; // the service's bridge protocol (docs/ARCHITECTURE.md, Names and constants)
const instance = crypto.randomUUID();
// tabId -> a token for that attach. cleanup detaches only the attachments that existed when it began: a
// tab Chrome detached meanwhile and the next service attached again has a new token, and is the new one's.
const attached = new Map<number, number>();
let attaches = 0;
// A session kept only for a hidden window's close, never the service's (SR-22): a tab attached just to
// close it (a popup), a dropped service's tab in a window its cleanup closes, and an agent's tab the badge
// took away while its window was closing. `windowId` is that window, once known. The badge counts it, the
// service cannot use it (ownTab), and it ends with its tab or with the window's close (letGo). The object
// is its token.
interface Hold { windowId?: number }
const temporary = new Map<number, Hold>();
const casting = new Set<number>(); // hidden agent tabs kept rendering by keepRendering

interface ForeignFrame { id: string; url: string | null; at: number }
// Chrome detaches every debugger from a tab that shows another extension's page
// (a password manager's autofill menu) and reports only target_closed; the
// last such frame per tab is kept so the detach can name it.
const foreign = new Map<number, ForeignFrame>();
let port: chrome.runtime.Port | null = null, timer: ReturnType<typeof setTimeout> | null = null, delay = 1000;
// When the current port was welcomed (Date.now()), else null. A welcomed link that stayed up STABLE_LINK
// was working: when it drops (a service restart, say) one retry comes after FAST_RETRY, then the usual
// backoff from `delay` (perf-ops-6). One that drops sooner keeps the 1 s, 2 s, ... backoff, so a link
// that keeps dropping is never retried more often than before.
let welcomedAt: number | null = null;
const STABLE_LINK = 10000, FAST_RETRY = 100;
// The CDP events the service reads, from its welcome (perf-data-3: phantab_cdp::EVENTS). Only these are
// forwarded; null (no welcome yet, or a service that predates the list) forwards every event. Only a
// port's first welcome sets it: a later one on the same connection changes nothing.
let forwarded: ReadonlySet<string> | null = null;
const welcomed = new WeakSet<chrome.runtime.Port>();
// THREAT-MODEL SR-90: whether this port's first welcome declared `devTools`. Without it the developer-tools
// commands are refused and their events never forwarded. `recording` holds each tab whose console
// (`Log.enable`) or network (`Network.enable`) recording the service started on its own target; only
// those tabs' developer-tools events cross, so a page never asked about sends what it sent before.
// SR-91: a trace (`Tracing.start`) is a recording too, ended by its `Tracing.tracingComplete`, whose
// stream handle `streams` keeps: `IO.read` and `IO.close` reach only that stream, on that tab.
let devTools = false;
type Recorded = 'console' | 'network' | 'trace';
const recording = new Map<number, Set<Recorded>>();
const streams = new Map<number, string>();
const recordedBy: Record<string, Recorded> = { 'Log.enable': 'console', 'Network.enable': 'network', 'Tracing.start': 'trace' };
/** The recording a developer-tools event belongs to: the trace's, the network's, or the console's. */
const recordingOf = (method: string): Recorded =>
  method.startsWith('Tracing.') ? 'trace' : method.startsWith('Network.') ? 'network' : 'console';
function stopRecording(tabId?: number): void {
  if (tabId === undefined) { recording.clear(); streams.clear(); } else { recording.delete(tabId); streams.delete(tabId); }
}
// The Chrome profile folder this copy was installed for, from the profile.json phantab install writes beside
// an extra profile's copy (`runtime/extension-profiles/<folder>/extension/`); the usual profile's copy has none. The
// hello names it, and the service checks that this profile lists exactly that folder (THREAT-MODEL SR-76).
// Nothing connects before it is read (`started`): a hello without it would claim the usual profile.
let profile: string | undefined;
let started = false;
async function readProfile(): Promise<void> {
  const found = await fetch(chrome.runtime.getURL('profile.json'))
    .then(r => (r.ok ? r.json() as Promise<unknown> : null))
    .catch(() => null) as { profile?: unknown } | null;
  if (typeof found?.profile === 'string' && found.profile) profile = found.profile;
}

/** The guard `clearForeignFrames` leaves in each frame's isolated world. */
interface ForeignFrameGuard {
  removed: string[];
  scan(el: Element): void;
  watch(root: Node): void;
  stop(): void;
}
declare global {
  var phantabForeignFrames: ForeignFrameGuard | undefined;
}

/** Arguments of a bridge op. The service is the only sender and shapes them per op. */
interface Args {
  tabId: number;
  windowId: number;
  sessionId?: string;
  method: string;
  params?: Record<string, unknown>;
  url?: string;
  left?: number;
  top?: number;
  width?: number;
  height?: number;
  shown?: boolean;
  state?: string;
  accept?: boolean;
  promptText?: string;
}
interface ServiceMessage { welcome?: unknown; events?: unknown; devTools?: unknown; refused?: unknown; id?: unknown; op?: string; args?: Args }
/** The CDP event params this worker reads itself; everything else is passed through untouched. */
interface CdpParams {
  stack?: { callFrames?: { url?: string }[] };
  url?: string;
  sessionId?: number;
  type?: string;
  stream?: string;
}
type AgentWindows = Record<string, boolean>;

// Agent windows this extension created: {windowId: shown}. Session storage
// survives worker restarts but not a browser restart.
// Kept in memory too, so a dialog in a hidden window is answered without a storage read (answerHiddenDialog).
// One storage read fills both this and minimizedKnown.
let known: AgentWindows | null = null;
// The agent's answer for a hidden tab's next dialog (answerNextDialog): used once, by the next dialog
// answerHiddenDialog answers in that tab, then the usual answers again. Dropped when the tab detaches or
// its window is shown, as the owner answers dialogs there.
const nextAnswers = new Map<number, { accept: boolean; promptText?: string }>();
let minimizedKnown: number[] | null = null;
async function loadSession(): Promise<void> {
  if (known && minimizedKnown) return;
  const stored = await chrome.storage.session.get(['windows', 'minimized']);
  known ??= (stored.windows as AgentWindows | undefined) || {};
  minimizedKnown ??= (stored.minimized as number[] | undefined) || [];
}
async function agentWindows(): Promise<AgentWindows> {
  await loadSession();
  return { ...known! };
}
async function saveAgentWindows(windows: AgentWindows): Promise<void> {
  known = { ...windows };
  await chrome.storage.session.set({ windows });
}
async function setAgentWindow(id: number, shown?: boolean): Promise<void> {
  const windows = await agentWindows();
  if (shown === undefined) delete windows[id]; else windows[id] = shown;
  await saveAgentWindows(windows);
}
// Agent windows the service hid by minimizing them (macOS, docs/MAC.md), in session storage like `windows`.
// Chrome restores the window a new tab lands in (a popup, a link to a new tab), which would put a hidden
// agent window on the owner's screen; such a window is minimized again (keepMinimized). Windows hides its
// agent windows through the OS and never minimizes them, so nothing there is recorded.
async function minimizedWindows(): Promise<Set<number>> {
  await loadSession();
  return new Set(minimizedKnown!);
}
async function setMinimized(id: number, on: boolean): Promise<void> {
  const ids = await minimizedWindows();
  if (ids.has(id) === on) return;
  if (on) ids.add(id); else ids.delete(id);
  minimizedKnown = [...ids];
  await chrome.storage.session.set({ minimized: minimizedKnown });
}
// For 2 s after a minimized agent window is made or a tab lands in it, minimizes it again whenever it reads
// otherwise, each time waiting until the minimize has settled. Stops at once if the service shows the
// window. One watch per window: a second call only extends the running one.
const watching = new Map<number, number>(); // windowId -> when its watch ends
async function keepMinimized(windowId: number): Promise<void> {
  const end = Date.now() + 2000;
  if (watching.has(windowId)) { watching.set(windowId, Math.max(end, watching.get(windowId)!)); return; }
  watching.set(windowId, end);
  try {
    while ((await minimizedWindows()).has(windowId)) {
      const { state } = await chrome.windows.get(windowId);
      // Checked again with no await before the update, so a show that came in meanwhile is never undone.
      if (!minimizedKnown!.includes(windowId)) return;
      if (state !== 'minimized') {
        await chrome.windows.update(windowId, { state: 'minimized' });
        await settledState(windowId, 'minimized');
      }
      if (Date.now() >= watching.get(windowId)!) return;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  } finally {
    watching.delete(windowId);
  }
}
// A dropped service forgets its pages: detach (or the next attach fails with
// "Another debugger is already attached") and close the hidden windows it left, through closeHiddenWindow.
// cleanup never detaches a tab of a hidden window it closes, not even after the wait: that close owns its
// tabs, Chrome ends their sessions when the tabs close, and the close detaches any left when it ends (letGo). A session cut short left the close's fallback,
// chrome.windows.remove, to raise a "Leave site?" that nobody answered (lane 4), and a stalled CDP (macOS
// minimize, docs/MAC.md) can hold a close past any wait here. chrome.windows.remove can answer before its
// dialog opens, so a detach even after the close returned could be too early. For the same reason a
// hidden window's record stays until the window is gone (windows.onRemoved), so answerHiddenDialog still
// answers there; those tabs are held for the close (Hold), no longer the service's. The other tabs are
// detached first, before any wait, so a service that reconnects within it can attach them again. Worker
// start (connect) waits at most 2 s for the closes; one still running goes on by itself, bounded by
// closeHiddenWindow's own deadlines. Only the attachments that existed when cleanup began are touched
// (their tokens), so a service that connects meanwhile keeps its own.
async function cleanup(): Promise<void> {
  const stale = new Map(attached);
  const hidden = Object.entries(await agentWindows()).filter(([, shown]) => !shown).map(([id]) => Number(id));
  const owned = new Map<number, number>(); // tab -> its hidden window
  if (hidden.length) for (const t of await chrome.tabs.query({})) if (hidden.includes(t.windowId)) owned.set(t.id!, t.windowId);
  for (const [tabId, token] of stale) {
    if (attached.get(tabId) !== token) continue; // no longer this attach: the next service's
    attached.delete(tabId);
    casting.delete(tabId);
    const windowId = owned.get(tabId);
    if (windowId !== undefined) temporary.set(tabId, { windowId }); // its window's close owns it
    else chrome.debugger.detach({ tabId }).catch(() => {});
  }
  showWorking();
  if (hidden.length) await within(Promise.allSettled(hidden.map(id => closeHiddenWindow(id))), 2000);
  const gone: number[] = [];
  for (const id of hidden) if (!await chrome.windows.get(id).then(() => true, () => false)) gone.push(id);
  // Read again: a service that connected during the wait may have recorded windows of its own.
  const windows = await agentWindows();
  for (const id of gone) delete windows[id];
  await saveAgentWindows(windows);
}
// What `p` gives within `ms`, else `late`. A rejection of `p` within it still rejects.
async function timed<T>(p: Promise<T>, ms: number, late: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([p, new Promise<T>(resolve => { timer = setTimeout(resolve, Math.max(0, ms), late); })]);
  } finally {
    clearTimeout(timer);
  }
}
// Whether `p` settled within `ms`. A rejection of `p` within it still rejects.
const within = (p: Promise<unknown>, ms: number): Promise<boolean> => timed(p.then(() => true), ms, false);

// Hidden agent windows make no sound: media a page plays there would come from nowhere the owner can see.
// A shown window has its sound back. Muting is not visible to the page.
async function hush(tabId: number, muted: boolean): Promise<void> { await chrome.tabs.update(tabId, { muted }); }
function post(message: object): void { try { port?.postMessage(message); } catch {} }
// The owner's sign that agents are working, with or without Chrome's debugging bar (extension/README.md).
function showWorking(): void {
  const working = attached.size + temporary.size > 0;
  chrome.action.setBadgeText({ text: working ? 'PT' : '' }).catch(() => {});
  chrome.action.setTitle({ title: working ? 'phantab: agents working, click to stop' : 'phantab bridge: no agent working' }).catch(() => {});
}
function retry(fast = false): void {
  if (port || timer) return;
  // Stays under the 30 s idle termination; chrome.alarms is the backstop when a timer dies with the worker.
  timer = setTimeout(() => { timer = null; connect(); }, fast ? FAST_RETRY : delay);
  if (!fast) delay = Math.min(delay * 2, 20000);
}
function connect(): void {
  if (port || !started) return;
  clearTimeout(timer ?? undefined); timer = null;
  let p: chrome.runtime.Port;
  try { p = chrome.runtime.connectNative(HOST); } catch { retry(); return; }
  port = p; forwarded = null; welcomedAt = null; devTools = false; stopRecording();
  p.onMessage.addListener((message: ServiceMessage) => receive(p, message));
  p.onDisconnect.addListener(() => {
    // Reading lastError marks it checked, so Chrome logs no "Unchecked runtime.lastError" for a host that is missing or exits.
    void chrome.runtime.lastError;
    if (port !== p) return;
    const stable = welcomedAt !== null && Date.now() - welcomedAt >= STABLE_LINK;
    port = null; forwarded = null; welcomedAt = null; devTools = false; stopRecording(); cleanup().catch(() => {}); retry(stable);
  });
  p.postMessage({ hello: { version: chrome.runtime.getManifest().version, protocol: PROTOCOL, instance, ...(profile ? { profile } : {}) } });
}

async function normalWindow(): Promise<number | undefined> {
  const agents = await agentWindows();
  const usable = (w: chrome.windows.Window | null | undefined): w is chrome.windows.Window =>
    !!w && w.type === 'normal' && !w.incognito && !(String(w.id) in agents);
  const last = await chrome.windows.getLastFocused({ windowTypes: ['normal'] }).catch(() => null);
  if (usable(last)) return last.id;
  return (await chrome.windows.getAll({ windowTypes: ['normal'] })).find(usable)?.id;
}
const WINDOW_STATES = new Set<string>(['normal', 'maximized', 'minimized']);
// A state change finishes after chrome.windows.update resolves (macOS animates it), so the state is read
// back until it matches: at most 2 s, every 50 ms. The last state read is the answer either way.
async function settledState(windowId: number, want: string): Promise<string | undefined> {
  const deadline = Date.now() + 2000;
  for (;;) {
    const { state } = await chrome.windows.get(windowId);
    if (state === want || Date.now() >= deadline) return state;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
}
// chrome.windows.remove runs each page's beforeunload, and on macOS Chrome restores a minimized window to
// draw its "Leave site?" (docs/MAC.md). CDP's Target.closeTarget closes a page without running it (macOS
// control, Chrome 156: the window stayed minimized and no dialog opened). Chrome takes it from an extension
// only for the tab it is sent to ("Not allowed" for another tab's target), so a tab this extension is not
// attached to, such as a popup, is attached for its close (`temporary`), with the Page domain on. The
// window's tabs are closed in parallel. A tab no debugger may attach to, one whose close was refused, or
// one still there 2 s after its close was sent goes with the window through chrome.windows.remove, which
// may still ask, unless the window was shown meanwhile: then it is the owner's, and is left open (no close
// is sent to it either once its record reads shown). Every
// session is kept through that fallback, so answerHiddenDialog answers there (the service turned the Page
// domain on in the agent's tab); the tab's close ends it. The sessions held for the close (Hold) are
// detached when it ends: at once when no fallback follows or it fails, else once the window is gone, at
// most 10 s later. A
// close that has not replied in 2 s (CDP stalls around a macOS minimize) counts as sent: the page may
// still go by itself. Every step is bounded: a Page.enable and a close's reply are each waited for 2 s at
// most and no close is sent after 4 s, the tabs then get 2 s to go, and chrome.windows.remove 2 s more:
// about 8 s in all, under the service's 15 s for an op (bridge.rs). A tab list or target list that cannot
// be read leaves the window to the fallback.
// One close per window: a second caller (a cleanup after another, closeTab during one) gets the first's
// close. After a fallback the window stays claimed until it is gone, at most 10 s: chrome.windows.remove
// resolves before its "Leave site?" is answered, and a second close then would find the popup's session
// taken and could only raise a dialog of its own.
const closingWindows = new Map<number, Promise<void>>();
interface Claim { over: boolean } // whether a window's close has ended
function closeHiddenWindow(windowId: number): Promise<void> {
  const running = closingWindows.get(windowId);
  if (running) return running;
  const claim: Claim = { over: false };
  const close = closeQuietly(windowId, claim);
  const done = close.then(() => {});
  closingWindows.set(windowId, done);
  const release = () => {
    claim.over = true;
    if (closingWindows.get(windowId) === done) closingWindows.delete(windowId);
    letGo(windowId);
  };
  close.then(fellBack => fellBack ? windowGone(windowId, 10000) : undefined).finally(release).catch(() => {});
  return done;
}
const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const windowOpen = (windowId: number) => chrome.windows.get(windowId).then(() => true, () => false);
async function windowGone(windowId: number, ms: number): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline && await windowOpen(windowId)) await pause(50);
}
// Whether the fallback, chrome.windows.remove, ran: the window may then still be asking.
async function closeQuietly(windowId: number, claim: Claim): Promise<boolean> {
  const sentBy = Date.now() + 4000;
  const targets = await timed(chrome.debugger.getTargets().catch(() => []), sentBy - Date.now(), []);
  const tabs = await timed(chrome.tabs.query({ windowId }).catch(() => []), sentBy - Date.now(), []);
  const sent = await Promise.all(tabs.map(({ id: tabId }) => {
    const targetId = targets.find(t => t.tabId === tabId)?.id;
    return tabId !== undefined && targetId !== undefined ? closeTarget(tabId, targetId, windowId, sentBy, claim) : false;
  }));
  const closing = new Set(tabs.filter((_, i) => sent[i]).map(t => t.id));
  const deadline = Date.now() + 2000;
  // The close finishes after the reply. The window goes by itself with its last tab. Without the deadline a
  // close that replied but never landed would hold this loop for good. Tabs that could not be read count
  // as left.
  const read = () => timed<chrome.tabs.Tab[] | undefined>(chrome.tabs.query({ windowId }).catch(() => undefined), deadline - Date.now(), undefined);
  let left = await read();
  while (left?.some(t => closing.has(t.id)) && Date.now() < deadline) {
    await pause(20);
    left = await read();
  }
  if (left?.length === 0) return false;
  // Only a recorded show is the owner's: a record already gone means the window went, and the remove says so.
  if ((await agentWindows())[windowId] === true) throw Error(`Window ${windowId} was shown while it closed: left open for the owner.`);
  try {
    await within(chrome.windows.remove(windowId), 2000);
  } catch (e) {
    if (await windowOpen(windowId)) throw e;
    return false; // gone: no "Leave site?" can follow
  }
  return true;
}
// Sends tabId's Target.closeTarget by `by`, attaching first if no session is open: whether it was sent and
// not refused. An attach that lands after the window's close ended is cut at once.
async function closeTarget(tabId: number, targetId: string, windowId: number, by: number, claim: Claim): Promise<boolean> {
  let sent = false, refused = false;
  const run = (async () => {
    if (!attached.has(tabId) && !temporary.has(tabId)) {
      const hold: Hold = { windowId };
      const attaching = chrome.debugger.attach({ tabId }, '1.3').then(() => {
        if (claim.over) { chrome.debugger.detach({ tabId }).catch(() => {}); return; }
        temporary.set(tabId, hold);
        showWorking();
      });
      attaching.catch(() => {});
      if (!await within(attaching, by - Date.now())) return;
      // Page.javascriptDialogOpening comes only with the Page domain on, so a "Leave site?" the fallback
      // raises here is answered like any other (answerHiddenDialog). A failed or stalled enable does not
      // hold the close: that only loses the answer to a dialog the close may never raise.
      await within(chrome.debugger.sendCommand({ tabId }, 'Page.enable').catch(() => {}), Math.min(2000, by - Date.now()));
    }
    // Given up on: nothing is sent after `by`, nor to a window shown meanwhile, which is the owner's. Read
    // with no await before the send, so a show that came in is never undone. A missing record is not shown.
    if (Date.now() >= by || known?.[windowId] === true) return;
    sent = true;
    // CDP's `success` is deprecated and always true: a refusal is an error.
    const closed = chrome.debugger.sendCommand({ tabId }, 'Target.closeTarget', { targetId }).catch(() => { refused = true; });
    await within(closed, Math.min(2000, by - Date.now()));
  })();
  await within(run.catch(() => {}), by - Date.now());
  return sent && !refused;
}
// Detaches the sessions held for a window's close, once it has ended.
function letGo(windowId: number): void {
  for (const [tabId, hold] of temporary) {
    if (hold.windowId !== windowId) continue;
    temporary.delete(tabId);
    chrome.debugger.detach({ tabId }).catch(() => {});
  }
  showWorking();
}
// A tab held for a window's close is not the service's (SR-22), and is refused like a detached one.
function ownTab(tabId: number): void {
  if (temporary.has(tabId)) throw Error(`Debugger is not attached to the tab with id: ${tabId}.`);
}
const tabInfo = (t: chrome.tabs.Tab) => ({ tabId: t.id, windowId: t.windowId, title: t.title, url: t.url });
const ops: Record<string, (args: Args) => unknown> = {
  ping: () => ({}),
  async attach({ tabId }) { await chrome.debugger.attach({ tabId }, '1.3'); attached.set(tabId, ++attaches); foreign.delete(tabId); stopRecording(tabId); showWorking(); return {}; },
  async detach({ tabId }) { ownTab(tabId); attached.delete(tabId); casting.delete(tabId); stopRecording(tabId); showWorking(); await chrome.debugger.detach({ tabId }); return {}; },
  // Only the methods phantab-cdp needs (SR-20): never cookies, storage, network or browser-wide commands.
  // The developer-tools part (SR-90) only on a connection whose welcome declared `devTools`.
  send: async ({ tabId, sessionId, method, params }) => {
    ownTab(tabId);
    const dev = typeof method === 'string' && DEVTOOLS_METHODS.has(method);
    if (typeof method !== 'string' || (!CDP_METHODS.has(method) && !dev)) throw Error('CDP method not allowed: ' + method);
    if (dev && !devTools) throw Error('CDP method not allowed: ' + method + ' (a developer tool; the service did not turn on devTools)');
    // phantab's isolated world never asks for universal access (Chrome's spelling), which would let it read
    // any origin with the owner's cookies.
    const universal = params?.grantUniveralAccess;
    if (universal != null && universal !== false) throw Error('CDP method not allowed: ' + method + ' with grantUniveralAccess');
    // SR-91: a stream read or close only for the tab's own finished trace.
    if (method === 'IO.read' || method === 'IO.close') {
      if (sessionId || !streams.has(tabId) || params?.handle !== streams.get(tabId)) throw Error('CDP method not allowed: ' + method + " (not this tab's trace)");
      if (method === 'IO.close') streams.delete(tabId);
    }
    // A recording starts on the tab's own target only, and is marked before the command so no event it
    // causes is dropped; a failed start unmarks it again.
    const starts = sessionId ? undefined : recordedBy[method];
    if (starts) { if (!recording.has(tabId)) recording.set(tabId, new Set()); recording.get(tabId)!.add(starts); }
    try { return await chrome.debugger.sendCommand(sessionId ? { tabId, sessionId } : { tabId }, method, params); }
    catch (e) { if (starts) recording.get(tabId)?.delete(starts); throw e; }
  },
  // A window hidden before its first paint stops rendering, and screenshots then hang. A running screencast
  // (tiny, every 60th frame, each acked below) keeps it producing frames while hidden.
  async keepRendering({ tabId }) {
    ownTab(tabId);
    await chrome.debugger.sendCommand({ tabId }, 'Page.startScreencast', { format: 'jpeg', quality: 1, maxWidth: 32, maxHeight: 32, everyNthFrame: 60 });
    casting.add(tabId);
    return {};
  },
  // On Windows, never state: 'minimized': Windows restores that to normal, on screen, and the window hook
  // needs a known place and size. On macOS minimized is how a window stays hidden (docs/MAC.md), so the
  // service asks for it there. Chrome refuses bounds together with minimized, and they are not set later
  // either: the viewport is emulated, show maximizes, and changing the bounds of a minimized window is not
  // known to keep it minimized on every platform, which would put it on the owner's screen.
  // A minimized window cannot be created minimized from an extension (macOS lane 4 and a control, Chrome
  // 156; `windows_api.cc`, `widget.cc`): with `focused: false` Chrome shows it through ShowInactive, which
  // drops the minimized state, and unset, `focused` defaults to true and the activation cancels the
  // asynchronous miniaturize. Either way it lands normal, on screen. So it is created inactive, which
  // takes no focus from the owner, then minimized, and the reply waits until it reads minimized. It shows
  // for about a second first (docs/MAC.md). CDP's createTarget minimizes in the same task, before the
  // first frame, but an extension cannot send it.
  async createWindow({ url, left, top, width, height, state }) {
    if (state !== undefined && state !== 'minimized') throw Error(`createWindow takes no state ${JSON.stringify(state)}; only 'minimized'.`);
    const w = (await chrome.windows.create(state === 'minimized' ? { url, focused: false } : { url, focused: false, left, top, width, height }))!;
    // macOS lane 4: the third agent window of a run read normal soon after it was made, before its page
    // did anything. So a minimize that does not settle is asked for again, and the window is watched for a
    // late restore (keepMinimized).
    if (state === 'minimized') {
      for (let tries = 0; tries < 3; tries++) {
        await chrome.windows.update(w.id!, { state });
        if (await settledState(w.id!, state) === state) break;
      }
      await setMinimized(w.id!, true);
      keepMinimized(w.id!).catch(() => {});
    }
    await setAgentWindow(w.id!, false);
    await hush(w.tabs![0]!.id!, true).catch(() => {});
    return { windowId: w.id, tabId: w.tabs![0]!.id };
  },
  // Owner-facing tabs open in one of the owner's own windows, never a hidden agent window.
  async createTab({ url }) {
    const windowId = await normalWindow();
    if (windowId === undefined) { const w = (await chrome.windows.create({ url, focused: true }))!; return { windowId: w.id, tabId: w.tabs![0]!.id }; }
    const t = await chrome.tabs.create({ windowId, url, active: true });
    await chrome.windows.update(windowId, { focused: true });
    return { windowId, tabId: t.id };
  },
  tabs: async () => (await chrome.tabs.query({})).map(tabInfo),
  tab: async ({ tabId }) => tabInfo(await chrome.tabs.get(tabId)),
  // A hidden window goes with its page, so a tab the page opened there (a popup, popupsAsTabs) is not
  // left running where nobody can see or close it, and with no "Leave site?" (closeHiddenWindow). A window
  // the owner was shown keeps its other tabs, and its page may still ask the owner.
  async closeTab({ tabId }) {
    const { windowId } = await chrome.tabs.get(tabId);
    if ((await agentWindows())[windowId] === false) await closeHiddenWindow(windowId);
    else await chrome.tabs.remove(tabId);
    return {};
  },
  async focus({ tabId }) {
    const t = (await chrome.tabs.update(tabId, { active: true }))!;
    await chrome.windows.update(t.windowId, { focused: true });
    return {};
  },
  // Show and hide on macOS, where agent windows are minimized rather than hidden by the OS (docs/MAC.md).
  // The owner's own windows are never touched. Shown-tracking stays with markShown, which the service
  // calls next.
  async windowState({ windowId, state }) {
    if (!WINDOW_STATES.has(state ?? '')) throw Error(`Unknown window state: ${state}`);
    if (!(String(windowId) in await agentWindows())) throw Error(`Window ${windowId} is not an agent window; its state is left alone.`);
    const want = state as `${chrome.windows.WindowState}`;
    // Recorded before the change, so keepMinimized never fights a show.
    await setMinimized(windowId, want === 'minimized');
    if (want === 'minimized') {
      await chrome.windows.update(windowId, { state: want });
    } else {
      // Chrome refuses to maximize a minimized or fullscreen window ("restore it to normal state first"),
      // and the restore is asynchronous, so the maximize waits until the window really is normal.
      if (want === 'maximized' && ['minimized', 'fullscreen'].includes((await chrome.windows.get(windowId)).state ?? '')) {
        await chrome.windows.update(windowId, { state: 'normal' });
        await settledState(windowId, 'normal');
      }
      await chrome.windows.update(windowId, { state: want, focused: true });
    }
    return { state: await settledState(windowId, want) };
  },
  async markShown({ windowId, shown }) {
    if (!(String(windowId) in await agentWindows())) return {};
    await setAgentWindow(windowId, !!shown);
    if (shown) for (const t of await chrome.tabs.query({ windowId })) nextAnswers.delete(t.id!);
    if (shown) await setMinimized(windowId, false);
    for (const t of await chrome.tabs.query({ windowId })) hush(t.id!, !shown).catch(() => {});
    // The owner's own autofill menu works again in a window handed to them.
    // Chrome serialises func into each frame: it must close over nothing. Own property only, as in
    // clearForeignFrames: <div id=phantabForeignFrames> is otherwise what the name reads.
    if (shown) for (const t of await chrome.tabs.query({ windowId })) chrome.scripting.executeScript({ target: { tabId: t.id!, allFrames: true }, func: () => { if (Object.hasOwn(globalThis, 'phantabForeignFrames')) globalThis.phantabForeignFrames!.stop(); } }).catch(() => {});
    return {};
  },
  // The answer for the next dialog in a hidden agent window's tab (`["dialog", ...]` steps). Dialogs the
  // owner can see are his to answer, so any other tab is refused.
  async answerNextDialog({ tabId, accept, promptText }) {
    const t = await chrome.tabs.get(tabId);
    if ((await agentWindows())[t.windowId] !== false) throw Error(`Tab ${tabId} is not in a hidden agent window; its dialogs are the owner's to answer.`);
    nextAnswers.set(tabId, typeof promptText === 'string' ? { accept: !!accept, promptText } : { accept: !!accept });
    return {};
  },
  // Removes other extensions' frames, never their host elements, and only where the owner
  // cannot see them. A password manager takes its elements out on blur and puts them back on
  // focus, so a one-time sweep misses them: a guard stays for the document's life and empties
  // each element as it is taken out. A frame added while the guard watches is removed too, but
  // it has already started loading by then, so that one still detaches the agent once.
  // executeScript across frames turns a throw into a null result with no error, which reads
  // as "nothing found"; the script reports its own failure so the caller can name it.
  async clearForeignFrames({ tabId }) {
    const t = await chrome.tabs.get(tabId);
    if ((await agentWindows())[t.windowId] !== false) throw Error(`Tab ${tabId} is not in a hidden agent window; its frames are left alone.`);
    // Chrome serialises func into each frame: it must close over nothing, so `own` arrives as an argument.
    const results = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, args: [chrome.runtime.id], func: (own: string) => {
      try {
        // Through the prototypes, never an element's or the document's own properties: a <form>'s
        // fields shadow those (<input name=children>), and so does <img name=documentElement>.
        const get = (proto: object, key: string) => Object.getOwnPropertyDescriptor(proto, key)!.get!;
        // The guard is the global's own property, never a lookup by name: until the first pass sets it,
        // the name reaches the window's named properties, and <div id=phantabForeignFrames> is that.
        const kept = Object.hasOwn(globalThis, 'phantabForeignFrames') ? globalThis.phantabForeignFrames : undefined;
        const guard: ForeignFrameGuard = kept || (globalThis.phantabForeignFrames = (() => {
          const childrenOf = get(Element.prototype, 'children'), tagOf = get(Element.prototype, 'tagName'), typeOf = get(Node.prototype, 'nodeType');
          const observed = new WeakSet<Node>();
          const scan = (el: Element): void => {
            // The API throws on anything but an HTMLElement; a page's first <svg> would end the scan.
            const shadow = el instanceof HTMLElement ? chrome.dom.openOrClosedShadowRoot(el) : null;
            if (shadow) { watch(shadow); for (const child of [...shadow.children]) scan(child); }
            if (/^(IFRAME|FRAME|EMBED|OBJECT)$/.test(tagOf.call(el) as string)) {
              const src = (el as HTMLIFrameElement).src || (el as HTMLObjectElement).data || '';
              if (src.startsWith('chrome-extension://') && !src.startsWith(`chrome-extension://${own}/`)) { guard.removed.push(src.split(/[?#]/)[0]!); el.remove(); return; }
            }
            for (const child of [...childrenOf.call(el) as HTMLCollection]) scan(child);
          };
          const observer = new MutationObserver(records => { for (const r of records) {
            if (r.type === 'attributes') { scan(r.target as Element); continue; }
            for (const n of [...r.addedNodes, ...r.removedNodes]) if (typeOf.call(n) === 1) scan(n as Element);
          } });
          const watch = (root: Node): void => { if (observed.has(root)) return; observed.add(root); observer.observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'data'] }); };
          return { removed: [], scan, watch, stop() { observer.disconnect(); delete globalThis.phantabForeignFrames; } };
        })());
        guard.watch(document); guard.scan(get(Document.prototype, 'documentElement').call(document) as Element);
        const removed = guard.removed; guard.removed = []; return { removed };
      } catch (e) { return { removed: [] as string[], error: `${location.origin}: ${(e as Error).message}` }; }
    } });
    const found = results.map(r => r.result).filter(r => !!r);
    return { removed: found.flatMap(r => r.removed), errors: found.flatMap(r => 'error' in r && r.error ? [r.error] : []) };
  },
};
/** A welcome's `events`: a non-empty list of method names, or null (forward everything) for anything else. */
function eventList(events: unknown): ReadonlySet<string> | null {
  return Array.isArray(events) && events.length > 0 && events.every(e => typeof e === 'string') ? new Set(events as string[]) : null;
}
async function receive(p: chrome.runtime.Port, message: ServiceMessage): Promise<void> {
  if (message.welcome) {
    delay = 1000;
    if (port === p) welcomedAt = Date.now();
    if (port === p && !welcomed.has(p)) { welcomed.add(p); forwarded = eventList(message.events); devTools = message.devTools === true; }
    return;
  }
  if (message.refused) { console.warn('phantab service refused this bridge:', message.refused); delay = 20000; return; }
  const { id, op, args } = message;
  try {
    const run = op !== undefined && Object.hasOwn(ops, op) ? ops[op] : undefined;
    if (!run) throw Error('Unknown bridge operation: ' + op);
    const result = await run(args || ({} as Args));
    if (port === p) p.postMessage({ id, result: result ?? {} });
  } catch (e) { if (port === p) p.postMessage({ id, error: (e as Error | undefined)?.message || String(e) }); }
}

const extensionHost = (url: string | undefined): string | null => { const m = /^chrome-extension:\/\/([^/]+)\//.exec(url || ''); return m && m[1] !== chrome.runtime.id ? m[1]! : null; };
function watchForeign(tabId: number, method: string, params: CdpParams): void {
  if (method === 'Page.frameAttached') {
    // A dynamic web-accessible URL hides the extension ID; the inserting content script's stack still names it.
    const id = (params.stack?.callFrames || []).map(f => extensionHost(f.url)).find(Boolean);
    if (id) foreign.set(tabId, { id, url: null, at: 0 });
  } else if (method === 'Page.frameRequestedNavigation' || method === 'Page.frameStartedNavigating') {
    const host = extensionHost(params.url); if (!host) return;
    const known = foreign.get(tabId);
    foreign.set(tabId, { id: known?.id || host, url: params.url!.split(/[?#]/)[0]!, at: Date.now() });
  }
}
// Chrome draws a hidden window's "Leave site?" as a window of its own, on the owner's screen with nothing
// behind it, and the close or navigation that raised it waits until someone answers. So a dialog in a hidden
// agent window is answered here, before it is drawn: answered by the service instead, one hop further, it
// stayed on screen for about 15 ms. Leave and alert are accepted, confirm and prompt dismissed; the service
// reports each one to the agent. Dialogs the owner can see (his windows, a shown agent window) are his.
// On macOS Chrome also restores a minimized window to show a dialog (macOS lane 4, window server: on
// screen about 1.5 s), so a minimized agent window is watched and minimized again (keepMinimized). The
// restore itself is not prevented. When the agent closes a hidden page there is normally no "Leave site?"
// to answer: closeHiddenWindow closes it without running beforeunload (docs/MAC.md). Its fallback may
// raise one, and keeps the tab's session and the window's record so it is answered here.
async function answerHiddenDialog(source: chrome.debugger.DebuggerSession, type: string | undefined): Promise<void> {
  const windowId = (await chrome.tabs.get(source.tabId!)).windowId;
  if ((await agentWindows())[windowId] !== false) return;
  const kept = (await minimizedWindows()).has(windowId) ? keepMinimized(windowId) : Promise.resolve();
  const target = source.sessionId ? { tabId: source.tabId, sessionId: source.sessionId } : { tabId: source.tabId };
  const next = nextAnswers.get(source.tabId!);
  nextAnswers.delete(source.tabId!);
  const answer = next ?? { accept: type === 'beforeunload' || type === 'alert' };
  await chrome.debugger.sendCommand(target, 'Page.handleJavaScriptDialog', answer);
  await kept;
}
chrome.debugger.onEvent.addListener((source, method, params) => {
  const tabId = source.tabId!;
  watchForeign(tabId, method, (params || {}) as CdpParams);
  if (method === 'Page.javascriptDialogOpening') answerHiddenDialog(source, (params as CdpParams).type).catch(() => {});
  if (temporary.has(tabId)) return; // not the service's
  if (method === 'Page.screencastFrame' && casting.has(tabId)) {
    chrome.debugger.sendCommand({ tabId }, 'Page.screencastFrameAck', { sessionId: (params as CdpParams).sessionId }).catch(() => {});
    return;
  }
  // SR-90: an ...ExtraInfo event carries a request's raw headers, cookies included: never forwarded.
  if (method.endsWith('ExtraInfo')) return;
  // A developer-tools event only for a tab the service is recording, on its own target, with devTools on.
  if (DEVTOOLS_EVENTS.has(method)) {
    if (devTools && !source.sessionId && recording.get(tabId)?.has(recordingOf(method))) {
      // A finished trace stops its recording, and leaves its stream for IO.read (SR-91).
      if (method === 'Tracing.tracingComplete') {
        recording.get(tabId)!.delete('trace');
        const stream = (params as CdpParams | undefined)?.stream;
        if (typeof stream === 'string') streams.set(tabId, stream);
      }
      post({ event: 'cdp', tabId, method, params });
    }
    return;
  }
  if (forwarded && !forwarded.has(method)) return; // read by nobody: animations, workers, ...
  post({ event: 'cdp', tabId, sessionId: source.sessionId, method, params });
});
chrome.debugger.onDetach.addListener((source, reason) => {
  const tabId = source.tabId!, at = Date.now();
  const held = temporary.delete(tabId);
  attached.delete(tabId); casting.delete(tabId); nextAnswers.delete(tabId); stopRecording(tabId); showWorking();
  if (held) { foreign.delete(tabId); return; } // not the service's: nothing to report
  // A closing tab detaches first; its removal usually follows within a few ms.
  setTimeout(async () => {
    const tabOpen = await chrome.tabs.get(tabId).then(() => true, () => false);
    const f = foreign.get(tabId); foreign.delete(tabId);
    post({ event: 'detach', tabId, reason, tabOpen, foreign: f?.url && at - f.at <= 1000 ? { id: f.id, url: f.url } : null });
  }, 200);
});
// What the Cancel on Chrome's bar does: the agents lose control at once. An extension's own detach fires no
// onDetach, so the event is posted here. A session in a window whose hidden close is running is held for
// that close (Hold) so the close stays quiet, and ends with it; every other one is detached now.
chrome.action.onClicked.addListener(() => {
  for (const tabId of [...attached.keys()]) {
    attached.delete(tabId); casting.delete(tabId); foreign.delete(tabId); stopRecording(tabId);
    post({ event: 'detach', tabId, reason: 'canceled_by_user' });
    const hold: Hold = {};
    temporary.set(tabId, hold);
    keepForClose(tabId, hold).catch(() => {});
  }
  for (const [tabId, hold] of temporary) {
    if (hold.windowId === undefined || closingWindows.has(hold.windowId)) continue;
    temporary.delete(tabId);
    chrome.debugger.detach({ tabId }).catch(() => {});
  }
  showWorking();
});
async function keepForClose(tabId: number, hold: Hold): Promise<void> {
  const windowId = await chrome.tabs.get(tabId).then(t => t.windowId, () => undefined);
  if (temporary.get(tabId) !== hold) return; // ended meanwhile
  if (windowId !== undefined && closingWindows.has(windowId)) { hold.windowId = windowId; return; }
  temporary.delete(tabId);
  chrome.debugger.detach({ tabId }).catch(() => {});
  showWorking();
}
// A tab a hidden page opens (a link to a new tab, or a popup, which phantab-cdp's popupsAsTabs turns into
// a tab) lands in the hidden window, silent like the rest of it. The agent's tab is made active again:
// a background tab stops producing frames, and a screenshot then waits for one that never comes.
chrome.tabs.onCreated.addListener(tab => { quietNewTab(tab).catch(() => {}); });
// On macOS, Chrome restores the minimized window too, so it is minimized again (keepMinimized).
async function quietNewTab(tab: chrome.tabs.Tab): Promise<void> {
  if (tab.id === undefined || (await agentWindows())[tab.windowId] !== false) return;
  const kept = (await minimizedWindows()).has(tab.windowId) ? keepMinimized(tab.windowId) : Promise.resolve();
  await hush(tab.id, true);
  if (tab.active && tab.openerTabId !== undefined && attached.has(tab.openerTabId)) await chrome.tabs.update(tab.openerTabId, { active: true });
  await kept;
}
chrome.tabs.onRemoved.addListener(tabId => { foreign.delete(tabId); stopRecording(tabId); post({ event: 'removed', tabId }); });
chrome.windows.onRemoved.addListener(windowId => { setAgentWindow(windowId).then(() => setMinimized(windowId, false)).catch(() => {}); });
chrome.runtime.onStartup.addListener(connect);
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'reconnect') connect(); });
void chrome.alarms.create('reconnect', { periodInMinutes: 0.5 });
// A fresh worker has no service link, so windows recorded by an earlier worker are orphans.
void Promise.all([cleanup().catch(() => {}), readProfile()]).finally(() => { started = true; connect(); });
