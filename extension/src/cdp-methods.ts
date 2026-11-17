// THREAT-MODEL SR-20: the only CDP methods the bridge `send` op relays to chrome.debugger. They are
// exactly what phantab-cdp sends on the relay path (crates/phantab-cdp/src), plus Target detach, and
// the developer-tools part below. Anything else (any other Network.*, Storage.*, Fetch.*, Browser.*,
// Security.*, Target.createBrowserContext, Page.setDownloadBehavior, an unknown name) is refused here
// and in the service.
//
// One list, two readers: the service parses this file at build time
// (crates/phantab/src/cdp_methods.rs), so keep one quoted name per line, in this form, and nothing
// else in quotes. Adding a method: add it here; the Rust and npm tests then check it is not banned.
export const CDP_METHODS: ReadonlySet<string> = new Set([
  'DOM.describeNode',
  'DOM.getBoxModel',
  'DOM.getFrameOwner',
  'DOM.getNodeForLocation',
  'DOM.resolveNode',
  'DOM.scrollIntoViewIfNeeded',
  'DOM.setFileInputFiles',
  'Emulation.clearDeviceMetricsOverride',
  'Emulation.setDeviceMetricsOverride',
  'Emulation.setFocusEmulationEnabled',
  'Emulation.setTouchEmulationEnabled',
  'Input.dispatchKeyEvent',
  'Input.dispatchMouseEvent',
  'Input.insertText',
  'Page.addScriptToEvaluateOnNewDocument',
  'Page.captureScreenshot',
  'Page.close',
  'Page.createIsolatedWorld',
  'Page.enable',
  'Page.getFrameTree',
  'Page.getLayoutMetrics',
  'Page.getNavigationHistory',
  'Page.navigate',
  'Page.navigateToHistoryEntry',
  'Page.reload',
  'Page.setLifecycleEventsEnabled',
  'Runtime.callFunctionOn',
  'Runtime.enable',
  'Runtime.releaseObject',
  'Runtime.runIfWaitingForDebugger',
  'Target.detachFromTarget',
  'Target.setAutoAttach',
]);

// THREAT-MODEL SR-90: the developer-tools commands, a second part of the list. They are relayed only on
// a connection whose welcome declared `devTools` (background.ts), and the service sends them only while
// its `devTools` setting is on. No cookie command and no other Network.* method belongs here.
export const DEVTOOLS_METHODS: ReadonlySet<string> = new Set([
  'Log.enable',
  'Network.enable',
  'Network.getResponseBody',
  'Runtime.terminateExecution',
]);

// THREAT-MODEL SR-90: the events a developer-tools recording reads, forwarded only for a tab whose
// recording the service started. An `...ExtraInfo` event is never forwarded, whatever any list says.
// The service keeps the same list as `phantab_cdp::DEVTOOLS_EVENTS`; the Rust tests keep the two equal.
export const DEVTOOLS_EVENTS: ReadonlySet<string> = new Set([
  'Log.entryAdded',
  'Network.loadingFailed',
  'Network.loadingFinished',
  'Network.requestWillBeSent',
  'Network.responseReceived',
  'Runtime.consoleAPICalled',
  'Runtime.exceptionThrown',
]);
