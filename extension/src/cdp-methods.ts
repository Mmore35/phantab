// THREAT-MODEL SR-20: the only CDP methods the bridge `send` op relays to chrome.debugger. They are
// exactly what phantab-cdp sends on the relay path (crates/phantab-cdp/src), plus Target detach.
// Anything else (Network.*, Storage.*, Fetch.*, Browser.*, Security.*, Target.createBrowserContext,
// Page.setDownloadBehavior, an unknown name) is refused here and in the service.
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
  'Page.navigate',
  'Page.setLifecycleEventsEnabled',
  'Runtime.callFunctionOn',
  'Runtime.enable',
  'Runtime.releaseObject',
  'Runtime.runIfWaitingForDebugger',
  'Target.detachFromTarget',
  'Target.setAutoAttach',
]);
