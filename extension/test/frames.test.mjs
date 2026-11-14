import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { startWorker, EXTENSION_ID } from './fake-chrome.mjs';

async function workerWithWindows() {
  const fake = await startWorker({ windows: [{ id: 1, lastFocused: true }], tabs: [{ id: 7, windowId: 1 }] });
  const hidden = (await fake.op('createWindow', { url: 'about:blank' })).result;
  const shown = (await fake.op('createWindow', { url: 'about:blank' })).result;
  await fake.op('markShown', { windowId: shown.windowId, shown: true });
  return { fake, hidden, shown };
}

test('clearForeignFrames refuses tabs outside a hidden agent window', async () => {
  const { fake, shown } = await workerWithWindows();
  const before = fake.callsOf('scripting.executeScript').length;
  assert.deepEqual(await fake.op('clearForeignFrames', { tabId: 7 }, 1), { id: 1, error: 'Tab 7 is not in a hidden agent window; its frames are left alone.' });
  assert.deepEqual(await fake.op('clearForeignFrames', { tabId: shown.tabId }, 2), { id: 2, error: `Tab ${shown.tabId} is not in a hidden agent window; its frames are left alone.` });
  assert.equal(fake.callsOf('scripting.executeScript').length, before);
});

test('clearForeignFrames injects into every frame and gathers removals and per-frame failures', async () => {
  const { fake, hidden } = await workerWithWindows();
  fake.state.executeResults = [
    { frameId: 0, result: { removed: ['chrome-extension://a/menu.html'] } },
    { frameId: 1, result: null },
    { frameId: 2, result: { removed: ['chrome-extension://b/x.html'], error: undefined } },
    { frameId: 3, result: { removed: [], error: 'https://x.test: boom' } },
  ];
  const reply = await fake.op('clearForeignFrames', { tabId: hidden.tabId }, 1);
  assert.deepEqual(reply, { id: 1, result: { removed: ['chrome-extension://a/menu.html', 'chrome-extension://b/x.html'], errors: ['https://x.test: boom'] } });
  const [injection] = fake.callsOf('scripting.executeScript').at(-1);
  assert.deepEqual(injection.target, { tabId: hidden.tabId, allFrames: true });
  assert.deepEqual(injection.args, [EXTENSION_ID]);
});

// A minimal DOM, enough for the guard: elements with children, shadow roots, MutationObserver. As in a
// browser, the properties the guard reads are getters on the prototypes, and `clobber` gives an element
// own properties that shadow them, as a <form>'s fields do.
function page({ failShadow = false, named = false } = {}) {
  // `named`: <div id=phantabForeignFrames>, which a window's named properties give for that name until
  // the global has an own property of it. Here the sandbox's prototype stands in for them.
  const context = named ? Object.create({ phantabForeignFrames: { tagName: 'DIV', id: 'phantabForeignFrames' } }) : {};
  vm.createContext(context);
  vm.runInContext(`
    class Node { constructor() { this.kids = []; this.parent = null; }
      get nodeType() { return 1; }
      append(...kids) { for (const k of kids) { k.parent = this; this.kids.push(k); } return this; }
      remove() { const i = this.parent.kids.indexOf(this); this.parent.kids.splice(i, 1); this.parent = null; } }
    class Element extends Node { constructor(tagName, props = {}) { super(); this.tag = tagName; Object.assign(this, props); }
      get tagName() { return this.tag; } get children() { return this.kids; } }
    class HTMLElement extends Element {}
    class SVGElement extends Element {}
    class ShadowRoot extends Node { get nodeType() { return 11; } get children() { return this.kids; } }
    class Document { constructor(root) { this.root = root; } get documentElement() { return this.root; } }
    globalThis.doc = root => new Document(root);
    globalThis.clobber = (el, props) => { for (const [k, v] of Object.entries(props)) Object.defineProperty(el, k, { value: v }); return el; };
    const observers = [];
    class MutationObserver { constructor(cb) { this.cb = cb; this.roots = []; this.connected = true; observers.push(this); }
      observe(root, options) { this.roots.push({ root, options }); } disconnect() { this.connected = false; } }
    const shadows = new WeakMap();
    globalThis.chrome = { dom: { openOrClosedShadowRoot(el) {
      if (!(el instanceof HTMLElement)) throw TypeError('not an HTMLElement');
      if (${failShadow}) throw Error('boom');
      return shadows.get(el) || null; } } };
    globalThis.location = { origin: 'https://site.test' };
    globalThis.h = (tag, props, ...kids) => new HTMLElement(tag, props).append(...kids);
    globalThis.svg = (...kids) => new SVGElement('svg').append(...kids);
    globalThis.attachShadow = (host, ...kids) => { const s = new ShadowRoot().append(...kids); shadows.set(host, s); return s; };
    globalThis.observers = observers;
    Object.assign(globalThis, { Node, Element, HTMLElement, Document, MutationObserver });
  `, context);
  return context;
}

// Values from the page's realm, copied into this one so deepEqual compares content, not prototypes.
function inPage(ctx, code) {
  const value = vm.runInContext(code, ctx);
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

async function guardSource() {
  const { fake, hidden } = await workerWithWindows();
  await fake.op('clearForeignFrames', { tabId: hidden.tabId });
  const [{ func }] = fake.callsOf('scripting.executeScript').at(-1);
  const [{ func: stop }] = fake.callsOf('scripting.executeScript').find(([i]) => !i.args);
  // Chrome serialises the function and runs it in the frame: only its source text travels.
  return { guard: func.toString(), stop: stop.toString() };
}

test('the injected guard is self-contained and removes only foreign extension frames', async () => {
  const { guard, stop } = await guardSource();
  const ctx = page();
  vm.runInContext(`
    globalThis.foreignInShadow = h('IFRAME', { src: 'chrome-extension://other/inline.html#f' });
    globalThis.host = h('DIV', {});
    attachShadow(host, foreignInShadow);
    globalThis.document = doc(h('HTML', {},
      h('BODY', {},
        h('IFRAME', { src: 'https://site.test/frame' }),
        h('IFRAME', { src: 'chrome-extension://${EXTENSION_ID}/viewer.html' }),
        h('IFRAME', { src: 'chrome-extension://other/menu.html?q=1' }),
        h('OBJECT', { data: 'chrome-extension://third/obj.html' }),
        svg(h('SPAN', {})),
        host)));
  `, ctx);
  const run = () => inPage(ctx, `(${guard})(${JSON.stringify(EXTENSION_ID)})`);
  assert.deepEqual(run(), { removed: [
    'chrome-extension://other/menu.html',
    'chrome-extension://third/obj.html',
    'chrome-extension://other/inline.html',
  ] });
  assert.deepEqual(inPage(ctx, `document.documentElement.children[0].children.map(e => e.src || e.tagName)`), ['https://site.test/frame', `chrome-extension://${EXTENSION_ID}/viewer.html`, 'svg', 'DIV']);
  assert.equal(vm.runInContext('host.children.length', ctx), 0, 'the host element stays; only its frame goes');

  // Nothing new: an empty report, and the same guard keeps watching the document and the shadow root once each.
  assert.deepEqual(run(), { removed: [] });
  assert.equal(vm.runInContext('observers.length', ctx), 1);
  assert.equal(vm.runInContext('observers[0].roots.length', ctx), 2);
  assert.deepEqual(inPage(ctx, 'observers[0].roots[0].options'), { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'data'] });

  // A frame put back on focus is caught by the observer, and the next call reports it.
  vm.runInContext(`
    globalThis.again = h('IFRAME', { src: 'chrome-extension://other/menu.html' });
    document.documentElement.children[0].append(again);
    observers[0].cb([{ type: 'childList', addedNodes: [again], removedNodes: [] }]);
    globalThis.renamed = h('IFRAME', { src: 'https://site.test/x' });
    document.documentElement.children[0].append(renamed);
    renamed.src = 'chrome-extension://fourth/late.html';
    observers[0].cb([{ type: 'attributes', target: renamed, addedNodes: [], removedNodes: [] }]);
  `, ctx);
  assert.deepEqual(run(), { removed: ['chrome-extension://other/menu.html', 'chrome-extension://fourth/late.html'] });

  // markShown's function ends the guard in the same frame.
  vm.runInContext(`(${stop})()`, ctx);
  assert.equal(vm.runInContext('observers[0].connected', ctx), false);
  assert.equal(vm.runInContext('globalThis.phantabForeignFrames', ctx), undefined);
});

test('the injected guard reports its own failure instead of throwing', async () => {
  const { guard } = await guardSource();
  const ctx = page({ failShadow: true });
  vm.runInContext(`globalThis.document = doc(h('HTML', {}));`, ctx);
  assert.deepEqual(inPage(ctx, `(${guard})('x')`), { removed: [], error: 'https://site.test: boom' });
});

test("markup that shadows a form's or the document's own properties does not end or steer the scan", async () => {
  const { guard } = await guardSource();
  const ctx = page();
  // <input name=children>, <input name=tagName> and <input name=nodeType> in a form, and
  // <img name=documentElement> on the document.
  vm.runInContext(`
    globalThis.field = () => h('INPUT', {});
    globalThis.form = clobber(h('FORM', {}, h('IFRAME', { src: 'chrome-extension://other/in-form.html' })), { children: field(), tagName: field(), nodeType: field() });
    globalThis.body = h('BODY', {}, form);
    globalThis.document = clobber(doc(h('HTML', {}, body)), { documentElement: h('IMG', {}) });
  `, ctx);
  const run = () => inPage(ctx, `(${guard})('x')`);
  assert.deepEqual(run(), { removed: ['chrome-extension://other/in-form.html'] });
  // A form added later reaches the scan through the observer, whose node-type check reads the prototype too.
  vm.runInContext(`
    globalThis.late = clobber(h('FORM', {}, h('IFRAME', { src: 'chrome-extension://other/late.html' })), { nodeType: field() });
    body.append(late);
    observers[0].cb([{ type: 'childList', addedNodes: [late], removedNodes: [] }]);
  `, ctx);
  assert.deepEqual(run(), { removed: ['chrome-extension://other/late.html'] });
});

test('an element named phantabForeignFrames neither ends the scan nor is taken for the guard', async () => {
  const { guard, stop } = await guardSource();
  const ctx = page({ named: true });
  vm.runInContext(`globalThis.document = doc(h('HTML', {}, h('BODY', {}, h('DIV', { id: 'phantabForeignFrames' }),
    h('IFRAME', { src: 'chrome-extension://other/menu.html' }))));`, ctx);
  // markShown's function before any guard: nothing to stop, and the element is left alone.
  assert.doesNotThrow(() => vm.runInContext(`(${stop})()`, ctx));
  const run = () => inPage(ctx, `(${guard})('x')`);
  assert.deepEqual(run(), { removed: ['chrome-extension://other/menu.html'] });
  assert.equal(vm.runInContext('Object.hasOwn(globalThis, "phantabForeignFrames")', ctx), true);
  assert.deepEqual(run(), { removed: [] });
  assert.equal(vm.runInContext('observers.length', ctx), 1, 'the second pass keeps the same guard');
  vm.runInContext(`(${stop})()`, ctx);
  assert.equal(vm.runInContext('observers[0].connected', ctx), false);
  assert.equal(vm.runInContext('globalThis.phantabForeignFrames.id', ctx), 'phantabForeignFrames', 'the name reads the element again');
});
