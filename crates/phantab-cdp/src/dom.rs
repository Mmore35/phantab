//! Element helpers: boxes, click, fill, select. Ports of puppeteer's `ElementHandle` and `Locator` logic
//! for plain CSS selectors in the main frame. Every function here runs in the frame's isolated world
//! ([`crate::page::ISOLATED_WORLD`]), so a page's scripts cannot change what it measures or finds; the one
//! exception, typing into a field, says why at its spot.
//!
//! Copyright 2017 Google Inc. Licensed under the Apache License, Version 2.0 (SPDX-License-Identifier:
//! Apache-2.0). This file holds code ported from puppeteer; see `NOTICE`.

use std::time::{Duration, Instant};

use futures_util::future::join_all;
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::handle::DisposeOnDrop;
use crate::page::millis;
use crate::{Arg, BoundingBox, CdpError, FrameId, JsHandle, Page};

/// Puppeteer's locator `RETRY_DELAY`.
const RETRY_DELAY: Duration = Duration::from_millis(100);

/// How long a selector click keeps retrying while something covers its target (a toast or a menu on
/// its way out) before it reports what covers it.
pub(crate) const COVERED_GRACE: Duration = Duration::from_secs(1);

/// Puppeteer's `typingThreshold`: shorter values are typed, longer ones set directly.
const TYPING_THRESHOLD: usize = 100;

// The functions on the target call the prototypes' own methods and getters, not the element's: on a
// <form>, markup such as <input name=getClientRects> shadows them, even in the isolated world. A value a
// custom element defines for itself is the page world's, which the isolated world never sees anyway.
const JS_BOX: &str = r"(element) => {
  if (!(element instanceof Element)) return null;
  if (Element.prototype.getClientRects.call(element).length === 0) return null;
  const rect = Element.prototype.getBoundingClientRect.call(element);
  return {x: rect.x, y: rect.y, width: rect.width, height: rect.height};
}";

const JS_CLIENT_RECTS: &str = r"(element) => {
  if (!(element instanceof Element)) return null;
  return [...Element.prototype.getClientRects.call(element)].map(rect => ({x: rect.x, y: rect.y, width: rect.width, height: rect.height}));
}";

// A frame element's content box from its border box and computed style: `left` and `top`, where it sits
// in the view (a `0.9px` padding counts, to the fraction), and `width` and `height`, its size as style
// gives it, untransformed, which `Page::frame_offset` holds `DOM.getBoxModel`'s content quad to; `x` and
// `y` are the border box's corner.
// `transformed` says what lies on the element's way up the flat tree (from an element to the <slot> it
// is assigned to, from a shadow root to its host, else to its parent), up to its document's root.
// 'turned' when something there scales, rotates, skews or mirrors it, or zooms it: an <svg> holds it, a
// `zoom` other than 1, a `scale` or `rotate` other than none or the identity, an `offset-path` other
// than none, a `transform` whose linear part (all but its translation) is not the identity, or a drawn
// size (`getBoundingClientRect`) other than the size its style gives, past a layout unit. Then where a
// page point falls in the frame's document is not known at all, and the click is refused (`turned`).
// The linear part is read from the typed value (`computedStyleMap`) at full precision, multiplied out
// over every function but a translation; the computed text's six digits would hide a
// `scale(1.0000001)`. Only when there is no typed value is the text read. 'moved' when nothing turns it
// but something may move it by a fraction the box model need not show: a `transform` (a translation,
// `translateZ` or a 3D matrix among them), an identity `scale` or `rotate` (`scale: 1`, `rotate:
// 0deg`, whose text could hide a fraction too), a `translate` or `perspective`, `transform-style:
// preserve-3d`, `backface-visibility: hidden`, a `will-change` for any of those, `position: sticky`, a
// scroll container scrolled by a fraction or with its padding box at one, or a <details>, <select> or
// <marquee> slotting it into the browser's own shadow root. Chrome paints another site's frame, and
// routes input to it, at a whole device pixel in its layer's space, so a `translate(0.5px)` moves the
// press by a fraction. Then the box rule answers (`Unsettled::Transformed`). `why` names the first
// thing found at the worst level, in these words, never the page's: what the walk finds comes before
// the drawn size. What the walk cannot see (a closed or the browser's own shadow root's wrapper that
// mirrors or turns the frame at its own size) only the box model's quads show (`offset_from`).
// A closed shadow root hides its slots from the world: `hosts` counts the elements on the way that
// could hold one (each light parent with no shadow root the world can see), and called with `hosts`
// true the function returns those elements instead, for `Page::frame_offset` to ask `DOM.describeNode`
// about. Each frame level is its own element's call, so every level up to the page is walked.
const JS_FRAME_OFFSET: &str = r"(element, hosts) => {
  if (Element.prototype.getClientRects.call(element).length === 0) return null;
  const rect = Element.prototype.getBoundingClientRect.call(element);
  const style = getComputedStyle(element);
  const read = (s, key) => CSSStyleDeclaration.prototype.getPropertyValue.call(s, key);
  const value = (key) => read(style, key);
  const px = (key) => parseFloat(value(key)) || 0;
  const left = px('padding-left') + px('border-left-width'), top = px('padding-top') + px('border-top-width');
  const right = px('padding-right') + px('border-right-width');
  const bottom = px('padding-bottom') + px('border-bottom-width');
  let width = px('width'), height = px('height');
  if (value('box-sizing') === 'border-box') {
    width -= left + right;
    height -= top + bottom;
  }
  const get = (proto, key) => Object.getOwnPropertyDescriptor(proto, key).get;
  const parentOf = get(Node.prototype, 'parentNode'), hostOf = get(ShadowRoot.prototype, 'host');
  const slotOf = get(Element.prototype, 'assignedSlot'), shadowOf = get(Element.prototype, 'shadowRoot');
  const localName = get(Element.prototype, 'localName'), docOf = get(Node.prototype, 'ownerDocument');
  const scrolledX = get(Element.prototype, 'scrollLeft'), scrolledY = get(Element.prototype, 'scrollTop');
  const rectOf = Element.prototype.getBoundingClientRect;
  const doc = docOf.call(element);
  const html = get(Document.prototype, 'documentElement').call(doc), body = get(Document.prototype, 'body').call(doc);
  const none = (s, key) => ['', 'none'].includes(read(s, key));
  const shown = (s) => ['overflow-x', 'overflow-y'].every((k) => ['', 'visible', 'clip'].includes(read(s, k)));
  // With the root's overflow visible, the body's is the view's, and the body scrolls nothing itself.
  const bodyIsView = !html || ['overflow-x', 'overflow-y'].every((k) => ['', 'visible'].includes(read(getComputedStyle(html), k)));
  const whole = (v) => v === Math.trunc(v);
  const flat = (n, t) => {
    try {
      const v = StylePropertyMapReadOnly.prototype.get.call(Element.prototype.computedStyleMap.call(n), 'transform');
      if (v instanceof CSSTransformValue) {
        let m = new DOMMatrix();
        for (const c of v) if (!(c instanceof CSSTranslate)) m = m.multiply(c.toMatrix());
        return m.m11 === 1 && m.m22 === 1 && m.m33 === 1 && m.m44 === 1 &&
          [m.m12, m.m13, m.m14, m.m21, m.m23, m.m24, m.m31, m.m32, m.m34].every((e) => e === 0);
      }
    } catch {}
    const m = /^matrix(3d)?\((.*)\)$/.exec(t);
    if (!m) return false;
    const got = m[2].split(',').map(Number);
    if (m[1]) return got.length === 16 && got[15] === 1 && [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0].every((e, i) => got[i] === e);
    return got.length === 6 && [1, 0, 0, 1].every((e, i) => got[i] === e);
  };
  let worst = 0, why = '';
  const mark = (level, what) => {
    if (level > worst) [worst, why] = [level, what];
  };
  const check = (n) => {
    if (typeof SVGElement === 'function' && n instanceof SVGElement) return mark(2, 'inside an <svg>');
    const s = n === element ? style : getComputedStyle(n);
    if (!['', '1', 'normal'].includes(read(s, 'zoom'))) mark(2, 'zoom');
    if (!none(s, 'offset-path')) mark(2, 'offset-path');
    // An identity `scale` or `rotate` (Tailwind's scale-100, rotate-0) is no turn, but its six digits
    // could hide one, as `transform: scale(1)`'s could: moved.
    const scale = read(s, 'scale'), rotate = read(s, 'rotate');
    if (!none(s, 'scale')) mark(scale.trim().split(/\s+/).every((p) => (p.endsWith('%') ? parseFloat(p) / 100 : Number(p)) === 1) ? 1 : 2, 'scale');
    if (!none(s, 'rotate')) {
      const angle = /^([-+]?(?:\d+\.?\d*|\.\d+)(?:e[-+]?\d+)?)(deg|rad|grad|turn)$/i.exec(rotate.trim().split(/\s+/).pop());
      mark(angle && Number(angle[1]) === 0 ? 1 : 2, 'rotate');
    }
    const t = read(s, 'transform');
    if (t !== '' && t !== 'none') mark(flat(n, t) ? 1 : 2, 'transform');
    for (const key of ['translate', 'perspective']) if (!none(s, key)) mark(1, key);
    if (read(s, 'transform-style') === 'preserve-3d') mark(1, 'transform-style');
    if (read(s, 'backface-visibility') === 'hidden') mark(1, 'backface-visibility');
    if (/(^|[\s,])(transform|translate|scale|rotate|perspective|offset-path|offset)([\s,]|$)/.test(read(s, 'will-change'))) mark(1, 'will-change');
    if (read(s, 'position') === 'sticky') mark(1, 'position: sticky');
    if (n !== element && n !== html && !(n === body && bodyIsView) && !shown(s)) {
      const b = rectOf.call(n);
      const x = b.left + (parseFloat(read(s, 'border-left-width')) || 0), y = b.top + (parseFloat(read(s, 'border-top-width')) || 0);
      if (![scrolledX.call(n), scrolledY.call(n), x, y].every(whole)) mark(1, 'a scroller at a fraction');
    }
  };
  const maybe = [];
  for (let n = element; n && worst < 2;) {
    if (n instanceof Element) check(n);
    if (n instanceof ShadowRoot) {
      n = hostOf.call(n);
      continue;
    }
    const slot = n instanceof Element ? slotOf.call(n) : null;
    if (slot) {
      n = slot;
      continue;
    }
    n = parentOf.call(n);
    if (!(n instanceof Element)) continue;
    const tag = localName.call(n);
    if (['details', 'select', 'marquee'].includes(tag)) mark(1, 'inside a <' + tag + '>');
    if (n !== html && !shadowOf.call(n)) maybe.push(n);
  }
  const near = (a, b) => Math.abs(a - b) <= 1 / 64 + Math.abs(b) * 1e-5;
  if (!near(rect.width, width + left + right) || !near(rect.height, height + top + bottom)) {
    mark(2, 'drawn at a size other than its own');
  }
  if (hosts === true) return maybe;
  const transformed = worst === 2 ? 'turned' : worst === 1 ? 'moved' : false;
  return {left: rect.left + left, top: rect.top + top, x: rect.left, y: rect.top, width, height, transformed, why, hosts: maybe.length};
}";

// `document` and the reads on it go through the prototypes: markup such as <img name=documentElement>
// shadows a document's own properties, even in the isolated world.
const JS_DOCUMENT_SIZE: &str = r"() => {
  const root = Object.getOwnPropertyDescriptor(Document.prototype, 'documentElement').get.call(document);
  return {documentWidth: root.clientWidth, documentHeight: root.clientHeight};
}";

const JS_ASSERT_CONNECTED: &str = r"(element) => {
  const get = (key) => Object.getOwnPropertyDescriptor(Node.prototype, key).get;
  if (!(element instanceof Node) || !get('isConnected').call(element)) return 'Node is detached from document';
  if (get('nodeType').call(element) !== Node.ELEMENT_NODE) return 'Node is not of type HTMLElement';
  return null;
}";

// Puppeteer checks the owner <svg> for SVG children (crbug.com/963246) in a separate step.
// phantab: the observer answers once the page renders a frame, and a hidden window may render none
// (engine `act`), so a 100 ms timer stands in. Then the answer is "not known to be in view", and the
// scroll that follows (`DOM.scrollIntoViewIfNeeded`) moves only what is not.
const JS_FULLY_IN_VIEWPORT: &str = r"async (element) => {
  let target = element;
  if (element instanceof SVGElement && !(element instanceof SVGSVGElement)) {
    target = element.ownerSVGElement ?? element;
  }
  const visibleRatio = await new Promise(resolve => {
    const observer = new IntersectionObserver(entries => {
      resolve(entries[0].intersectionRatio);
      observer.disconnect();
    });
    observer.observe(target);
    setTimeout(() => { observer.disconnect(); resolve(null); }, 100);
  });
  return visibleRatio === 1;
}";

const JS_SCROLL_INTO_VIEW: &str = r"(element) => {
  Element.prototype.scrollIntoView.call(element, {block: 'center', inline: 'center', behavior: 'instant'});
}";

// What is on top at (x, y) in the element's own document or shadow root, looking into each open shadow
// root on the way. Null when it is the element, inside it, or inside a <label> for it (a styled checkbox
// hides its input under its label), but not inside content in that label that takes a click of its own:
// a link, a button, a form control, another <label> (nested, for another control), a <details> or
// <summary>, a <video> or <audio> with `controls`, an <img> with a `usemap`, an editable region or an
// element with an `onclick` the world can see (attribute or property); a "terms" link over the checkbox
// takes the click. A handler added with `addEventListener` that cancels the click is not seen: no
// world can list another's listeners, so a plain <span> in the label that takes the click that way
// still counts as the checkbox's (SR-34's known residual). Otherwise a short name for what is there
// (tag and id, each at most 32 characters: they are the page's words), or '' when nothing is (the
// point is outside the view).
// Ancestors count as covering: the click would go to them. So does a frame (<iframe>, <object> and the
// like) inside the element or its label, unless it is the element: the press would land in the frame's
// document, which may be another site's.
// With `strict` (the fallback when `DOM.getNodeForLocation` cannot settle it, see `Page::frame_on_top`),
// any frame element whose box holds the point covers it too, wherever it sits and whatever its style,
// unless it is the element or holds it: the hit test sees through a frame with `pointer-events: none`,
// but Chrome can still route the press into a cross-site one (headless Chrome did, into an `opacity: 0`
// frame inside a card link). That also refuses a frame under opaque content, so it fails closed; with
// no frame box at the point it refuses nothing more than the plain test does. The frames
// are `frames` (the element's frame's child frame elements, from the frame tree, so one in a closed
// shadow root counts) and the <iframe>, <frame>, <object>, <embed> and <fencedframe> elements in the
// element's document and its open shadow roots (500 roots).
// Everything is read through the isolated world's own prototypes, never the element's properties:
// markup such as <input name=closest> in a covering <form> would shadow those.
const JS_HIT: &str = r"(element, x, y, strict, ...frames) => {
  const get = (proto, key) => Object.getOwnPropertyDescriptor(proto, key).get;
  const localName = get(Element.prototype, 'localName'), idOf = get(Element.prototype, 'id');
  const shadowOf = get(Element.prototype, 'shadowRoot'), parentOf = get(Node.prototype, 'parentNode');
  const hostOf = get(ShadowRoot.prototype, 'host'), control = get(HTMLLabelElement.prototype, 'control');
  const docOf = get(Node.prototype, 'ownerDocument'), rectOf = Element.prototype.getBoundingClientRect;
  const hasAttr = Element.prototype.hasAttribute, clickOf = get(HTMLElement.prototype, 'onclick');
  const takesClick = (n) => {
    const tag = localName.call(n);
    return ['a', 'area', 'button', 'input', 'select', 'textarea', 'summary', 'label', 'details'].includes(tag) ||
      (['video', 'audio'].includes(tag) && hasAttr.call(n, 'controls')) || (tag === 'img' && hasAttr.call(n, 'usemap')) ||
      hasAttr.call(n, 'contenteditable') || hasAttr.call(n, 'onclick') ||
      (n instanceof HTMLElement && clickOf.call(n) != null);
  };
  const at = (root) =>
    (root instanceof ShadowRoot ? ShadowRoot.prototype : Document.prototype).elementFromPoint.call(root, x, y);
  const qsa = (root, s) =>
    (root instanceof Document ? Document.prototype : DocumentFragment.prototype).querySelectorAll.call(root, s);
  const up = (n) => (n instanceof ShadowRoot ? hostOf.call(n) : parentOf.call(n));
  const isFrame = (n) => ['iframe', 'frame', 'object', 'embed', 'fencedframe'].includes(localName.call(n));
  const name = (n) => {
    const id = idOf.call(n);
    return localName.call(n).slice(0, 32) + (id ? '#' + id.slice(0, 32) : '');
  };
  // Whether n is the element or inside it or a label for it (and not inside something in the label that
  // takes the click), and the first frame element on the way up.
  const owned = (n) => {
    let framed = null, taken = false;
    for (; n; n = up(n)) {
      if (n === element) return {framed};
      if (!(n instanceof Element)) continue;
      if (n instanceof HTMLLabelElement && control.call(n) === element) return taken ? null : {framed};
      if (!framed && isFrame(n)) framed = n;
      taken = taken || takesClick(n);
    }
    return null;
  };
  let hit = at(Node.prototype.getRootNode.call(element));
  for (let i = 0; hit && i < 32; i++) {
    const root = shadowOf.call(hit);
    const inner = root && at(root);
    if (!inner || inner === hit) break;
    hit = inner;
  }
  if (!hit) return '';
  const mine = owned(hit);
  if (!mine) return name(hit);
  if (mine.framed) return name(mine.framed);
  if (!strict) return null;
  const roots = [docOf.call(element)];
  for (let i = 0; i < roots.length && i < 500; i++) {
    for (const n of qsa(roots[i], '*')) {
      const root = shadowOf.call(n);
      if (root) roots.push(root);
    }
  }
  const holds = (f) => {
    for (let n = element; n; n = up(n)) if (n === f) return true;
    return false;
  };
  const found = roots.slice(0, 500).flatMap((root) => [...qsa(root, 'iframe, frame, object, embed, fencedframe')]);
  for (const f of [...frames, ...found]) {
    const r = rectOf.call(f);
    const inBox = x >= r.left && x < r.right && y >= r.top && y < r.bottom;
    if (inBox && f !== element && !holds(f)) return name(f);
  }
  return null;
}";

// `found` is what `DOM.getNodeForLocation` put on top at the click point (or the element of the frame
// holding that), `target` the element or the frame element holding it, both in one isolated world. A
// short name for `found` when it covers the target, else null. Without `own`, `found` is a frame element,
// and covers unless it is `target` or holds it. With `own`, it is anything else, which both answers put
// on top, and it covers unless it is the target's own: `target`, inside it (through shadow roots, open
// or closed), or inside a <label> for it and not inside content there that takes a click of its own, as
// `JS_HIT`'s `owned` has it. The page's hit test said the same just before; this answer is the later
// one, so an overlay a timer slid in since is refused.
const JS_ON_TOP: &str = r"(found, target, own) => {
  const get = (proto, key) => Object.getOwnPropertyDescriptor(proto, key).get;
  const localName = get(Element.prototype, 'localName'), idOf = get(Element.prototype, 'id');
  const parentOf = get(Node.prototype, 'parentNode'), hostOf = get(ShadowRoot.prototype, 'host');
  const control = get(HTMLLabelElement.prototype, 'control');
  const hasAttr = Element.prototype.hasAttribute, clickOf = get(HTMLElement.prototype, 'onclick');
  const takesClick = (n) => {
    const tag = localName.call(n);
    return ['a', 'area', 'button', 'input', 'select', 'textarea', 'summary', 'label', 'details'].includes(tag) ||
      (['video', 'audio'].includes(tag) && hasAttr.call(n, 'controls')) || (tag === 'img' && hasAttr.call(n, 'usemap')) ||
      hasAttr.call(n, 'contenteditable') || hasAttr.call(n, 'onclick') ||
      (n instanceof HTMLElement && clickOf.call(n) != null);
  };
  const up = (n) => (n instanceof ShadowRoot ? hostOf.call(n) : parentOf.call(n));
  const name = (n) => {
    if (!(n instanceof Element)) return 'node';
    const id = idOf.call(n);
    return localName.call(n).slice(0, 32) + (id ? '#' + id.slice(0, 32) : '');
  };
  if (own) {
    let taken = false;
    for (let n = found; n; n = up(n)) {
      if (n === target) return null;
      if (!(n instanceof Element)) continue;
      if (n instanceof HTMLLabelElement && control.call(n) === target) return taken ? name(found) : null;
      taken = taken || takesClick(n);
    }
    return name(found);
  }
  if (!(found instanceof Element) || !['iframe', 'frame', 'object', 'embed', 'fencedframe'].includes(localName.call(found))) return null;
  for (let n = target; n; n = up(n)) if (n === found) return null;
  return name(found);
}";

/// The frame elements, as `JS_HIT`'s `isFrame` and `JS_ON_TOP` list them.
const FRAME_TAGS: [&str; 5] = ["iframe", "frame", "object", "embed", "fencedframe"];

// Resolves once the page has rendered a frame, so input it was sent has been handled: the browser hands
// a page pointer moves at the start of a frame. That is about one frame where the page renders (a shown
// tab, or a hidden workspace page kept rendering). A page that renders none (a background tab, or a
// hidden window not kept rendering) resolves on the timer instead, never on the frame; Chrome can hold
// its timers to about once a second there, so it can take about 1 s.
const JS_NEXT_FRAME: &str =
    r"() => new Promise(resolve => { requestAnimationFrame(() => resolve()); setTimeout(resolve, 100); })";

const JS_QUERY: &str = r"(selector) => Document.prototype.querySelector.call(document, selector)";

/// A document's scroll, read in its isolated world, where the page cannot replace `scrollX`.
const JS_SCROLL: &str = "() => [scrollX, scrollY]";

const JS_SELECT: &str = r"(element, vals) => {
  const values = new Set(vals);
  if (!(element instanceof HTMLSelectElement)) {
    throw new Error('Element is not a <select> element.');
  }
  const selectedValues = new Set();
  if (!element.multiple) {
    for (const option of element.options) option.selected = false;
    for (const option of element.options) {
      if (values.has(option.value)) {
        option.selected = true;
        selectedValues.add(option.value);
        break;
      }
    }
  } else {
    for (const option of element.options) {
      option.selected = values.has(option.value);
      if (option.selected) selectedValues.add(option.value);
    }
  }
  element.dispatchEvent(new Event('input', {bubbles: true}));
  element.dispatchEvent(new Event('change', {bubbles: true}));
  return [...selectedValues.values()];
}";

const JS_FOCUS: &str = r"(element) => {
  if (!(element instanceof HTMLElement)) throw new Error('Cannot focus non-HTMLElement');
  return HTMLElement.prototype.focus.call(element);
}";

const JS_INPUT_KIND: &str = r"(el) => {
  if (el instanceof HTMLSelectElement) return 'select';
  if (el instanceof HTMLTextAreaElement) return 'typeable-input';
  if (el instanceof HTMLInputElement) {
    switch (el.type) {
      case 'checkbox': case 'radio': return 'checkable-input';
      case 'text': case 'url': case 'tel': case 'search': case 'password': case 'number': case 'email':
        return 'typeable-input';
      default: return 'other-input';
    }
  }
  switch (Element.prototype.getAttribute.call(el, 'role')) {
    case 'checkbox': case 'radio': case 'switch': return 'checkable-input';
  }
  const editable = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'isContentEditable').get;
  if (el instanceof HTMLElement && editable.call(el)) return 'contenteditable';
  return 'unknown';
}";

// The field's text now, and whether it is content-editable (then its text is innerText): puppeteer's
// fill reads these in the page, and the engine decides from them what to clear and what to type.
const JS_CURRENT_TEXT: &str = r"(element) => {
  const get = (proto, key) => Object.getOwnPropertyDescriptor(proto, key).get;
  if (element instanceof HTMLElement && get(HTMLElement.prototype, 'isContentEditable').call(element)) {
    return {editable: true, text: get(HTMLElement.prototype, 'innerText').call(element)};
  }
  return {editable: false, text: String(element.value)};
}";

// The main world's writes: each of `texts` in turn, then, for a fill set directly, puppeteer's input and
// change events. Nothing comes back from here.
const JS_WRITE_TEXT: &str = r"(element, editable, texts, events) => {
  for (const text of texts) {
    if (editable) element.innerText = text; else element.value = text;
  }
  if (events) {
    element.dispatchEvent(new Event('input', {bubbles: true}));
    element.dispatchEvent(new Event('change', {bubbles: true}));
  }
}";

const JS_CHECKED_STATE: &str = r"(toggleEl) => {
  const input = toggleEl instanceof HTMLInputElement, aria = Element.prototype.getAttribute.call(toggleEl, 'aria-checked');
  if ((input && toggleEl.indeterminate) || aria === 'mixed') return 'mixed';
  return (input && toggleEl.checked) || aria === 'true';
}";

/// How [`Page::press_element`] failed: before the press, or at it.
#[derive(Debug, Clone, PartialEq)]
pub enum ClickError {
    /// Nothing was pressed: the click stopped before the button went down. [`CdpError::Covered`] is one.
    NotPressed(CdpError),
    /// The press or its release failed, so the press may still have landed.
    Pressed(CdpError),
}

impl ClickError {
    /// The error itself, whichever side of the press it came from.
    pub fn into_inner(self) -> CdpError {
        match self {
            ClickError::NotPressed(e) | ClickError::Pressed(e) => e,
        }
    }
}

/// How every [`CdpError::Covered`] that names what covers the element begins, so a caller that rewrites
/// errors by their words can leave it: that name is the page's. The one other refusal, an element in a
/// turned frame (`turned`), carries only this crate's words.
pub const COVERED_PREFIX: &str = "Element is covered at its click point by ";

fn covered(what: &str) -> CdpError {
    let what = if what.is_empty() {
        "nothing the page shows (the point is outside the view)".to_owned()
    } else {
        format!("<{what}>")
    };
    CdpError::Covered(format!(
        "{COVERED_PREFIX}{what}, so the click was not sent. Close what covers it (a dialog or banner) or \
         scroll it into view, and try again, or use click_xy to click that point on purpose."
    ))
}

/// The refusal for an element in a frame that something on the page scales, rotates, skews, mirrors or
/// zooms (`what` says which, in this crate's words, never the page's): where a page point falls in that
/// frame's document is not known, so neither check can tell what the press would hit there.
/// When `what` is [`UNREAD`], no command said where the frame is drawn: that is phantab's failure, not
/// the page's doing, and the refusal says so (review r10 N-2).
fn turned(what: &str) -> CdpError {
    if what == UNREAD {
        tracing::warn!(reason = ?Unsettled::Transformed, "a frame's box model did not read; the click is refused");
        return CdpError::Covered(
            "phantab could not read where the element's frame is drawn, so where a press would land in it \
             is not known, and the click was not sent. Try again, or use click_xy to click a point on \
             purpose."
                .to_owned(),
        );
    }
    tracing::debug!(reason = ?Unsettled::Transformed, what, "a frame on the way is turned; the click is refused");
    CdpError::Covered(format!(
        "The element is in a frame that the page scales, rotates or zooms ({what}), so where a press \
         would land in it is not known, and the click was not sent. Use click_xy to click a point on \
         purpose."
    ))
}

fn parse_box(v: &Value) -> Option<BoundingBox> {
    serde_json::from_value(v.clone()).ok()
}

/// Why [`Page::frame_on_top`] could not settle a click check, so the box rule answered instead
/// (`Page::assert_uncovered`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsettled {
    /// The two answers differ: something that takes no pointer events lies over the click point, a
    /// decoy over a frame or an honest icon.
    Decoy,
    /// The click point falls between whole pixels in a frame's document (a fractional frame offset or
    /// scroll), and the command takes whole pixels only.
    BetweenPixels,
    /// A frame element on the way, or an element above it in the flat tree, may move it by a fraction
    /// (a translation, a 3D or sticky layer, a scroller at a fraction), is slotted into a shadow root
    /// the world cannot open, or its box model does not match its style (page zoom can do that) or lies
    /// too far out to read to a layout unit, so where the point falls in its document is not known
    /// exactly. One that scales, rotates or zooms it is refused instead, and the click is not sent.
    Transformed,
    /// The node on top is a pseudo-element (`::before`, `::after`), which has no element to check.
    Pseudo,
    /// A command failed or answered something unexpected (an extension older than the service refuses
    /// one, or the frame changed under it).
    Failed,
}

impl Unsettled {
    /// Every reason, in order.
    #[cfg(feature = "test-seams")]
    pub const ALL: [Unsettled; 5] = [
        Unsettled::Decoy,
        Unsettled::BetweenPixels,
        Unsettled::Transformed,
        Unsettled::Pseudo,
        Unsettled::Failed,
    ];
}

/// A click check [`Page::frame_on_top`] could not settle: why, and what said so.
#[derive(Debug)]
struct Doubt {
    why: Unsettled,
    error: Box<CdpError>,
}

impl Doubt {
    fn new(why: Unsettled, error: impl Into<String>) -> Doubt {
        Doubt { why, error: Box::new(CdpError::Other(error.into())) }
    }
}

impl From<CdpError> for Doubt {
    fn from(error: CdpError) -> Doubt {
        Doubt { why: Unsettled::Failed, error: Box::new(error) }
    }
}

/// Where a frame's content box sits in its parent's view, why that may be only rough, and what turns
/// the frame, when something does (then no point in it is known, and the click is refused).
#[derive(Debug)]
struct FrameOffset {
    left: f64,
    top: f64,
    doubt: Option<Doubt>,
    turned: Option<String>,
}

/// Where a frame's content box sits on the page, summed over its ancestors ([`FrameOffset`] at each).
#[derive(Debug)]
struct Origin {
    x: f64,
    y: f64,
    doubt: Option<Doubt>,
    turned: Option<String>,
}

/// What [`FrameOffset`]'s `turned` says when `DOM.getBoxModel` failed or gave no quads: a turn is not
/// ruled out, so the click is refused, but [`turned`] does not blame the page for it. The walk's own
/// words (`JS_FRAME_OFFSET`'s `why`) are never this.
const UNREAD: &str = "the frame's box model did not read";

/// Lets each handle go without waiting for the answer; the guards' drops then do nothing.
fn release_all(handles: &[DisposeOnDrop]) {
    for h in handles {
        h.0.release();
    }
}

/// A frame element [`Page::frame_origin_keeping`] kept, and where its border box and its content box
/// were, `[x, y, left, top]` (`None` when that did not read). Guarded, so a click check dropped while
/// it holds them (a timeout or an abort) still lets them go.
struct Kept {
    el: DisposeOnDrop,
    at: Option<[f64; 4]>,
}

/// Where an element's border box is in its document's view, and its content box (the border box plus
/// computed padding and border), `[x, y, left, top]`, as `JS_FRAME_OFFSET` reads them, sum for sum: a
/// scroll above it moves both, a padding or border a timer changed only the second (review r10 F-1).
const JS_PLACE: &str = r"(element) => {
  const rect = Element.prototype.getBoundingClientRect.call(element);
  const style = getComputedStyle(element);
  const px = (key) => parseFloat(CSSStyleDeclaration.prototype.getPropertyValue.call(style, key)) || 0;
  const left = px('padding-left') + px('border-left-width'), top = px('padding-top') + px('border-top-width');
  return [rect.left, rect.top, rect.left + left, rect.top + top];
}";

/// `[x, y, left, top]` from [`JS_FRAME_OFFSET`]'s answer or [`JS_PLACE`]'s.
fn place_of(v: &Value) -> Option<[f64; 4]> {
    let n = |key: &str, i: usize| v.get(key).or_else(|| v.get(i)).and_then(Value::as_f64);
    Some([n("x", 0)?, n("y", 1)?, n("left", 2)?, n("top", 3)?])
}

/// The most elements on a frame element's way up that [`Page::frame_offset`] asks `DOM.describeNode`
/// about; past it, the frame's place is in doubt.
const MAX_HOSTS: u64 = 200;

/// One layout unit at page zoom 100% and a device scale of 1.
const LAYOUT_UNIT: f64 = 1.0 / 64.0;

/// Whether `quad`, a size from `DOM.getBoxModel`, and `style`, the computed style's, are one size: a
/// layout unit apart, plus what computed style's six significant digits lose (a 10,000-px frame reads to
/// a hundredth). The box model's quads are `float32`, exact to a layout unit within 2^18 px
/// (`FAR_OUT`). A scale too small to fail this is not found here: `JS_FRAME_OFFSET` finds it where the
/// world can see it, reading each transform on the way up the flat tree (through slots and shadow
/// hosts) from its typed value at full precision, and a frame slotted into a shadow root the world
/// cannot open is in doubt (`Page::frame_offset` asks `DOM.describeNode` about the hosts).
fn one_size(quad: f64, style: f64) -> bool {
    (quad - style).abs() <= LAYOUT_UNIT + style.abs() * 1e-5
}

/// Past this, a `float32` quad from `DOM.getBoxModel` no longer holds every layout unit (1/64 px), so
/// a border-to-content difference read there may be off by a fraction.
const FAR_OUT: f64 = 262_144.0;

/// Whether `q`, a quad from `DOM.getBoxModel` (top left, top right, bottom right, bottom left, as x
/// and y), is an upright rectangle the right way round: no rotation, skew or mirroring.
#[allow(clippy::float_cmp)]
fn upright(q: &[f64; 8]) -> bool {
    q[1] == q[3] && q[5] == q[7] && q[0] == q[6] && q[2] == q[4] && q[2] > q[0] && q[5] > q[1]
}

/// Something that takes no pointer events lies over the click point: the two answers differ.
fn decoy() -> Doubt {
    Doubt::new(Unsettled::Decoy, "something that takes no pointer events lies over the click point")
}

/// [`Page::frame_on_top_in`]'s answer from what it read: `node`, `DOM.describeNode`'s (`None` when the
/// node is inside a frame in this process, and `found` that frame's element), `found` the node on top
/// and `target` the element or the frame element holding it, both in one isolated world.
async fn on_top(
    node: Result<Option<Value>, CdpError>,
    found: &JsHandle,
    target: &JsHandle,
    agree: bool,
) -> Result<Option<String>, Doubt> {
    // Whether `found` is not a frame element, and so must be the element's own.
    let mut own = false;
    if let Some(node) = node? {
        let local = node.pointer("/node/localName").and_then(Value::as_str).unwrap_or_default();
        if !FRAME_TAGS.contains(&local) {
            if !agree {
                return Err(decoy());
            }
            // Both answers put a `::before` or `::after` on top: it has no element to resolve, and whose
            // it is, is not known here.
            if node.pointer("/node/pseudoType").is_some() {
                return Err(Doubt::new(Unsettled::Pseudo, "the node at the click point is a pseudo-element"));
            }
            own = true;
        }
    }
    match found.evaluate(JS_ON_TOP, vec![Arg::Handle(target), Arg::Value(json!(own))]).await?.as_str() {
        Some(what) => Ok(Some(what.to_owned())),
        None if agree => Ok(None),
        None => Err(decoy()),
    }
}

/// The whole number nearest the middle of `[start, start + len)` and inside it (`len` is at least 1).
fn snap(start: f64, len: f64) -> f64 {
    let s = (start + len / 2.0).round();
    if s >= start + len { s - 1.0 } else { s }
}

/// Whether `v` is a whole number. At page zoom 100% and a device scale of 1, layout positions are
/// multiples of 1/64 px, exact in an `f64`, as are their sums, so the test is exact: any fraction left
/// is one the press really has. Under page zoom, or a fractional device scale
/// (125%), CSS positions are layout units divided by the scale, not exact: a whole point can read a
/// hair off whole, and then the box rule answers (it fails closed). A point that reads whole is that
/// point.
#[allow(clippy::float_cmp)]
fn is_whole(v: f64) -> bool {
    v == v.trunc()
}

/// A `[x, y]` read (`JS_SCROLL`'s) as two numbers, or none: never a 0 for what is not a number.
fn two_numbers(v: &Value) -> Option<(f64, f64)> {
    Some((v.get(0)?.as_f64()?, v.get(1)?.as_f64()?))
}

/// [`Page::frame_offset`]'s answer from `JS_FRAME_OFFSET`'s `style` and `DOM.getBoxModel`'s `model`.
/// The quads are checked whatever the style says, before any doubt is returned: a closed or the
/// browser's own shadow root's wrapper can mirror or turn the frame at its own size, where the world
/// sees only what may move it ('moved', a `translate: 0px` on the host, a <details>), and the box rule
/// cannot see a mirror. So a box model that could not be read, or reads as no quads, turns the frame
/// too: a turn is not ruled out (review r9 M-1).
fn offset_from(style: &Value, model: Result<Value, CdpError>) -> Option<FrameOffset> {
    let num = |key: &str| style.get(key).and_then(Value::as_f64);
    let (Some(left), Some(top)) = (num("left"), num("top")) else { return None };
    let rough = |why: Unsettled, error: String| {
        Some(FrameOffset { left, top, doubt: Some(Doubt::new(why, error)), turned: None })
    };
    let turned = |what: String| Some(FrameOffset { left, top, doubt: None, turned: Some(what) });
    // A plain `false` is nothing on the way, 'moved' a doubt; anything else turns it: it fails closed.
    let why: String = style.get("why").and_then(Value::as_str).unwrap_or_default().chars().take(64).collect();
    let moved = match style.get("transformed") {
        Some(Value::Bool(false)) => false,
        Some(Value::String(s)) if s == "moved" => true,
        _ if why.is_empty() => return turned("the frame element or one above it".to_owned()),
        _ => return turned(why),
    };
    let model = match model {
        Ok(model) => model,
        Err(e) => {
            tracing::debug!(error = %e, "DOM.getBoxModel failed for a frame element");
            return turned(UNREAD.to_owned());
        }
    };
    let quad = |key: &str| -> Option<[f64; 8]> {
        let q = model.pointer(&format!("/model/{key}"))?.as_array()?;
        let q: Option<Vec<f64>> = q.iter().map(Value::as_f64).collect();
        q?.try_into().ok()
    };
    let (Some(content), Some(border), Some(x), Some(y), Some(width), Some(height)) =
        (quad("content"), quad("border"), num("x"), num("y"), num("width"), num("height"))
    else {
        tracing::debug!("DOM.getBoxModel gave no quads for a frame element");
        return turned(UNREAD.to_owned());
    };
    // A quad turned or mirrored: something the world did not see turns the frame (a closed shadow
    // root's wrapper); `rotate(180deg)` keeps the size, so only the corners' order tells.
    if !upright(&content) || !upright(&border) {
        return turned("its box is not an upright rectangle the right way round".to_owned());
    }
    if moved {
        return rough(
            Unsettled::Transformed,
            format!("the frame element or one above it may move it ({why})"),
        );
    }
    let sized = one_size(content[2] - content[0], width) && one_size(content[5] - content[1], height);
    let near = content.iter().chain(&border).all(|v| v.abs() < FAR_OUT);
    if !sized || !near {
        let what = format!("the frame's content box {content:?} is not {width} x {height}, or lies far out");
        return rough(Unsettled::Transformed, what);
    }
    // The quad's own space need not be the view's (page zoom): only its differences are taken.
    Some(FrameOffset {
        left: x + (content[0] - border[0]),
        top: y + (content[1] - border[1]),
        doubt: None,
        turned: None,
    })
}

/// Puppeteer's `intersectBoundingBox`: clip a box to a `width x height` document.
pub(crate) fn intersect_box(b: &mut BoundingBox, width: f64, height: f64) {
    b.width = if b.x >= 0.0 { (width - b.x).min(b.width) } else { width.min(b.width + b.x) }.max(0.0);
    b.height = if b.y >= 0.0 { (height - b.y).min(b.height) } else { height.min(b.height + b.y) }.max(0.0);
    b.x = b.x.max(0.0);
    b.y = b.y.max(0.0);
}

impl Page {
    /// The bounding box of `frame`'s `<iframe>` element in page coordinates; `None` for the main frame
    /// or a frame element outside the layout.
    pub async fn frame_element_box(&self, frame: &FrameId) -> Result<Option<BoundingBox>, CdpError> {
        let Some(el) = self.frame_element(frame).await? else { return Ok(None) };
        let el = DisposeOnDrop(el);
        let r = self.element_box(&el.0).await;
        el.0.dispose().await;
        r
    }

    /// Runs `js` on `frame`'s element in its parent document and returns the value; `None` for the main
    /// frame. Guarded like [`Page::frame_element_box`]: a call dropped while it holds the element (a
    /// timeout) still lets it go.
    pub async fn frame_element_evaluate(&self, frame: &FrameId, js: &str) -> Result<Option<Value>, CdpError> {
        let Some(el) = self.frame_element(frame).await? else { return Ok(None) };
        let el = DisposeOnDrop(el);
        let r = el.0.evaluate(js, vec![]).await;
        el.0.dispose().await;
        r.map(Some)
    }

    /// Puppeteer's `ElementHandle.boundingBox`: the element's box in page coordinates.
    pub async fn element_box(&self, el: &JsHandle) -> Result<Option<BoundingBox>, CdpError> {
        let Some(b) = parse_box(&el.evaluate(JS_BOX, vec![]).await?) else { return Ok(None) };
        let Some((dx, dy)) = self.top_left_of_frame(el.frame()).await? else { return Ok(None) };
        Ok(Some(BoundingBox { x: b.x + dx, y: b.y + dy, ..b }))
    }

    /// The offset of `frame`'s content box inside the page, summed over its ancestors.
    async fn top_left_of_frame(&self, frame: &FrameId) -> Result<Option<(f64, f64)>, CdpError> {
        Ok(self.frame_origin(frame, false).await?.map(|o| (o.x, o.y)))
    }

    /// [`Page::top_left_of_frame`], with the first doubt about an offset on the way, and the first
    /// thing that turns a frame on the way. `exact` asks each level what a closed shadow root could hide
    /// ([`Page::frame_offset`]): the click check's frame query needs that, nothing else does.
    async fn frame_origin(&self, frame: &FrameId, exact: bool) -> Result<Option<Origin>, CdpError> {
        self.frame_origin_keeping(frame, exact, None).await
    }

    /// [`Page::frame_origin`], keeping in `kept`, when it is given, each level's frame element beside
    /// where its border box and content box were read (`JS_FRAME_OFFSET`'s `x`, `y`, `left` and `top`),
    /// for [`Page::frame_on_top_in`] to read again: any scroll in a document or scroller above the frame
    /// moves both, and a padding or border changed since moves the second. The caller lets them go.
    async fn frame_origin_keeping(
        &self,
        frame: &FrameId,
        exact: bool,
        mut kept: Option<&mut Vec<Kept>>,
    ) -> Result<Option<Origin>, CdpError> {
        let mut origin = Origin { x: 0.0, y: 0.0, doubt: None, turned: None };
        let mut current = frame.clone();
        while let Some(parent) = self.parent_frame(&current) {
            let Some(offset) = self.frame_offset(&current, exact, kept.as_deref_mut()).await? else {
                return Ok(None);
            };
            origin.x += offset.left;
            origin.y += offset.top;
            origin.doubt = origin.doubt.or(offset.doubt);
            origin.turned = origin.turned.or(offset.turned);
            current = parent;
        }
        Ok(Some(origin))
    }

    /// Where `frame`'s content box sits in its parent's view: its element's border box, plus border and
    /// padding as layout has them, from `DOM.getBoxModel` (at a device scale of 1, a `0.9px` padding is
    /// 57/64 px in layout, and computed style says 0.9). When something on the element's way up turns
    /// it (`JS_FRAME_OFFSET`'s 'turned'), or its quads are not upright rectangles the right way round,
    /// or the box model could not be read (a turn is not ruled out), the offset says what turns it, and
    /// the click is refused; the quads are checked even when the walk found only what may move it.
    /// When something may move it by a fraction ('moved'), or the content quad is not the size the
    /// element's style gives, or lies far out, the offset is only rough (border box plus computed
    /// padding and border, `JS_FRAME_OFFSET`'s), and says why. With `kept`, the frame element is kept
    /// there, not let go. Only the click check's frame query needs the exact
    /// point (`Page::frame_on_top_in`), and it takes none that is rough; the box rule and the page's hit
    /// test take the offset as it is, the box model's unless it is in doubt.
    ///
    /// With `exact`, the elements on the way that could host a closed shadow root (`JS_FRAME_OFFSET`'s
    /// `hosts`) are each asked `DOM.describeNode`, which reports a shadow root of any kind, and one with
    /// any puts the offset in doubt: a rendered element under a host the world cannot see into is
    /// slotted into that host's shadow root, whose slot and wrappers the world cannot read. That is two
    /// more round trips at the level (the elements' handles, then every description at once).
    async fn frame_offset(
        &self,
        frame: &FrameId,
        exact: bool,
        kept: Option<&mut Vec<Kept>>,
    ) -> Result<Option<FrameOffset>, CdpError> {
        let el = self
            .frame_element(frame)
            .await?
            .ok_or_else(|| CdpError::Other("Unsupported frame type".into()))?;
        // Guarded like `frame_element_box`'s: a nested frame's read dropped here still releases it.
        let el = DisposeOnDrop(el);
        let model = async {
            let id =
                el.0.object_id().ok_or_else(|| CdpError::Other("the frame element has no object".into()))?;
            self.inner.send(el.0.context().session.as_ref(), "DOM.getBoxModel", json!({"objectId": id})).await
        };
        let hosts = async {
            if exact {
                el.0.evaluate_handle(JS_FRAME_OFFSET, vec![Arg::Value(json!(true))])
                    .await
                    .map(|h| Some(DisposeOnDrop(h)))
            } else {
                Ok(None)
            }
        };
        let (read, model, hosts) =
            futures_util::future::join3(el.0.evaluate(JS_FRAME_OFFSET, vec![]), model, hosts).await;
        match kept {
            Some(kept) => {
                let at = read.as_ref().ok().and_then(place_of);
                kept.push(Kept { el, at });
            }
            None => el.0.release(),
        }
        let count = read.as_ref().ok().and_then(|style| style.get("hosts")).and_then(Value::as_u64);
        let mut offset = read.map(|style| offset_from(&style, model));
        match (&mut offset, hosts) {
            (Ok(Some(o)), hosts) if exact && o.doubt.is_none() && o.turned.is_none() => {
                o.doubt = self.closed_host(hosts, count).await;
            }
            (_, Ok(Some(hosts))) => hosts.0.release(),
            _ => {}
        }
        offset
    }

    /// A doubt when an element in `hosts` (`JS_FRAME_OFFSET`'s, `count` of them) has a shadow root the
    /// world cannot see, or when that cannot be told. Every handle is let go without waiting.
    async fn closed_host(
        &self,
        hosts: Result<Option<DisposeOnDrop>, CdpError>,
        count: Option<u64>,
    ) -> Option<Doubt> {
        let hosts = match hosts {
            Ok(Some(hosts)) => hosts,
            Ok(None) => {
                return Some(Doubt::new(Unsettled::Failed, "the elements above the frame were not read"));
            }
            Err(e) => return Some(e.into()),
        };
        // Guarded as the frame element is, from its read on: a read dropped here still lets it go.
        let r = self.closed_host_in(&hosts.0, count).await;
        hosts.0.release();
        r
    }

    async fn closed_host_in(&self, hosts: &JsHandle, count: Option<u64>) -> Option<Doubt> {
        let Some(count) = count else {
            return Some(Doubt::new(Unsettled::Failed, "the frame's offset read no count of hosts"));
        };
        if count == 0 {
            return None;
        }
        if count > MAX_HOSTS {
            let what =
                format!("{count} elements above the frame could each slot it into a closed shadow root");
            return Some(Doubt::new(Unsettled::Transformed, what));
        }
        // Each element as a handle of its own, all at once, beside the list's length (the list and the
        // count were two reads, and the page may have changed between them), read in the world from the
        // world's array: `Runtime.callFunctionOn`, already relayed, so the bridge's list gains nothing.
        let session = hosts.context().session.as_ref();
        // Each guarded as it comes back, so a read dropped before they are all in still lets them go.
        let each = join_all((0..count).map(|i| async move {
            hosts.evaluate_handle("(a, i) => a[i]", vec![Arg::Value(json!(i))]).await.map(DisposeOnDrop)
        }));
        let (read, length) =
            futures_util::future::join(each, hosts.evaluate("(a) => a.length", vec![])).await;
        let failed = read.iter().find_map(|h| h.as_ref().err().map(ToString::to_string));
        let items: Vec<DisposeOnDrop> = read.into_iter().filter_map(Result::ok).collect();
        let r = if let Some(e) = failed {
            Some(Doubt::new(Unsettled::Failed, format!("the elements above the frame were not read: {e}")))
        } else if length.ok().and_then(|n| n.as_u64()) != Some(count) {
            Some(Doubt::new(Unsettled::Failed, "the elements above the frame changed while they were read"))
        } else if items.iter().all(|h| h.0.object_id().is_some()) {
            let described = join_all(items.iter().map(|h| {
                let params = json!({"objectId": h.0.object_id().unwrap_or_default(), "depth": 0});
                self.inner.send(session, "DOM.describeNode", params)
            }))
            .await;
            let mut doubt = None;
            for node in described {
                match node {
                    Ok(node) => {
                        let roots = node.pointer("/node/shadowRoots").and_then(Value::as_array);
                        if doubt.is_none() && roots.is_some_and(|r| !r.is_empty()) {
                            let what = "the frame, or an element above it, is slotted into a shadow root the \
                                        world cannot open, so what moves it there is not known";
                            doubt = Some(Doubt::new(Unsettled::Transformed, what));
                        }
                    }
                    Err(e) => doubt = doubt.or_else(|| Some(e.into())),
                }
            }
            doubt
        } else {
            Some(Doubt::new(Unsettled::Failed, "an element above the frame read as no object"))
        };
        for h in &items {
            h.0.release();
        }
        r
    }

    /// A document's size, `JS_DOCUMENT_SIZE`'s, to clip boxes to.
    async fn document_size(&self, frame: &FrameId) -> Result<(f64, f64), CdpError> {
        let size = self.evaluate(frame, JS_DOCUMENT_SIZE, vec![]).await?;
        let w = size.get("documentWidth").and_then(Value::as_f64).unwrap_or(0.0);
        let h = size.get("documentHeight").and_then(Value::as_f64).unwrap_or(0.0);
        Ok((w, h))
    }

    /// Puppeteer's `clickablePoint`: the centre of the first client rect that is still at least 1x1
    /// after clipping to every enclosing document. (The brief said `DOM.getContentQuads`; puppeteer 25.11
    /// uses `getClientRects`, and this follows the code.)
    pub async fn clickable_point(&self, el: &JsHandle) -> Result<(f64, f64), CdpError> {
        let (b, _) = self.clickable_box(el).await?;
        Ok((b.x + b.width / 2.0, b.y + b.height / 2.0))
    }

    /// [`Page::clickable_point`] on whole CSS pixels, still inside the box: the point a click is checked
    /// at and then pressed at, the very same one. `DOM.getNodeForLocation` takes whole pixels only, and
    /// a box's centre can fall between two (a 101-px-wide box), where a frame narrower than a pixel
    /// could hold the pressed point and not the checked one. Refused for an element in a frame that the
    /// page turns ([`FrameOffset`]'s `turned`): no point in it is known.
    async fn press_point(&self, el: &JsHandle) -> Result<(f64, f64), CdpError> {
        let (b, turn) = self.clickable_box(el).await?;
        if let Some(what) = turn {
            return Err(turned(&what));
        }
        Ok((snap(b.x, b.width), snap(b.y, b.height)))
    }

    /// The first client rect still at least 1x1 after clipping to every enclosing document, in page
    /// coordinates, and what turns a frame on the way, when something does. Each document's size is
    /// read beside what comes before it: the rects, or the frame's offset.
    async fn clickable_box(&self, el: &JsHandle) -> Result<(BoundingBox, Option<String>), CdpError> {
        let not_clickable = || CdpError::Other("Node is either not clickable or not an Element".into());
        let mut frame = el.frame().clone();
        let (rects, size) =
            futures_util::future::join(el.evaluate(JS_CLIENT_RECTS, vec![]), self.document_size(&frame))
                .await;
        let mut boxes: Vec<BoundingBox> =
            rects?.as_array().map(|a| a.iter().filter_map(parse_box).collect()).unwrap_or_default();
        if boxes.is_empty() {
            return Err(not_clickable());
        }
        let (mut w, mut h) = size?;
        let mut turn = None;
        loop {
            for b in &mut boxes {
                intersect_box(b, w, h);
            }
            let Some(parent) = self.parent_frame(&frame) else { break };
            let (offset, size) = futures_util::future::join(
                self.frame_offset(&frame, false, None),
                self.document_size(&parent),
            )
            .await;
            let Some(FrameOffset { left, top, turned, .. }) = offset? else { return Err(not_clickable()) };
            turn = turn.or(turned);
            for b in &mut boxes {
                b.x += left;
                b.y += top;
            }
            (w, h) = size?;
            frame = parent;
        }
        let b = boxes.into_iter().find(|b| b.width >= 1.0 && b.height >= 1.0).ok_or_else(not_clickable)?;
        Ok((b, turn))
    }

    async fn assert_connected(&self, el: &JsHandle) -> Result<(), CdpError> {
        match el.evaluate(JS_ASSERT_CONNECTED, vec![]).await? {
            Value::String(e) => Err(CdpError::Other(e)),
            _ => Ok(()),
        }
    }

    /// Whether the element is attached is read beside whether it is in view: neither waits on the other,
    /// and the first answer that counts is the attachment's.
    async fn scroll_into_view_if_needed(&self, el: &JsHandle) -> Result<(), CdpError> {
        let (connected, in_view) =
            futures_util::future::join(self.assert_connected(el), el.evaluate(JS_FULLY_IN_VIEWPORT, vec![]))
                .await;
        connected?;
        if in_view? == Value::Bool(true) {
            return Ok(());
        }
        self.assert_connected(el).await?;
        let session = el.context().session.clone();
        let scrolled = match el.object_id() {
            Some(id) => self
                .inner
                .send(session.as_ref(), "DOM.scrollIntoViewIfNeeded", json!({"objectId": id}))
                .await
                .is_ok(),
            None => false,
        };
        if !scrolled {
            el.evaluate(JS_SCROLL_INTO_VIEW, vec![]).await?;
        }
        Ok(())
    }

    /// [`Page::press_element`], with either kind of failure as its error.
    pub async fn click_element(&self, el: &JsHandle) -> Result<(), CdpError> {
        self.press_element(el).await.map_err(ClickError::into_inner)
    }

    /// Puppeteer's `ElementHandle.click`: scroll into view if needed, then click the clickable point,
    /// but only once [`Page::assert_uncovered`] finds the element itself there. A real mouse click goes
    /// to whatever is on top, so without the check a page (or an ad frame) could put something over the
    /// target and take the agent's click.
    ///
    /// The check runs twice: before the pointer moves, and again once the page has taken the move and
    /// had a frame to act on it, just before the press. The page's own `mousemove` and `pointerover`
    /// handlers run as the pointer arrives, so one could slide an overlay in or let it take pointer
    /// events; the second check sees that. (Sending move and press together would not help: those
    /// handlers run between the two all the same.) What it cannot see is work such a handler leaves for
    /// later, a timer that fires between the second check and the press.
    ///
    /// Neither wait on the way needs the page to render: each has a timer beside it, so a hidden window
    /// that draws no frames still clicks.
    ///
    /// # Errors
    /// [`ClickError::NotPressed`] for every failure before the button goes down (a refusal, a detached or
    /// zero-size element, a navigation, a command that timed out), [`ClickError::Pressed`] for one at
    /// the press or the release, which may have landed.
    pub async fn press_element(&self, el: &JsHandle) -> Result<(), ClickError> {
        let before = async {
            self.scroll_into_view_if_needed(el).await?;
            let (x, y) = self.press_point(el).await?;
            self.assert_uncovered(el, x, y).await?;
            self.mouse_move(x, y).await?;
            el.evaluate(JS_NEXT_FRAME, vec![]).await?;
            self.assert_uncovered(el, x, y).await
        };
        before.await.map_err(ClickError::NotPressed)?;
        self.mouse_press_release().await.map_err(ClickError::Pressed)
    }

    /// Fails with [`CdpError::Covered`] unless the element is on top at page point (x, y): in its own
    /// document, and its frame's `<iframe>` element in each enclosing one (the page's hit test, in
    /// [`Page::hit_chain`]). Then, last, as near the press as it can be, [`Page::frame_on_top`] looks
    /// for a frame on top there that the page's hit test sees through, and for anything else on top
    /// that is not the element's own (an overlay slid in since the hit test). When that cannot settle
    /// it, the hit chain runs again with the box of every frame element counting (`JS_HIT`'s
    /// `strict`), looked for by the frame tree too, since a closed shadow root hides it from the page's
    /// hit test. Four round trips in the main frame (the hit test beside the scroll read, the two
    /// answers, what the node is beside resolving it and reading again the scroll and where each
    /// frame element placing the process is, and the judgement;
    /// the handles are let go without waiting), plus a few per level in an iframe, two of them for
    /// each frame level above a process's root to ask what a closed shadow root there could hide
    /// (`Page::frame_offset`'s `exact`).
    async fn assert_uncovered(&self, el: &JsHandle, x: f64, y: f64) -> Result<(), CdpError> {
        // The scroll of the element's own process, which the frame query adds, is read beside the hit
        // test: neither waits on the other.
        let scroll = async {
            match self.local_root(el.frame()) {
                Ok(root) => self.evaluate(&root, JS_SCROLL, vec![]).await,
                Err(e) => Err(e),
            }
        };
        let (hit, scroll) = futures_util::future::join(self.hit_chain(el, x, y, false), scroll).await;
        hit?;
        match self.frame_on_top(el, x, y, scroll).await {
            Ok(None) => Ok(()),
            Ok(Some(what)) => Err(covered(&what)),
            // Content that takes no pointer events lies over the point, the point falls between pixels
            // in a frame, a frame on the way is transformed, the node is a pseudo-element, or a command
            // failed (an extension older than the service refuses it, the frame changed under it): fail
            // closed, refusing any frame whose box holds the point. `Unsettled` names each.
            Err(doubt) => {
                let why = "the node at the click point is unsettled; every frame box there covers it";
                tracing::debug!(reason = ?doubt.why, error = %doubt.error, "{why}");
                #[cfg(feature = "test-seams")]
                self.inner.strict_fallbacks[doubt.why as usize]
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.hit_chain(el, x, y, true).await
            }
        }
    }

    /// Test builds only: how many click checks on this page have fallen back to the box rule for `why`,
    /// because [`Page::frame_on_top`] could not settle them. The real-Chrome lane reads it to tell which
    /// check answered, and why.
    #[cfg(feature = "test-seams")]
    #[must_use]
    pub fn strict_fallbacks(&self, why: Unsettled) -> usize {
        self.inner.strict_fallbacks[why as usize].load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The page's hit test at page point (x, y), in the element's frame and then each one above it,
    /// where the frame holding the element is the element. With `strict`, any other frame there whose
    /// box holds the point covers it too.
    async fn hit_chain(&self, el: &JsHandle, x: f64, y: f64, strict: bool) -> Result<(), CdpError> {
        let mut frame = el.frame().clone();
        // Every frame element is guarded, so a check dropped partway (a timeout or an abort) lets it go.
        let owners = if strict { self.child_frame_elements(&frame).await } else { Vec::new() };
        let r = self.hit_test(el, &frame, x, y, strict, &owners).await;
        release_all(&owners);
        r?;
        while let Some(parent) = self.parent_frame(&frame) {
            let owner = DisposeOnDrop(
                self.frame_element(&frame)
                    .await?
                    .ok_or_else(|| CdpError::Other("Unsupported frame type".into()))?,
            );
            let owners = if strict { self.child_frame_elements(&parent).await } else { Vec::new() };
            let r = self.hit_test(&owner.0, &parent, x, y, strict, &owners).await;
            owner.0.release();
            release_all(&owners);
            r?;
            frame = parent;
        }
        Ok(())
    }

    /// Whether a frame is on top at page point (x, y) for the press, even one the page's hit test sees
    /// through: `elementFromPoint` skips a frame with `pointer-events: none`, yet headless Chrome routed
    /// the press into such a cross-site frame inside a card link. `DOM.getNodeForLocation`, with
    /// `pointer-events: none` ignored, names the topmost node there as layout has it, looking into
    /// closed shadow roots and into frames in the same process; it runs once in the element's process
    /// and once in each process above. `Some(name)` when what it finds is a frame element other than
    /// the element or one holding it, or is inside such a frame. A frame under opaque content, or
    /// `visibility: hidden`, is not on top, so it does not count. Anything else on top must be the
    /// element's own (the element, inside it, or a label for it), as the page's hit test found just
    /// before: this answer is the later one.
    ///
    /// An error means it could not tell, and the box rule answers instead; [`Unsettled`] says why: the
    /// topmost node is not the one the press goes to with `pointer-events` honoured (something that
    /// takes no pointer events lies over it, and could be a decoy over a frame), the point falls between
    /// whole pixels in a frame's document, a frame on the way is transformed, the node is a
    /// pseudo-element, or a command failed.
    ///
    /// `scroll` is the element's own process's scroll (`JS_SCROLL`), read already; each process above
    /// reads its own. Every handle it resolves is let go without waiting for the answer.
    async fn frame_on_top(
        &self,
        el: &JsHandle,
        x: f64,
        y: f64,
        scroll: Result<Value, CdpError>,
    ) -> Result<Option<String>, Doubt> {
        let mut frame = el.frame().clone();
        let mut owner: Option<DisposeOnDrop> = None;
        let mut scroll = Some(scroll);
        let r = loop {
            let root = match self.local_root(&frame) {
                Ok(root) => root,
                Err(e) => break Err(e.into()),
            };
            let here = scroll.take();
            match self.frame_on_top_in(owner.as_ref().map_or(el, |o| &o.0), &frame, &root, here, (x, y)).await
            {
                Ok(None) => {}
                other => break other,
            }
            let Some(parent) = self.parent_frame(&root) else { break Ok(None) };
            // In the process above, the element is the frame element holding this process's frames.
            let next = match self.frame_element(&root).await {
                Ok(Some(next)) => DisposeOnDrop(next),
                Ok(None) => break Err(CdpError::Other("Unsupported frame type".into()).into()),
                Err(e) => break Err(e.into()),
            };
            if let Some(old) = owner.replace(next) {
                old.0.release();
            }
            frame = parent;
        };
        if let Some(owner) = owner {
            owner.0.release();
        }
        r
    }

    /// The highest frame above `frame` (or itself) in the same session: what `DOM.getNodeForLocation`
    /// hit-tests from there.
    fn local_root(&self, frame: &FrameId) -> Result<FrameId, CdpError> {
        let session = self.inner.session_of(frame)?;
        let mut root = frame.clone();
        while let Some(parent) = self.parent_frame(&root) {
            if self.inner.session_of(&parent)? != session {
                break;
            }
            root = parent;
        }
        Ok(root)
    }

    /// [`Page::frame_on_top`] in one process: `target` is in `frame`, which `root` holds; `scroll` is
    /// `root`'s, if it was read already. The frame elements placing `root` are let go however it ends.
    async fn frame_on_top_in(
        &self,
        target: &JsHandle,
        frame: &FrameId,
        root: &FrameId,
        scroll: Option<Result<Value, CdpError>>,
        (x, y): (f64, f64),
    ) -> Result<Option<String>, Doubt> {
        let mut kept = Vec::new();
        let r = self.frame_on_top_kept(target, frame, root, scroll, (x, y), &mut kept).await;
        for k in &kept {
            k.el.0.release();
        }
        r
    }

    async fn frame_on_top_kept(
        &self,
        target: &JsHandle,
        frame: &FrameId,
        root: &FrameId,
        scroll: Option<Result<Value, CdpError>>,
        (x, y): (f64, f64),
        kept: &mut Vec<Kept>,
    ) -> Result<Option<String>, Doubt> {
        let read_scroll = async {
            match scroll {
                Some(scroll) => scroll,
                None => self.evaluate(root, JS_SCROLL, vec![]).await,
            }
        };
        let (origin, scroll) =
            futures_util::future::join(self.frame_origin_keeping(root, true, Some(&mut *kept)), read_scroll)
                .await;
        let Origin { x: dx, y: dy, doubt, turned } =
            origin?.ok_or_else(|| CdpError::Other("the frame's place on the page is unknown".into()))?;
        // A frame on the way that the page turns (the page's hit test, which runs first, refuses it, so
        // this is one turned since), or one that may move it by a fraction, is slotted where the world
        // cannot see: where the point falls here is not known exactly.
        if let Some(what) = turned {
            return Err(Doubt::new(Unsettled::Transformed, format!("a frame on the way is turned ({what})")));
        }
        if let Some(doubt) = doubt {
            return Err(doubt);
        }
        // The command takes the root document's coordinates, so its scroll is added (Chrome's
        // `InspectorDOMAgent::getNodeForLocation` maps them with `DocumentToFrame`). A wrong space
        // names another node with no error, so `tests/chrome.rs` (`scrolled`) clicks with the page
        // scrolled both ways, and in scrolled frames. Read in the world, where the page cannot replace
        // `scrollX`.
        // A read that is not two numbers is an error, never a scroll of 0, which would ask about
        // another point with no error.
        let scroll = scroll?;
        let Some((sx, sy)) = two_numbers(&scroll) else {
            return Err(CdpError::Other(format!("the frame's scroll read as {scroll}")).into());
        };
        // The press is sent at (x, y), whole CSS pixels in the main frame (`press_point`), and the
        // command takes whole pixels only. In a frame placed at a fractional offset, or a document
        // scrolled by a fraction, the point falls between pixels here. Asking at the neighbouring
        // pixels would not close that: a frame narrower than a pixel can lie between them. So the box
        // rule, exact to the fraction, answers there instead.
        let (px, py) = (x - dx + sx, y - dy + sy);
        if !is_whole(px) || !is_whole(py) {
            let what = format!("the click point ({px}, {py}) falls between pixels here");
            return Err(Doubt::new(Unsettled::BetweenPixels, what));
        }
        let session = self.inner.session_of(root)?;
        // Whole, and inside the view, far from the limits.
        #[allow(clippy::cast_possible_truncation)]
        let (px, py) = (px as i64, py as i64);
        // Asked twice at the one point: with `pointer-events: none` ignored, for what layout has on top,
        // and honoured, for what the press goes to as the page's own hit test sees it. When the two
        // differ, something that takes no pointer events lies over what the press would hit, and a
        // decoy (a `::after` or a span over a frame) would hide a frame from the first answer: the box
        // rule answers then. An honest button with a decorative overlay (an icon, a ripple) still
        // clicks, unless a frame's box holds the point: a play button over another site's video frame,
        // its icon taking no pointer events, is refused (SR-34's known false refusal). Without UA
        // shadow DOM, a node in the browser's own shadow root of an <object>, <embed> or <input> comes
        // back as that element.
        let ask = |ignore: bool| {
            let params = json!({
                "x": px, "y": py, "includeUserAgentShadowDOM": false, "ignorePointerEventsNone": ignore
            });
            self.inner.send(session.as_ref(), "DOM.getNodeForLocation", params)
        };
        let (top, routed) = futures_util::future::join(ask(true), ask(false)).await;
        let (top, routed) = (top?, routed?);
        let (Some(backend), Some(node_frame)) = (top.get("backendNodeId"), top["frameId"].as_str()) else {
            return Err(CdpError::Other("DOM.getNodeForLocation returned no node".into()).into());
        };
        let agree =
            routed.get("backendNodeId") == Some(backend) && routed["frameId"].as_str() == Some(node_frame);
        let up_to_root = |from: FrameId| {
            let mut path = vec![from];
            while path.last() != Some(root) {
                let parent = path.last().and_then(|f| self.parent_frame(f))?;
                path.push(parent);
            }
            Some(path)
        };
        let elsewhere = || CdpError::Other("the node at the point is in a frame outside this process".into());
        let theirs = up_to_root(FrameId::from(node_frame)).ok_or_else(elsewhere)?;
        let ours = up_to_root(frame.clone()).ok_or_else(elsewhere)?;
        // The deepest frame holding both the node and the element: compare what each is there.
        let (up_theirs, common) =
            theirs.iter().enumerate().find(|(_, f)| ours.contains(*f)).ok_or_else(elsewhere)?;
        let up_ours = ours.iter().position(|f| f == common).unwrap_or(0);
        // What the node is, the node itself (or the element of the frame holding it) and the frame
        // element holding the target, all at once: none waits on another.
        let mine = up_theirs == 0;
        let describe = async {
            if !mine {
                return Ok(None);
            }
            let params = json!({"backendNodeId": backend});
            self.inner.send(session.as_ref(), "DOM.describeNode", params).await.map(Some)
        };
        // Both guarded as they come back, so a check dropped while the others are pending lets them go.
        let found = async {
            if mine {
                return self.resolve_in_world(common, backend.clone()).await.map(DisposeOnDrop);
            }
            // Inside a frame in this process: that frame's element is what is on top.
            let element = self.frame_element(&theirs[up_theirs - 1]).await;
            element.and_then(|f| {
                f.map(DisposeOnDrop).ok_or_else(|| CdpError::Other("Unsupported frame type".into()))
            })
        };
        let holder = async {
            if up_ours == 0 {
                Ok::<_, CdpError>(None)
            } else {
                Ok(self.frame_element(&ours[up_ours - 1]).await?.map(DisposeOnDrop))
            }
        };
        // The scroll again, and where each frame element placing this process's root is, beside those:
        // a page that scrolled since they were read, in this process or in any document or scroller
        // above it, would have had the command asked about another point, with no error (review r9 S-1).
        let again = self.still_placed(root, kept, (sx, sy));
        let (node, found, holder, still) = futures_util::future::join4(describe, found, holder, again).await;
        let moved = !still;
        // Each is a guard, let go however this ends, without waiting for the answer: none is used past it.
        let (found, holder) = match (found, holder) {
            (Ok(found), Ok(holder)) => (found, holder),
            (found, holder) => {
                return Err(found.err().or(holder.err()).map_or_else(
                    || CdpError::Other("the node on top was not resolved".into()).into(),
                    Doubt::from,
                ));
            }
        };
        if moved {
            Err(Doubt::new(Unsettled::Failed, "the page scrolled during the check"))
        } else {
            on_top(node, &found.0, holder.as_ref().map_or(target, |h| &h.0), agree).await
        }
    }

    /// Whether `root`'s scroll still reads `scroll`, and each frame element in `kept` is still where it
    /// was read, its border box and its content box: all at once. Any read that fails says no.
    async fn still_placed(&self, root: &FrameId, kept: &[Kept], scroll: (f64, f64)) -> bool {
        let places = join_all(kept.iter().map(|k| k.el.0.evaluate(JS_PLACE, vec![])));
        let (now, places) = futures_util::future::join(self.evaluate(root, JS_SCROLL, vec![]), places).await;
        let same = |(k, place): (&Kept, Result<Value, CdpError>)| {
            k.at.is_some() && place.ok().and_then(|p| place_of(&p)) == k.at
        };
        now.ok().and_then(|now| two_numbers(&now)) == Some(scroll) && kept.iter().zip(places).all(same)
    }

    /// The node `backend` as a handle in `frame`'s isolated world. The caller disposes it.
    async fn resolve_in_world(&self, frame: &FrameId, backend: Value) -> Result<JsHandle, CdpError> {
        let ctx = self.inner.world_for(frame).await?;
        let resolved = self
            .inner
            .send(
                ctx.session.as_ref(),
                "DOM.resolveNode",
                json!({"backendNodeId": backend, "executionContextId": ctx.id}),
            )
            .await?;
        let object = resolved
            .get("object")
            .cloned()
            .ok_or_else(|| CdpError::Other("DOM.resolveNode returned no object".into()))?;
        Ok(JsHandle::new(self.inner.clone(), ctx, object))
    }

    /// The frame elements of `frame`'s child frames, in `frame`'s isolated world, for the hit test.
    async fn child_frame_elements(&self, frame: &FrameId) -> Vec<DisposeOnDrop> {
        // All at once: each owner is a few round trips, and a page can hold dozens of ad frames. Each is
        // guarded as it comes back, so a check dropped before they are all in lets them go.
        let children = self.inner.children_of(frame);
        let found = join_all(children.iter().map(|child| async move {
            Ok::<_, CdpError>(self.frame_element(child).await?.map(DisposeOnDrop))
        }))
        .await;
        let mut owners = Vec::new();
        for (child, owner) in children.iter().zip(found) {
            match owner {
                Ok(Some(owner)) => owners.push(owner),
                Ok(None) => {}
                // Most often the frame detached since the tree was read, and then it cannot take the
                // click; anything else leaves this one frame to the hit test's own walk of the
                // document, which misses it only in a closed shadow root, so say so.
                Err(e) => {
                    tracing::debug!(frame = %child, error = %e, "frame owner not resolved for the hit test");
                }
            }
        }
        owners
    }

    async fn hit_test(
        &self,
        el: &JsHandle,
        frame: &FrameId,
        x: f64,
        y: f64,
        strict: bool,
        frames: &[DisposeOnDrop],
    ) -> Result<(), CdpError> {
        let Some(origin) = self.frame_origin(frame, false).await? else { return Err(covered("")) };
        // A frame on the way that the page turns: no point in it is known, so neither check is either.
        if let Some(what) = origin.turned {
            return Err(turned(&what));
        }
        let (dx, dy) = (origin.x, origin.y);
        let mut args = vec![Arg::Value(json!(x - dx)), Arg::Value(json!(y - dy)), Arg::Value(json!(strict))];
        args.extend(frames.iter().map(|f| Arg::Handle(&f.0)));
        match el.evaluate(JS_HIT, args).await? {
            Value::String(what) => Err(covered(&what)),
            _ => Ok(()),
        }
    }

    async fn focus_element(&self, el: &JsHandle) -> Result<(), CdpError> {
        el.evaluate(JS_FOCUS, vec![]).await.map(drop)
    }

    /// `document.querySelector` in the main frame; `None` when nothing matches.
    pub async fn query_selector(&self, selector: &str) -> Result<Option<JsHandle>, CdpError> {
        let main = self.main_frame()?;
        let h = self.evaluate_handle(&main, JS_QUERY, vec![Arg::Value(json!(selector))]).await?;
        if h.is_nullish() {
            return Ok(None);
        }
        Ok(Some(h))
    }

    /// Puppeteer's locator loop: find the element, run `action`, and on any failure retry every 100 ms
    /// until the locator timeout. The element is only required to exist (the engine turns off the
    /// visibility, enabled, stable-box and in-viewport conditions). Deviations: the wait polls
    /// `querySelector` from here instead of an in-page observer, and a closed page fails at once instead
    /// of being retried until the timeout.
    async fn with_located<F, Fut>(&self, selector: &str, action: F) -> Result<(), CdpError>
    where
        F: Fn(JsHandle) -> Fut,
        Fut: Future<Output = (JsHandle, Result<(), CdpError>)>,
    {
        let timeout = self.options().locator_timeout;
        let last: Mutex<Option<CdpError>> = Mutex::new(None);
        let attempts = async {
            let mut covered_since: Option<Instant> = None;
            loop {
                let outcome = match self.query_selector(selector).await {
                    Ok(Some(h)) => {
                        let (h, r) = action(h).await;
                        h.dispose().await;
                        r
                    }
                    Ok(None) => Err(CdpError::Other(format!("No element found for selector: {selector}"))),
                    Err(e) => Err(e),
                };
                match outcome {
                    Ok(()) => return Ok(()),
                    Err(e) if e.is_closed() => return Err(e),
                    // Something on top may be on its way out; past the grace it is reported as it is,
                    // never as a timeout (the engine reads "timed out" as "may still have landed").
                    Err(e @ CdpError::Covered(_)) => {
                        let since = *covered_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= COVERED_GRACE {
                            return Err(e);
                        }
                        *last.lock() = Some(e);
                    }
                    Err(e) => {
                        covered_since = None;
                        *last.lock() = Some(e);
                    }
                }
                tokio::time::sleep(RETRY_DELAY).await;
            }
        };
        if timeout.is_zero() {
            return attempts.await;
        }
        match tokio::time::timeout(timeout, attempts).await {
            Ok(r) => r,
            Err(_) => match last.lock().take() {
                Some(e @ CdpError::Covered(_)) => Err(e),
                last => Err(CdpError::WaitTimeout { ms: millis(timeout), last: last.map(|e| e.to_string()) }),
            },
        }
    }

    /// Clicks the first element matching `selector` in the main frame, with the engine's locator rules.
    pub async fn click_selector(&self, selector: &str) -> Result<(), CdpError> {
        self.with_located(selector, |h| async move {
            let r = self.click_element(&h).await;
            (h, r)
        })
        .await
    }

    /// Puppeteer's `Locator.fill` for the first element matching `selector` in the main frame.
    pub async fn fill(&self, selector: &str, text: &str) -> Result<(), CdpError> {
        self.with_located(selector, |h| async move {
            let r = self.fill_element(&h, text).await;
            (h, r)
        })
        .await
    }

    async fn fill_element(&self, el: &JsHandle, value: &str) -> Result<(), CdpError> {
        let kind = el.evaluate(JS_INPUT_KIND, vec![]).await?;
        match kind.as_str().unwrap_or("unknown") {
            "checkable-input" => {
                let state = el.evaluate(JS_CHECKED_STATE, vec![]).await?;
                // `!!value` for a string: anything but "" means checked.
                if state == json!("mixed") || state != Value::Bool(!value.is_empty()) {
                    self.click_element(el).await?;
                }
                Ok(())
            }
            "select" => self.select_element(el, &[value.to_owned()]).await.map(drop),
            kind @ ("contenteditable" | "typeable-input" | "other-input") => {
                self.write_text(el, kind, value).await
            }
            _ => Err(CdpError::Other("Element cannot be filled out.".into())),
        }
    }

    /// Puppeteer's fill of a text field: a short value is typed after clearing what does not lead up to
    /// it; a long one, or an input that is not typed into, is set at once. Everything it reads, the field's
    /// text now, and the focus are done in the isolated world, and the engine works out what to clear and
    /// type, so what phantab types is the agent's text and nothing the page chose.
    ///
    /// The writes alone are made in the main world, through `main_world_handle`: a framework such as React
    /// keeps its own copy of a field's value on the main world's element, and only a write through it reads
    /// back the way puppeteer's fill (and so the engine before this) left it. The page sees the text the
    /// moment it lands, and gets the typed keys as any page does: its own handlers can move them to another
    /// field, which is the page's to do with its own fields.
    async fn write_text(&self, el: &JsHandle, kind: &str, value: &str) -> Result<(), CdpError> {
        let now = el.evaluate(JS_CURRENT_TEXT, vec![]).await?;
        let editable = now.get("editable").and_then(Value::as_bool).unwrap_or(false);
        let current = now.get("text").and_then(Value::as_str).unwrap_or("");
        if current == value {
            return Ok(());
        }
        let typed = kind != "other-input" && value.encode_utf16().count() < TYPING_THRESHOLD;
        let (writes, rest): (Vec<&str>, &str) = if !typed {
            (vec![value], "")
        } else if current.is_empty() || !value.starts_with(current) {
            (vec![""], value)
        } else {
            (vec!["", current], &value[current.len()..])
        };
        if !typed {
            self.focus_element(el).await?;
        }
        let main = self.main_world_handle(el).await?;
        let args = vec![Arg::Value(json!(editable)), Arg::Value(json!(writes)), Arg::Value(json!(!typed))];
        let r = main.evaluate(JS_WRITE_TEXT, args).await;
        main.dispose().await;
        r?;
        if !rest.is_empty() {
            self.focus_element(el).await?;
            self.type_text(rest).await?;
        }
        Ok(())
    }

    async fn select_element(&self, el: &JsHandle, values: &[String]) -> Result<Vec<String>, CdpError> {
        let v = el.evaluate(JS_SELECT, vec![Arg::Value(json!(values))]).await?;
        Ok(v.as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
            .unwrap_or_default())
    }

    /// Puppeteer's `page.select`: selects options of the `<select>` matching `selector` by value and
    /// returns the values now selected.
    pub async fn select(&self, selector: &str, values: &[String]) -> Result<Vec<String>, CdpError> {
        let el = self
            .query_selector(selector)
            .await?
            .ok_or_else(|| CdpError::Other(format!("No element found for selector: {selector}")))?;
        let r = self.select_element(&el, values).await;
        el.dispose().await;
        r
    }

    /// Puppeteer's `page.$eval`: runs `js` with the first element matching `selector` as its argument.
    pub async fn eval_on_selector(&self, selector: &str, js: &str) -> Result<Value, CdpError> {
        let el = self.query_selector(selector).await?.ok_or_else(|| {
            CdpError::Other(format!("failed to find element matching selector \"{selector}\""))
        })?;
        let r = el.evaluate(js, vec![]).await;
        el.dispose().await;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intersect_clips_like_puppeteer() {
        let mut b = BoundingBox { x: -10.0, y: 5.0, width: 30.0, height: 200.0 };
        intersect_box(&mut b, 100.0, 100.0);
        assert_eq!(b, BoundingBox { x: 0.0, y: 5.0, width: 20.0, height: 95.0 });
        let mut b = BoundingBox { x: 150.0, y: 0.0, width: 10.0, height: 10.0 };
        intersect_box(&mut b, 100.0, 100.0);
        assert_eq!(b.width, 0.0);
    }

    /// The click's two waits, run under node where neither the observer nor `requestAnimationFrame`
    /// ever calls back, as in a hidden window that draws no frames: both must still resolve, the first
    /// with "not known to be in view". With an observer that answers, the first keeps its answer.
    /// Skipped without node.
    #[test]
    fn the_click_waits_end_without_a_rendered_frame() {
        let script = format!(
            r"globalThis.SVGElement = class {{}}; globalThis.SVGSVGElement = class {{}};
let answers = false;
globalThis.IntersectionObserver = class {{
  constructor(cb) {{ this.cb = cb; }}
  observe(t) {{ if (answers) queueMicrotask(() => this.cb([{{intersectionRatio: 1}}])); }}
  disconnect() {{}}
}};
globalThis.requestAnimationFrame = () => 0;
const hung = setTimeout(() => {{ console.log('hung'); process.exit(1); }}, 5000);
const inView = ({JS_FULLY_IN_VIEWPORT});
const nextFrame = ({JS_NEXT_FRAME});
const without = await inView({{}});
await nextFrame();
answers = true;
const withIt = await inView({{}});
clearTimeout(hung);
console.log(JSON.stringify([without, withIt]));"
        );
        let Some((ok, said)) = node("waits", &script) else { return };
        assert!(ok, "a wait needs a frame: {said}");
        assert_eq!(said.trim(), "[false,true]");
    }

    /// Runs `script` as an ES module under node: whether it exited 0, and what it printed. `None`
    /// (skipped) without node.
    fn node(name: &str, script: &str) -> Option<(bool, String)> {
        let dir = std::env::temp_dir().join(format!("phantab-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{name}.mjs"));
        std::fs::write(&file, script).unwrap();
        let out = std::process::Command::new("node").arg(&file).output();
        let _ = std::fs::remove_dir_all(&dir);
        let out = out.map_err(|e| eprintln!("skipped: no node ({e})")).ok()?;
        Some((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
    }

    /// What `JS_FRAME_OFFSET` reads of the DOM and CSSOM, mocked for node.
    const FRAME_OFFSET_MOCKS: &str = r"class CSSStyleDeclaration {
  constructor(v) { this.v = v; }
  getPropertyValue(k) { return this.v[k] ?? ''; }
}
class Node {
  get parentNode() { return this.up ?? null; }
  get ownerDocument() { return globalThis.document; }
}
class ShadowRoot extends Node { get host() { return this.owner; } }
class Element extends Node {
  constructor(rect, style, up, tag = 'div') { super(); this.rect = rect; this.style = style; this.up = up; this.tag = tag; }
  getClientRects() { return [this.rect]; }
  getBoundingClientRect() { return this.rect; }
  get assignedSlot() { return this.slot ?? null; }
  get shadowRoot() { return this.open ?? null; }
  get localName() { return this.tag; }
  get scrollLeft() { return this.sx ?? 0; }
  get scrollTop() { return this.sy ?? 0; }
  computedStyleMap() { return new Map(this.typed ? [['transform', this.typed]] : []); }
}
class Document extends Node {
  get documentElement() { return this.root; }
  get body() { return null; }
}
class DOMMatrix {
  constructor(m) {
    const v = m ?? [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1];
    v.forEach((e, i) => { this['m' + (1 + Math.floor(i / 4)) + (1 + (i % 4))] = e; });
  }
  multiply(o) {
    const a = (i, j) => this['m' + i + j], b = (i, j) => o['m' + i + j], out = [];
    for (let i = 1; i <= 4; i++) for (let j = 1; j <= 4; j++) {
      let sum = 0;
      for (let k = 1; k <= 4; k++) sum += a(i, k) * b(k, j);
      out.push(sum);
    }
    return new DOMMatrix(out);
  }
}
class CSSTransformValue extends Array {}
class CSSTranslate { toMatrix() { throw new TypeError('relative lengths'); } }
class CSSScale {
  constructor(k) { this.k = k; }
  toMatrix() { return new DOMMatrix([this.k, 0, 0, 0, 0, this.k, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1]); }
}
Object.assign(globalThis, { CSSStyleDeclaration, Node, ShadowRoot, Element, Document, DOMMatrix,
  CSSTransformValue, CSSTranslate, StylePropertyMapReadOnly: Map });
globalThis.getComputedStyle = (e) => new CSSStyleDeclaration(e.style);
globalThis.document = new Document();
document.root = new Element({left: 0, top: 0}, {}, document, 'html');";

    /// A frame element's offset counts a fractional padding to the fraction (`parseInt` made `0.9px` 0,
    /// so a frame's point read whole where it was not), and its style's size is its content box's,
    /// whatever its `box-sizing`. Up the flat tree (through a slot, a shadow root's host): what scales,
    /// rotates or zooms it is 'turned', read from the typed matrix at full precision where there is one;
    /// what may move it by a fraction is 'moved'; plain style is neither. `hosts` counts the light
    /// parents a closed shadow root could hide in, and lists them when asked. Skipped without node.
    #[test]
    fn a_frame_offset_keeps_the_fraction_of_its_padding() {
        let script = format!(
            r"{FRAME_OFFSET_MOCKS}
const offset = ({JS_FRAME_OFFSET});
const style = {{'padding-left': '0.9px', 'border-left-width': '0px', 'padding-top': '0px',
  'border-top-width': '2px', 'padding-right': '1px', 'border-right-width': '0px', 'padding-bottom': '0px',
  'border-bottom-width': '2px', width: '200px', height: '60px', 'box-sizing': 'content-box'}};
const at = {{left: 10, top: 900, width: 201.9, height: 64}};
const box = (s, up = document.root, tag) => new Element(at, s, up, tag);
const under = (parent) => offset(new Element(at, style, parent)).transformed;
const shadow = new ShadowRoot();
shadow.owner = box({{zoom: '1.5'}}, box({{}}));
// Slotted: the slot's wrapper translates it, and the light parent (the host) is plain.
const host = box({{}}), inner = new ShadowRoot();
inner.owner = host;
host.open = inner;
const slot = box({{}}, box({{transform: 'matrix(1, 0, 0, 1, 0.5, 0)'}}, inner), 'slot');
const slotted = new Element(at, style, host);
slotted.slot = slot;
// Six digits say the identity; the typed value says a scale.
const hidden = box({{transform: 'matrix(1, 0, 0, 1, 0, 0)'}});
hidden.typed = CSSTransformValue.from([new CSSScale(1.0000001)]);
const shifted = box({{transform: 'matrix(1, 0, 0, 1, 3, 0)'}});
shifted.typed = CSSTransformValue.from([new CSSTranslate(), new CSSScale(1)]);
console.log(JSON.stringify([
  offset(new Element(at, style)),
  offset(new Element(at, {{...style, width: '201.9px', height: '64px', 'box-sizing': 'border-box'}})),
  under(box({{}}, box({{transform: 'matrix(1, 0, 0, 1, 0.5, 0)'}}))),
  under(box({{transform: 'matrix(1, 0, 0, 1, 0, 0)', zoom: '1'}})),
  under(box({{transform: 'matrix3d(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 4, 1)'}})),
  offset(new Element(at, {{...style, translate: '0.5px'}})).transformed,
  under(box({{}}, shadow)),
  under(box({{transform: 'none', scale: 'none', rotate: 'none', 'offset-path': 'none', zoom: 'normal'}})),
  under(box({{rotate: '1deg'}})),
  under(box({{transform: 'matrix(1.5, 0, 0, 1.5, 0, 0)'}})),
  under(box({{transform: 'matrix3d(1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, -0.002, 0, 0, 0, 1)'}})),
  under(hidden),
  under(shifted),
  under(box({{'will-change': 'opacity, transform'}})),
  under(box({{'will-change': 'contents'}})),
  under(box({{position: 'sticky'}})),
  under(Object.assign(box({{'overflow-y': 'auto'}}), {{sy: 0.5}})),
  under(new Element({{left: 10.5, top: 900}}, {{'overflow-x': 'scroll'}}, document.root)),
  under(new Element({{left: 10, top: 900}}, {{'overflow-x': 'scroll'}}, document.root)),
  under(box({{}}, box({{}}, document.root, 'details'))),
  offset(slotted).transformed,
  offset(new Element({{...at, width: 300}}, style)).transformed,
  offset(slotted).hosts,
  offset(new Element(at, style, box({{}}, box({{}})))).hosts,
  offset(new Element(at, style, box({{}}, box({{}}))), true).length,
  // The identity `scale` and `rotate` (Tailwind's scale-100, rotate-0) only move it; any other turns it.
  under(box({{scale: '1'}})),
  under(box({{scale: '100% 100%'}})),
  under(box({{scale: '1 1 1'}})),
  under(box({{rotate: '0deg'}})),
  under(box({{rotate: 'x 0deg'}})),
  under(box({{scale: '1 -1'}})),
  under(box({{scale: '1.5'}})),
  under(box({{rotate: '0.5turn'}})),
  under(box({{rotate: 'x 180deg'}})),
]));"
        );
        let Some((ok, said)) = node("offset", &script) else { return };
        assert!(ok, "{said}");
        let at = r#"{"left":10.9,"top":902,"x":10,"y":900,"width":200,"height":60,"transformed":false,"why":"","hosts":0}"#;
        let rest = concat!(
            r#""moved","moved","moved","moved","turned",false,"turned","turned","turned","turned","moved","#,
            r#""moved",false,"moved","moved","moved",false,"moved","moved","turned",1,2,2,"#,
            r#""moved","moved","moved","moved","moved","turned","turned","turned","turned""#
        );
        assert_eq!(said.trim(), format!("[{at},{at},{rest}]"));
    }

    /// Sizes agree to a layout unit and to what computed style's six digits lose, so a frame wider
    /// than 10,000 px is not taken for a transformed one.
    #[test]
    fn a_size_agrees_to_what_its_two_reads_can_tell() {
        assert!(one_size(200.0, 200.0) && one_size(200.015_625, 200.0));
        assert!(!one_size(200.031_25, 200.0) && !one_size(100.0, 200.0));
        assert!(one_size(10_000.25, 10_000.2) && one_size(123_456.75, 123_457.0));
        assert!(!one_size(10_050.0, 10_000.0));
    }

    /// The press point is whole CSS pixels, nearest the box's centre, and inside the box.
    #[test]
    fn the_press_point_is_a_whole_pixel_inside_the_box() {
        for (start, len, want) in
            [(10.0, 30.0, 25.0), (10.3, 30.0, 25.0), (0.0, 101.0, 51.0), (10.0, 1.0, 10.0)]
        {
            assert_eq!(snap(start, len), want, "{start} + {len}");
        }
        for (start, len) in [(10.3, 1.0), (10.5, 1.0), (10.999, 1.0), (-3.25, 1.5), (7.0, 2.0)] {
            let s = snap(start, len);
            assert!(s >= start && s < start + len && is_whole(s), "{start} + {len}: {s}");
        }
        assert!(is_whole(2410.0) && !is_whole(50.5) && !is_whole(1_500.015_625));
    }

    /// The hit test's fallback frame rule (`strict`, when `DOM.getNodeForLocation` cannot settle it), in
    /// a fake DOM under node: the point inside any frame element's box is refused, whatever its style
    /// and wherever it sits, even when `elementFromPoint` sees through it (`pointer-events: none`),
    /// unless that frame is the element or holds it. With no frame box at the point it refuses nothing
    /// (a decorative overlay still clicks). Without `strict`, the page's hit test alone decides.
    #[test]
    fn a_frame_whose_box_holds_the_point_covers_it() {
        let script = format!(
            r"class Node {{
  constructor() {{ this.kids = []; this.up = null; }}
  get parentNode() {{ return this.up; }}
  get ownerDocument() {{ return globalThis.document; }}
  getRootNode() {{ let n = this; while (n.up) n = n.up; return n; }}
  append(...kids) {{ for (const k of kids) {{ k.up = this; this.kids.push(k); }} return this; }}
  all() {{ return this.kids.flatMap((k) => [k, ...k.all()]); }}
}}
class Element extends Node {{
  constructor(tag, id, box) {{ super(); this.tag = tag; this.ident = id; this.box = box; this.attrs = {{}}; }}
  get localName() {{ return this.tag; }}
  get id() {{ return this.ident; }}
  get shadowRoot() {{ return null; }}
  hasAttribute(k) {{ return k in this.attrs; }}
  getBoundingClientRect() {{ const [left, top, w, h] = this.box; return {{left, top, right: left + w, bottom: top + h}}; }}
}}
class HTMLElement extends Element {{ get onclick() {{ return this.handler ?? null; }} }}
class HTMLLabelElement extends HTMLElement {{ get control() {{ return this.ctl ?? null; }} }}
class DocumentFragment extends Node {{
  querySelectorAll(s) {{ const tags = s.split(',').map((t) => t.trim()); return this.all().filter((n) => s === '*' || tags.includes(n.tag)); }}
}}
class ShadowRoot extends DocumentFragment {{ get host() {{ return null; }} elementFromPoint() {{ return null; }} }}
class Document extends Node {{ elementFromPoint() {{ return globalThis.hit; }} }}
Document.prototype.querySelectorAll = DocumentFragment.prototype.querySelectorAll;
Object.assign(globalThis, {{ Node, Element, HTMLElement, HTMLLabelElement, DocumentFragment, ShadowRoot, Document }});
const hitTest = ({JS_HIT});
const el = (tag, id, box, ...kids) => new HTMLElement(tag, id, box).append(...kids);
const results = [];
const check = (strict, body, hit, element, ...frames) => {{
  globalThis.document = new Document().append(body);
  globalThis.hit = hit;
  results.push(hitTest(element, 10, 10, strict, ...frames));
}};
const run = (...args) => check(true, ...args);
// A see-through frame inside a card link: the hit test sees the link.
let frame = el('iframe', '', [0, 0, 100, 30]), card = el('a', 'card', [0, 0, 100, 30], frame);
run(el('body', '', [0, 0, 800, 600], card), card, card);
// The same frame known only from the frame tree (a closed shadow root).
frame = el('iframe', '', [0, 0, 100, 30]); card = el('a', 'card', [0, 0, 100, 30]);
run(el('body', '', [0, 0, 800, 600], card), card, card, frame);
// A frame laid over the button, not inside it.
let button = el('button', 'go', [0, 0, 100, 30]);
run(el('body', '', [0, 0, 800, 600], button, el('iframe', 'ad', [0, 0, 300, 300])), button, button);
// A frame elsewhere.
button = el('button', 'go', [0, 0, 100, 30]);
run(el('body', '', [0, 0, 800, 600], button, el('iframe', 'ad', [200, 200, 100, 100])), button, button);
// In a frame above, the element is the frame that holds the target.
frame = el('iframe', '', [0, 0, 500, 300]);
run(el('body', '', [0, 0, 800, 600], frame), frame, frame, frame);
// An <object> whose fallback holds the element.
button = el('button', 'go', [0, 0, 100, 30]);
const object = el('object', '', [0, 0, 300, 300], button);
run(el('body', '', [0, 0, 800, 600], object), button, button, object);
// A button with a decorative overlay and no frame anywhere: strict refuses nothing more.
button = el('button', 'go', [0, 0, 100, 30], el('span', 'ripple', [0, 0, 100, 30]));
run(el('body', '', [0, 0, 800, 600], button), button, button);
// An <embed> and an <object> laid over the button, found in the document as frames.
button = el('button', 'go', [0, 0, 100, 30]);
run(el('body', '', [0, 0, 800, 600], button, el('embed', '', [0, 0, 300, 300])), button, button);
button = el('button', 'go', [0, 0, 100, 30]);
run(el('body', '', [0, 0, 800, 600], button, el('object', 'o', [0, 0, 300, 300])), button, button);
// Not strict: the see-through frame in the card is left to `DOM.getNodeForLocation`.
frame = el('iframe', '', [0, 0, 100, 30]); card = el('a', 'card', [0, 0, 100, 30], frame);
check(false, el('body', '', [0, 0, 800, 600], card), card, card, frame);
// A label for the checkbox laid over it: its own text is the checkbox's, but a link, a button, an
// editable region or an element with a click handler in it takes the click.
const labelled = (inner, hit = inner) => {{
  const box = el('input', 'cb', [0, 0, 20, 20]);
  const label = new HTMLLabelElement('label', '', [0, 0, 100, 30]).append(inner);
  label.ctl = box;
  check(false, el('body', '', [0, 0, 800, 600], box, label), hit, box);
}};
const span = () => el('span', 's', [0, 0, 100, 30]);
labelled(span());
labelled(el('a', 'terms', [0, 0, 100, 30]));
const deep = span();
labelled(el('button', 'b', [0, 0, 100, 30], deep), deep);
let edit = span(); edit.attrs.contenteditable = '';
labelled(edit);
let handled = span(); handled.attrs.onclick = 'go()';
labelled(handled);
handled = span(); handled.handler = () => {{}};
labelled(handled);
// A nested label (for another control), a <details>, a <video> or <audio> with controls and an image
// map take the click too; the same <video> without controls does not.
labelled(new HTMLLabelElement('label', 'other', [0, 0, 100, 30]));
labelled(el('details', 'more', [0, 0, 100, 30]));
let media = el('video', 'v', [0, 0, 100, 30]); media.attrs.controls = '';
labelled(media);
media = el('audio', 'a', [0, 0, 100, 30]); media.attrs.controls = '';
labelled(media);
labelled(el('video', 'quiet', [0, 0, 100, 30]));
const map = el('img', 'map', [0, 0, 100, 30]); map.attrs.usemap = '#m';
labelled(map);
console.log(JSON.stringify(results));"
        );
        let Some((ok, said)) = node("hit", &script) else { return };
        assert!(ok, "{said}");
        assert_eq!(
            said.trim(),
            concat!(
                r#"["iframe","iframe","iframe#ad",null,null,null,null,"embed","object#o",null,"#,
                r#"null,"a#terms","span#s","span#s","span#s","span#s","label#other","details#more","#,
                r#""video#v","audio#a",null,"img#map"]"#
            )
        );
    }

    /// What `DOM.getNodeForLocation` put on top covers the click when it is a frame element other than
    /// the target or one holding it, or, as anything else (`own`), when it is not the target's own: the
    /// target, inside it (through a shadow root) or inside a label for it.
    #[test]
    fn the_node_on_top_covers_as_another_frame_or_as_another_s_content() {
        let script = format!(
            r"class Node {{
  constructor(tag, id) {{ this.tag = tag; this.ident = id; this.up = null; }}
  get parentNode() {{ return this.up; }}
  append(...kids) {{ for (const k of kids) k.up = this; return this; }}
}}
class Element extends Node {{
  get localName() {{ return this.tag; }}
  get id() {{ return this.ident; }}
  hasAttribute(k) {{ return k in (this.attrs ?? {{}}); }}
}}
class HTMLElement extends Element {{ get onclick() {{ return this.handler ?? null; }} }}
class HTMLLabelElement extends HTMLElement {{ get control() {{ return this.ctl; }} }}
class ShadowRoot extends Node {{ get host() {{ return this.owner; }} }}
Object.assign(globalThis, {{ Node, Element, HTMLElement, HTMLLabelElement, ShadowRoot }});
const onTop = ({JS_ON_TOP});
const el = (tag, id, ...kids) => new HTMLElement(tag, id).append(...kids);
const ad = el('iframe', 'ad'), button = el('button', 'go'), framed = el('iframe', '');
const object = el('object', '', el('div', '', button));
const text = new Node('#text', '');
const icon = el('span', 'icon'), inner = el('span', ''), host = el('my-button', '');
button.append(icon);
const shadow = new ShadowRoot('#shadow', '').append(inner);
shadow.owner = host;
const bold = el('b', 'text'), inLink = el('i', ''), link = el('a', 'terms', inLink);
const handled = el('span', 'h');
handled.attrs = {{onclick: 'go()'}};
const nested = new HTMLLabelElement('label', 'other'), inSummary = el('span', 'd');
const player = el('video', 'v'), still = el('video', 's'), mapped = el('img', 'm');
player.attrs = {{controls: ''}};
mapped.attrs = {{usemap: '#m'}};
const label = new HTMLLabelElement('label', '').append(bold, link, handled, nested, el('details', '', inSummary), player, still, mapped);
label.ctl = button;
console.log(JSON.stringify([
  onTop(ad, button, false),          // a frame laid over the button
  onTop(el('div', 'x'), button, false), // other content, as a frame: not one
  onTop(framed, framed, false),      // the frame holding the target, in the process above
  onTop(object, button, false),      // an <object> whose fallback holds the target
  onTop(text, button, false),        // not an element
  onTop(el('div', 'overlay'), button, true), // an overlay slid in since the hit test
  onTop(button, button, true),       // the target
  onTop(icon, button, true),         // inside it
  onTop(inner, host, true),          // inside its shadow root
  onTop(bold, button, true),         // inside a label for it
  onTop(el('div', ''), framed, true), // anything but the frame, in the process above
  onTop(text, button, true),         // not an element, and not the target's
  onTop(link, button, true),         // a link in a label for it
  onTop(inLink, button, true),       // inside that link
  onTop(handled, button, true),      // something in the label with a click handler
  onTop(nested, button, true),       // a label for another control in the label
  onTop(inSummary, button, true),    // inside a <details> in the label
  onTop(player, button, true),       // a <video> with controls in the label
  onTop(still, button, true),        // a <video> without them
  onTop(mapped, button, true),       // an image map in the label
]));"
        );
        let Some((ok, said)) = node("on-top", &script) else { return };
        assert!(ok, "{said}");
        assert_eq!(
            said.trim(),
            concat!(
                r#"["iframe#ad",null,null,null,null,"div#overlay",null,null,null,null,"div","node","a#terms","i","#,
                r#""span#h","label#other","span#d","video#v",null,"img#m"]"#
            )
        );
    }
}
