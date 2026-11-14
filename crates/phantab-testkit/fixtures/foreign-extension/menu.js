// Bitwarden 2026.10's inline menu pattern: a button and a list element, each a closed
// shadow root holding an iframe of this extension's dynamic page, made once; appended to
// the body on a field's focus or click (a hidden page's click does not focus) and removed
// on blur. ?autoclose=<ms> removes them after a delay, as a click elsewhere does; ?sticky
// keeps them through blur until then; ?reinit makes fresh elements on every focus, as
// Bitwarden's re-init (on its login or a setting change) does once.
const query = new URLSearchParams(location.search);
let elements = null;
function make(tag) {
  const host = document.createElement(tag);
  const frame = document.createElement('iframe');
  frame.src = chrome.runtime.getURL('overlay/menu.html');
  host.attachShadow({mode: 'closed'}).append(frame);
  return host;
}
const open = event => {
  if (event.target.tagName !== 'INPUT') return;
  elements ||= [make('phantab-test-menu-button'), make('phantab-test-menu-list')];
  for (const host of elements) if (!host.isConnected) document.body.append(host);
  if (query.has('autoclose')) setTimeout(() => elements?.forEach(host => host.remove()), Number(query.get('autoclose')));
};
for (const type of ['focusin', 'click']) document.addEventListener(type, open, true);
document.addEventListener('focusout', () => {
  if (query.has('sticky')) return;
  elements?.forEach(host => host.remove());
  if (query.has('reinit')) elements = null;
}, true);
