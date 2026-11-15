() => {
  const wallTitle = /just a moment|attention required|are you (a )?(human|robot)|verify(ing)? you are (a )?human|security check|one more step/i.test(document.title);
  const fields = [...document.querySelectorAll('textarea[name="g-recaptcha-response"],textarea[name="h-captcha-response"],input[name="cf-turnstile-response"]')];
  const seen = e => { const b = e.getBoundingClientRect(); if (!(b.width > 0 && b.height > 0)) return false; const c = getComputedStyle(e); return c.visibility !== 'hidden' && c.display !== 'none'; };
  const usable = [...document.querySelectorAll('a[href],button,select,textarea,input:not([type="hidden"]),[contenteditable="true"]')]
    .filter(e => !fields.includes(e) && !e.disabled && seen(e)).length;
  // Per kind, open shadow roots included, for sign-in's solved rule (pipeline::captcha_solved). `fields`
  // stays the light DOM's: the hand-off rule (engine::verify::classify) reads it.
  const deep = (root, sel, out) => { out.push(...root.querySelectorAll(sel)); for (const e of root.querySelectorAll('*')) if (e.shadowRoot) deep(e.shadowRoot, sel, out); return out; };
  const every = deep(document, 'textarea[name="g-recaptcha-response"],textarea[name="h-captcha-response"],input[name="cf-turnstile-response"]', []);
  const byName = {};
  for (const name of ['g-recaptcha-response', 'h-captcha-response', 'cf-turnstile-response']) {
    const found = every.filter(f => f.name === name);
    byName[name] = { total: found.length, empty: found.filter(f => f.value.length === 0).length };
  }
  return { wallTitle, fields: { total: fields.length, empty: fields.filter(f => f.value.length === 0).length }, byName, usable };
}