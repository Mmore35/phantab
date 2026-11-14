() => {
  const wallTitle = /just a moment|attention required|are you (a )?(human|robot)|verify(ing)? you are (a )?human|security check|one more step/i.test(document.title);
  const fields = [...document.querySelectorAll('textarea[name="g-recaptcha-response"],textarea[name="h-captcha-response"],input[name="cf-turnstile-response"]')];
  const seen = e => { const b = e.getBoundingClientRect(); if (!(b.width > 0 && b.height > 0)) return false; const c = getComputedStyle(e); return c.visibility !== 'hidden' && c.display !== 'none'; };
  const usable = [...document.querySelectorAll('a[href],button,select,textarea,input:not([type="hidden"]),[contenteditable="true"]')]
    .filter(e => !fields.includes(e) && !e.disabled && seen(e)).length;
  return { wallTitle, fields: { total: fields.length, empty: fields.filter(f => f.value.length === 0).length }, usable };
}