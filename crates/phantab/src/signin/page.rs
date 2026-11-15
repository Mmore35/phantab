//! The sign-in call's in-page functions (THREAT-MODEL SR-34), hardened by the reads in [`PATCHES`], and
//! the one-line lambdas the call runs on their handles. Each file holds the function expression alone, as
//! `page_js` does. [`WATCH_INPUT`], [`INPUT_SEEN`] and [`STOP_WATCH`] watch a frame's
//! inputs while the pointer aims at a field.

/// `findSignIn`: the page-side object a call keeps a handle on, with a report safe to bring back.
pub(crate) const FIND_SIGN_IN: &str = include_str!("../page_js/signin_find.js");
/// `fillFields(o, asked, values)`: `moved`, `not-taken` or `filled`.
pub(crate) const FILL_FIELDS: &str = include_str!("../page_js/signin_fill.js");
/// `aimAt(o)`: where a person would click, or null.
pub(crate) const AIM_AT: &str = include_str!("../page_js/signin_aim.js");
/// `readInputs()`: `{href, text, values}` of a frame.
pub(crate) const READ_INPUTS: &str = include_str!("../page_js/signin_read_inputs.js");
/// `blankInputs(wanted)`: an index list, or `'passwords'`.
pub(crate) const BLANK_INPUTS: &str = include_str!("../page_js/signin_blank_inputs.js");

pub(crate) const REPORT: &str = "o=>o.report";
pub(crate) const HREF: &str = "()=>location.href";
pub(crate) const BLANK: &str = "o=>o.blank?.()";
pub(crate) const STATE: &str = "o=>o.state()";
pub(crate) const SUBMIT_BY_FORM: &str = "o=>o.submitByForm";
pub(crate) const REQUEST_SUBMIT: &str = "o=>HTMLFormElement.prototype.requestSubmit.call(o.form)";
/// The control's handle, for the locator click that presses it.
pub(crate) const CONTROL: &str = "o=>o.control";
/// Starts watching the control's document for a trusted pointer move, the sign that Chrome routes input
/// into its frame. With
/// [`INPUT_SEEN`] it only decides when the click goes, never what is filled or sent. Not `:hover`: in
/// headless Chrome the frame saw every move and never matched `:hover` (macOS, 2026-11-10), so a wait on
/// it always ran its full time. The document and its listener through the prototypes, as every sign-in
/// script reads (SR-34): a `<form role=button>` control's `<input name=ownerDocument>` shadows the first.
pub(crate) const WATCH_INPUT: &str = "o=>{o.inputSeen=false;const c=new AbortController();o.stopWatch=()=>c.abort();const d=Object.getOwnPropertyDescriptor(Node.prototype,'ownerDocument').get.call(o.control);EventTarget.prototype.addEventListener.call(d,'pointermove',e=>{if(e.isTrusted)o.inputSeen=true},{capture:true,signal:c.signal});return true}";
/// Whether that move came; once it has, the watch ends.
pub(crate) const INPUT_SEEN: &str = "o=>{const s=o.inputSeen===true;if(s)o.stopWatch?.();return s}";
/// Ends the watch when the wait gave up on it.
pub(crate) const STOP_WATCH: &str = "o=>{o.stopWatch?.()}";

/// phantab's page functions for `browser_sign_up`. `findSignUp`: the sign-up form's new-password fields,
/// with a report safe to bring back.
pub(crate) const FIND_SIGN_UP: &str = include_str!("../page_js/signup_find.js");
/// `fillSignUp(o, asked, value)`: `moved`, `not-taken` or `filled`. Never ticks a box or submits.
pub(crate) const FILL_SIGN_UP: &str = include_str!("../page_js/signup_fill.js");
/// The sign-up sweep's read: `{href, text, values, types}` of a frame's inputs and textareas.
pub(crate) const READ_SIGN_UP: &str = include_str!("../page_js/signup_read.js");
/// The sign-up sweep's blank: an index list into [`READ_SIGN_UP`]'s.
pub(crate) const BLANK_SIGN_UP: &str = include_str!("../page_js/signup_blank.js");

/// Every page function and lambda the call runs on a handle, pinned by [`tests`].
#[cfg(test)]
pub(crate) const SOURCES: &[(&str, &str)] = &[
    ("signin_find.js", FIND_SIGN_IN),
    ("signin_fill.js", FILL_FIELDS),
    ("signin_aim.js", AIM_AT),
    ("signin_read_inputs.js", READ_INPUTS),
    ("signin_blank_inputs.js", BLANK_INPUTS),
    ("report", REPORT),
    ("href", HREF),
    ("blank", BLANK),
    ("state", STATE),
    ("submitByForm", SUBMIT_BY_FORM),
    ("requestSubmit", REQUEST_SUBMIT),
    ("control", CONTROL),
    ("signup_find.js", FIND_SIGN_UP),
    ("signup_fill.js", FILL_SIGN_UP),
    ("signup_read.js", READ_SIGN_UP),
    ("signup_blank.js", BLANK_SIGN_UP),
];

/// The hardened reads, each `(file, the plain read, phantab's text)`: reads through
/// the prototypes where markup could shadow a form's or a document's own properties (in every script,
/// the sweep's `readInputs` and `blankInputs` included), an action that cannot be resolved marked for the
/// call to refuse, and no aim at a frame element inside the control (THREAT-MODEL SR-34). Each phantab
/// text is marked `phantab:` in the file where it adds a line. The test finds each once, with the plain
/// read gone.
#[cfg(test)]
pub(crate) const PATCHES: &[(&str, &str, &str)] = &[
    (
        "signin_find.js",
        r"()=>{
  const walk=()=>{const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of roots[i].querySelectorAll('*'))if(el.shadowRoot)roots.push(el.shadowRoot);return roots;};
  const all=s=>walk().flatMap(root=>[...root.querySelectorAll(s)]);
  const low=(el,n)=>(el?.getAttribute(n)||'').toLowerCase();
",
        r"()=>{
  // phantab: through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <input name=getAttribute> shadows.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,attr=Element.prototype.getAttribute,contains=Node.prototype.contains,rootOf=Node.prototype.getRootNode,shadowOf=get(Element.prototype,'shadowRoot'),parentOf=get(Node.prototype,'parentElement'),hostOf=get(ShadowRoot.prototype,'host'),baseOf=get(Node.prototype,'baseURI'),doc=k=>get(Document.prototype,k).call(document);
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s),hostAbove=n=>{const r=rootOf.call(n);return r instanceof ShadowRoot?hostOf.call(r):null;};
  const tagOf=get(Element.prototype,'tagName'),connected=get(Node.prototype,'isConnected'),closest=Element.prototype.closest,visible=Element.prototype.checkVisibility,rectOf=Element.prototype.getBoundingClientRect,inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined,formOf=el=>el instanceof HTMLFormElement?undefined:el.form;
  const walk=()=>{const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}return roots;};
  const all=s=>walk().flatMap(root=>[...qsa(root,s)]);
  const low=(el,n)=>((el?attr.call(el,n):null)||'').toLowerCase();
",
    ),
    (
        "signin_find.js",
        r"b.left+scrollX<document.documentElement.scrollWidth;",
        r"b.left+scrollX<doc('documentElement').scrollWidth;",
    ),
    ("signin_find.js", r"(document.body?.innerText||'')", r"(doc('body')?.innerText||'')"),
    ("signin_find.js", r"test(document.title)};", r"test(doc('title'))};"),
    (
        "signin_find.js",
        r"const inside=(box,el)=>{for(let n=el;n;n=n.getRootNode().host)if(box.contains(n))return true;return false;};",
        r"const inside=(box,el)=>{for(let n=el;n;n=hostAbove(n))if(contains.call(box,n))return true;return false;};",
    ),
    (
        "signin_find.js",
        r"box=box.parentElement||box.getRootNode().host;",
        r"box=parentOf.call(box)||hostAbove(box);",
    ),
    (
        "signin_find.js",
        r"  // By getAttribute, since form.action and form.method read an <input name=action> instead of the attribute.
  const action=()=>{const a=control?.getAttribute?.('formaction')||form?.getAttribute('action');if(!a||/^\s*javascript:/i.test(a))return null;try{return new URL(a,form?.baseURI||document.baseURI).href;}catch{return null;}};",
        r"  // By getAttribute, since form.action and form.method read an <input name=action> instead of the attribute.
  // phantab: an action it cannot resolve is not null (no action) but a mark the call refuses on.
  const action=()=>{const a=(control?attr.call(control,'formaction'):null)||(form?attr.call(form,'action'):null);if(!a||/^\s*javascript:/i.test(a))return null;try{return new URL(a,baseOf.call(form||document)).href;}catch{return {unresolved:true};}};",
    ),
    (
        "signin_fill.js",
        r"(o,asked,values)=>{
",
        r"(o,asked,values)=>{
  // phantab: through the prototypes, never the form's own properties, which markup such as <input name=getAttribute> shadows.
  const attr=Element.prototype.getAttribute,listen=EventTarget.prototype.addEventListener;
",
    ),
    (
        "signin_fill.js",
        r"  addEventListener('pagehide',o.blank,{once:true});",
        r"  listen.call(window,'pagehide',o.blank,{once:true});",
    ),
    (
        "signin_fill.js",
        r"o.form.getRootNode().addEventListener('submit',e=>{",
        r"listen.call(Node.prototype.getRootNode.call(o.form),'submit',e=>{",
    ),
    (
        "signin_fill.js",
        r"test(o.form.getAttribute('action')||''))return;",
        r"test(attr.call(o.form,'action')||''))return;",
    ),
    (
        "signin_fill.js",
        r"if((e.submitter?.getAttribute('formmethod')||o.form.getAttribute('method')||'get')",
        r"if(((e.submitter?attr.call(e.submitter,'formmethod'):null)||attr.call(o.form,'method')||'get')",
    ),
    (
        "signin_find.js",
        r#"    if(!el.isConnected||el.closest('[aria-hidden="true"],[inert]')||!el.checkVisibility({opacityProperty:true,visibilityProperty:true}))return false;"#,
        r#"    if(!connected.call(el)||closest.call(el,'[aria-hidden="true"],[inert]')||!visible.call(el,{opacityProperty:true,visibilityProperty:true}))return false;"#,
    ),
    (
        "signin_find.js",
        r"const b=el.getBoundingClientRect();return b.width>=2",
        r"const b=rectOf.call(el);return b.width>=2",
    ),
    (
        "signin_find.js",
        r"const label=el=>((el.tagName==='INPUT'?el.value||el.getAttribute('alt'):el.innerText)||el.getAttribute('aria-label')||el.getAttribute('title')||'')",
        r"const label=el=>((tagOf.call(el)==='INPUT'?el.value||attr.call(el,'alt'):inner(el))||attr.call(el,'aria-label')||attr.call(el,'title')||'')",
    ),
    (
        "signin_find.js",
        r"const typed=el=>el.tagName==='INPUT'?['submit','image'].includes(type(el)):el.tagName==='BUTTON'&&(!el.getAttribute('type')||type(el)==='submit');",
        r"const typed=el=>tagOf.call(el)==='INPUT'?['submit','image'].includes(type(el)):tagOf.call(el)==='BUTTON'&&(!attr.call(el,'type')||type(el)==='submit');",
    ),
    (
        "signin_find.js",
        r"const clickable=el=>el.tagName==='INPUT'?['submit','image','button'].includes(type(el)):el.tagName==='BUTTON'?type(el)!=='reset':el.tagName==='A'?",
        r"const clickable=el=>tagOf.call(el)==='INPUT'?['submit','image','button'].includes(type(el)):tagOf.call(el)==='BUTTON'?type(el)!=='reset':tagOf.call(el)==='A'?",
    ),
    (
        "signin_find.js",
        r"let pool=form?candidates.filter(el=>el.form===form||inside(form,el)):[];",
        r"let pool=form?candidates.filter(el=>formOf(el)===form||inside(form,el)):[];",
    ),
    (
        "signin_find.js",
        r"const near=candidates.filter(el=>inside(box,el)&&(!form||!el.form||el.form===form));",
        r"const near=candidates.filter(el=>inside(box,el)&&(!form||!formOf(el)||formOf(el)===form));",
    ),
    (
        "signin_find.js",
        r"pool.some(el=>el.tagName!=='A'&&SIGNUP.test(label(el)))",
        r"pool.some(el=>tagOf.call(el)!=='A'&&SIGNUP.test(label(el)))",
    ),
    (
        "signin_aim.js",
        r"o=>{
  const c=o.control;if(c.disabled||c.getAttribute('aria-disabled')==='true')return null;
  c.scrollIntoView({",
        r"o=>{
  // phantab: through the prototypes, never the control's own properties, which the fields of a <form role=button> (<input name=getAttribute>) shadow.
  const E=Element.prototype,N=Node.prototype,c=o.control;if((c instanceof HTMLFormElement?undefined:c.disabled)||E.getAttribute.call(c,'aria-disabled')==='true')return null;
  E.scrollIntoView.call(c,{",
    ),
    ("signin_aim.js", r"const b=c.getBoundingClientRect(),", r"const b=E.getBoundingClientRect.call(c),"),
    (
        "signin_aim.js",
        r"  return hit&&(hit===c||c.contains(hit))?{x,y}:null;",
        r"  // phantab: not when a frame element is what the press would land on: an <iframe> inside the control, or in an open shadow root there.
  const get=k=>Object.getOwnPropertyDescriptor(Element.prototype,k).get;let deep=hit;for(let i=0,r;deep&&i<32&&(r=get('shadowRoot').call(deep));i++){const d=r.elementFromPoint(x,y);if(!d||d===deep)break;deep=d;}
  return hit&&(hit===c||N.contains.call(c,hit))&&!(deep!==c&&/^(iframe|frame|object|embed|fencedframe)$/.test(get('localName').call(deep)))?{x,y}:null;",
    ),
    (
        "signin_aim.js",
        r"hit=c.getRootNode().elementFromPoint(x,y);",
        r"root=N.getRootNode.call(c),hit=(root instanceof ShadowRoot?ShadowRoot.prototype:Document.prototype).elementFromPoint.call(root,x,y);",
    ),
    (
        "signin_read_inputs.js",
        r"  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of roots[i].querySelectorAll('*'))if(el.shadowRoot)roots.push(el.shadowRoot);
",
        r"  // phantab: through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <img name=querySelectorAll> shadows, nor a <form>'s, which its fields shadow.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,shadowOf=get(Element.prototype,'shadowRoot'),doc=k=>get(Document.prototype,k).call(document),inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined;
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s);
  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
",
    ),
    (
        "signin_read_inputs.js",
        r"const text=[document.title,document.body?.innerText||''];",
        r"const text=[doc('title'),inner(doc('body'))||''];",
    ),
    (
        "signin_read_inputs.js",
        r"if(child.innerText)text.push(child.innerText);",
        r"if(inner(child))text.push(inner(child));",
    ),
    (
        "signin_read_inputs.js",
        r"roots.flatMap(root=>[...root.querySelectorAll('input')]).map(el=>el.value)",
        r"roots.flatMap(root=>[...qsa(root,'input')]).map(el=>el.value)",
    ),
    (
        "signin_blank_inputs.js",
        r"  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of roots[i].querySelectorAll('*'))if(el.shadowRoot)roots.push(el.shadowRoot);
",
        r"  // phantab: through the prototypes, never the document's own properties, which markup such as <img name=querySelectorAll> shadows.
  const shadowOf=Object.getOwnPropertyDescriptor(Element.prototype,'shadowRoot').get,qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s);
  const roots=[document];for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
",
    ),
    (
        "signin_blank_inputs.js",
        r"roots.flatMap(root=>[...root.querySelectorAll('input')]).forEach(",
        r"roots.flatMap(root=>[...qsa(root,'input')]).forEach(",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page_js::tests::{check_patches, hashes};

    /// SHA-256 of each of [`SOURCES`], in its order. A deliberate change updates its line here (the
    /// failure prints the new list).
    const GOLDEN: &[(&str, &str)] = &[
        ("signin_find.js", "da85d1bfc94d6dd6eea94998930edc867ca836d9bf50b0fc491e7689d0af743b"),
        ("signin_fill.js", "2e472029d1d239e6a78e25ac333e484931b618defeb29e956b12d7172a6ad2df"),
        ("signin_aim.js", "05c929e482a8ffd3ccf33dd44f1981b2c9fedf228b1397f36cd92a878af2be9b"),
        ("signin_read_inputs.js", "00f7ac15d25370a411725233a145f010c8548067fd3bf941f5d12a8c99d4814a"),
        ("signin_blank_inputs.js", "9ba591c6e56e658955f27bf64f3ba1564f26e9491d821ac32ecb5b43b266866f"),
        ("report", "f40cbacf90f05e55c929dca00b035496d817ef37714887bdc0969db3bd56b41f"),
        ("href", "0ee7ce44d8d9f481d97202a74b7cbd0bc286e8b0d5aeb586b2c37727210c5b9c"),
        ("blank", "2f01294471ffac344f1b1e5365316352ddae67d4d7c838db060fb9ef7f3fd5ba"),
        ("state", "f25eece6846b5a430a3a1c3968af185325a2eed5167f9741f5eb4d9dc7fa5640"),
        ("submitByForm", "806a324fac2dcc263d0d850d12f7e5577260a64b38c948ddd41268c52acac600"),
        ("requestSubmit", "02b6832b1295c98cbf4e5249fbd2a62f421e9b82c9e38d876dddf0ff48eef12c"),
        ("control", "504307c47b1fd7a301c2d7b3e6f2a31d7c9ac2a2642665d3404c6c52bf065d5f"),
    ];

    #[test]
    fn every_sign_in_function_is_its_golden_text() {
        let found = hashes(SOURCES);
        let golden: Vec<(&str, String)> = GOLDEN.iter().map(|(n, h)| (*n, (*h).to_owned())).collect();
        assert_eq!(
            found, golden,
            "a sign-in page function changed; if on purpose, update GOLDEN to the list on the left"
        );
    }

    #[test]
    fn every_patch_is_in_place() {
        check_patches(PATCHES, SOURCES);
    }
}
