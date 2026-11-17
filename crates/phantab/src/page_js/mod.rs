//! Functions the engine runs inside pages (THREAT-MODEL SR-34). Each file holds the function expression
//! alone, without the `const x=` around it or a trailing newline.
//!
//! [`tests`] pins every file to its SHA-256, so a change to what a page runs is always a deliberate one,
//! and checks each of [`PATCHES`] (the hardened reads) is in place.

/// `actionable`: true when the selector's element can be acted on, else why not. Why not is a string, except
/// that a selector with no element on a loaded page answers `['not found', <the page's element count>]`, so
/// an action's wait can tell a page that has stopped changing (`read::poll`). When an open shadow root has
/// the selector's element, which selectors never reach, the answer says where to `click_xy` it instead,
/// with a null mark, so the wait ends there. A true second argument (a picture's wait,
/// `read::poll_pictured`) lets a disabled or `aria-disabled` element be ready; an act never passes it.
pub const ACTIONABLE: &str = include_str!("actionable.js");
/// `present`: the selector exists and the text is on the page (either may be absent).
pub const PRESENT: &str = include_str!("present.js");
/// `readFrame`: one frame's text and controls, through open shadow roots.
pub const READ_FRAME: &str = include_str!("read_frame.js");
/// The workspace window's title check: the new window's page carries its token.
pub const TITLE_IS: &str = include_str!("title_is.js");
/// `act`'s click in a hidden workspace window: a DOM click, since hidden targets paint no frames.
pub const CLICK: &str = include_str!("click.js");
/// `act`'s select: each `[value, label]` of a `<select>`'s options, or null for any other element, so a
/// select can be matched by the label a person sees as well as by its value.
pub const SELECT_OPTIONS: &str = include_str!("select_options.js");

/// What the main frame says about a
/// verification check. It only reads. It counts the provider response fields by value length and never
/// returns a value, so a solved token never leaves the page.
pub const VERIFY_STATE: &str = include_str!("verify_state.js");

/// The engine's page functions, pinned by [`tests`]. The sign-in page functions (`signin_*.js`) are
/// pinned by `signin::page`'s own test.
pub const SOURCES: &[(&str, &str)] = &[
    ("actionable.js", ACTIONABLE),
    ("present.js", PRESENT),
    ("read_frame.js", READ_FRAME),
    ("title_is.js", TITLE_IS),
    ("click.js", CLICK),
    ("select_options.js", SELECT_OPTIONS),
];

/// The hardened reads, each `(file, the plain read, phantab's text)`: reads through
/// the prototypes where markup could shadow a document's or a form's own properties (`<img name=body>`
/// empties the page text, `<img name=querySelectorAll>` stops every read), as the sign-in scripts do
/// (THREAT-MODEL SR-34). A phantab text that adds a line marks it `phantab:`. `click.js` is left as it
/// is: a `<form>` whose field shadows `click` makes it throw, so nothing is clicked.
#[cfg(test)]
pub(crate) const PATCHES: &[(&str, &str, &str)] = &[
    (
        "actionable.js",
        r"const e=document.querySelector(s);",
        r"const e=Document.prototype.querySelector.call(document,s);",
    ),
    ("actionable.js", r"if(e.disabled||", r"if((e instanceof HTMLFormElement?undefined:e.disabled)||"),
    (
        "actionable.js",
        r"e.getAttribute('aria-disabled')",
        r"Element.prototype.getAttribute.call(e,'aria-disabled')",
    ),
    (
        "actionable.js",
        r"const b=e.getBoundingClientRect();",
        r"const b=Element.prototype.getBoundingClientRect.call(e);",
    ),
    (
        "actionable.js",
        r"document.readyState",
        r"Object.getOwnPropertyDescriptor(Document.prototype,'readyState').get.call(document)",
    ),
    (
        "actionable.js",
        r"document.getElementsByTagName('*')",
        r"Document.prototype.getElementsByTagName.call(document,'*')",
    ),
    ("present.js", r"!document.querySelector(s)", r"!Document.prototype.querySelector.call(document,s)"),
    (
        "present.js",
        r"(document.body?.innerText||'')",
        r"((b=>b&&Object.getOwnPropertyDescriptor(HTMLElement.prototype,'innerText').get.call(b))(Object.getOwnPropertyDescriptor(Document.prototype,'body').get.call(document))||'')",
    ),
    (
        "title_is.js",
        r"document.title===t",
        r"Object.getOwnPropertyDescriptor(Document.prototype,'title').get.call(document)===t",
    ),
    (
        "read_frame.js",
        r"  for(let i=0;i<roots.length&&i<500;i++)for(const el of roots[i].querySelectorAll('*'))if(el.shadowRoot)roots.push(el.shadowRoot);
",
        r"  // phantab: through the prototypes, never a document's or a form's own properties, which markup such as <img name=body> or <img name=querySelectorAll> shadows, nor a <form role=button>'s, which its fields shadow.
  const get=(p,k)=>Object.getOwnPropertyDescriptor(p,k).get,shadowOf=get(Element.prototype,'shadowRoot'),tagOf=get(Element.prototype,'tagName'),idOf=get(Element.prototype,'id'),attr=Element.prototype.getAttribute,rects=Element.prototype.getClientRects,doc=k=>get(Document.prototype,k).call(document);
  const qsa=(r,s)=>(r instanceof Document?Document.prototype:DocumentFragment.prototype).querySelectorAll.call(r,s),inner=el=>el instanceof HTMLElement?get(HTMLElement.prototype,'innerText').call(el):undefined;
  for(let i=0;i<roots.length&&i<500;i++)for(const el of qsa(roots[i],'*')){const s=shadowOf.call(el);if(s)roots.push(s);}
",
    ),
    (
        "read_frame.js",
        r"const text=[document.body?.innerText||''],found=[];",
        r"const text=[inner(doc('body'))||''],found=[];",
    ),
    (
        "read_frame.js",
        r"if(child.getClientRects().length&&!['STYLE','SCRIPT','LINK','SLOT'].includes(child.tagName)&&child.innerText)text.push(child.innerText);",
        r"if(rects.call(child).length&&!['STYLE','SCRIPT','LINK','SLOT'].includes(tagOf.call(child))&&inner(child))text.push(inner(child));",
    ),
    ("read_frame.js", r"for(const el of root.querySelectorAll(", r"for(const el of qsa(root,"),
    ("read_frame.js", r"const box=el.getClientRects()[0];", r"const box=rects.call(el)[0];"),
    (
        "read_frame.js",
        r"[...found.filter(f=>f.el.tagName!=='A'),...found.filter(f=>f.el.tagName==='A')]",
        r"[...found.filter(f=>tagOf.call(f.el)!=='A'),...found.filter(f=>tagOf.call(f.el)==='A')]",
    ),
    (
        "read_frame.js",
        r"return {tag:el.tagName.toLowerCase(),id:el.id||undefined,name:el.getAttribute('name')||undefined,type:el.getAttribute('type')||undefined,text:((el.tagName==='TEXTAREA'?'':el.innerText)||el.getAttribute('aria-label')||el.getAttribute('placeholder')||'').slice(0,160),href:el.tagName==='A'?el.href:undefined,",
        r"const tag=tagOf.call(el);
    return {tag:tag.toLowerCase(),id:idOf.call(el)||undefined,name:attr.call(el,'name')||undefined,type:attr.call(el,'type')||undefined,text:((tag==='TEXTAREA'?'':inner(el))||attr.call(el,'aria-label')||attr.call(el,'placeholder')||'').slice(0,160),href:tag==='A'?el.href:undefined,",
    ),
    ("read_frame.js", r"return {title:document.title,", r"return {title:doc('title'),"),
];

#[cfg(test)]
pub(crate) mod tests {
    use sha2::Digest as _;

    use super::*;

    /// SHA-256 of each of [`SOURCES`], in its order. A deliberate change to a page function updates its
    /// line here (the failure prints the new list).
    const GOLDEN: &[(&str, &str)] = &[
        ("actionable.js", "d7dce2882d8e53274b13862ece6d8f55622ac23696c86d8ee3b66f84697511c5"),
        ("present.js", "10aef376a543e1a0e9b3957ec0432541bfdb1b37920755c79b8febe5e714d296"),
        ("read_frame.js", "a40eefd4242dc11bb91485ba02f284a8c47473da508a3e28b09fb0584ec851dc"),
        ("title_is.js", "c39aa650861140b8f6eee917025d12e6b423ac10ebf26639a43a5dc43c3abfc9"),
        ("click.js", "67034e2d21ed6407789dba9496c5cfff6baf6e589fb6527f37d45b26b8de654a"),
        ("select_options.js", "00a830ec9a4699ccc585f0855d24b786e8e438e7760061384886436e3a6b2d1a"),
    ];

    /// `(name, SHA-256)` of each `(name, body)`, after checking each body is one expression's text.
    pub(crate) fn hashes(sources: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
        sources
            .iter()
            .map(|(name, body)| {
                assert!(!body.is_empty() && !body.ends_with('\n') && !body.contains('\r'), "{name}");
                (*name, crate::util::hex(&sha2::Sha256::digest(body.as_bytes())))
            })
            .collect()
    }

    /// Each hardened text is in its file exactly once, and the plain read it replaced is gone.
    pub(crate) fn check_patches(patches: &[(&str, &str, &str)], sources: &[(&str, &str)]) {
        for (file, plain, ours) in patches {
            assert_ne!(plain, ours, "{file}");
            let body = sources.iter().find(|(n, _)| n == file).map(|(_, b)| *b);
            let Some(body) = body else { panic!("{file} is not a listed file") };
            assert_eq!(body.matches(ours).count(), 1, "{file}: a patch is not there once: {ours}");
            assert!(
                !body.replacen(ours, "", 1).contains(plain),
                "{file}: the plain read is still there: {plain}"
            );
        }
    }

    #[test]
    fn every_page_function_is_its_golden_text() {
        let found = hashes(SOURCES);
        let golden: Vec<(&str, String)> = GOLDEN.iter().map(|(n, h)| (*n, (*h).to_owned())).collect();
        assert_eq!(
            found, golden,
            "a page function changed; if on purpose, update GOLDEN to the list on the left"
        );
    }

    #[test]
    fn every_patch_is_in_place() {
        check_patches(PATCHES, SOURCES);
    }
}
