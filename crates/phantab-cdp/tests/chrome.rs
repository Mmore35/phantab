//! Real-Chrome lane. Set `PHANTAB_TEST_CHROME` to a Chrome executable to run it; without it the test
//! prints a skip line and passes. It launches its own headless Chrome on a temporary profile and closes
//! only that browser.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: a failed step should fail the test"
)]

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures_util::FutureExt as _;
use phantab_cdp::{
    Browser, CdpError, FrameId, LaunchOptions, Page, PageOptions, PasskeyAsks, Transport, Unsettled,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Routes = Arc<dyn Fn(&str) -> Option<(String, bool)> + Send + Sync>;

/// A tiny HTTP/1.1 server: one response per connection. A route may ask to stall the body (`true`),
/// which keeps a navigation from ever reaching `DOMContentLoaded`.
async fn serve(listener: TcpListener, routes: Routes) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { return };
        let routes = routes.clone();
        tokio::spawn(async move {
            let _ = respond(stream, &routes).await;
        });
    }
}

async fn respond(mut stream: TcpStream, routes: &Routes) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    match routes(&path) {
        Some((body, false)) => {
            let msg = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(msg.as_bytes()).await?;
        }
        Some((body, true)) => {
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n",
                )
                .await?;
            stream.write_all(b"<!doctype html><title>slow</title>").await?;
            stream.flush().await?;
            tokio::time::sleep(Duration::from_secs(60)).await;
            stream.write_all(body.as_bytes()).await?;
        }
        None => {
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
        }
    }
    stream.shutdown().await
}

struct Fixtures {
    parent: String,
    child_port: u16,
    dead: String,
}

async fn start_fixtures() -> Fixtures {
    let child = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let child_port = child.local_addr().unwrap().port();
    let parent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let parent_port = parent.local_addr().unwrap().port();
    // Scrolled, its frames are the parent's site: another site's to this one.
    let child_scrolled =
        format!("<!doctype html>{}", scrolled_body(&format!("http://127.0.0.1:{parent_port}/")));
    tokio::spawn(serve(
        child,
        // `/child?xclear`, `/child?xpad` and the like are `/child` too, each its own frame to find by its
        // URL. A press anywhere in it marks its body `pressed`, for `#xclear`, and `at` where it landed
        // in the frame's document, for `#xpad`.
        Arc::new(move |path: &str| {
            match path.split('?').next().unwrap_or(path) {
            "/child" => Some((
                "<!doctype html><body style=\"margin:0\"><div id=c>child-content</div>\
                 <button id=b onclick=\"document.body.dataset.clicked='yes'; window.bClicked = true\">b</button>\
                 <script>addEventListener('pointerdown', (e) => { document.body.dataset.pressed = 'yes';\
                 document.body.dataset.at = e.clientX + ',' + e.clientY }, true)</script></body>"
                    .to_owned(),
                false,
            )),
            "/scrolled-sub" => Some((child_scrolled.clone(), false)),
            _ => None,
        }
        }),
    ));

    let child_src = format!("http://localhost:{child_port}/child");
    let scrolled_sub = format!("<!doctype html>{}", scrolled_body(&child_src));
    // The same, in a page twice its size, holding it from its own site and from another one.
    let scrolled = format!(
        "<!doctype html>{}<iframe id=same src=\"/scrolled-sub\" \
         style=\"position:absolute;left:2000px;top:2000px;width:400px;height:300px;border:0\"></iframe>\
         <iframe id=cross src=\"http://localhost:{child_port}/scrolled-sub\" \
         style=\"position:absolute;left:2000px;top:2500px;width:400px;height:300px;border:0\"></iframe>",
        scrolled_body(&child_src).replace("width:3000px;height:3000px", "width:4000px;height:4000px")
    );
    let oopif = format!(
        "<!doctype html><body style=\"margin:0\"><p>parent</p>\
         <iframe id=f src=\"http://localhost:{child_port}/child\" \
         style=\"position:absolute;left:30px;top:40px;width:200px;height:100px;border:0\"></iframe></body>"
    );
    let form = "<!doctype html><body>\
        <form id=form onsubmit=\"event.preventDefault(); window.submitted = true\">\
          <input id=name> <input id=k onkeydown=\"window.keys.push(event.key)\">\
          <select id=color><option value=red>Red</option><option value=green>Green</option>\
            <option value=blue>Blue</option></select>\
          <button type=submit tabindex=-1>Submit</button>\
        </form>\
        <input id=after>\
        <button id=go onclick=\"document.body.dataset.clicked = 'yes'\">Go</button>\
        <script>window.keys = []</script></body>"
        .to_owned();
    tokio::spawn(serve(
        parent,
        Arc::new(move |path: &str| match path {
            "/" => Some(("<!doctype html><title>home</title><p id=p>hello</p>".to_owned(), false)),
            "/oopif" => Some((oopif.clone(), false)),
            "/form" => Some((form.clone(), false)),
            "/isolation" => Some((ISOLATION.to_owned(), false)),
            "/scrolled" => Some((scrolled.clone(), false)),
            "/scrolled-sub" => Some((scrolled_sub.clone(), false)),
            "/slow" => Some(("<p>late</p>".to_owned(), true)),
            _ => None,
        }),
    ));

    // A port nobody listens on, for the error page.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    Fixtures {
        parent: format!("http://127.0.0.1:{parent_port}"),
        child_port,
        dead: format!("http://127.0.0.1:{dead_port}/"),
    }
}

const NAV: Duration = Duration::from_secs(15);

async fn eval(page: &Page, js: &str) -> Value {
    let main = page.main_frame().unwrap();
    page.evaluate_main(&main, js, vec![]).await.unwrap()
}

async fn wait_for_frame(page: &Page, needle: &str) -> FrameId {
    for _ in 0..200 {
        if let Some(f) = page.frames().into_iter().find(|f| f.url.contains(needle)) {
            return f.id;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no frame with url containing {needle}: {:?}", page.frames());
}

/// The cross-site fixture frame `child?{id}`, by its whole id: one id can begin another (`xscale` and
/// `xscalec`, `xslot` and `xslotc`), and [`wait_for_frame`]'s `contains` hands back whichever frame
/// Chrome lists first. At 80bbf11 a macOS run's `#xscale` lane gave `#xscalec`'s words.
async fn wait_for_child(page: &Page, port: u16, id: &str) -> FrameId {
    let url = format!("localhost:{port}/child?{id}");
    for _ in 0..200 {
        if let Some(f) = page.frames().into_iter().find(|f| f.url.ends_with(&url)) {
            return f.id;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no frame at {url}: {:?}", page.frames());
}

async fn evaluate_and_handles(page: &Page, fx: &Fixtures) {
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    assert_eq!(page.url(), format!("{}/", fx.parent));
    let main = page.main_frame().unwrap();
    assert_eq!(
        page.evaluate(&main, "(a, b) => a + b", vec![json!(2).into(), json!(3).into()]).await.unwrap(),
        json!(5)
    );
    assert_eq!(page.evaluate(&main, "async () => document.title", vec![]).await.unwrap(), json!("home"));
    let el = page.evaluate_handle(&main, "() => document.getElementById('p')", vec![]).await.unwrap();
    assert!(el.object_id().is_some());
    assert_eq!(
        el.evaluate("(e, s) => e.textContent + s", vec![json!("!").into()]).await.unwrap(),
        json!("hello!")
    );
    assert_eq!(page.evaluate(&main, "(e) => e.id", vec![(&el).into()]).await.unwrap(), json!("p"));
    el.dispose().await;
    assert!(page.evaluate(&main, "(e) => e.id", vec![(&el).into()]).await.is_err());
    let err = page.evaluate(&main, "() => { throw new TypeError('bad') }", vec![]).await.unwrap_err();
    assert_eq!(err.to_string(), "bad");
    assert!(!err.is_navigating());
}

async fn oopif(browser: &Browser, page: &Page, fx: &Fixtures) {
    page.set_viewport(Some((800, 600))).await.unwrap();
    page.goto(&format!("{}/oopif", fx.parent), NAV).await.unwrap();
    let child = wait_for_frame(page, &format!("localhost:{}/child", fx.child_port)).await;

    // It really is out of process: Chrome lists a separate iframe target.
    let targets = browser.connection().send(None, "Target.getTargets", json!({})).await.unwrap();
    let iframes = targets["targetInfos"].as_array().unwrap().iter().filter(|t| t["type"] == "iframe").count();
    assert!(iframes >= 1, "expected an OOPIF target: {targets}");

    let mut text = Value::Null;
    for _ in 0..40 {
        match page.evaluate(&child, "() => document.getElementById('c')?.textContent ?? null", vec![]).await {
            Ok(v) if !v.is_null() => {
                text = v;
                break;
            }
            Ok(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) if e.is_navigating() => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => panic!("evaluate in OOPIF: {e}"),
        }
    }
    assert_eq!(text, json!("child-content"));
    assert_eq!(page.evaluate(&child, "() => location.hostname", vec![]).await.unwrap(), json!("localhost"));

    let b = page.frame_element_box(&child).await.unwrap().expect("iframe box");
    assert!((b.x - 30.0).abs() < 1.0 && (b.y - 40.0).abs() < 1.0, "{b:?}");
    assert!((b.width - 200.0).abs() < 1.0 && (b.height - 100.0).abs() < 1.0, "{b:?}");
    let main = page.main_frame().unwrap();
    assert_eq!(page.frame_element_box(&main).await.unwrap(), None);

    // A click at the iframe's coordinates lands inside the OOPIF.
    let bb = page.evaluate(&child, "() => { const r = document.getElementById('b').getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2] }", vec![]).await.unwrap();
    let (x, y) = (bb[0].as_f64().unwrap() + b.x, bb[1].as_f64().unwrap() + b.y);
    // Chrome routes input to an OOPIF only once its first frame is composited, which can trail the
    // child's load by a few frames; until then the click hits the parent. So the click is retried.
    let mut clicked = Value::Null;
    for _ in 0..20 {
        page.mouse_click(x, y).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        clicked = page.evaluate(&child, "() => document.body.dataset.clicked ?? null", vec![]).await.unwrap();
        if !clicked.is_null() {
            break;
        }
    }
    assert_eq!(clicked, json!("yes"));
    page.set_viewport(None).await.unwrap();
}

async fn navigation(browser: &Browser, fx: &Fixtures) {
    let page = browser.new_page().await.unwrap();
    let err = page.goto(&fx.dead, NAV).await.unwrap_err();
    assert_eq!(err.to_string(), format!("net::ERR_CONNECTION_REFUSED at {}", fx.dead));
    assert!(!err.is_timeout());

    let err = page.goto(&format!("{}/slow", fx.parent), Duration::from_millis(1500)).await.unwrap_err();
    assert_eq!(err, CdpError::NavigationTimeout(1500));
    assert_eq!(err.to_string(), "Navigation timeout of 1500 ms exceeded");
    assert!(err.is_timeout());

    // The page recovers with the next navigation.
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    assert_eq!(eval(&page, "() => document.title").await, json!("home"));

    // Same-document navigation.
    page.goto(&format!("{}/#frag", fx.parent), NAV).await.unwrap();
    assert_eq!(page.url(), format!("{}/#frag", fx.parent));

    // An evaluation cut off by a navigation reports itself as navigating.
    let main = page.main_frame().unwrap();
    let p2 = page.clone();
    let pending =
        tokio::spawn(async move { p2.evaluate(&main, "() => new Promise(() => {})", vec![]).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    page.goto(&format!("{}/form", fx.parent), NAV).await.unwrap();
    let err = tokio::time::timeout(Duration::from_secs(10), pending).await.unwrap().unwrap().unwrap_err();
    assert!(err.is_navigating(), "{err:?}");
    page.close().await.unwrap();
}

async fn screenshot(page: &Page, fx: &Fixtures) {
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    let data = page.screenshot_jpeg(70).await.unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(data).unwrap();
    assert_eq!(&bytes[..3], &[0xFF, 0xD8, 0xFF]);
    assert!(page.screenshot_jpeg(101).await.is_err());

    // A clip comes back at its size times the scale (the live viewer's zoom on a check).
    let clip = phantab_cdp::BoundingBox { x: 10.0, y: 20.0, width: 120.0, height: 60.0 };
    let data = page.screenshot_jpeg_clip(70, clip, 2.0).await.unwrap();
    let bytes = base64::engine::general_purpose::STANDARD.decode(data).unwrap();
    assert_eq!(jpeg_size(&bytes), Some((240, 120)));
    let v = page.visual_viewport().await.unwrap();
    assert!(v.width > 0.0 && v.height > 0.0, "{v:?}");
    // Its fallback, for an extension that refuses Page.getLayoutMetrics, reads the same viewport.
    let own = page.page_visual_viewport().await.unwrap();
    let near = |a: f64, b: f64| (a - b).abs() < 1.0;
    assert!(
        near(own.x, v.x) && near(own.y, v.y) && near(own.width, v.width) && near(own.height, v.height),
        "{own:?} vs {v:?}"
    );
}

/// Width and height from a JPEG's start-of-frame marker.
fn jpeg_size(b: &[u8]) -> Option<(u16, u16)> {
    let mut i = 2;
    while i + 9 < b.len() {
        if b[i] != 0xFF {
            return None;
        }
        let marker = b[i + 1];
        let len = usize::from(u16::from_be_bytes([b[i + 2], b[i + 3]]));
        if (0xC0..=0xC2).contains(&marker) {
            let h = u16::from_be_bytes([b[i + 5], b[i + 6]]);
            let w = u16::from_be_bytes([b[i + 7], b[i + 8]]);
            return Some((w, h));
        }
        i += 2 + len;
    }
    None
}

async fn forms_and_keyboard(page: &Page, fx: &Fixtures) {
    page.goto(&format!("{}/form", fx.parent), NAV).await.unwrap();
    page.emulate_focus(true).await.unwrap();

    page.fill("#name", "Ada Lovelace").await.unwrap();
    assert_eq!(page.eval_on_selector("#name", "(e) => e.value").await.unwrap(), json!("Ada Lovelace"));
    // Fill replaces, it does not append.
    page.fill("#name", "Grace").await.unwrap();
    assert_eq!(page.eval_on_selector("#name", "(e) => e.value").await.unwrap(), json!("Grace"));

    assert_eq!(page.select("#color", &["green".to_owned()]).await.unwrap(), ["green"]);
    assert_eq!(page.eval_on_selector("#color", "(e) => e.value").await.unwrap(), json!("green"));
    let err = page.select("#missing", &["x".to_owned()]).await.unwrap_err();
    assert_eq!(err.to_string(), "No element found for selector: #missing");
    let err = page.eval_on_selector("#missing", "(e) => e").await.unwrap_err();
    assert!(err.to_string().contains("failed to find element matching selector \"#missing\""), "{err}");

    page.click_selector("#go").await.unwrap();
    assert_eq!(eval(page, "() => document.body.dataset.clicked ?? null").await, json!("yes"));

    page.click_selector("#k").await.unwrap();
    page.type_text("hi\u{e9}").await.unwrap();
    assert_eq!(page.eval_on_selector("#k", "(e) => e.value").await.unwrap(), json!("hi\u{e9}"));
    page.key_press("Enter").await.unwrap();
    assert_eq!(eval(page, "() => window.submitted === true").await, json!(true));
    page.key_press("Tab").await.unwrap();
    // Tab leaves #k for the select, then the next input.
    assert_eq!(eval(page, "() => document.activeElement.id").await, json!("color"));
    page.key_press("Tab").await.unwrap();
    assert_eq!(eval(page, "() => document.activeElement.id").await, json!("after"));
    // As in puppeteer, Shift changes `KeyA` to "A"; the name "a" has no shifted form.
    page.key_down("Shift").await.unwrap();
    page.key_press("KeyA").await.unwrap();
    page.key_up("Shift").await.unwrap();
    assert_eq!(page.eval_on_selector("#after", "(e) => e.value").await.unwrap(), json!("A"));
    assert_eq!(eval(page, "() => window.keys").await, json!(["h", "i", "Enter", "Tab"]));

    page.mouse_wheel(100.0).await.unwrap();
    page.mouse_reset().await.unwrap();
}

/// A page that tampers with its own globals and lays a banner over a button. The label's span covers its
/// checkbox the way a styled checkbox does; the card link's frame takes no pointer events, and is still
/// on top for the press.
const ISOLATION: &str = "<!doctype html><body style=\"margin:0\"><p id=p>real</p>\
    <button id=under onclick=\"window.underClicked = true\" \
      style=\"position:absolute;left:10px;top:60px;width:100px;height:30px\">Under</button>\
    <div id=cover style=\"position:fixed;left:0;top:50px;width:300px;height:60px;background:#fff\"></div>\
    <label style=\"position:absolute;left:10px;top:200px;display:block;width:60px;height:30px\">\
      <input type=checkbox id=cb style=\"margin:0;width:20px;height:20px\">\
      <span style=\"position:absolute;left:0;top:0;width:60px;height:30px\"></span></label>\
    <button id=framed style=\"position:absolute;left:150px;top:200px;width:100px;height:30px\">F\
      <iframe style=\"position:absolute;left:0;top:0;width:100px;height:30px;border:0;opacity:0\"></iframe></button>\
    <label style=\"position:absolute;left:300px;top:200px;display:block;width:60px;height:30px\">\
      <input type=checkbox id=cb2 style=\"margin:0;width:20px;height:20px\">\
      <iframe style=\"position:absolute;left:0;top:0;width:60px;height:30px;border:0;opacity:0\"></iframe></label>\
    <input type=checkbox id=cb3 style=\"position:absolute;left:460px;top:105px;margin:0;width:20px;height:20px\">\
    <label for=cb3 style=\"position:absolute;left:450px;top:100px;display:block;width:100px;height:30px\">\
      <a id=terms href=\"#\" onclick=\"window.termsClicked = true; return false\" \
        style=\"display:block;width:100px;height:30px\">terms</a></label>\
    <div id=host style=\"position:absolute;left:10px;top:300px;width:100px;height:30px\"></div>\
    <div id=ohost style=\"position:absolute;left:150px;top:300px;width:100px;height:30px\"></div>\
    <div id=chost style=\"position:absolute;left:300px;top:300px;width:100px;height:30px\"></div>\
    <a id=card href=\"#\" onclick=\"window.cardClicked = true; return false\" \
      style=\"position:absolute;left:150px;top:400px;display:block;width:100px;height:30px\">C\
      <iframe style=\"position:absolute;left:0;top:0;width:100px;height:30px;border:0;opacity:0;pointer-events:none\">\
      </iframe></a>\
    <iframe sandbox srcdoc=\"<p id=s>sandboxed</p>\" \
      style=\"position:absolute;left:300px;top:400px;width:100px;height:30px;border:0\"></iframe>\
    <script>const fill = 'position:absolute;left:0;top:0;width:100px;height:30px;border:0';\
      host.attachShadow({mode: 'open'}).innerHTML = `<button style=\"${fill}\" onclick=\"window.hostClicked = true\">In</button>`;\
      ohost.attachShadow({mode: 'open'}).innerHTML = `<iframe style=\"${fill};opacity:0\"></iframe>`;\
      chost.attachShadow({mode: 'closed'}).innerHTML = `<iframe style=\"${fill};opacity:0\"></iframe>`;</script>\
    <script>window.secret = 'main'; window.underClicked = window.cardClicked = window.termsClicked = false;\
      document.querySelector = () => null;\
      Element.prototype.getBoundingClientRect = () => ({x: -999, y: -999, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0});\
      String.prototype.slice = function () { return String(this); };\
    </script></body>";

/// SR-34: phantab's scripts run in an isolated world, so the page's globals and prototype patches are
/// not theirs; and a selector click on a covered element is refused, not sent to what covers it.
async fn isolation(page: &Page, fx: &Fixtures) {
    page.goto(&format!("{}/isolation", fx.parent), NAV).await.unwrap();
    let main = page.main_frame().unwrap();
    let js = "() => [document.querySelector('#p')?.textContent ?? null, typeof window.secret, \
              document.getElementById('p').getBoundingClientRect().width > 0]";
    assert_eq!(page.evaluate(&main, js, vec![]).await.unwrap(), json!(["real", "undefined", true]));
    assert_eq!(eval(page, "() => window.secret").await, json!("main"), "the page world is still reachable");

    let err = page.click_selector("#under").await.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(err.to_string().contains("covered at its click point by <div#cover>"), "{err}");
    assert_eq!(eval(page, "() => window.underClicked ?? null").await, json!(false), "nothing was clicked");
    page.evaluate(&main, "() => document.getElementById('cover').remove()", vec![]).await.unwrap();
    page.click_selector("#under").await.unwrap();
    assert_eq!(eval(page, "() => window.underClicked ?? null").await, json!(true));

    // A label's own content over its control is the control.
    page.click_selector("#cb").await.unwrap();
    assert_eq!(
        page.evaluate(&main, "() => document.getElementById('cb').checked", vec![]).await.unwrap(),
        json!(true)
    );

    // But a link in a label over it takes the click, not the checkbox (review r7 F5).
    let err = page.click_selector("#cb3").await.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(err.to_string().contains("by <a#terms>"), "{err}");
    let read = "() => [document.getElementById('cb3').checked, window.termsClicked ?? null]";
    assert_eq!(eval(page, read).await, json!([false, false]), "nothing was clicked");

    // The page's own `slice` cannot stretch the world's caps (sec-web-1).
    assert_eq!(page.evaluate(&main, "() => 'abcdef'.slice(0, 2)", vec![]).await.unwrap(), json!("ab"));
    assert_eq!(eval(page, "() => 'abcdef'.slice(0, 2)").await, json!("abcdef"), "the page's own is patched");

    // A frame at the click point is what a press would land on, even inside the element or its label,
    // or in its shadow root, open or closed: its document gets the click, not the element.
    for sel in ["#framed", "#cb2", "#ohost", "#chost"] {
        let err = page.click_selector(sel).await.unwrap_err();
        assert!(matches!(err, CdpError::Covered(_)), "{sel}: {err:?}");
        assert!(err.to_string().contains("by <iframe>"), "{sel}: {err}");
    }
    assert_eq!(
        page.evaluate(&main, "() => document.getElementById('cb2').checked", vec![]).await.unwrap(),
        json!(false)
    );
    // An open shadow root's own content over its host is the host.
    page.click_selector("#host").await.unwrap();
    assert_eq!(eval(page, "() => window.hostClicked ?? null").await, json!(true));
    // A frame with `pointer-events: none` is refused all the same: the hit test sees through it, but
    // Chrome can route the press into it (below, with another site's frame).
    let (r, why) = click_counting(page, "#card").await;
    let err = r.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(err.to_string().contains("by <iframe>"), "{err}");
    assert_eq!(why, [], "the node on top settled it, not the box rule");
    assert_eq!(eval(page, "() => window.cardClicked ?? null").await, json!(false), "nothing was clicked");

    // Another site's frame in a closed shadow root is found by the frame tree all the same.
    let add = "(src) => { const h = document.createElement('div'); h.id = 'xhost';\
               h.style.cssText = 'position:absolute;left:10px;top:400px;width:100px;height:30px';\
               document.body.append(h); h.attachShadow({mode: 'closed'}).innerHTML = `<iframe src=\"${src}\" \
               style=\"position:absolute;left:0;top:0;width:100px;height:30px;border:0;opacity:0\"></iframe>`; }";
    let src = format!("http://localhost:{}/child", fx.child_port);
    page.evaluate(&main, add, vec![json!(src).into()]).await.unwrap();
    wait_for_frame(page, &format!("localhost:{}/child", fx.child_port)).await;
    let err = page.click_selector("#xhost").await.unwrap_err();
    assert!(matches!(err, CdpError::Covered(_)), "{err:?}");
    assert!(err.to_string().contains("by <iframe>"), "{err}");

    cross_site_frames(page, fx, &main, &src).await;

    // A sandboxed frame without allow-scripts runs none of its own, yet the world is made there (I5).
    let sandboxed = wait_for_frame(page, "about:srcdoc").await;
    let text = "() => document.getElementById('s')?.textContent ?? null";
    assert_eq!(page.evaluate(&sandboxed, text, vec![]).await.unwrap(), json!("sandboxed"));

    // A navigation drops the world; the next call makes a new one in the new document.
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    assert_eq!(page.evaluate(&main, "() => document.title", vec![]).await.unwrap(), json!("home"));
}

/// A document larger than the view both ways, laid over another site's frame (`frame_src`) as large
/// as itself, and far down and right in it: a card link holding such a frame that takes no pointer
/// events, and a button. A check that asked about a point other than the press's would find the frame
/// beneath (or nothing, past the end), and refuse the button. The body is left open, so a page can add
/// to it.
fn scrolled_body(frame_src: &str) -> String {
    format!(
        "<body style=\"margin:0;width:3000px;height:3000px\">\
         <iframe src=\"{frame_src}\" style=\"position:absolute;left:0;top:0;width:3000px;height:3000px;\
         border:0\"></iframe>\
         <a id=card href=\"#\" onclick=\"window.cardClicked = true; return false\" \
         style=\"position:absolute;left:1500px;top:1500px;display:block;width:100px;height:30px\">C\
         <iframe src=\"{frame_src}\" style=\"position:absolute;left:0;top:0;width:100px;height:30px;border:0;\
         opacity:0;pointer-events:none\"></iframe></a>\
         <button id=behind onclick=\"window.behindClicked = true\" \
         style=\"position:absolute;left:1510px;top:1710px;width:100px;height:30px;z-index:1\">B</button>\
         <script>window.cardClicked = window.behindClicked = false</script>"
    )
}

/// SR-34 with the page scrolled both ways: `DOM.getNodeForLocation` takes document coordinates, and a
/// wrong space would name another node with no error, so the frame on top would go unseen. In the main
/// frame, in a scrolled frame of the same site (the main frame's session, hit-tested from the top), and
/// in a scrolled frame of another site (its own session): the card's frame refuses the click, and the
/// button over a frame clicks.
async fn scrolled(page: &Page, fx: &Fixtures) {
    page.goto(&format!("{}/scrolled", fx.parent), NAV).await.unwrap();
    let main = page.main_frame().unwrap();
    let same = wait_for_frame(page, &format!("{}/scrolled-sub", fx.parent)).await;
    let cross = wait_for_frame(page, &format!("localhost:{}/scrolled-sub", fx.child_port)).await;
    // The main frame's two, the two in each scrolled frame, and those two.
    for _ in 0..200 {
        if page.frames().len() >= 9 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(page.frames().len(), 9, "{:?}", page.frames());
    let read = |frame: &FrameId, js: &'static str| {
        let frame = frame.clone();
        async move { page.evaluate_main(&frame, js, vec![]).await.unwrap() }
    };
    for (name, frame) in [("main", &main), ("same-site frame", &same), ("cross-site frame", &cross)] {
        let card =
            page.evaluate_handle(frame, "() => document.getElementById('card')", vec![]).await.unwrap();
        let before = fallbacks(page);
        let err = page.click_element(&card).await.unwrap_err();
        card.dispose().await;
        assert_eq!(risen(page, before), [], "{name}: the node on top settled it");
        assert!(matches!(err, CdpError::Covered(_)), "{name}: {err:?}");
        assert!(err.to_string().contains("by <iframe>"), "{name}: {err}");
        assert_eq!(
            read(frame, "() => window.cardClicked ?? null").await,
            json!(false),
            "{name}: not clicked"
        );
        // Scrolled both ways to show the card, in its own document and in the main one.
        for (whose, f) in [("its", frame), ("the main", &main)] {
            let at = read(f, "() => [scrollX, scrollY]").await;
            let both = at[0].as_f64().unwrap() > 0.0 && at[1].as_f64().unwrap() > 0.0;
            assert!(both, "{name}: {whose} document is scrolled both ways: {at}");
        }

        click_until(page, frame, "behind", "behindClicked", name, &[]).await;
    }
}

/// [`cross_site_frames`]'s fixture, built in the page's own world from the other site's `src`.
const CROSS_SITE: &str = "(src) => { window.xfixture = true; const none = 'border:0;opacity:0;pointer-events:none';\
               const fill = 'position:absolute;left:0;top:0;width:100px;height:30px';\
               for (const id of ['xunder', 'xbehind', 'deco', 'play']) { window[id + 'Clicked'] = false; }\
               const card = (id, top, extra, s = src) => { const a = document.createElement('a'); a.id = id;\
               window[id + 'Clicked'] = false; a.href = '#'; a.onclick = () => { window[id + 'Clicked'] = true; return false; };\
               a.style.cssText = `position:absolute;left:450px;top:${top}px;display:block;width:100px;height:30px`;\
               a.innerHTML = `C<iframe src=\"${s}\" style=\"${fill};${none}\"></iframe>${extra}`; return a; };\
               const b = document.createElement('button'); b.id = 'xunder'; b.textContent = 'U';\
               b.onclick = () => { window.xunderClicked = true; };\
               b.style.cssText = 'position:absolute;left:450px;top:500px;width:100px;height:30px';\
               const over = document.createElement('iframe'); over.src = src;\
               over.style.cssText = `position:absolute;left:440px;top:490px;width:200px;height:60px;${none}`;\
               const behind = document.createElement('iframe'); behind.src = src;\
               behind.style.cssText = 'position:absolute;left:600px;top:0;width:150px;height:3000px;border:0';\
               const front = document.createElement('button'); front.id = 'xbehind'; front.textContent = 'B';\
               front.onclick = () => { window.xbehindClicked = true; };\
               front.style.cssText = 'position:absolute;left:610px;top:2410px;width:100px;height:30px;z-index:1';\
               const style = document.createElement('style');\
               style.textContent = `#xafter::after { content: ''; ${fill}; z-index: 1; pointer-events: none }\
                 #xpseudo::before { content: ''; ${fill}; z-index: 1 }\
                 .xdetails::details-content { transform: scaleX(-1) }`;\
               const deco = document.createElement('button'); deco.id = 'deco';\
               deco.onclick = () => { window.decoClicked = true; };\
               deco.style.cssText = 'position:absolute;left:10px;top:600px;width:100px;height:30px';\
               deco.innerHTML = `D<span style=\"${fill};pointer-events:none\"></span>`;\
               const play = document.createElement('button'); play.id = 'play';\
               play.onclick = () => { window.playClicked = true; };\
               play.style.cssText = 'position:absolute;left:610px;top:2500px;width:100px;height:30px;z-index:1';\
               play.innerHTML = `P<span style=\"${fill};pointer-events:none\"></span>`;\
               const framed = (id, css) => { const f = document.createElement('iframe'); f.src = src + '?' + id;\
               f.style.cssText = `position:absolute;${css};width:180px;height:60px;border:0`; return f; };\
               const turn = document.createElement('div');\
               turn.style.cssText = 'position:absolute;left:0;top:1100px;width:400px;height:80px;transform:translate(0.5px)';\
               turn.append(framed('xtranslate', 'left:99.5px;top:0'));\
               const slotted = (id, mode, wrap, top, css, host = '') => { const h = document.createElement('div');\
               h.style.cssText = `position:absolute;left:0;top:${top}px;width:400px;height:80px;${host}`;\
               h.attachShadow({mode}).innerHTML = `<div style=\"position:relative;width:400px;height:80px;${wrap}\"><slot></slot></div>`;\
               h.append(framed(id, css)); return h; };\
               const sticky = document.createElement('div');\
               sticky.style.cssText = 'position:absolute;left:0;top:1500px;width:400px;height:200px';\
               sticky.append(framed('xsticky', 'position:sticky;display:block;top:0;margin-left:100px'));\
               const scroller = document.createElement('div');\
               scroller.style.cssText = 'position:absolute;left:0.5px;top:1750px;width:400px;height:80px;overflow:auto';\
               scroller.append(framed('xscroller', 'left:99.5px;top:0'));\
               const scale = document.createElement('div');\
               scale.style.cssText = 'position:absolute;left:0;top:1850px;width:400px;height:80px;transform:scale(1.5);transform-origin:0 0';\
               scale.append(framed('xscale', 'left:100px;top:0'));\
               const details = document.createElement('details'); details.open = true; details.className = 'xdetails';\
               details.style.cssText = 'position:absolute;left:0;top:2050px;width:400px;height:80px;display:block';\
               details.append(framed('xdetails', 'left:100px;top:0'));\
               const tiny = document.createElement('div');\
               tiny.style.cssText = 'position:absolute;left:0;top:2150px;width:400px;height:80px;transform:scale(1.0000001);transform-origin:0 0';\
               tiny.append(framed('xtiny', 'left:100px;top:0'));\
               const filter = document.createElement('div');\
               filter.style.cssText = 'position:absolute;left:0.5px;top:180px;width:400px;height:70px;filter:brightness(1.01)';\
               filter.append(framed('xfilter', 'left:9.5px;top:0'));\
               const defs = document.createElementNS('http://www.w3.org/2000/svg', 'svg');\
               defs.setAttribute('width', '0'); defs.setAttribute('height', '0'); defs.style.cssText = 'position:absolute;left:0;top:0';\
               defs.innerHTML = '<filter id=\"xshift\" x=\"-1\" y=\"0\" width=\"3\" height=\"1\"><feOffset dx=\"40\" dy=\"0\"/></filter>';\
               const shift = document.createElement('div');\
               shift.style.cssText = 'position:absolute;left:0;top:2350px;width:400px;height:80px;filter:url(#xshift)';\
               shift.append(framed('xshift', 'left:100px;top:0'));\
               document.head.append(style);\
               document.body.append(card('xcard', 400, ''), b, over, behind, front, card('xafter', 600, ''),\
                 card('xspan', 700, `<span style=\"${fill};z-index:1;pointer-events:none\"></span>`), deco,\
                 card('xclear', 800, `<span style=\"${fill};z-index:1\"></span>`, src + '?xclear'), play,\
                 framed('xpad', 'left:10px;top:100px;padding-left:0.9px'),\
                 framed('xwhole', 'left:200px;top:100px;padding-left:1px'), turn, card('xpseudo', 1000, ''),\
                 slotted('xslot', 'open', 'transform:translate(0.5px)', 1200, 'left:99.5px;top:0'),\
                 slotted('xslotc', 'closed', 'translate:0.5px', 1300, 'left:99.5px;top:0'),\
                 slotted('xscalec', 'closed', 'transform:scale(1.5);transform-origin:0 0', 1400, 'left:100px;top:0'),\
                 slotted('xmirrorc', 'closed', 'transform:scaleX(-1)', 2250, 'left:100px;top:0', 'translate:0px'),\
                 sticky, scroller, scale, details, tiny, filter, defs, shift); }";

/// SR-34, part of [`isolation`]: frames of another site (`src`) in the main frame that the page's hit
/// test sees through, and content that takes no pointer events laid over them.
async fn cross_site_frames(page: &Page, fx: &Fixtures, main: &FrameId, src: &str) {
    // Another site's frame with `opacity: 0` and `pointer-events: none` inside a card link, and one laid
    // over a button: `elementFromPoint` sees through both, and headless Chrome sent the press into the
    // first. `DOM.getNodeForLocation`, with `pointer-events: none` ignored, finds the frame on top, and
    // nothing is pressed. A button laid over another site's frame is on top, and clicks: that frame is
    // a column from the top of the page, and the button far down it, so a check that missed the scroll
    // would ask about a point on the column (or below the page) and refuse it.
    // Then decoys that take no pointer events over a card's frame, a `::after` and a span: the node
    // on top is the decoy, the press goes to the card, so the box rule answers (`Decoy`), and refuses.
    // A button with such an overlay (an icon) and no frame there goes to the box rule too, and clicks;
    // over another site's frame (`#play`, a play button over a video) it is refused: SR-34's known
    // false refusal. A `::before` that takes pointer events over a card's frame (`#xpseudo`) is a
    // pseudo-element, with no element to check: the box rule answers (`Pseudo`), and refuses. A
    // transparent cover that takes pointer events over a card's frame (`#xclear`) is the card's own and
    // passes the check; the press goes to the card, never its frame (review r6 F2, r7 F4). And frames
    // placed at a fractional offset, by a `padding-left: 0.9px` (`BetweenPixels`) or inside a
    // `translate(0.5px)` (`Transformed`): the box rule clicks their buttons. So it does for frames that
    // something up the flat tree may move by a fraction: slotted into an open or a closed shadow root
    // through a translated wrapper, sticky, or in a scroller at a fractional corner (`Transformed`).
    // Frames that the page scales or mirrors, in the open, through a closed shadow root's wrapper (its
    // host only moving it as far as the walk sees), in a <details>'s mirrored `::details-content`, or by
    // a scale computed style reads as 1, are refused before the pointer moves (review r8 M1, S1, S3;
    // r9 M-1, F-1). A frame under a `filter`, and a `position: fixed` one with the page scrolled, are
    // pressed where they were checked (review r9 F-2).
    for lane in ["xclear", "xpad", "xfilter", "xfixed", "xshift", "turned"] {
        let _ = std::fs::remove_file(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sr34-{lane}.txt")),
        );
    }
    // In the page's own world: its handlers set the flags the lanes read there.
    page.evaluate_main(main, CROSS_SITE, vec![json!(src).into()]).await.unwrap();
    assert_eq!(
        eval(page, "() => window.xfixture ?? null").await,
        json!(true),
        "the flags are where they are read"
    );
    // #xhost's, and the twenty-one here.
    for _ in 0..200 {
        if page
            .frames()
            .iter()
            .filter(|f| f.url.contains(&format!("localhost:{}/child", fx.child_port)))
            .count()
            >= 22
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let decoy: &[Unsettled] = &[Unsettled::Decoy];
    for (sel, clicked, want) in [
        ("#xcard", "xcardClicked", &[][..]),
        ("#xunder", "xunderClicked", &[]),
        ("#xafter", "xafterClicked", decoy),
        ("#xspan", "xspanClicked", decoy),
        // The known false refusal: a play button over another site's video, its icon taking no
        // pointer events.
        ("#play", "playClicked", decoy),
        ("#xpseudo", "xpseudoClicked", &[Unsettled::Pseudo]),
    ] {
        let (r, why) = click_counting(page, sel).await;
        let err = r.unwrap_err();
        assert!(matches!(err, CdpError::Covered(_)), "{sel}: {err:?}");
        assert!(err.to_string().contains("by <iframe>"), "{sel}: {err}");
        assert_eq!(why, want, "{sel}: the box rule answered only for a decoy");
        assert_eq!(
            eval(page, &format!("() => window.{clicked} ?? null")).await,
            json!(false),
            "{sel}: nothing was clicked"
        );
    }
    let (r, why) = click_counting(page, "#deco").await;
    r.unwrap();
    assert_eq!(why, decoy, "the overlay sent it to the box rule");
    assert_eq!(
        eval(page, "() => window.decoClicked ?? null").await,
        json!(true),
        "with no frame there, it clicks"
    );
    click_until(page, main, "xbehind", "xbehindClicked", "over a frame", &[]).await;
    fractional(page, fx).await;
    moved_and_turned(page, fx).await;
    clear(page, fx, main).await;
}

/// Part of [`cross_site_frames`]: frames that something up the flat tree may move by a fraction, which
/// the box rule answers for (`Transformed`), and frames that the page scales or mirrors, which are
/// refused before the pointer moves, nothing pressed in them (review r8 M1, S1, S3). Two of those the
/// walk sees only as moved, the mirror hidden from it in a closed or a UA shadow root: the box model's
/// quads refuse them (review r9 M-1). What each refusal said goes to `sr34-turned.txt` (`status`).
/// These refuse before any press, so they prove nothing about Chrome pressing through a cover.
async fn moved_and_turned(page: &Page, fx: &Fixtures) {
    let frame = async |id: &str| wait_for_child(page, fx.child_port, id).await;
    for (id, what) in [
        ("xslot", "a frame slotted into an open shadow root, under a translate(0.5px)"),
        ("xslotc", "a frame slotted into a closed shadow root, under a translate: 0.5px"),
        ("xsticky", "a sticky frame"),
        ("xscroller", "a frame in a scroller at a fractional corner"),
    ] {
        let f = frame(id).await;
        click_until(page, &f, "b", "bClicked", what, &[Unsettled::Transformed]).await;
    }
    // `::details-content` is Chrome 131's; without it `#xdetails` is not mirrored, and is skipped.
    let parts = eval(page, "() => CSS.supports('selector(::details-content)')").await == json!(true);
    let mut said = Vec::new();
    for (id, what) in [
        ("xscale", "a frame in a scale(1.5)"),
        ("xscalec", "a frame slotted into a closed shadow root, under a scale(1.5)"),
        // What the walk sees only moves it (a `translate: 0px` on the host, the <details>), and the
        // mirror is where the world cannot look: only the box model's quads show it (review r9 M-1).
        (
            "xmirrorc",
            "a frame slotted into a closed shadow root under a scaleX(-1), its host at translate: 0px",
        ),
        ("xdetails", "a frame in a <details open> whose ::details-content is scaleX(-1)"),
        // A scale that computed style's six digits read as 1: only the typed value tells (review r9 F-1).
        ("xtiny", "a frame in a scale(1.0000001)"),
    ] {
        if id == "xdetails" && !parts {
            said.push(format!("{id}: skipped, this Chrome has no ::details-content"));
            continue;
        }
        let f = frame(id).await;
        let el = page.evaluate_handle(&f, "() => document.getElementById('b')", vec![]).await.unwrap();
        let before = fallbacks(page);
        let r = page.click_element(&el).await;
        el.dispose().await;
        let err = r.expect_err(what);
        said.push(format!("{id}: {err}"));
        status("turned", &said.join("\n"));
        assert!(matches!(err, CdpError::Covered(_)), "{what}: {err:?}");
        assert!(err.to_string().contains("scales, rotates or zooms"), "{what}: {err}");
        assert_eq!(risen(page, before), [], "{what}: refused before either check");
        // Read from the DOM, which every world shares.
        let read = "() => [document.body.dataset.clicked ?? null, document.body.dataset.pressed ?? null]";
        let seen = page.evaluate_main(&f, read, vec![]).await.unwrap();
        assert_eq!(seen, json!([null, null]), "{what}: nothing was pressed in the frame");
    }
    status("turned", &said.join("\n"));
}

/// Part of [`cross_site_frames`]: frames placed at a fractional offset, and ones at a whole one: in the
/// open, under a `filter` at a half-pixel wrapper, and `position: fixed` in a scrolled page.
async fn fractional(page: &Page, fx: &Fixtures) {
    let frame = async |id: &str| wait_for_child(page, fx.child_port, id).await;
    // In the first view, the main frame not scrolled: the frames' own offsets alone place them.
    page.evaluate(&page.main_frame().unwrap(), "() => scrollTo(0, 0)", vec![]).await.unwrap();
    // A frame at a whole offset (201, 100): the node on top settles it, and the frame's document gets
    // the press at the very point checked.
    let whole = frame("xwhole").await;
    click_until(page, &whole, "b", "bClicked", "a whole frame", &[]).await;
    let (checked, got) = pressed_at(page, &whole, (201.0, 100.0)).await;
    assert_eq!(got, checked, "a whole frame gets the press where it was checked");
    // The same at (10, 180), whole in layout, in a wrapper at `left: 0.5px` with a `filter`, which
    // nothing sends to the box rule: Chrome must not carry the half pixel into the frame (review r9 F-2).
    let filtered = frame("xfilter").await;
    click_until(page, &filtered, "b", "bClicked", "a frame under a filter", &[]).await;
    let (checked, got) = pressed_at(page, &filtered, (10.0, 180.0)).await;
    status(
        "xfilter",
        &format!("SR-34 #xfilter: checked at {checked:?} in the frame, the frame got the press at {got:?}"),
    );
    assert_eq!(got, checked, "a frame under a filter gets the press where it was checked");
    fixed(page, fx).await;
    shifted(page, fx).await;

    // In a frame offset by `0.9px` (57/64 px in layout at a device scale of 1), the button's point falls
    // between pixels: the box rule answers. Chrome places such a frame at a whole device pixel, so where
    // its document gets the press is recorded beside the point checked.
    let pad = frame("xpad").await;
    click_until(page, &pad, "b", "bClicked", "a fractional frame", &[Unsettled::BetweenPixels]).await;
    let (checked, got) = pressed_at(page, &pad, (10.0 + 57.0 / 64.0, 100.0)).await;
    status(
        "xpad",
        &format!(
            "SR-34 #xpad: checked at {checked:?} in the frame (device scale 1), the frame got the press at {got:?}"
        ),
    );

    // A frame at `left: 99.5px` inside a `translate(0.5px)`: whole on paper, yet placed by its
    // transform's pixel grid, so the box rule answers.
    let turned = frame("xtranslate").await;
    click_until(page, &turned, "b", "bClicked", "a frame in a translate", &[Unsettled::Transformed]).await;
}

/// Part of [`fractional`]: a frame at a whole offset in a wrapper whose SVG filter draws it 40 px to
/// the right (`feOffset`), so what a person sees is not where layout has it (review r10 F-2). A filter
/// moves neither layout nor hit testing, and nothing sends it to the box rule: the press goes to the
/// point layout gives, which the check asked about, and the frame's document gets it there, not 40 px
/// off. If Chrome routed the press by the drawn pixels instead, the frame would get no press there (the
/// point lies left of the drawn frame), and the lane fails.
async fn shifted(page: &Page, fx: &Fixtures) {
    let main = page.main_frame().unwrap();
    let f = wait_for_child(page, fx.child_port, "xshift").await;
    // In the isolated world: the page's own `getBoundingClientRect` is patched.
    let place = "() => { scrollTo(0, 2200); const f = [...document.querySelectorAll('iframe')]\
                 .find((e) => e.src.endsWith('?xshift')); const r = f.getBoundingClientRect(); return [r.left, r.top]; }";
    let at = page.evaluate(&main, place, vec![]).await.unwrap();
    let at = (at[0].as_f64().unwrap(), at[1].as_f64().unwrap());
    assert_eq!(at, (at.0.round(), at.1.round()), "the frame is at a whole offset in the view");
    click_until(page, &f, "b", "bClicked", "a frame an SVG filter draws 40 px off", &[]).await;
    let (checked, got) = pressed_at(page, &f, at).await;
    status(
        "xshift",
        &format!(
            "SR-34 #xshift: frame at {at:?}, checked at {checked:?} in the frame, the frame got the press at {got:?}"
        ),
    );
    page.evaluate(&main, "() => scrollTo(0, 0)", vec![]).await.unwrap();
    assert_eq!(got, checked, "a frame drawn off by a filter gets the press where layout has it");
}

/// Part of [`fractional`]: a `position: fixed` frame at (200, 260) in the view, the page scrolled by
/// whole pixels: the node on top settles it, and the frame gets the press where it was checked (review
/// r9 F-2). Added for this lane and removed after it, so it covers no other.
async fn fixed(page: &Page, fx: &Fixtures) {
    let main = page.main_frame().unwrap();
    let add = format!(
        "() => {{ scrollTo(0, 37); const f = document.createElement('iframe'); f.id = 'xfixed';\
         f.src = 'http://localhost:{}/child?xfixed';\
         f.style.cssText = 'position:fixed;left:200px;top:260px;width:180px;height:60px;border:0';\
         document.body.append(f); }}",
        fx.child_port
    );
    page.evaluate_main(&main, &add, vec![]).await.unwrap();
    let f = wait_for_child(page, fx.child_port, "xfixed").await;
    click_until(page, &f, "b", "bClicked", "a fixed frame", &[]).await;
    let (checked, got) = pressed_at(page, &f, (200.0, 260.0)).await;
    status(
        "xfixed",
        &format!("SR-34 #xfixed: checked at {checked:?} in the frame, the frame got the press at {got:?}"),
    );
    let remove = "() => { document.getElementById('xfixed').remove(); scrollTo(0, 0); }";
    page.evaluate_main(&main, remove, vec![]).await.unwrap();
    assert_eq!(got, checked, "a fixed frame gets the press where it was checked");
}

/// Where the press on `#b` in `frame` was checked, in the frame's document, its content box at `at` in
/// the page (`press_point`'s whole pixel nearest the button's centre), and where the frame's document
/// got it (`pointerdown`'s `clientX`, `clientY`).
async fn pressed_at(page: &Page, frame: &FrameId, at: (f64, f64)) -> ((f64, f64), (f64, f64)) {
    let rect = "() => { const r = document.getElementById('b').getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; }";
    let r = page.evaluate(frame, rect, vec![]).await.unwrap();
    let n = |i: usize| r[i].as_f64().unwrap();
    let snap = |start: f64, len: f64| {
        let s = (start + len / 2.0).round();
        if s >= start + len { s - 1.0 } else { s }
    };
    let checked = (snap(at.0 + n(0), n(2)) - at.0, snap(at.1 + n(1), n(3)) - at.1);
    let got = page.evaluate_main(frame, "() => document.body.dataset.at ?? null", vec![]).await.unwrap();
    let got = got.as_str().unwrap_or_else(|| panic!("{frame}: the frame got no press"));
    let (x, y) = got.split_once(',').unwrap();
    (checked, (x.parse().unwrap(), y.parse().unwrap()))
}

/// Part of [`cross_site_frames`]: a transparent cover over a card's frame, taking pointer events. Both
/// answers put it on top, and it is the card's own, so the check passes, and the card takes the press:
/// phantab does not falsely refuse a transparent cover. That is all the lane proves. Whether Chrome
/// presses through such a cover into the frame beneath (as it did through `#xcard`'s see-through one)
/// it does not prove: the control, a bare press with the cover gone, did not reach the frame on the
/// macOS headless Chrome (fdf4346, 817fcd1), so it is reported, never asserted. No lane proves pressing
/// through: the S5 lanes refuse before any press (review r9 S-3), so it is a residual, which the
/// `Covered` refusal of a frame on top bounds and does not close. The outcome goes to `sr34-xclear.txt`
/// (`status`).
async fn clear(page: &Page, fx: &Fixtures, main: &FrameId) {
    let frame = wait_for_child(page, fx.child_port, "xclear").await;
    let cover = |shown: bool| {
        let js = format!(
            "() => {{ const c = document.getElementById('xclear'); c.scrollIntoView({{block: 'center'}});\
             c.querySelector('span').style.display = '{}'; const r = c.getBoundingClientRect();\
             return [Math.round(r.left + r.width / 2), Math.round(r.top + r.height / 2)]; }}",
            if shown { "" } else { "none" }
        );
        async move { page.evaluate(main, &js, vec![]).await.unwrap() }
    };
    let pressed = async || {
        let js = "() => document.body.dataset.pressed ?? null";
        page.evaluate_main(&frame, js, vec![]).await.unwrap() == json!("yes")
    };
    let clicked = async || eval(page, "() => window.xclearClicked ?? null").await == json!(true);

    // The control: no cover, and a bare press at the card's centre (no check). Reported, not asserted.
    let at = cover(false).await;
    let (x, y) = (at[0].as_f64().unwrap(), at[1].as_f64().unwrap());
    let mut reached = false;
    for _ in 0..20 {
        page.mouse_click(x, y).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        if pressed().await {
            reached = true;
            break;
        }
        eval(page, "() => { window.xclearClicked = false; }").await;
    }
    let control = if reached {
        "control: the frame took the press"
    } else {
        "control: Chrome did not press through (the cover result is a non-refusal check only)"
    };
    page.evaluate_main(&frame, "() => { delete document.body.dataset.pressed; }", vec![]).await.unwrap();
    eval(page, "() => { window.xclearClicked = false; }").await;

    // With the cover: the check passes on the node on top, and the card takes the press; a refusal, a
    // fallback, the frame taking the press, or nobody, fails.
    cover(true).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (r, seen) = click_counting(page, "#xclear").await;
    let outcome = 'took: {
        if let Err(e) = r {
            break 'took Err(format!("refused: {e}"));
        }
        if !seen.is_empty() {
            break 'took Err("the box rule answered".to_owned());
        }
        for _ in 0..20 {
            if pressed().await {
                break 'took Err("the frame under the cover took the press".to_owned());
            }
            if clicked().await {
                break 'took Ok("the card took the press".to_owned());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err("neither the card nor its frame took the press".to_owned())
    };
    let said = match &outcome {
        Ok(said) => format!("pass: {said}"),
        Err(said) => format!("FAIL: {said}"),
    };
    let line =
        format!("SR-34 #xclear: {control}; at ({x}, {y}) with the cover: {said}; box rule reasons {seen:?}");
    status("xclear", &line);
    assert!(
        outcome.is_ok(),
        "{line} (with the cover, the card takes the press and the box rule never answers)"
    );
}

/// Writes `said`, one lane's outcome, to `sr34-<lane>.txt` in Cargo's scratch directory for this test
/// target (`<target>/tmp`), so a run whose output is kept back (`scripts/check.sh` hides it) can be
/// read: `cat target/tmp/sr34-*.txt`.
fn status(lane: &str, said: &str) {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sr34-{lane}.txt"));
    std::fs::write(&path, format!("{said}\n")).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    eprintln!("{said}");
}

/// How many click checks on `page` have fallen back to the box rule, for each reason.
fn fallbacks(page: &Page) -> [usize; 5] {
    Unsettled::ALL.map(|why| page.strict_fallbacks(why))
}

/// The reasons the box rule answered for since `before`, in [`Unsettled::ALL`]'s order.
fn risen(page: &Page, before: [usize; 5]) -> Vec<Unsettled> {
    let now = fallbacks(page);
    Unsettled::ALL
        .into_iter()
        .zip(now.into_iter().zip(before))
        .filter(|(_, (n, b))| n > b)
        .map(|(w, _)| w)
        .collect()
}

/// Clicks `sel` in the main frame: the result, and why the box rule answered (SR-34's fallback), if it
/// did.
async fn click_counting(page: &Page, sel: &str) -> (Result<(), CdpError>, Vec<Unsettled>) {
    let before = fallbacks(page);
    let r = page.click_selector(sel).await;
    (r, risen(page, before))
}

/// Clicks `#id` in `frame` until the page sets `window.flag`: each try must pass the check, with the
/// box rule answering for the reasons `want` only (with none, the node on top settles it; the box rule
/// would refuse it, a frame's box holding the point). Chrome routes input to another site's frame only
/// once it has drawn a frame, so a press can land elsewhere first.
async fn click_until(page: &Page, frame: &FrameId, id: &str, flag: &str, what: &str, want: &[Unsettled]) {
    let find = format!("() => document.getElementById('{id}')");
    let read = format!("() => window.{flag} ?? null");
    for _ in 0..20 {
        let el = page.evaluate_handle(frame, &find, vec![]).await.unwrap();
        let before = fallbacks(page);
        let r = page.click_element(&el).await;
        el.dispose().await;
        r.unwrap_or_else(|e| panic!("{what}: the button over a frame is on top: {e}"));
        assert_eq!(risen(page, before), want, "{what}: why the box rule answered");
        if page.evaluate_main(frame, &read, vec![]).await.unwrap() == json!(true) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{what}: the button over a frame never took the click");
}

/// SR-61: with `popups_as_tabs`, a popup the page asks for opens as a tab of the page's own window, by
/// `window.open` or by the three-argument `document.open`, which Blink sends to the native `open`.
async fn popups(browser: &Browser, fx: &Fixtures) {
    let page =
        browser.new_page_with(PageOptions { popups_as_tabs: true, ..PageOptions::default() }).await.unwrap();
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    let conn = browser.connection();
    let window_of = async |tid: &str| {
        conn.send(None, "Browser.getWindowForTarget", json!({"targetId": tid})).await.unwrap()["windowId"]
            .clone()
    };
    let own = window_of(page.target_id().unwrap()).await;
    let main = page.main_frame().unwrap();
    let ways = [
        ("?w", "() => { window.open(location.href + '?w', '_blank', 'popup,width=300,height=200'); }"),
        ("?d", "() => { document.open(location.href + '?d', '_blank', 'popup,width=300,height=200'); }"),
        ("?u", "() => { document.open(location.href + '?u', '_blank', undefined); }"),
        // An `open` taken from a fresh iframe's initial about:blank, which gets the script too.
        (
            "?f",
            "() => { const f = document.body.appendChild(document.createElement('iframe'));              f.contentWindow.open(location.href + '?f', '_blank', 'popup,width=300,height=200'); }",
        ),
    ];
    for (mark, js) in ways {
        page.evaluate_main(&main, js, vec![]).await.unwrap();
        let mut opened = None;
        for _ in 0..100 {
            let targets = conn.send(None, "Target.getTargets", json!({})).await.unwrap();
            opened = targets["targetInfos"].as_array().unwrap().iter().find_map(|t| {
                let ours = t["type"] == "page" && t["url"].as_str().is_some_and(|u| u.ends_with(mark));
                ours.then(|| t["targetId"].as_str().unwrap().to_owned())
            });
            if opened.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let tid = opened.unwrap_or_else(|| panic!("{js}: nothing opened"));
        assert_eq!(window_of(&tid).await, own, "{js}: a tab of the page's own window");
        conn.send(None, "Target.closeTarget", json!({"targetId": tid})).await.unwrap();
    }
    page.close().await.unwrap();
}

/// The tab's `WebAuthn` answered by a CDP virtual authenticator, set up before the page loads. Every test
/// that can reach `navigator.credentials.get` or `.create` needs it: without one, Chrome hands the
/// request to the OS, and Windows draws its "Choose a passkey" dialog on the owner's screen even for a
/// headless browser. Send it on the page's own session: a second CDP session on the tab does not
/// share it. Never send `WebAuthn.disable` while the page can still call `WebAuthn`.
async fn virtual_authenticator(page: &Page) {
    page.send("WebAuthn.enable", json!({})).await.unwrap();
    let options = json!({"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": true,
        "hasUserVerification": true, "isUserVerified": true,
    }});
    page.send("WebAuthn.addVirtualAuthenticator", options).await.unwrap();
}

/// `PASSKEY_WATCH` counts a page's passkey requests through the prototype, through a password
/// manager's override assigned after it (Bitwarden's order), and in a fresh iframe, and leaves out
/// autofill (`mediation: "conditional"`) and requests with no `publicKey`. Native calls carry an
/// aborted signal, so they settle at once, and a virtual authenticator answers anything that gets
/// further (see [`virtual_authenticator`]).
async fn passkeys(browser: &Browser, fx: &Fixtures) {
    let page =
        browser.new_page_with(PageOptions { watch_passkeys: true, ..PageOptions::default() }).await.unwrap();
    virtual_authenticator(&page).await;
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    let main = page.main_frame().unwrap();
    let asks = async || page.passkey_asks(&main).await.unwrap();
    assert_eq!(asks().await, Some(PasskeyAsks::default()));

    let native = "async (extra) => { try { await navigator.credentials.get({ ...extra, \
        publicKey: { challenge: new Uint8Array(32), timeout: 1000, allowCredentials: [] }, \
        signal: AbortSignal.abort() }); return 'answered'; } catch (e) { return e.name; } }";
    let call = async |extra: Value| {
        page.evaluate_main(&main, native, vec![phantab_cdp::Arg::Value(extra)]).await.unwrap()
    };
    assert_eq!(call(json!({})).await, json!("AbortError"));
    assert_eq!(asks().await, Some(PasskeyAsks { asked: 1, pending: 0, answered: 0 }));
    // Autofill asks nothing until the owner picks a passkey; a request with no `publicKey` is not one.
    assert_eq!(call(json!({"mediation": "conditional"})).await, json!("AbortError"));
    let plain = "async () => { try { await navigator.credentials.get({ signal: AbortSignal.abort() }); } \
        catch (e) { return e.name; } }";
    assert_eq!(page.evaluate_main(&main, plain, vec![]).await.unwrap(), json!("AbortError"));
    assert_eq!(asks().await, Some(PasskeyAsks { asked: 1, pending: 0, answered: 0 }));

    // A Bitwarden-like override: it binds what is there, assigns its own, and answers later.
    let manager = "() => { const fallback = navigator.credentials.get.bind(navigator.credentials); \
        navigator.credentials.get = (o) => o && o.publicKey \
          ? new Promise((resolve) => { window.release = () => resolve({ id: 'fake' }); }) : fallback(o); \
        window.got = navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32) } }); \
        return typeof navigator.credentials.get; }";
    assert_eq!(page.evaluate_main(&main, manager, vec![]).await.unwrap(), json!("function"));
    assert_eq!(asks().await, Some(PasskeyAsks { asked: 2, pending: 1, answered: 0 }));
    let released = "async () => { window.release(); return (await window.got).id; }";
    assert_eq!(page.evaluate_main(&main, released, vec![]).await.unwrap(), json!("fake"), "passed through");
    assert_eq!(asks().await, Some(PasskeyAsks { asked: 2, pending: 0, answered: 1 }));

    // A fresh iframe's initial about:blank gets the script too, with its own numbers.
    let framed = "async () => { const f = document.body.appendChild(document.createElement('iframe')); \
        const w = f.contentWindow; try { await w.navigator.credentials.get({ \
        publicKey: { challenge: new Uint8Array(32) }, signal: AbortSignal.abort() }); } catch (e) {} \
        return w.__phantabPasskeys.read(); }";
    assert_eq!(
        page.evaluate_main(&main, framed, vec![]).await.unwrap(),
        json!({"asked": 1, "pending": 0, "answered": 0})
    );
    assert_eq!(asks().await, Some(PasskeyAsks { asked: 2, pending: 0, answered: 1 }));
    page.close().await.unwrap();

    // Off by default: nothing is counted, and the read says so.
    let page = browser.new_page().await.unwrap();
    page.goto(&format!("{}/", fx.parent), NAV).await.unwrap();
    assert_eq!(page.passkey_asks(&page.main_frame().unwrap()).await.unwrap(), None);
    page.close().await.unwrap();
}

async fn closing(browser: &Browser) {
    let page = browser.new_page().await.unwrap();
    page.close().await.unwrap();
    assert!(page.is_closed());
    assert!(page.send("Runtime.evaluate", json!({"expression": "1"})).await.unwrap_err().is_closed());

    // Closed from outside: the page learns it from the browser's detach event.
    let page = browser.new_page().await.unwrap();
    let tid = page.target_id().unwrap().to_owned();
    browser.connection().send(None, "Target.closeTarget", json!({"targetId": tid})).await.unwrap();
    let mut closed = page.closed();
    tokio::time::timeout(Duration::from_secs(5), closed.wait_for(Option::is_some)).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_chrome() {
    let Some(exe) = std::env::var_os("PHANTAB_TEST_CHROME") else {
        eprintln!("skip: PHANTAB_TEST_CHROME not set");
        return;
    };
    let fx = start_fixtures().await;
    let browser = Browser::launch(LaunchOptions {
        executable: exe.into(),
        headless: true,
        user_data_dir: None,
        args: vec![],
    })
    .await
    .unwrap();
    let outcome = AssertUnwindSafe(async {
        let pages = browser.pages().await.unwrap();
        assert!(!pages.is_empty(), "the launch tab is listed");
        let page = browser.new_page().await.unwrap();
        evaluate_and_handles(&page, &fx).await;
        oopif(&browser, &page, &fx).await;
        screenshot(&page, &fx).await;
        forms_and_keyboard(&page, &fx).await;
        isolation(&page, &fx).await;
        scrolled(&page, &fx).await;
        popups(&browser, &fx).await;
        passkeys(&browser, &fx).await;
        navigation(&browser, &fx).await;
        closing(&browser).await;
    })
    .catch_unwind()
    .await;
    // Always close our browser (and its temp profile), even when an assertion failed.
    browser.close().await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// TCP ports the process `pid` listens on, from the OS's own socket table.
fn listening_ports(pid: u32) -> Vec<u16> {
    let pid = pid.to_string();
    let mut ports = Vec::new();
    #[cfg(windows)]
    for proto in ["TCP", "TCPv6"] {
        let out = std::process::Command::new("netstat").args(["-ano", "-p", proto]).output().unwrap();
        assert!(out.status.success(), "netstat -p {proto} failed");
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // Proto, local address, foreign address, state, pid.
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() == 5 && cols[3] == "LISTENING" && cols[4] == pid {
                ports.extend(cols[1].rsplit(':').next().and_then(|p| p.parse::<u16>().ok()));
            }
        }
    }
    #[cfg(unix)]
    {
        // Exit 1 with no output means no such socket.
        let out = std::process::Command::new("lsof")
            .args(["-nP", "-a", "-p", &pid, "-iTCP", "-sTCP:LISTEN", "-Fn"])
            .output()
            .unwrap();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(name) = line.strip_prefix('n') {
                ports.extend(name.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()));
            }
        }
    }
    ports
}

fn scratch_profile(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("phantab-cdp-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn remove_profile(dir: &std::path::Path) {
    // Windows keeps profile files locked for a moment after Chrome exits.
    for _ in 0..50 {
        if std::fs::remove_dir_all(dir).is_ok() || !dir.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// THREAT-MODEL R13: a launched browser (the engine's isolated-headless one) is reached over its
/// debugging pipe and opens no debugging port: no `DevToolsActivePort` and no listening socket. The same
/// checks against a launch that asks for a port show they would see one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_launched_browser_opens_no_devtools_port() {
    let Some(exe) = std::env::var_os("PHANTAB_TEST_CHROME") else {
        eprintln!("skip: PHANTAB_TEST_CHROME not set");
        return;
    };
    let launch = |profile: &std::path::Path, args: Vec<String>| {
        Browser::launch(LaunchOptions {
            executable: exe.clone().into(),
            headless: true,
            user_data_dir: Some(profile.to_owned()),
            args,
        })
    };

    let profile = scratch_profile("pipe");
    let browser = launch(&profile, vec![]).await.unwrap();
    let outcome = AssertUnwindSafe(async {
        assert_eq!(browser.ws_url(), None, "launched over the pipe");
        let page = browser.new_page().await.unwrap();
        page.goto("data:text/html,<title>piped</title>", NAV).await.unwrap();
        assert_eq!(eval(&page, "() => document.title").await, json!("piped"));
        assert!(!profile.join("DevToolsActivePort").exists(), "Chrome wrote DevToolsActivePort");
        let pid = browser.pid().unwrap();
        assert_eq!(listening_ports(pid), Vec::<u16>::new(), "the piped Chrome (pid {pid}) listens");
    })
    .catch_unwind()
    .await;
    browser.close().await.unwrap();
    remove_profile(&profile).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    let profile = scratch_profile("port");
    let browser = launch(&profile, vec!["--remote-debugging-port=0".to_owned()]).await.unwrap();
    let outcome = AssertUnwindSafe(async {
        let url = browser.ws_url().expect("a port launch has a WebSocket").to_owned();
        let port: u16 = url.trim_start_matches("ws://127.0.0.1:").split('/').next().unwrap().parse().unwrap();
        assert!(profile.join("DevToolsActivePort").exists());
        let pid = browser.pid().unwrap();
        assert!(listening_ports(pid).contains(&port), "the port check misses {port} for pid {pid}");
    })
    .catch_unwind()
    .await;
    browser.close().await.unwrap();
    remove_profile(&profile).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
