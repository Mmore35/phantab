//! The fixture server, driven by a tiny blocking HTTP client.
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code: a failed step should fail the test")]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use phantab_testkit::{
    FixtureServer, Listener, fixture_paths, fixture_source, fixtures_dir, foreign_extension_dir,
};

struct Reply {
    status: u16,
    headers: String,
    body: String,
}

fn send(port: u16, raw: &str) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Reply { status, headers: head.to_owned(), body: body.to_owned() }
}

fn get(port: u16, target: &str) -> Reply {
    send(port, &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
}

fn post(port: u16, target: &str, body: &str) -> Reply {
    send(
        port,
        &format!(
            "POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn serves_pages_with_both_origins_filled_in() {
    let server = FixtureServer::start().unwrap();
    assert_eq!(server.url("/a"), format!("http://127.0.0.1:{}/a", server.port()));
    assert_eq!(server.twin_url("/a"), format!("http://localhost:{}/a", server.twin_port()));
    assert_ne!(server.port(), server.twin_port());

    let page = get(server.port(), "/frames/cross-site");
    assert_eq!(page.status, 200);
    assert!(page.headers.contains("Content-Type: text/html; charset=utf-8"));
    assert!(page.headers.contains("Cache-Control: no-store"));
    assert!(page.body.contains(&server.twin_url("/snapshot/inner")), "{}", page.body);
    assert!(!page.body.contains("{{"));

    // The .html spelling serves the same page; the twin serves the same set.
    assert_eq!(get(server.port(), "/sign-in/one.html").body, get(server.twin_port(), "/sign-in/one").body);
    let twin = server.requests().into_iter().find(|r| r.listener == Listener::Twin).unwrap();
    assert_eq!(twin.url, server.twin_url("/sign-in/one"));
}

#[test]
fn twin_answers_on_ipv6_when_there_is_one() {
    let server = FixtureServer::start().unwrap();
    if !server.twin_has_ipv6() {
        eprintln!("skip: no IPv6 loopback");
        return;
    }
    let mut stream = TcpStream::connect(("::1", server.twin_port())).unwrap();
    stream.write_all(b"GET /engine/basic HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200"));
}

#[test]
fn query_values_are_escaped_into_pages() {
    let server = FixtureServer::start().unwrap();
    let page = get(server.port(), "/snapshot/inner?n=%3Cb%3E");
    assert!(page.body.contains("&lt;b&gt;"));
    assert!(!page.body.contains("<b>"));
}

/// Fixture keys on disk: every file under `dir`, minus the foreign extension.
fn walk(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path != foreign_extension_dir() {
                walk(&path, base, out);
            }
        } else {
            let key = path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            out.insert(key.strip_suffix(".html").unwrap_or(&key).to_owned());
        }
    }
}

#[test]
fn every_page_renders_and_every_file_is_listed() {
    let server = FixtureServer::start().unwrap();
    for key in fixture_paths() {
        let page = get(server.port(), &format!("/{key}?n=x"));
        assert_eq!(page.status, 200, "{key}");
        assert!(!page.body.contains("{{"), "{key} kept a template token");
        assert!(!page.body.trim().is_empty(), "{key} is empty");
    }
    let mut on_disk = BTreeSet::new();
    walk(&fixtures_dir(), &fixtures_dir(), &mut on_disk);
    let listed: BTreeSet<String> = fixture_paths().map(str::to_owned).collect();
    assert_eq!(on_disk, listed, "src/pages.rs must list every file under fixtures/");
    assert!(fixture_source("sign-in/one").unwrap().contains("type=\"password\""));
    assert!(foreign_extension_dir().join("manifest.json").is_file());
}

#[test]
fn index_and_missing_pages() {
    let server = FixtureServer::start().unwrap();
    let index = get(server.port(), "/");
    assert!(index.body.contains("href=\"/sign-in/one\""));
    let missing = get(server.port(), "/no/such/page");
    assert_eq!((missing.status, missing.body.as_str()), (404, "none"));
}

#[test]
fn slow_waits_then_serves() {
    let server = FixtureServer::start().unwrap();
    let started = Instant::now();
    let page = get(server.port(), "/slow?ms=300&then=/engine/basic");
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert_eq!(page.body, get(server.port(), "/engine/basic").body);
    let plain = get(server.port(), "/slow?ms=0");
    assert!(plain.body.contains("Waited 0 ms"));
}

#[test]
fn redirects_and_statuses() {
    let server = FixtureServer::start().unwrap();
    let to = server.twin_url("/engine/basic");
    let found = get(server.port(), &format!("/redirect?to={to}"));
    assert_eq!(found.status, 302);
    assert!(found.headers.contains(&format!("Location: {to}")));
    assert_eq!(get(server.port(), "/redirect?to=/x&status=307").status, 307);
    assert_eq!(get(server.port(), "/status?code=503").status, 503);
}

#[test]
fn posts_are_recorded_and_answered() {
    let server = FixtureServer::start().unwrap();
    let landed = post(server.port(), "/post/ok?step=1", "user=a%40b.test&pass=S3ntinel+pw%2B%2F%3D%21");
    assert!(landed.body.contains("Welcome back"));
    assert!(post(server.port(), "/post/userstep", "email=a").body.contains("type=\"password\""));
    assert!(post(server.port(), "/post/tocode", "pass=x").body.contains("one-time-code"));
    assert!(post(server.port(), "/post/tokey", "pass=x").body.contains("security key"));
    assert!(post(server.port(), "/post/thendetach", "pass=x").body.contains("/hook/detach-me"));
    // A GET form's submission is a post too, with the value in its query.
    assert!(get(server.port(), "/post/get?pass=leaked").body.contains("Welcome back"));
    get(server.port(), "/engine/basic");

    let posts = server.posts();
    assert_eq!(posts.len(), 6);
    assert_eq!(posts[0].path, "/post/ok");
    assert_eq!(posts[0].query_param("step").as_deref(), Some("1"));
    assert_eq!(posts[0].form("user").as_deref(), Some("a@b.test"));
    assert_eq!(posts[0].form("pass").as_deref(), Some("S3ntinel pw+/=!"));
    assert_eq!(posts[0].header("content-type"), Some("application/x-www-form-urlencoded"));
    assert_eq!(posts[0].url, server.url("/post/ok?step=1"));
    assert_eq!(posts[5].method, "GET");
    assert_eq!(posts[5].query_param("pass").as_deref(), Some("leaked"));
    assert!(server.saw("S3ntinel pw+/=!"), "decoded body is searched");
    assert!(server.saw("leaked"));
    assert!(!server.saw("never-sent"));
    server.clear_requests();
    assert!(server.requests().is_empty());
}

#[test]
fn echo_is_escaped() {
    let server = FixtureServer::start().unwrap();
    let page = post(server.port(), "/post/echo", "pass=%3Cscript%3Ex");
    assert_eq!(page.body, "<title>Oops</title><p>You typed &lt;script&gt;x</p>");
}

#[test]
fn malformed_requests_are_refused() {
    let server = FixtureServer::start().unwrap();
    let chunked =
        send(server.port(), "POST /post/ok HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert_eq!(chunked.status, 501);
    assert_eq!(send(server.port(), "nonsense\r\n\r\n").status, 400);
}

#[tokio::test]
async fn gates_hold_hooks_until_released() {
    let server = FixtureServer::start().unwrap();
    let port = server.port();
    // Without a gate a hook answers at once.
    assert_eq!(tokio::task::spawn_blocking(move || get(port, "/hook/free").body).await.unwrap(), "ok");

    let gate = server.gate("detach-me");
    let held = tokio::task::spawn_blocking(move || post(port, "/hook/detach-me", "").body);
    assert!(gate.arrived(Duration::from_secs(5)).await);
    assert_eq!(gate.arrivals(), 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!held.is_finished(), "the hook answered before release");
    gate.release();
    assert_eq!(held.await.unwrap(), "ok");

    // A dropped gate lets everything through.
    let again = server.gate("later");
    let held = tokio::task::spawn_blocking(move || get(port, "/hook/later").body);
    assert!(again.arrived(Duration::from_secs(5)).await);
    drop(again);
    assert_eq!(held.await.unwrap(), "ok");
}

#[tokio::test]
async fn wait_for_request_sees_old_and_new_requests() {
    let server = FixtureServer::start().unwrap();
    let port = server.port();
    get(port, "/engine/basic");
    let old = server.wait_for_request(|r| r.path == "/engine/basic", Duration::from_secs(1)).await;
    assert!(old.is_some());
    let none = server.wait_for_request(|r| r.path == "/never", Duration::from_millis(100)).await;
    assert!(none.is_none());
    let later = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(150));
        post(port, "/post/late", "a=1");
    });
    let found = server.wait_for_request(|r| r.path == "/post/late", Duration::from_secs(5)).await.unwrap();
    assert_eq!(found.form("a").as_deref(), Some("1"));
    later.await.unwrap();
}

#[test]
fn drop_stops_listening() {
    let server = FixtureServer::start().unwrap();
    let port = server.port();
    let held = server.gate("forever");
    let client = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(b"GET /hook/forever HTTP/1.1\r\n\r\n").unwrap();
        let mut out = Vec::new();
        let _ = stream.read_to_end(&mut out);
    });
    std::thread::sleep(Duration::from_millis(100));
    std::mem::forget(held);
    drop(server);
    client.join().unwrap();
    assert!(TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500)).is_err());
}
