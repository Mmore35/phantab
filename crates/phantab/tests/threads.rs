//! perf-idle-2: the OS threads of a real service, MCP server and native host. Only the service has tokio
//! workers (`phantab::mode`), so an idle MCP session or host costs a handful of threads, not one per CPU.
// Test helpers fail by panicking, like the tests themselves (clippy.toml allows it only inside #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{Runtime, frame, read_frame};
use serde_json::json;

/// Most threads an idle MCP server or host may run: its own, tokio's stdio readers and writers, and
/// what the OS adds (the Windows loader's pool). A worker per CPU would pass this on few machines only.
const CLIENT_MAX: usize = 8;
/// The service: its workers on top of that.
const SERVICE_MAX: usize = CLIENT_MAX + phantab::mode::SERVICE_WORKERS;

/// The live thread count of process `pid`.
fn threads(pid: u32) -> usize {
    if cfg!(target_os = "linux") {
        return std::fs::read_dir(format!("/proc/{pid}/task")).unwrap().count();
    }
    let out = if cfg!(windows) {
        let count = format!("(Get-Process -Id {pid}).Threads.Count");
        Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &count]).output()
    } else {
        // macOS: one line per thread after the header.
        Command::new("ps").args(["-M", "-p", &pid.to_string()]).output()
    };
    let text = String::from_utf8(out.unwrap().stdout).unwrap();
    if cfg!(windows) { text.trim().parse().unwrap() } else { text.lines().count().saturating_sub(1) }
}

/// The fewest threads seen over a moment: the OS's own short-lived threads come and go at start.
fn settled_threads(pid: u32) -> usize {
    std::thread::sleep(Duration::from_millis(1500));
    (0..3)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(300));
            threads(pid)
        })
        .min()
        .unwrap()
}

#[test]
fn only_the_service_runs_worker_threads() {
    let rt = Runtime::new();
    rt.install_extension_in_profile();
    let service = rt.serve();

    let mut mcp = rt
        .command(&["mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut to_mcp = mcp.stdin.take().unwrap();
    let mut from_mcp = BufReader::new(mcp.stdout.take().unwrap());
    let initialize = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "threads", "version": "1" } } });
    writeln!(to_mcp, "{initialize}").unwrap();
    let mut line = String::new();
    from_mcp.read_line(&mut line).unwrap();
    assert!(line.contains("serverInfo"), "{line}");
    writeln!(to_mcp, "{}", json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).unwrap();

    let origin = format!("chrome-extension://{}/", *phantab::bridge::EXTENSION_ID);
    let mut host = rt
        .command(&[&origin, "--parent-window=0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut to_host = host.stdin.take().unwrap();
    let mut from_host = host.stdout.take().unwrap();
    to_host
        .write_all(&frame(&json!({ "hello": { "version": "1.0.0", "protocol": 1, "instance": "threads" } })))
        .unwrap();
    to_host.flush().unwrap();
    assert_eq!(read_frame(&mut from_host), Some(json!({ "welcome": true, "events": phantab_cdp::EVENTS })));

    let (mcp_threads, host_threads, service_threads) =
        (settled_threads(mcp.id()), settled_threads(host.id()), settled_threads(service.endpoint.pid));
    assert!(mcp_threads <= CLIENT_MAX, "an idle MCP server runs {mcp_threads} threads");
    assert!(host_threads <= CLIENT_MAX, "an idle native host runs {host_threads} threads");
    assert!(service_threads <= SERVICE_MAX, "an idle service runs {service_threads} threads");

    drop(to_mcp);
    drop(to_host);
    let _ = mcp.kill();
    let _ = host.kill();
    let _ = mcp.wait();
    let _ = host.wait();
}
