//! Native host mode. Chrome starts this binary for the phantab bridge extension with the
//! caller's origin as the first argument. It starts the service if needed, joins `/bridge`, then pipes
//! native-messaging frames both ways unchanged.
//!
//! Stdout carries native-messaging frames only; anything else breaks the link.

use std::io::Write as _;

use bytes::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use zeroize::Zeroize as _;

use crate::bridge::{self, EXTENSION_ID};
use crate::paths::BRIDGE_UPGRADE;
use crate::runtime::ensure_service;

/// Whether `arg` (argv[1]) is Chrome starting a native host.
#[must_use]
pub fn is_host_invocation(arg: &str) -> bool {
    arg.starts_with("chrome-extension://")
}

/// One `{refused}` frame for the extension to show, then exit 1.
fn refuse(message: &str) -> ! {
    if let Ok(data) = bridge::frame(&serde_json::json!({ "refused": message })) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(&data);
        let _ = out.flush();
    }
    std::process::exit(1)
}

/// Runs the host for the extension at `origin`. Never returns: the process ends with the link.
pub async fn run(origin: &str) -> ! {
    // Only our extension, checked before the endpoint is read or the service started (THREAT-MODEL
    // SR-15): Chrome lists allowed origins in the host manifest, but a copied manifest could name more.
    if origin != format!("chrome-extension://{}/", *EXTENSION_ID) {
        refuse("This native host serves only the phantab bridge extension.");
    }
    // The join goes on the connection the service proved itself on (SR-13), so the token reaches only
    // that listener.
    let mut proven = match ensure_service(true).await {
        Ok(p) => p,
        Err(err) => refuse(&err.to_string()),
    };
    let req = Request::get("/bridge")
        .header("Connection", "Upgrade")
        .header("Upgrade", BRIDGE_UPGRADE)
        .header("Authorization", format!("Bearer {}", proven.endpoint.token));
    let res = match proven.send(req, Bytes::new()).await {
        Ok(r) => r,
        Err(err) => refuse(&format!("Browser service unreachable: {err}")),
    };
    if res.status() != StatusCode::SWITCHING_PROTOCOLS {
        refuse(&format!("Browser service refused the bridge ({}).", res.status().as_u16()));
    }
    let upgraded = match hyper::upgrade::on(res).await {
        Ok(u) => u,
        Err(err) => refuse(&format!("Browser service unreachable: {err}")),
    };
    let (mut from_service, mut to_service) = tokio::io::split(TokioIo::new(upgraded));
    // Chrome closes stdin when the extension disconnects; the service ending the socket ends this host.
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 64 * 1024];
        // SR-17: a header past 64 MiB from Chrome closes the link; bytes still pass unchanged.
        let mut guard = bridge::FrameGuard::new(bridge::FROM_CHROME_LIMIT);
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let failed = guard.check(&buf[..n]).is_err()
                        || to_service.write_all(&buf[..n]).await.is_err()
                        || to_service.flush().await.is_err();
                    // SR-47: a relayed chunk may carry a fill value; it does not stay in this buffer.
                    buf[..n].zeroize();
                    if failed {
                        break;
                    }
                }
            }
        }
        let _ = to_service.shutdown().await;
    });
    let mut stdout = tokio::io::stdout();
    let mut buf = vec![0u8; 64 * 1024];
    // SR-17: Chrome takes at most 1 MiB from a host; a larger frame from the service ends the link
    // before any of it reaches stdout.
    let mut guard = bridge::FrameGuard::new(bridge::TO_CHROME_LIMIT);
    loop {
        match from_service.read(&mut buf).await {
            Ok(0) => {
                let _ = stdout.flush().await;
                std::process::exit(0)
            }
            Ok(n) => {
                let failed = guard.check(&buf[..n]).is_err()
                    || stdout.write_all(&buf[..n]).await.is_err()
                    || stdout.flush().await.is_err();
                // SR-47: a fill value goes to Chrome in these chunks; none stays in the buffer.
                buf[..n].zeroize();
                if failed {
                    std::process::exit(1)
                }
            }
            Err(_) => std::process::exit(1),
        }
    }
}
