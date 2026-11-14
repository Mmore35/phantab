//! Chrome's debugging pipe under a [`Connection`] (`--remote-debugging-pipe`). No port is open, so no
//! other local process can reach a browser launched this way (THREAT-MODEL R13). Each message is JSON
//! followed by one NUL byte, in both directions (Chromium `devtools_pipe_handler.cc`, the `ASCIIZ`
//! reader and writer).
//!
//! The two ends are blocking OS pipes, so each gets its own thread rather than a runtime task: a
//! blocked read must never hold up tokio, nor keep a runtime from shutting down.

use std::io::{ErrorKind, Read, Write};

use crate::CdpError;
use crate::connection::{Connection, MAX_MESSAGE, Outgoing};

/// The pipe's read size. Chrome writes in 64 KiB packets.
const CHUNK: usize = 64 << 10;

/// One message as it goes down the pipe: the text, then its NUL terminator.
fn frame(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(0);
    bytes
}

/// Splits the bytes read from the pipe into NUL-terminated messages.
#[derive(Debug, Default)]
struct NulFramer {
    /// The start of a message whose NUL has not arrived yet. It holds no NUL.
    pending: Vec<u8>,
}

impl NulFramer {
    /// Adds `bytes` and returns every message they complete, without the NUL. `Err(len)` when the
    /// unterminated message has grown past `max` bytes.
    fn push(&mut self, bytes: &[u8], max: usize) -> Result<Vec<Vec<u8>>, usize> {
        // Only the new bytes are searched: `pending` holds no NUL, and a large message arrives in
        // many reads.
        let mut scan = self.pending.len();
        self.pending.extend_from_slice(bytes);
        let mut out = Vec::new();
        let mut start = 0;
        while let Some(n) = self.pending[scan..].iter().position(|&b| b == 0) {
            let end = scan + n;
            out.push(self.pending[start..end].to_vec());
            start = end + 1;
            scan = start;
        }
        self.pending.drain(..start);
        if self.pending.len() > max {
            return Err(self.pending.len());
        }
        Ok(out)
    }
}

fn spawn_io(name: &str, f: impl FnOnce() + Send + 'static) -> Result<(), CdpError> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(f)
        .map(drop)
        .map_err(|e| CdpError::Other(format!("cannot start the {name} thread: {e}")))
}

impl Connection {
    /// Speaks CDP over a debugging pipe: `from_browser` is the end Chrome writes, `to_browser` the end
    /// it reads. Closing the connection closes `to_browser`, which Chrome takes as its signal to exit.
    pub fn pipe<R, W>(from_browser: R, to_browser: W) -> Result<Connection, CdpError>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let (conn, mut out_rx, feed) = Connection::new(None);

        let writer_feed = feed.clone();
        let mut writer = to_browser;
        spawn_io("phantab-cdp-pipe-write", move || {
            while let Some(m) = out_rx.blocking_recv() {
                match m {
                    Outgoing::Text(text) => {
                        if let Err(e) = writer.write_all(&frame(&text)).and_then(|()| writer.flush()) {
                            // A broken pipe is Chrome's end gone, the same end the reader reports, so it is
                            // named the same: which thread sees it first is a race (a send racing an exit).
                            let reason = if e.kind() == ErrorKind::BrokenPipe {
                                "Pipe closed".to_owned()
                            } else {
                                format!("Pipe write failed: {e}")
                            };
                            writer_feed.end(&reason);
                            return;
                        }
                    }
                    Outgoing::Close => return,
                }
            }
        })?;

        let mut reader = from_browser;
        spawn_io("phantab-cdp-pipe-read", move || {
            let mut framer = NulFramer::default();
            let mut chunk = vec![0u8; CHUNK];
            let reason = loop {
                let n = match reader.read(&mut chunk) {
                    // Chrome closed its end: it exited, or was killed.
                    Ok(0) => break "Pipe closed".to_owned(),
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == ErrorKind::BrokenPipe => break "Pipe closed".to_owned(),
                    Err(e) => break format!("Pipe read failed: {e}"),
                };
                match framer.push(&chunk[..n], MAX_MESSAGE) {
                    Ok(messages) => {
                        for m in messages {
                            if !feed.deliver(&String::from_utf8_lossy(&m)) {
                                return;
                            }
                        }
                    }
                    Err(len) => {
                        break format!("Pipe message of over {len} bytes refused (limit {MAX_MESSAGE})");
                    }
                }
            };
            feed.end(&reason);
        })?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::{SessionId, Transport, TransportEvent};

    fn texts(messages: Vec<Vec<u8>>) -> Vec<String> {
        messages.into_iter().map(|m| String::from_utf8(m).unwrap()).collect()
    }

    #[test]
    fn frames_end_with_one_nul_and_split_wherever_the_reads_fall() {
        assert_eq!(frame(r#"{"id":1}"#), b"{\"id\":1}\0");
        // serde_json escapes a NUL inside a string, so a framed command holds exactly one.
        let text = json!({"params": {"text": "a\u{0}b"}}).to_string();
        assert!(!text.as_bytes().contains(&0), "{text}");
        assert_eq!(frame(&text), [text.as_bytes(), b"\0"].concat());

        let mut f = NulFramer::default();
        assert_eq!(f.push(b"{\"a\":1}\0{\"b\"", 100), Ok(vec![b"{\"a\":1}".to_vec()]));
        assert_eq!(f.push(b":2}", 100), Ok(vec![]));
        assert_eq!(texts(f.push(b"\0{}\0\0x", 100).unwrap()), ["{\"b\":2}", "{}", ""]);
        assert_eq!(texts(f.push(b"y\0", 100).unwrap()), ["xy"]);
        assert_eq!(f.pending, Vec::<u8>::new());

        // Byte by byte, as a slow pipe may deliver it.
        let mut f = NulFramer::default();
        let mut got = Vec::new();
        for b in b"one\0two\0" {
            got.extend(texts(f.push(&[*b], 100).unwrap()));
        }
        assert_eq!(got, ["one", "two"]);

        let mut f = NulFramer::default();
        assert_eq!(f.push(b"12345", 4), Err(5));
        let mut f = NulFramer::default();
        assert_eq!(f.push(b"1234\0", 4), Ok(vec![b"1234".to_vec()]));
    }

    /// A fake browser on the far end of two OS pipes: it answers `Target.attachToTarget` with an attach
    /// event, the answer and one page event, refuses `Fail`, never answers `Hang`, and on `Quit` closes
    /// its end.
    fn fake_browser(commands: std::io::PipeReader, mut events: std::io::PipeWriter) {
        std::thread::spawn(move || {
            let mut commands = BufReader::new(commands);
            let mut send = |v: Value| events.write_all(&frame(&v.to_string())).unwrap();
            loop {
                let mut raw = Vec::new();
                if commands.read_until(0, &mut raw).unwrap() == 0 {
                    return;
                }
                assert_eq!(raw.pop(), Some(0), "every command ends with NUL");
                let cmd: Value = serde_json::from_slice(&raw).unwrap();
                let id = cmd["id"].clone();
                match cmd["method"].as_str().unwrap() {
                    "Target.attachToTarget" => {
                        send(json!({"method": "Target.attachedToTarget", "params": {"sessionId": "S1"}}));
                        send(json!({"id": id, "result": {"sessionId": "S1"}}));
                        send(json!({"sessionId": "S1", "method": "Page.loadEventFired", "params": {"t": 1}}));
                    }
                    "Fail" => send(json!({"id": id, "error": {"code": -32000, "message": "No way"}})),
                    "Hang" => {}
                    _ => return,
                }
            }
        });
    }

    #[tokio::test]
    async fn a_pipe_connection_routes_answers_and_events_and_reports_its_end() {
        let (browser_in, to_browser) = std::io::pipe().unwrap();
        let (from_browser, browser_out) = std::io::pipe().unwrap();
        fake_browser(browser_in, browser_out);
        let conn = Connection::pipe(from_browser, to_browser).unwrap();
        assert_eq!(conn.url(), None);

        let r = conn.send(None, "Target.attachToTarget", json!({"targetId": "T"})).await.unwrap();
        assert_eq!(r, json!({"sessionId": "S1"}));
        let mut events = conn.take_events(&SessionId::from("S1"));
        let ev = tokio::time::timeout(Duration::from_secs(5), events.recv()).await.unwrap().unwrap();
        assert_eq!(
            ev,
            TransportEvent::Event {
                session: Some(SessionId::from("S1")),
                method: "Page.loadEventFired".into(),
                params: json!({"t": 1}),
            }
        );

        let e = conn.send(None, "Fail", json!({})).await.unwrap_err();
        assert_eq!(e.to_string(), "Protocol error (Fail): No way");

        let hung = tokio::spawn({
            let conn = conn.clone();
            async move { conn.send(None, "Hang", json!({})).await }
        });
        let quit = conn.send(None, "Quit", json!({})).await.unwrap_err();
        assert!(quit.is_closed(), "{quit}");
        assert!(hung.await.unwrap().unwrap_err().is_closed());
        let end = tokio::time::timeout(Duration::from_secs(5), events.recv()).await.unwrap().unwrap();
        assert_eq!(end, TransportEvent::Closed("Pipe closed".into()));
        assert!(conn.is_closed());
        assert!(conn.send(None, "After", json!({})).await.unwrap_err().is_closed());
    }
}
