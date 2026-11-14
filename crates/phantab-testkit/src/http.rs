//! Just enough HTTP/1.1 for fixture pages: one request per connection, then close.

use std::fmt::Write as _;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The request line plus headers may not exceed this.
pub const HEAD_LIMIT: usize = 64 * 1024;
/// A request body may not exceed this.
pub const BODY_LIMIT: usize = 1024 * 1024;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// The target before `?`, still percent-encoded.
    pub path: String,
    /// The target after `?`, without it; empty when there is none.
    pub query: String,
    /// Header names lower-cased, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum ReadError {
    /// The peer closed before sending a request (a speculative connection).
    Closed,
    /// Answer with this status and close.
    Reject(u16, &'static str),
    /// The connection failed; nothing can be answered.
    Io,
}

impl From<io::Error> for ReadError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub async fn read_request(stream: &mut (impl AsyncRead + Unpin)) -> Result<Request, ReadError> {
    let mut buf = Vec::with_capacity(4096);
    let head_end = loop {
        if let Some(at) = find(&buf, b"\r\n\r\n") {
            break at;
        }
        if buf.len() > HEAD_LIMIT {
            return Err(ReadError::Reject(431, "request head too large"));
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(if buf.is_empty() {
                ReadError::Closed
            } else {
                ReadError::Reject(400, "request ended inside its head")
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec())
        .map_err(|_| ReadError::Reject(400, "head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(ReadError::Reject(400, "bad request line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(ReadError::Reject(505, "only HTTP/1.x"));
    }
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(ReadError::Reject(400, "bad header line"));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    if header("transfer-encoding").is_some_and(|v| !v.eq_ignore_ascii_case("identity")) {
        return Err(ReadError::Reject(501, "chunked request bodies are not supported"));
    }
    let length = match header("content-length") {
        None => 0,
        Some(v) => v.parse::<usize>().map_err(|_| ReadError::Reject(400, "bad content-length"))?,
    };
    if length > BODY_LIMIT {
        return Err(ReadError::Reject(413, "request body too large"));
    }
    let mut body = buf.split_off(head_end + 4);
    if body.len() < length {
        let have = body.len();
        body.resize(length, 0);
        stream.read_exact(&mut body[have..]).await?;
    }
    body.truncate(length);
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target.to_owned(), String::new()),
    };
    // A fragment never reaches a server, but a hand-written client might send one.
    let path = path.split('#').next().unwrap_or_default().to_owned();
    Ok(Request { method: method.to_owned(), path, query, headers, body })
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "text/html; charset=utf-8".to_owned())],
            body: body.into().into_bytes(),
        }
    }

    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "text/plain; charset=utf-8".to_owned())],
            body: body.into().into_bytes(),
        }
    }

    pub fn redirect(status: u16, to: &str) -> Self {
        Self { status, headers: vec![("Location", to.to_owned())], body: Vec::new() }
    }

    pub async fn write(&self, stream: &mut (impl AsyncWrite + Unpin), head_only: bool) -> io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (name, value) in &self.headers {
            let _ = write!(head, "{name}: {value}\r\n");
        }
        let _ = write!(
            head,
            "Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
            self.body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        if !head_only {
            stream.write_all(&self.body).await?;
        }
        stream.flush().await
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Percent-decodes `s`. With `plus_is_space`, `+` reads as a space (form and query encoding).
/// Invalid escapes stay as written; invalid UTF-8 is replaced.
pub fn percent_decode(s: &str, plus_is_space: bool) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' if plus_is_space => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Splits `a=1&b=2` into decoded pairs, the way `URLSearchParams` reads a query or form body.
pub fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode(name, true), percent_decode(value, true))
        })
        .collect()
}

/// Escapes text for an HTML text node or a quoted attribute.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        assert_eq!(percent_decode("a%20b+c", false), "a b+c");
        assert_eq!(percent_decode("a%20b+c", true), "a b c");
        assert_eq!(percent_decode("100%", true), "100%");
        assert_eq!(percent_decode("%zz%4", true), "%zz%4");
        assert_eq!(percent_decode("%C3%A9", false), "é");
    }

    #[test]
    fn splits_forms() {
        assert_eq!(
            form_pairs("user=a%40b.test&pass=S3ntinel+pw%2B%2F%3D%21&flag"),
            vec![
                ("user".to_owned(), "a@b.test".to_owned()),
                ("pass".to_owned(), "S3ntinel pw+/=!".to_owned()),
                ("flag".to_owned(), String::new())
            ]
        );
    }

    #[test]
    fn escapes() {
        assert_eq!(html_escape(r#"<a href="x">&'"#), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }

    #[tokio::test]
    async fn reads_a_post() {
        let raw = b"POST /post/ok?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
        let req = read_request(&mut &raw[..]).await.unwrap();
        assert_eq!((req.method.as_str(), req.path.as_str(), req.query.as_str()), ("POST", "/post/ok", "x=1"));
        assert_eq!(req.body, b"hello");
        assert_eq!(req.headers[0], ("host".to_owned(), "a".to_owned()));
    }

    #[tokio::test]
    async fn refuses_chunked_and_oversized() {
        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(read_request(&mut &chunked[..]).await, Err(ReadError::Reject(501, _))));
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", BODY_LIMIT + 1);
        assert!(matches!(read_request(&mut big.as_bytes()).await, Err(ReadError::Reject(413, _))));
        assert!(matches!(read_request(&mut &b""[..]).await, Err(ReadError::Closed)));
    }
}
