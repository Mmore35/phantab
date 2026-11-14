//! The WebSocket wire under a [`Connection`]: [`Browser::connect`](crate::Browser::connect) to a running
//! browser, and a launch that asks for `--remote-debugging-port` (lanes that need a port of their own).

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::CdpError;
use crate::connection::{Connection, MAX_MESSAGE, Outgoing};

impl Connection {
    /// Connects to a browser (or page) devtools WebSocket URL.
    pub async fn connect(ws_url: &str) -> Result<Connection, CdpError> {
        let config =
            WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
        let (stream, _) = tokio_tungstenite::connect_async_with_config(ws_url, Some(config), true)
            .await
            .map_err(|e| CdpError::Other(format!("WebSocket connect to {ws_url} failed: {e}")))?;
        let (mut sink, mut source) = stream.split();
        let (conn, mut out_rx, feed) = Connection::new(Some(ws_url.to_owned()));

        let writer_feed = feed.clone();
        tokio::spawn(async move {
            while let Some(m) = out_rx.recv().await {
                let (m, is_close) = match m {
                    Outgoing::Text(t) => (Message::text(t), false),
                    Outgoing::Close => (Message::Close(None), true),
                };
                if let Err(e) = sink.send(m).await {
                    writer_feed.end(&format!("WebSocket write failed: {e}"));
                    return;
                }
                if is_close {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        tokio::spawn(async move {
            let reason = loop {
                let text = match source.next().await {
                    Some(Ok(Message::Text(t))) => t.as_str().to_owned(),
                    Some(Ok(Message::Binary(b))) => String::from_utf8_lossy(&b).into_owned(),
                    Some(Ok(Message::Close(frame))) => {
                        break frame.map_or_else(
                            || "WebSocket closed".to_owned(),
                            |f| format!("WebSocket closed: {}", f.reason.as_str()),
                        );
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => break format!("WebSocket error: {e}"),
                    None => break "WebSocket closed".to_owned(),
                };
                if !feed.deliver(&text) {
                    return;
                }
            };
            feed.end(&reason);
        });
        Ok(conn)
    }
}
