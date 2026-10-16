// Test adapter only. The runner supplies the pinned upstream WebSocket module.
#[path = "../websocket.rs"]
mod websocket;

use websocket::{Message, Reader, Writer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
        let mut reader = Reader::new(tokio::io::stdin(), 1024 * 1024);
        let mut writer = Writer::new(tokio::io::stdout());
        while let Some(message) = reader.next().await? {
            match message {
                Message::Text(text) => writer.text(&text).await?,
                Message::Binary(data) => writer.binary(&data).await?,
                Message::Ping(data) => writer.pong(&data).await?,
                Message::Pong(_) => {},
                Message::Close(_) => { writer.close(Some((1000, "done"))).await?; break; }
            }
        }
        writer.shutdown().await?;
        Ok(())
    })
}
