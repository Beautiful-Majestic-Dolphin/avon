use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::protocol::{HelperRequest, HelperResponse};

pub struct HelperClient {
    stream: BufReader<UnixStream>,
}

impl HelperClient {
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await.context("connect helper")?;
        Ok(Self {
            stream: BufReader::new(stream),
        })
    }

    pub async fn request(&mut self, req: HelperRequest) -> Result<HelperResponse> {
        let line = serde_json::to_string(&req)? + "\n";
        self.stream.get_mut().write_all(line.as_bytes()).await?;
        self.stream.get_mut().flush().await?;
        let mut buf = String::new();
        self.stream.read_line(&mut buf).await?;
        if buf.len() > super::protocol::MAX_LINE_BYTES {
            anyhow::bail!("helper response too large");
        }
        let resp: HelperResponse = serde_json::from_str(buf.trim())?;
        Ok(resp)
    }
}
