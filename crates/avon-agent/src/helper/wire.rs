//! Newline-delimited JSON over a Unix socket, with file descriptors riding
//! along as ancillary data.
//!
//! Both ends read through `recvmsg` rather than a `BufReader` for one reason:
//! the TUN descriptor arrives attached to the very line that announces it, and
//! a buffered reader would consume the payload without ever seeing the control
//! message. The read is capped so a peer cannot make either side allocate.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use tokio::io::Interest;
use tokio::net::UnixStream;

use super::protocol::{HelperError, ProtocolError, MAX_LINE_BYTES};

/// Read chunk size; the line cap is enforced on the accumulated buffer.
const CHUNK: usize = 8192;

pub struct Wire {
    stream: UnixStream,
    /// Bytes received but not yet consumed as a line.
    buf: Vec<u8>,
    /// Descriptors received with a line that has not been handed out yet.
    fds: Vec<OwnedFd>,
}

impl Wire {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            buf: Vec::with_capacity(CHUNK),
            fds: Vec::new(),
        }
    }

    /// The next line, plus any descriptors that arrived with it. `Ok(None)` is
    /// a clean EOF.
    pub async fn read_line(&mut self) -> Result<Option<(String, Vec<OwnedFd>)>, HelperError> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let rest = self.buf.split_off(pos + 1);
                let mut line = std::mem::replace(&mut self.buf, rest);
                line.pop(); // the newline
                let text = String::from_utf8(line)
                    .map_err(|_| HelperError::Protocol("request is not utf-8".into()))?;
                return Ok(Some((text, std::mem::take(&mut self.fds))));
            }
            if self.buf.len() > MAX_LINE_BYTES {
                return Err(ProtocolError::Oversized(self.buf.len()).into());
            }
            // `async_io` retries on EWOULDBLOCK *and* clears the readiness it was
            // handed, which a bare `readable().await` does not: without it a
            // spurious wakeup spins the helper at 100% CPU.
            let raw = self.stream.as_raw_fd();
            let (n, chunk, fds) = self
                .stream
                .async_io(Interest::READABLE, || recv_chunk(raw))
                .await?;
            if n == 0 {
                return Ok(None);
            }
            self.fds.extend(fds);
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub async fn write_line(&mut self, line: &str) -> Result<(), HelperError> {
        self.send(line, None).await
    }

    /// Write a line with `fd` attached as `SCM_RIGHTS`.
    pub async fn write_line_with_fd(&mut self, line: &str, fd: RawFd) -> Result<(), HelperError> {
        self.send(line, Some(fd)).await
    }

    async fn send(&mut self, line: &str, fd: Option<RawFd>) -> Result<(), HelperError> {
        let mut payload = line.as_bytes().to_vec();
        payload.push(b'\n');
        let mut sent = 0usize;
        while sent < payload.len() {
            // The descriptor rides with the first write only.
            let attach = fd.filter(|_| sent == 0);
            let raw = self.stream.as_raw_fd();
            let chunk = &payload[sent..];
            let n = self
                .stream
                .async_io(Interest::WRITABLE, || send_chunk(raw, chunk, attach))
                .await?;
            sent += n;
        }
        Ok(())
    }
}

/// One `recvmsg`, returning the bytes read, the buffer and any descriptors that
/// came with them. A free function so it can be handed to `async_io`, which owns
/// the readiness bookkeeping.
fn recv_chunk(fd: RawFd) -> std::io::Result<(usize, [u8; CHUNK], Vec<OwnedFd>)> {
    let mut chunk = [0u8; CHUNK];
    let mut cmsg = nix::cmsg_space!([RawFd; 2]);
    let mut fds: Vec<OwnedFd> = Vec::new();
    let n;
    {
        let mut iov = [IoSliceMut::new(&mut chunk)];
        let msg = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
            .map_err(std::io::Error::from)?;
        n = msg.bytes;
        if let Ok(cmsgs) = msg.cmsgs() {
            for c in cmsgs {
                if let ControlMessageOwned::ScmRights(raw) = c {
                    // SAFETY: the kernel just installed these descriptors in this
                    // process; nothing else owns them.
                    fds.extend(raw.into_iter().map(|f| unsafe { OwnedFd::from_raw_fd(f) }));
                }
            }
        }
    }
    Ok((n, chunk, fds))
}

fn send_chunk(fd: RawFd, payload: &[u8], attach: Option<RawFd>) -> std::io::Result<usize> {
    let iov = [IoSlice::new(payload)];
    let attached = attach.map(|f| [f]);
    let cmsgs: Vec<ControlMessage> = attached
        .as_ref()
        .map(|f| vec![ControlMessage::ScmRights(f)])
        .unwrap_or_default();
    sendmsg::<()>(fd, &iov, &cmsgs, MsgFlags::empty(), None).map_err(std::io::Error::from)
}
