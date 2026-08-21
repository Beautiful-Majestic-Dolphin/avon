use std::net::{SocketAddr, TcpListener, UdpSocket};

/// Bind to port 0 and return the address the OS chose. The socket is closed
/// immediately; the port is free for the caller to bind.
pub fn free_udp_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind udp")
        .local_addr()
        .expect("local addr")
}

pub fn free_tcp_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind tcp")
        .local_addr()
        .expect("local addr")
}
