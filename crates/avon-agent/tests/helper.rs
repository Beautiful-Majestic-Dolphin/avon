#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
//! The helper is the only privileged part of the agent, so its IPC contract is
//! tested as an attack surface: names, routes and firewall scope are all
//! rejected before anything reaches the kernel, a stranger's uid never gets a
//! reply, and an oversized line closes the connection unparsed.

use std::time::Duration;

use avon_agent::helper::client::HelperClient;
use avon_agent::helper::protocol::{
    validate, validate_ifname, FirewallRules, HelperRequest, HelperState, ProtocolError,
    MAX_LINE_BYTES,
};
use avon_agent::helper::server;

fn state_with(allowed: &[&str]) -> HelperState {
    HelperState {
        tun_name: Some("avon0".into()),
        allowed_routes: allowed.iter().map(|c| c.parse().unwrap()).collect(),
    }
}

#[test]
fn interface_names_are_strictly_validated() {
    for good in ["avon", "avon0", "avon9", "avon42"] {
        validate_ifname(good).unwrap();
    }
    for bad in [
        "avon123",
        "eth0",
        "avon0 ",
        "../../dev/net/tun",
        "avon0;rm -rf /",
        "avon\u{0}1",
        "AVON0",
        "",
        "avon-x",
    ] {
        assert!(
            matches!(validate_ifname(bad), Err(ProtocolError::BadName(_))),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn routes_outside_the_allowed_set_are_rejected() {
    let st = state_with(&["100.64.0.0/10", "172.30.0.0/24"]);
    let ok = HelperRequest::SetRoutes {
        add: vec!["172.30.0.0/24".into(), "100.64.1.0/24".into()],
        remove: vec![],
    };
    validate(&ok, &st).unwrap();

    let default_route = HelperRequest::SetRoutes {
        add: vec!["0.0.0.0/0".into()],
        remove: vec![],
    };
    assert!(matches!(
        validate(&default_route, &st),
        Err(ProtocolError::RouteNotAllowed(_))
    ));

    let adjacent = HelperRequest::SetRoutes {
        add: vec!["172.30.1.0/24".into()],
        remove: vec![],
    };
    assert!(
        validate(&adjacent, &st).is_err(),
        "adjacent prefix outside the allowed set"
    );

    let not_a_cidr = HelperRequest::SetRoutes {
        add: vec!["172.30.0.0/24; ip route flush".into()],
        remove: vec![],
    };
    assert!(matches!(
        validate(&not_a_cidr, &st),
        Err(ProtocolError::BadCidr(_))
    ));

    let too_many = HelperRequest::SetRoutes {
        add: (0..2000)
            .map(|i| format!("100.64.{}.{}/32", i / 256, i % 256))
            .collect(),
        remove: vec![],
    };
    assert!(matches!(
        validate(&too_many, &st),
        Err(ProtocolError::TooManyRoutes(_))
    ));

    // Before Configure nothing is allowed.
    assert!(matches!(
        validate(&ok, &HelperState::default()),
        Err(ProtocolError::NotConfigured)
    ));
}

#[test]
fn firewall_rules_are_typed_and_scoped() {
    let st = state_with(&["172.30.0.0/24"]);
    let ok = HelperRequest::ApplyFirewall {
        rules: FirewallRules {
            allow_cidrs: vec!["172.30.0.0/24".into()],
            tun_name: "avon0".into(),
            block_default: false,
        },
    };
    validate(&ok, &st).unwrap();

    let wrong_tun = HelperRequest::ApplyFirewall {
        rules: FirewallRules {
            allow_cidrs: vec!["172.30.0.0/24".into()],
            tun_name: "eth0".into(),
            block_default: false,
        },
    };
    assert!(validate(&wrong_tun, &st).is_err());

    let other_tun = HelperRequest::ApplyFirewall {
        rules: FirewallRules {
            allow_cidrs: vec!["172.30.0.0/24".into()],
            tun_name: "avon1".into(),
            block_default: false,
        },
    };
    assert!(
        validate(&other_tun, &st).is_err(),
        "a valid name the helper did not create is still refused"
    );

    let out_of_scope = HelperRequest::ApplyFirewall {
        rules: FirewallRules {
            allow_cidrs: vec!["10.0.0.0/8".into()],
            tun_name: "avon0".into(),
            block_default: false,
        },
    };
    assert!(matches!(
        validate(&out_of_scope, &st),
        Err(ProtocolError::RouteNotAllowed(_))
    ));

    // Raw rule text can never be smuggled in: unknown fields are a parse error.
    let smuggled = r#"{"op":"apply_firewall","rules":{"allow_cidrs":[],"tun_name":"avon0","block_default":false,"raw":"flush ruleset"}}"#;
    assert!(serde_json::from_str::<HelperRequest>(smuggled).is_err());
}

#[test]
fn mtu_is_bounded_on_create() {
    let st = HelperState::default();
    validate(
        &HelperRequest::CreateTun {
            name: "avon0".into(),
            mtu: 1280,
        },
        &st,
    )
    .unwrap();
    for bad in [0u16, 575, 9001] {
        assert!(matches!(
            validate(
                &HelperRequest::CreateTun {
                    name: "avon0".into(),
                    mtu: bad
                },
                &st
            ),
            Err(ProtocolError::BadMtu(_))
        ));
    }
}

#[tokio::test]
async fn peer_uid_mismatch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("helper.sock");
    let me = nix::unistd::geteuid().as_raw();
    if me == 0 {
        eprintln!("skipping: peer-uid mismatch test needs a non-root euid");
        return;
    }
    let s = sock.clone();
    // Serve for a uid we are not.
    let srv = tokio::spawn(async move { server::serve(&s, me + 1).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut c = HelperClient::connect(&sock).await.unwrap();
    let err = c.create_tun("avon0", 1280).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains("TunReady"),
        "no response may be served to a mismatched uid: {msg}"
    );
    srv.abort();
}

#[tokio::test]
async fn oversized_requests_close_the_connection_without_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("helper.sock");
    let me = nix::unistd::geteuid().as_raw();
    let s = sock.clone();
    let srv = tokio::spawn(async move { server::serve(&s, me).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut raw = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let huge = vec![b'{'; MAX_LINE_BYTES + 1024]; // no newline, larger than the cap
    raw.write_all(&huge).await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
        .await
        .expect("server must hang up")
        .unwrap();
    assert_eq!(
        n, 0,
        "server must close (EOF), not answer, on an oversized request"
    );
    srv.abort();
}

#[tokio::test]
async fn invalid_requests_are_answered_with_an_error_and_the_session_survives() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("helper.sock");
    let me = nix::unistd::geteuid().as_raw();
    let s = sock.clone();
    let srv = tokio::spawn(async move { server::serve(&s, me).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut c = HelperClient::connect(&sock).await.unwrap();
    // A route request before Configure is refused, but the connection stays up.
    let err = c
        .set_routes(&["10.0.0.0/8".parse().unwrap()], &[])
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("Configure") || err.to_string().contains("configure"),
        "unexpected error: {err}"
    );
    // And a name the helper will never create is refused too.
    let err = c.create_tun("eth0", 1280).await.unwrap_err();
    assert!(err.to_string().contains("eth0"), "unexpected error: {err}");
    srv.abort();
}

/// Child half of the fd-passing test below. Runs only when re-executed by the
/// parent with `AVON_HELPER_CHILD_SOCK` set (as uid 65534); a normal test run
/// returns immediately.
#[tokio::test]
async fn helper_fd_child() {
    let Ok(sock) = std::env::var("AVON_HELPER_CHILD_SOCK") else {
        return;
    };
    assert_ne!(
        nix::unistd::geteuid().as_raw(),
        0,
        "child must be unprivileged"
    );
    let mut c = HelperClient::connect(std::path::Path::new(&sock))
        .await
        .unwrap();
    let tun = c.create_tun("avon7", 1280).await.unwrap();
    c.configure(
        "100.127.7.1/30".parse().unwrap(),
        None,
        1280,
        &["100.127.7.0/30".parse().unwrap()],
    )
    .await
    .unwrap();

    let mut ping = tokio::process::Command::new("/bin/ping")
        .args(["-c", "1", "-W", "1", "100.127.7.2"])
        .spawn()
        .unwrap();
    // The interface generates IPv6 router/neighbour solicitations as it comes
    // up, so the ICMPv4 echo is not necessarily the first packet out.
    use avon_tunnel::PacketSource;
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no ICMPv4 packet arrived on the fd the helper created"
        );
        tokio::time::timeout_at(deadline, tun.next_packet(&mut buf))
            .await
            .expect("timed out waiting for a packet")
            .expect("read from the tun fd");
        if buf.first().map(|b| b >> 4) == Some(4) && buf.get(9) == Some(&1) {
            break;
        }
    }
    let _ = ping.kill().await;
}

#[tokio::test]
async fn helper_creates_tun_and_passes_fd_to_unprivileged_child() {
    if std::env::var("AVON_TEST_ROOT").ok().as_deref() != Some("1") {
        eprintln!("skipping: requires root (set AVON_TEST_ROOT=1 inside the e2e container)");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);
    let dir = tempfile::tempdir().unwrap();
    // uid 65534 (nobody) must be able to traverse to the socket.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let sock = dir.path().join("helper.sock");
    const NOBODY: u32 = 65534;
    let s = sock.clone();
    let srv = tokio::spawn(async move { server::serve(&s, NOBODY).await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let exe = std::env::current_exe().unwrap();
    let mut cmd = tokio::process::Command::new(exe);
    cmd.args(["helper_fd_child", "--exact", "--nocapture"])
        .env("AVON_HELPER_CHILD_SOCK", &sock)
        .uid(NOBODY)
        .gid(NOBODY);
    let status = tokio::time::timeout(Duration::from_secs(30), cmd.status())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.success(),
        "unprivileged child must receive the TUN fd and read a packet"
    );
    srv.abort();
}
