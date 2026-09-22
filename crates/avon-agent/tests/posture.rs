#![allow(clippy::unwrap_used, clippy::panic)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use avon_agent::platform::posture::{Posture, PostureCollector};
use avon_agent_core::traits::PostureProvider;
use avon_keystore::ProviderKind;

// The Linux probes read under AVON_TEST_FAKE_ROOT, which is process-wide
// state, and cargo runs these tests on parallel threads. One test removing
// the variable while another is mid-collect sends the latter to the real
// /proc, which is how the LUKS test came back None on CI. Every test that
// collects holds this lock for its whole body.
static ENV: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn collection_completes_quickly_and_reports_the_provider() {
    let _env = ENV.lock().await;
    let c = PostureCollector::new(Duration::from_secs(60), ProviderKind::Tpm2);
    let start = std::time::Instant::now();
    let p = c.collect().await;
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "posture probes must not stall the agent"
    );
    assert!(!p.os_name.is_empty());
    assert!(p.collected_at_unix >= now() - 5);
    assert_eq!(
        p.key_provider, "tpm2",
        "the posture must name the provider holding the device key"
    );
    assert_eq!(p.agent_version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn last_update_is_never_the_current_time() {
    let _env = ENV.lock().await;
    let p = PostureCollector::new(Duration::from_secs(60), ProviderKind::Software)
        .collect()
        .await;
    if let Some(ts) = p.last_update_unix {
        assert!(
            ts < now() - 60,
            "last_update_unix looks fabricated: {ts} vs now {}",
            now()
        );
    }
}

#[tokio::test]
async fn results_are_cached_within_the_ttl() {
    let _env = ENV.lock().await;
    let c = PostureCollector::new(Duration::from_secs(300), ProviderKind::Software);
    let first = c.collect().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = c.collect().await;
    assert_eq!(
        first.collected_at_unix, second.collected_at_unix,
        "the TTL must prevent re-probing"
    );
}

/// The regression this change exists for: the pulse loop reaches posture
/// through `PostureProvider`, and that path used to build a fresh struct with
/// every signal hardcoded to `None`, discarding whatever had been probed.
#[tokio::test]
async fn the_trait_reports_what_the_collector_probed() {
    let _env = ENV.lock().await;
    let c = PostureCollector::new(Duration::from_secs(300), ProviderKind::Tpm2);
    let direct = c.collect().await;
    let through_trait = PostureProvider::collect(&c).await;
    assert_eq!(
        direct, through_trait,
        "the pulse path must send what the collector probed, not a default"
    );
    assert_eq!(through_trait.key_provider, "tpm2");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_reports_none_when_the_sources_are_absent() {
    let _env = ENV.lock().await;
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("proc")).unwrap();
    std::fs::write(root.path().join("proc/mounts"), "").unwrap();
    std::env::set_var("AVON_TEST_FAKE_ROOT", root.path());
    let p = PostureCollector::new(Duration::from_millis(1), ProviderKind::Software)
        .collect()
        .await;
    std::env::remove_var("AVON_TEST_FAKE_ROOT");
    assert_eq!(
        p.disk_encrypted, None,
        "an empty /proc/mounts must not imply an unencrypted disk"
    );
    assert_eq!(p.last_update_unix, None);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_detects_a_luks_root_from_the_injected_root() {
    let _env = ENV.lock().await;
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("proc")).unwrap();
    std::fs::create_dir_all(root.path().join("sys/class/block/dm-0/dm")).unwrap();
    std::fs::write(
        root.path().join("proc/mounts"),
        "/dev/mapper/root / ext4 rw,relatime 0 0\n",
    )
    .unwrap();
    std::fs::write(root.path().join("sys/class/block/dm-0/dm/name"), "root\n").unwrap();
    std::fs::write(
        root.path().join("sys/class/block/dm-0/dm/uuid"),
        "CRYPT-LUKS2-abc-root\n",
    )
    .unwrap();
    std::env::set_var("AVON_TEST_FAKE_ROOT", root.path());
    let p = PostureCollector::new(Duration::from_millis(1), ProviderKind::Software)
        .collect()
        .await;
    std::env::remove_var("AVON_TEST_FAKE_ROOT");
    assert_eq!(p.disk_encrypted, Some(true));
}

/// A probed signal must survive the trait boundary, not just the inherent
/// call: this is the path a posture-conditioned policy actually depends on.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_luks_reaches_the_wire_through_the_trait() {
    let _env = ENV.lock().await;
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("proc")).unwrap();
    std::fs::create_dir_all(root.path().join("sys/class/block/dm-0/dm")).unwrap();
    std::fs::write(
        root.path().join("proc/mounts"),
        "/dev/mapper/root / ext4 rw,relatime 0 0\n",
    )
    .unwrap();
    std::fs::write(root.path().join("sys/class/block/dm-0/dm/name"), "root\n").unwrap();
    std::fs::write(
        root.path().join("sys/class/block/dm-0/dm/uuid"),
        "CRYPT-LUKS2-abc-root\n",
    )
    .unwrap();
    std::env::set_var("AVON_TEST_FAKE_ROOT", root.path());
    let c = PostureCollector::new(Duration::from_millis(1), ProviderKind::Software);
    let p = PostureProvider::collect(&c).await;
    std::env::remove_var("AVON_TEST_FAKE_ROOT");
    assert_eq!(p.disk_encrypted, Some(true));
}

// How many times `flaky_probe` should panic before it starts answering. Shared
// between tests, so every test that uses it holds `ENV` like the others.
static PANICS_LEFT: AtomicUsize = AtomicUsize::new(0);

fn flaky_probe() -> Posture {
    let will_panic = PANICS_LEFT
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
        .is_ok();
    if will_panic {
        panic!("the probe blew up");
    }
    Posture {
        os_name: "probed".into(),
        os_version: "1".into(),
        ..Posture::default()
    }
}

/// A probe that panics must not turn into a posture with a blank OS name on
/// the wire; the trait path used to carry `std::env::consts::OS` at minimum.
#[tokio::test]
async fn a_panicking_probe_falls_back_to_the_os_name() {
    let _env = ENV.lock().await;
    PANICS_LEFT.store(1, Ordering::SeqCst);
    let c = PostureCollector::with_probe(
        Duration::from_secs(300),
        ProviderKind::Software,
        flaky_probe,
    );
    let p = c.collect().await;
    assert_eq!(p.os_name, std::env::consts::OS);
    assert_eq!(p.key_provider, "software");
    assert_eq!(p.agent_version, env!("CARGO_PKG_VERSION"));
}

/// The fallback is a stand-in for one pulse, not something to serve for the
/// whole TTL: the next collect must probe again.
#[tokio::test]
async fn a_panicking_probe_is_not_cached() {
    let _env = ENV.lock().await;
    PANICS_LEFT.store(1, Ordering::SeqCst);
    let c = PostureCollector::with_probe(
        Duration::from_secs(300),
        ProviderKind::Software,
        flaky_probe,
    );
    let _ = c.collect().await;
    let second = c.collect().await;
    assert_eq!(
        second.os_name, "probed",
        "the fallback must not occupy the cache"
    );
}
