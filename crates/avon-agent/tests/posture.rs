#![allow(clippy::unwrap_used)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use avon_agent::platform::posture::PostureCollector;
use avon_keystore::ProviderKind;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn collection_completes_quickly_and_reports_the_provider() {
    let c = PostureCollector::new(Duration::from_secs(60));
    let start = std::time::Instant::now();
    let p = c.collect(ProviderKind::Software).await;
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "posture probes must not stall the agent"
    );
    assert!(!p.os_name.is_empty());
    assert!(p.collected_at_unix >= now() - 5);
}

#[tokio::test]
async fn last_update_is_never_the_current_time() {
    let p = PostureCollector::new(Duration::from_secs(60))
        .collect(ProviderKind::Software)
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
    let c = PostureCollector::new(Duration::from_secs(300));
    let first = c.collect(ProviderKind::Software).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = c.collect(ProviderKind::Software).await;
    assert_eq!(
        first.collected_at_unix, second.collected_at_unix,
        "the TTL must prevent re-probing"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_reports_none_when_the_sources_are_absent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("proc")).unwrap();
    std::fs::write(root.path().join("proc/mounts"), "").unwrap();
    std::env::set_var("AVON_TEST_FAKE_ROOT", root.path());
    let p = PostureCollector::new(Duration::from_millis(1))
        .collect(ProviderKind::Software)
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
    let p = PostureCollector::new(Duration::from_millis(1))
        .collect(ProviderKind::Software)
        .await;
    std::env::remove_var("AVON_TEST_FAKE_ROOT");
    assert_eq!(p.disk_encrypted, Some(true));
}
