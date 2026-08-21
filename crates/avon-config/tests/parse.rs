#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::net::SocketAddr;

use avon_config::{
    ConfigError, DatabaseArgs, LogFormat, ObservabilityArgs, RedisArgs, TlsArgs, Validate,
};
use clap::Parser;

#[derive(Parser, Debug)]
struct TestCli {
    #[command(flatten)]
    db: DatabaseArgs,
    #[command(flatten)]
    redis: RedisArgs,
    #[command(flatten)]
    obs: ObservabilityArgs,
}

#[derive(Parser, Debug)]
struct TlsCli {
    #[command(flatten)]
    tls: TlsArgs,
}

#[test]
fn parses_from_flags() {
    let cli = TestCli::try_parse_from([
        "svc",
        "--database-url",
        "postgres://u:p@db:5432/avon?sslmode=verify-full",
        "--redis-url",
        "rediss://redis:6379/0",
    ])
    .unwrap();
    assert_eq!(cli.db.max_connections, 10);
    assert!(cli.db.require_tls);
    assert_eq!(cli.obs.log_level, "info");
    assert_eq!(cli.obs.log_format, LogFormat::Json);
    assert_eq!(
        cli.obs.metrics_addr,
        "0.0.0.0:9090".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        cli.obs.health_addr,
        "0.0.0.0:8080".parse::<SocketAddr>().unwrap()
    );
    cli.db.validate().unwrap();
    cli.redis.validate().unwrap();
    cli.obs.validate().unwrap();
}

#[test]
fn database_url_is_required() {
    let err = TestCli::try_parse_from(["svc", "--redis-url", "rediss://r/0"]).unwrap_err();
    assert!(err.to_string().contains("--database-url"), "{err}");
}

#[test]
fn rejects_non_postgres_scheme() {
    let cli = TestCli::try_parse_from([
        "svc",
        "--database-url",
        "mysql://x/y",
        "--redis-url",
        "rediss://r/0",
    ])
    .unwrap();
    let err = cli.db.validate().unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::Invalid {
                field: "database-url",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn require_tls_rejects_plain_redis_url() {
    let cli = TestCli::try_parse_from([
        "svc",
        "--database-url",
        "postgres://x/y",
        "--redis-url",
        "redis://r/0",
    ])
    .unwrap();
    let err = cli.redis.validate().unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::Invalid {
                field: "redis-url",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn redis_plain_allowed_when_tls_not_required() {
    let cli = TestCli::try_parse_from([
        "svc",
        "--database-url",
        "postgres://x/y",
        "--redis-url",
        "redis://r/0",
        "--redis-require-tls=false",
    ])
    .unwrap();
    cli.redis.validate().unwrap();
}

#[test]
fn tls_files_must_exist() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let ca = dir.path().join("ca.pem");
    std::fs::write(&cert, "x").unwrap();
    std::fs::write(&key, "x").unwrap();
    let cli = TlsCli::try_parse_from([
        "svc",
        "--tls-cert",
        cert.to_str().unwrap(),
        "--tls-key",
        key.to_str().unwrap(),
        "--tls-ca",
        ca.to_str().unwrap(),
    ])
    .unwrap();
    let err = cli.tls.validate().unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::MissingFile {
                field: "tls-ca",
                ..
            }
        ),
        "{err:?}"
    );
    std::fs::write(&ca, "x").unwrap();
    cli.tls.validate().unwrap();
}

#[test]
fn log_level_must_be_a_valid_filter() {
    let cli = TestCli::try_parse_from([
        "svc",
        "--database-url",
        "postgres://x/y",
        "--redis-url",
        "rediss://r/0",
        "--log-level",
        "loud",
    ])
    .unwrap();
    assert!(cli.obs.validate().is_err());
}
