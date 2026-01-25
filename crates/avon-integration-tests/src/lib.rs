//! AVON Integration Test Library
//!
//! This crate provides test infrastructure and utilities for integration testing
//! the AVON platform. It includes:
//!
//! - Test environment setup with PostgreSQL and Redis containers
//! - Mock control plane services
//! - Test agent creation and management
//! - Helper functions for common test scenarios
//!
//! # Usage
//!
//! ```ignore
//! use avon_integration_tests::setup::*;
//!
//! #[tokio::test]
//! async fn test_example() {
//!     let env = TestEnvironment::new().await.unwrap();
//!     let agent = create_enrolled_agent(env.clone(), "test-agent").await;
//!     // ... test logic
//! }
//! ```

pub mod setup;

pub use setup::*;
