//! Integration tests for device enrollment flow.

use std::sync::Arc;

use avon_integration_tests::setup::*;

#[tokio::test]
async fn test_device_enrollment_flow() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let enrollment = create_enrollment(&env, "test-device", "linux").await;

    let agent = create_test_agent(env.clone()).await;
    agent.enroll(&enrollment.token).await.expect("Enrollment should succeed");

    let device = get_device(&env, agent.device_id()).await;
    assert!(device.is_some(), "Device should be registered");
    assert_eq!(device.unwrap().status, "active");

    let auth_result = agent.authenticate().await;
    assert!(auth_result.is_ok(), "Agent should be able to authenticate");
}

#[tokio::test]
async fn test_enrollment_with_invalid_token() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_test_agent(env.clone()).await;
    let result = agent.enroll("invalid-token").await;

    assert!(result.is_err(), "Enrollment with invalid token should fail");
    assert!(matches!(result.unwrap_err(), ConnectionError::NotEnrolled));
}

#[tokio::test]
async fn test_enrollment_token_consumed() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let enrollment = create_enrollment(&env, "test-device", "linux").await;

    let agent1 = create_test_agent(env.clone()).await;
    agent1.enroll(&enrollment.token).await.expect("First enrollment should succeed");

    let agent2 = create_test_agent(env.clone()).await;
    let result = agent2.enroll(&enrollment.token).await;

    assert!(result.is_err(), "Second enrollment with same token should fail");
}

#[tokio::test]
async fn test_multiple_device_enrollment() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let enrollment1 = create_enrollment(&env, "device-1", "linux").await;
    let enrollment2 = create_enrollment(&env, "device-2", "windows").await;
    let enrollment3 = create_enrollment(&env, "device-3", "macos").await;

    let agent1 = create_test_agent(env.clone()).await;
    let agent2 = create_test_agent(env.clone()).await;
    let agent3 = create_test_agent(env.clone()).await;

    agent1.enroll(&enrollment1.token).await.expect("Enrollment 1 should succeed");
    agent2.enroll(&enrollment2.token).await.expect("Enrollment 2 should succeed");
    agent3.enroll(&enrollment3.token).await.expect("Enrollment 3 should succeed");

    assert!(get_device(&env, agent1.device_id()).await.is_some());
    assert!(get_device(&env, agent2.device_id()).await.is_some());
    assert!(get_device(&env, agent3.device_id()).await.is_some());
}

#[tokio::test]
async fn test_unenrolled_agent_cannot_authenticate() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_test_agent(env.clone()).await;

    let result = agent.authenticate().await;
    assert!(result.is_err(), "Unenrolled agent should not authenticate");
}
