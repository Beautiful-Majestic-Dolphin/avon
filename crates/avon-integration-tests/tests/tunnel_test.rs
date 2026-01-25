//! Integration tests for tunnel establishment.

use std::sync::Arc;

use avon_integration_tests::setup::*;

#[tokio::test]
async fn test_tunnel_establishment() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;
    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let session_id = agent_a.connect_to(agent_b.device_id().clone()).await
        .expect("Connection should succeed");

    assert!(agent_a.has_tunnel(&session_id).await, "Agent A should have tunnel");
}

#[tokio::test]
async fn test_tunnel_data_transfer() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;
    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let session_id = agent_a.connect_to(agent_b.device_id().clone()).await
        .expect("Connection should succeed");

    let test_data = b"Hello, AVON!";
    agent_a.send_through_tunnel(&session_id, test_data).await
        .expect("Send should succeed");
}

#[tokio::test]
async fn test_tunnel_without_policy_fails() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;

    assert!(result.is_err(), "Connection without policy should fail");
    assert!(matches!(result.unwrap_err(), ConnectionError::PolicyDenied));
}

#[tokio::test]
async fn test_tunnel_to_nonexistent_peer() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "agent").await;
    let fake_device_id = avon_common::DeviceId::new();

    let result = agent.connect_to(fake_device_id).await;

    assert!(result.is_err(), "Connection to nonexistent peer should fail");
    assert!(matches!(result.unwrap_err(), ConnectionError::PeerNotFound));
}

#[tokio::test]
async fn test_multiple_tunnels() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;
    let agent_c = create_enrolled_agent(env.clone(), "agent-c").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_c.device_id(), &pod.id).await;
    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let session_ab = agent_a.connect_to(agent_b.device_id().clone()).await
        .expect("Connection A->B should succeed");
    let session_ac = agent_a.connect_to(agent_c.device_id().clone()).await
        .expect("Connection A->C should succeed");

    assert!(agent_a.has_tunnel(&session_ab).await);
    assert!(agent_a.has_tunnel(&session_ac).await);
    assert_ne!(session_ab, session_ac, "Sessions should be different");
}

#[tokio::test]
async fn test_bidirectional_tunnel() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;
    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let session_ab = agent_a.connect_to(agent_b.device_id().clone()).await
        .expect("Connection A->B should succeed");
    let session_ba = agent_b.connect_to(agent_a.device_id().clone()).await
        .expect("Connection B->A should succeed");

    assert!(agent_a.has_tunnel(&session_ab).await);
    assert!(agent_b.has_tunnel(&session_ba).await);
}
