//! Integration tests for high availability and failover.

use std::sync::Arc;
use std::time::Duration;

use avon_integration_tests::setup::*;

#[tokio::test]
async fn test_control_plane_failover() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;

    assert!(agent.is_connected().await, "Agent should be connected initially");

    agent.disconnect().await;
    assert!(!agent.is_connected().await, "Agent should be disconnected");

    tokio::time::sleep(Duration::from_millis(500)).await;

    agent.reconnect().await.expect("Reconnection should succeed");
    assert!(agent.is_connected().await, "Agent should reconnect");
}

#[tokio::test]
async fn test_reconnection_preserves_state() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;
    let device_id = agent.device_id().clone();

    agent.disconnect().await;
    agent.reconnect().await.expect("Reconnection should succeed");

    let device = get_device(&env, &device_id).await;
    assert!(device.is_some(), "Device state should be preserved");
    assert_eq!(device.unwrap().status, "active");
}

#[tokio::test]
async fn test_multiple_reconnections() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;

    for i in 0..5 {
        agent.disconnect().await;
        assert!(!agent.is_connected().await, "Should be disconnected on iteration {}", i);

        tokio::time::sleep(Duration::from_millis(50)).await;

        agent.reconnect().await.expect(&format!("Reconnection {} should succeed", i));
        assert!(agent.is_connected().await, "Should be connected after reconnection {}", i);
    }

    assert!(agent.authenticate().await.is_ok(), "Should authenticate after multiple reconnections");
}

#[tokio::test]
async fn test_tunnel_survives_brief_disconnect() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;
    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let session_id = agent_a.connect_to(agent_b.device_id().clone()).await
        .expect("Connection should succeed");

    assert!(agent_a.has_tunnel(&session_id).await, "Tunnel should exist");

    agent_a.disconnect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    agent_a.reconnect().await.expect("Reconnection should succeed");

    assert!(agent_a.has_tunnel(&session_id).await, "Tunnel should survive brief disconnect");
}

#[tokio::test]
async fn test_concurrent_agents_reconnection() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agents: Vec<_> = futures::future::join_all(
        (0..5).map(|i| {
            let env = env.clone();
            async move {
                create_enrolled_agent(env, &format!("agent-{}", i)).await
            }
        })
    ).await;

    for agent in &agents {
        agent.disconnect().await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let reconnect_futures: Vec<_> = agents.iter()
        .map(|agent| agent.reconnect())
        .collect();

    let results = futures::future::join_all(reconnect_futures).await;

    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Agent {} should reconnect successfully", i);
    }

    for agent in &agents {
        assert!(agent.is_connected().await, "All agents should be connected");
    }
}

#[tokio::test]
async fn test_authentication_after_reconnect() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;

    assert!(agent.authenticate().await.is_ok(), "Initial auth should succeed");

    agent.disconnect().await;
    agent.reconnect().await.expect("Reconnection should succeed");

    assert!(agent.authenticate().await.is_ok(), "Auth after reconnect should succeed");
}
