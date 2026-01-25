//! Integration tests for token rotation.

use std::sync::Arc;
use std::time::Duration;

use avon_integration_tests::setup::*;

#[tokio::test]
async fn test_token_rotation() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;

    let initial_token = agent.current_token().await;

    agent.rotate_token().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let new_token = agent.current_token().await;
    assert_ne!(initial_token, new_token, "Token should have changed after rotation");

    assert!(agent.authenticate().await.is_ok(), "Agent should still authenticate after rotation");
}

#[tokio::test]
async fn test_multiple_rotations() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;

    let mut previous_token = agent.current_token().await;

    for i in 0..5 {
        agent.rotate_token().await;
        let current_token = agent.current_token().await;
        assert_ne!(previous_token, current_token, "Token {} should be different", i);
        previous_token = current_token;
    }

    assert!(agent.authenticate().await.is_ok(), "Agent should authenticate after multiple rotations");
}

#[tokio::test]
async fn test_rotation_preserves_tunnels() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;
    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let session_id = agent_a.connect_to(agent_b.device_id().clone()).await
        .expect("Connection should succeed");

    assert!(agent_a.has_tunnel(&session_id).await, "Tunnel should exist before rotation");

    agent_a.rotate_token().await;

    assert!(agent_a.has_tunnel(&session_id).await, "Tunnel should persist after rotation");
}

#[tokio::test]
async fn test_concurrent_rotation() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent1 = create_enrolled_agent(env.clone(), "agent-1").await;
    let agent2 = create_enrolled_agent(env.clone(), "agent-2").await;
    let agent3 = create_enrolled_agent(env.clone(), "agent-3").await;

    let initial1 = agent1.current_token().await;
    let initial2 = agent2.current_token().await;
    let initial3 = agent3.current_token().await;

    let (r1, r2, r3) = tokio::join!(
        async { agent1.rotate_token().await; agent1.current_token().await },
        async { agent2.rotate_token().await; agent2.current_token().await },
        async { agent3.rotate_token().await; agent3.current_token().await },
    );

    assert_ne!(initial1, r1, "Agent 1 token should change");
    assert_ne!(initial2, r2, "Agent 2 token should change");
    assert_ne!(initial3, r3, "Agent 3 token should change");

    assert!(agent1.authenticate().await.is_ok());
    assert!(agent2.authenticate().await.is_ok());
    assert!(agent3.authenticate().await.is_ok());
}

#[tokio::test]
async fn test_rotation_token_uniqueness() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent = create_enrolled_agent(env.clone(), "test-agent").await;

    let mut tokens = Vec::new();
    tokens.push(agent.current_token().await);

    for _ in 0..10 {
        agent.rotate_token().await;
        tokens.push(agent.current_token().await);
    }

    for i in 0..tokens.len() {
        for j in (i + 1)..tokens.len() {
            assert_ne!(tokens[i], tokens[j], "All tokens should be unique");
        }
    }
}
