//! Integration tests for policy enforcement.

use std::sync::Arc;

use avon_integration_tests::setup::*;

#[tokio::test]
async fn test_policy_deny() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod_a = create_pod(&env, "pod-a").await;
    let pod_b = create_pod(&env, "pod-b").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod_a.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod_b.id).await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ConnectionError::PolicyDenied));
}

#[tokio::test]
async fn test_policy_allow_same_pod() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "shared-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod.id).await;

    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result.is_ok(), "Connection within same pod with allow policy should succeed");
}

#[tokio::test]
async fn test_policy_allow_cross_pod() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod_a = create_pod(&env, "pod-a").await;
    let pod_b = create_pod(&env, "pod-b").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod_a.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod_b.id).await;

    create_policy(&env, &pod_a.id, &pod_b.id, "allow").await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result.is_ok(), "Connection with cross-pod allow policy should succeed");
}

#[tokio::test]
async fn test_policy_asymmetric() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod_a = create_pod(&env, "pod-a").await;
    let pod_b = create_pod(&env, "pod-b").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod_a.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod_b.id).await;

    create_policy(&env, &pod_a.id, &pod_b.id, "allow").await;

    let result_ab = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result_ab.is_ok(), "A->B should succeed with policy");

    let result_ba = agent_b.connect_to(agent_a.device_id().clone()).await;
    assert!(result_ba.is_err(), "B->A should fail without reverse policy");
}

#[tokio::test]
async fn test_device_in_multiple_pods() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod_engineering = create_pod(&env, "engineering").await;
    let pod_servers = create_pod(&env, "servers").await;
    let pod_admin = create_pod(&env, "admin").await;

    add_device_to_pod(&env, agent_a.device_id(), &pod_engineering.id).await;
    add_device_to_pod(&env, agent_a.device_id(), &pod_admin.id).await;
    add_device_to_pod(&env, agent_b.device_id(), &pod_servers.id).await;

    create_policy(&env, &pod_admin.id, &pod_servers.id, "allow").await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result.is_ok(), "Agent A (in admin pod) should connect to server");
}

#[tokio::test]
async fn test_no_policy_default_deny() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result.is_err(), "Default should be deny");
    assert!(matches!(result.unwrap_err(), ConnectionError::PolicyDenied));
}

#[tokio::test]
async fn test_policy_with_unassigned_devices() {
    let env = Arc::new(TestEnvironment::new().await.expect("Failed to create test environment"));

    let agent_a = create_enrolled_agent(env.clone(), "agent-a").await;
    let agent_b = create_enrolled_agent(env.clone(), "agent-b").await;

    let pod = create_pod(&env, "test-pod").await;
    add_device_to_pod(&env, agent_a.device_id(), &pod.id).await;

    create_policy(&env, &pod.id, &pod.id, "allow").await;

    let result = agent_a.connect_to(agent_b.device_id().clone()).await;
    assert!(result.is_err(), "Connection to device not in pod should fail");
}
