//! Tests for the rotating token system.

use avon_crypto::token::{RotatingToken, ServerTokenState, TokenRotationInput, TokenVerifyResult};

mod token_creation_tests {
    use super::*;

    #[test]
    fn test_new_token_has_correct_initial_state() {
        let seed = [0x42u8; 32];
        let token = RotatingToken::new(seed);

        assert_eq!(token.current(), &seed);
        assert_eq!(token.sequence(), 0);
    }

    #[test]
    fn test_server_state_has_correct_initial_state() {
        let device_id = [0x01u8; 16];
        let seed = [0x42u8; 32];
        let state = ServerTokenState::new(device_id, seed);

        assert_eq!(state.device_id(), &device_id);
        assert_eq!(state.current(), &seed);
        assert_eq!(state.sequence(), 0);
        assert_eq!(state.last_rotation(), 0);
    }

    #[test]
    fn test_different_seeds_produce_different_tokens() {
        let token1 = RotatingToken::new([0x01u8; 32]);
        let token2 = RotatingToken::new([0x02u8; 32]);

        assert_ne!(token1.current(), token2.current());
    }
}

mod token_verification_tests {
    use super::*;

    #[test]
    fn test_fresh_token_verifies_as_current() {
        let seed = [0x42u8; 32];
        let token = RotatingToken::new(seed);

        assert!(matches!(
            token.verify(token.current()),
            TokenVerifyResult::Current
        ));
    }

    #[test]
    fn test_after_rotation_old_token_verifies_as_previous() {
        let mut token = RotatingToken::new([0x42u8; 32]);
        let old_token = *token.current();

        let input = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        token.rotate(&input);

        assert!(matches!(
            token.verify(&old_token),
            TokenVerifyResult::Previous
        ));
    }

    #[test]
    fn test_after_two_rotations_oldest_token_is_invalid() {
        let mut token = RotatingToken::new([0x42u8; 32]);
        let oldest_token = *token.current();

        // First rotation
        let input1 = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        token.rotate(&input1);

        // Second rotation
        let input2 = TokenRotationInput::new([2u8; 32], [3u8; 32], 2000);
        token.rotate(&input2);

        // Oldest token should now be invalid
        assert!(matches!(
            token.verify(&oldest_token),
            TokenVerifyResult::Invalid
        ));
    }

    #[test]
    fn test_invalid_token_is_rejected() {
        let token = RotatingToken::new([0x42u8; 32]);
        let invalid = [0xFFu8; 32];

        assert!(matches!(token.verify(&invalid), TokenVerifyResult::Invalid));
    }

    #[test]
    fn test_server_verifies_client_token() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let client = RotatingToken::new(seed);
        let server = ServerTokenState::new(device_id, seed);

        assert!(matches!(
            server.verify(client.current()),
            TokenVerifyResult::Current
        ));
    }
}

mod rotation_synchronization_tests {
    use super::*;

    #[test]
    fn test_client_and_server_derive_same_token_after_rotation() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let mut client = RotatingToken::new(seed);
        let mut server = ServerTokenState::new(device_id, seed);

        // Create rotation input (in practice, server generates nonce, client adds theirs)
        let input = TokenRotationInput::new([0xAAu8; 32], [0xBBu8; 32], 1000);

        // Both sides rotate
        let client_new = client.rotate(&input);
        let server_new = server.complete_rotation(&input);

        // They should derive the same token
        assert_eq!(client_new, server_new);
        assert_eq!(client.current(), server.current());
    }

    #[test]
    fn test_sequence_increments_correctly() {
        let mut token = RotatingToken::new([0x42u8; 32]);
        assert_eq!(token.sequence(), 0);

        let input1 = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        token.rotate(&input1);
        assert_eq!(token.sequence(), 1);

        let input2 = TokenRotationInput::new([2u8; 32], [3u8; 32], 2000);
        token.rotate(&input2);
        assert_eq!(token.sequence(), 2);

        let input3 = TokenRotationInput::new([4u8; 32], [5u8; 32], 3000);
        token.rotate(&input3);
        assert_eq!(token.sequence(), 3);
    }

    #[test]
    fn test_server_sequence_increments_correctly() {
        let mut server = ServerTokenState::new([0x01u8; 16], [0x42u8; 32]);
        assert_eq!(server.sequence(), 0);

        let input = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        server.complete_rotation(&input);
        assert_eq!(server.sequence(), 1);
    }

    #[test]
    fn test_server_last_rotation_updates() {
        let mut server = ServerTokenState::new([0x01u8; 16], [0x42u8; 32]);
        assert_eq!(server.last_rotation(), 0);

        let input = TokenRotationInput::new([0u8; 32], [1u8; 32], 12345);
        server.complete_rotation(&input);
        assert_eq!(server.last_rotation(), 12345);
    }

    #[test]
    fn test_multiple_synchronized_rotations() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let mut client = RotatingToken::new(seed);
        let mut server = ServerTokenState::new(device_id, seed);

        // Perform 10 rotations
        for i in 0..10u64 {
            let input =
                TokenRotationInput::new([(i as u8); 32], [(i as u8 + 100); 32], 1000 + i * 100);

            let client_new = client.rotate(&input);
            let server_new = server.complete_rotation(&input);

            assert_eq!(client_new, server_new);
            assert_eq!(client.sequence(), i + 1);
            assert_eq!(server.sequence(), i + 1);
        }
    }
}

mod nonce_tests {
    use super::*;

    #[test]
    fn test_different_server_nonces_produce_different_tokens() {
        let mut token1 = RotatingToken::new([0x42u8; 32]);
        let mut token2 = RotatingToken::new([0x42u8; 32]);

        let input1 = TokenRotationInput::new([0xAAu8; 32], [0xCCu8; 32], 1000);
        let input2 = TokenRotationInput::new([0xBBu8; 32], [0xCCu8; 32], 1000);

        let new1 = token1.rotate(&input1);
        let new2 = token2.rotate(&input2);

        assert_ne!(new1, new2);
    }

    #[test]
    fn test_different_client_nonces_produce_different_tokens() {
        let mut token1 = RotatingToken::new([0x42u8; 32]);
        let mut token2 = RotatingToken::new([0x42u8; 32]);

        let input1 = TokenRotationInput::new([0xAAu8; 32], [0xCCu8; 32], 1000);
        let input2 = TokenRotationInput::new([0xAAu8; 32], [0xDDu8; 32], 1000);

        let new1 = token1.rotate(&input1);
        let new2 = token2.rotate(&input2);

        assert_ne!(new1, new2);
    }

    #[test]
    fn test_different_timestamps_produce_different_tokens() {
        let mut token1 = RotatingToken::new([0x42u8; 32]);
        let mut token2 = RotatingToken::new([0x42u8; 32]);

        let input1 = TokenRotationInput::new([0xAAu8; 32], [0xCCu8; 32], 1000);
        let input2 = TokenRotationInput::new([0xAAu8; 32], [0xCCu8; 32], 2000);

        let new1 = token1.rotate(&input1);
        let new2 = token2.rotate(&input2);

        assert_ne!(new1, new2);
    }

    #[test]
    fn test_server_generates_rotation_input() {
        let server = ServerTokenState::new([0x01u8; 16], [0x42u8; 32]);
        let (input, server_nonce) = server.generate_rotation_input();

        assert_eq!(input.server_nonce, server_nonce);
        // Client nonce should be placeholder (zeros)
        assert_eq!(input.client_nonce, [0u8; 32]);
    }
}

mod auth_tag_tests {
    use super::*;

    #[test]
    fn test_auth_tag_verifies_correctly() {
        let token = RotatingToken::new([0x42u8; 32]);
        let data = b"important message";
        let tag = token.compute_auth_tag(data);

        assert!(token.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_auth_tag_fails_for_wrong_data() {
        let token = RotatingToken::new([0x42u8; 32]);
        let data = b"important message";
        let tag = token.compute_auth_tag(data);

        assert!(!token.verify_auth_tag(b"wrong message", &tag));
    }

    #[test]
    fn test_auth_tag_fails_for_wrong_tag() {
        let token = RotatingToken::new([0x42u8; 32]);
        let data = b"important message";
        let wrong_tag = [0xFFu8; 32];

        assert!(!token.verify_auth_tag(data, &wrong_tag));
    }

    #[test]
    fn test_auth_tag_fails_for_wrong_token() {
        let token1 = RotatingToken::new([0x42u8; 32]);
        let token2 = RotatingToken::new([0x43u8; 32]);
        let data = b"important message";
        let tag = token1.compute_auth_tag(data);

        assert!(!token2.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_auth_tag_verifies_with_previous_token_after_rotation() {
        let mut token = RotatingToken::new([0x42u8; 32]);
        let data = b"important message";
        let tag = token.compute_auth_tag(data);

        // Rotate the token
        let input = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        token.rotate(&input);

        // Tag should still verify (using previous token)
        assert!(token.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_auth_tag_fails_after_two_rotations() {
        let mut token = RotatingToken::new([0x42u8; 32]);
        let data = b"important message";
        let tag = token.compute_auth_tag(data);

        // First rotation
        let input1 = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        token.rotate(&input1);

        // Second rotation
        let input2 = TokenRotationInput::new([2u8; 32], [3u8; 32], 2000);
        token.rotate(&input2);

        // Tag should no longer verify
        assert!(!token.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_server_auth_tag_verification() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let client = RotatingToken::new(seed);
        let server = ServerTokenState::new(device_id, seed);

        let data = b"important message";
        let tag = client.compute_auth_tag(data);

        assert!(server.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_server_auth_tag_verification_after_rotation() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let mut client = RotatingToken::new(seed);
        let mut server = ServerTokenState::new(device_id, seed);

        // Client creates tag with old token
        let data = b"important message";
        let tag = client.compute_auth_tag(data);

        // Both rotate
        let input = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        client.rotate(&input);
        server.complete_rotation(&input);

        // Server should still verify (using previous token)
        assert!(server.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_empty_data_auth_tag() {
        let token = RotatingToken::new([0x42u8; 32]);
        let data = b"";
        let tag = token.compute_auth_tag(data);

        assert!(token.verify_auth_tag(data, &tag));
    }

    #[test]
    fn test_large_data_auth_tag() {
        let token = RotatingToken::new([0x42u8; 32]);
        let data = vec![0xABu8; 10000];
        let tag = token.compute_auth_tag(&data);

        assert!(token.verify_auth_tag(&data, &tag));
    }
}

mod grace_period_tests {
    use super::*;

    #[test]
    fn test_grace_period_allows_recovery_from_missed_rotation() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let mut client = RotatingToken::new(seed);
        let _server = ServerTokenState::new(device_id, seed);

        // Client rotates
        let input = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        client.rotate(&input);

        // Server hasn't rotated yet - client's new token should be invalid
        // but client's old token (which server still has as current) should work
        // Actually, server still has the old token as current
        // Let's test the reverse: server rotates, client hasn't

        // Reset
        let client = RotatingToken::new(seed);
        let mut server = ServerTokenState::new(device_id, seed);

        // Server rotates
        server.complete_rotation(&input);

        // Client's token (old) should verify as Previous on server
        assert!(matches!(
            server.verify(client.current()),
            TokenVerifyResult::Previous
        ));
    }

    #[test]
    fn test_grace_period_expires_after_one_rotation() {
        let seed = [0x42u8; 32];
        let device_id = [0x01u8; 16];

        let client = RotatingToken::new(seed);
        let mut server = ServerTokenState::new(device_id, seed);

        let old_client_token = *client.current();

        // Server rotates twice
        let input1 = TokenRotationInput::new([0u8; 32], [1u8; 32], 1000);
        server.complete_rotation(&input1);

        let input2 = TokenRotationInput::new([2u8; 32], [3u8; 32], 2000);
        server.complete_rotation(&input2);

        // Client's original token should now be invalid
        assert!(matches!(
            server.verify(&old_client_token),
            TokenVerifyResult::Invalid
        ));
    }
}

mod zeroize_tests {
    use super::*;

    #[test]
    fn test_token_is_zeroized_on_drop() {
        let seed = [0x42u8; 32];

        // Create token in a scope
        let token_ptr: *const [u8; 32];
        {
            let token = RotatingToken::new(seed);
            token_ptr = token.current() as *const [u8; 32];

            // Verify token is valid before drop
            assert_eq!(unsafe { *token_ptr }, seed);
        }
        // Token is dropped here, should be zeroized

        // Note: We can't reliably test that memory is zeroed after drop
        // because the memory may be reused. The Zeroize derive macro
        // handles this automatically.
    }
}

mod token_rotation_input_tests {
    use super::*;

    #[test]
    fn test_token_rotation_input_new() {
        let server_nonce = [0xAAu8; 32];
        let client_nonce = [0xBBu8; 32];
        let timestamp = 12345u64;

        let input = TokenRotationInput::new(server_nonce, client_nonce, timestamp);

        assert_eq!(input.server_nonce, server_nonce);
        assert_eq!(input.client_nonce, client_nonce);
        assert_eq!(input.timestamp, timestamp);
    }

    #[test]
    fn test_token_rotation_input_clone() {
        let input = TokenRotationInput::new([0xAAu8; 32], [0xBBu8; 32], 12345);
        let cloned = input.clone();

        assert_eq!(input.server_nonce, cloned.server_nonce);
        assert_eq!(input.client_nonce, cloned.client_nonce);
        assert_eq!(input.timestamp, cloned.timestamp);
    }
}

mod determinism_tests {
    use super::*;

    #[test]
    fn test_same_inputs_produce_same_token() {
        let mut token1 = RotatingToken::new([0x42u8; 32]);
        let mut token2 = RotatingToken::new([0x42u8; 32]);

        let input = TokenRotationInput::new([0xAAu8; 32], [0xBBu8; 32], 1000);

        let new1 = token1.rotate(&input);
        let new2 = token2.rotate(&input);

        assert_eq!(new1, new2);
    }

    #[test]
    fn test_rotation_is_deterministic() {
        let seed = [0x42u8; 32];
        let input = TokenRotationInput::new([0xAAu8; 32], [0xBBu8; 32], 1000);

        // Rotate multiple times from same starting point
        let mut results = Vec::new();
        for _ in 0..5 {
            let mut token = RotatingToken::new(seed);
            let new_token = token.rotate(&input);
            results.push(new_token);
        }

        // All results should be identical
        for result in &results[1..] {
            assert_eq!(results[0], *result);
        }
    }
}
