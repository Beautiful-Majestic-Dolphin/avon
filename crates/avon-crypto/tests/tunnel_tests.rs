//! Tests for tunnel encryption and session key derivation.

use avon_crypto::hybrid::key_exchange::{hybrid_encapsulate, HybridKeyPair};
use avon_crypto::session::TunnelKeys;
use avon_crypto::tunnel::{TunnelCipher, TunnelDirection, TunnelPacket};

mod tunnel_cipher_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);

        let plaintext = b"Hello, tunnel!";
        let aad = b"session-id";

        let packet = cipher.encrypt(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&packet, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        let cipher1 = TunnelCipher::new(key1, TunnelDirection::Initiator);
        let cipher2 = TunnelCipher::new(key2, TunnelDirection::Initiator);

        let plaintext = b"secret data";
        let packet = cipher1.encrypt(plaintext, b"").unwrap();

        // Decryption with wrong key should fail
        let result = cipher2.decrypt(&packet, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);

        let plaintext = b"secret data";
        let mut packet = cipher.encrypt(plaintext, b"").unwrap();

        // Tamper with ciphertext
        if !packet.ciphertext.is_empty() {
            packet.ciphertext[0] ^= 0xFF;
        }

        let result = cipher.decrypt(&packet, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x42u8; 32];
        let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);

        let plaintext = b"secret data";
        let packet = cipher.encrypt(plaintext, b"correct aad").unwrap();

        // Decryption with wrong AAD should fail
        let result = cipher.decrypt(&packet, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);

        let plaintext = b"";
        let packet = cipher.encrypt(plaintext, b"").unwrap();
        let decrypted = cipher.decrypt(&packet, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let cipher = TunnelCipher::new(key, TunnelDirection::Initiator);

        let plaintext = vec![0xABu8; 65536]; // 64KB
        let packet = cipher.encrypt(&plaintext, b"").unwrap();
        let decrypted = cipher.decrypt(&packet, b"").unwrap();

        assert_eq!(decrypted, plaintext);
    }
}

mod nonce_counter_tests {
    use super::*;

    #[test]
    fn test_nonce_counter_increments() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);

        assert_eq!(cipher.nonce_counter(), 0);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.nonce_counter(), 1);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.nonce_counter(), 2);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.nonce_counter(), 3);
    }

    #[test]
    fn test_remaining_nonces() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        assert_eq!(cipher.remaining_nonces(), u64::MAX);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.remaining_nonces(), u64::MAX - 1);

        cipher.encrypt(b"test", b"").unwrap();
        assert_eq!(cipher.remaining_nonces(), u64::MAX - 2);
    }

    #[test]
    fn test_each_encryption_uses_unique_nonce() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);

        let packet1 = cipher.encrypt(b"test", b"").unwrap();
        let packet2 = cipher.encrypt(b"test", b"").unwrap();
        let packet3 = cipher.encrypt(b"test", b"").unwrap();

        // All nonces should be different
        assert_ne!(packet1.nonce, packet2.nonce);
        assert_ne!(packet2.nonce, packet3.nonce);
        assert_ne!(packet1.nonce, packet3.nonce);
    }
}

mod direction_tests {
    use super::*;

    #[test]
    fn test_initiator_and_responder_use_different_nonce_spaces() {
        let key = [0x42u8; 32];
        let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
        let responder = TunnelCipher::new(key, TunnelDirection::Responder);

        let packet1 = initiator.encrypt(b"test", b"").unwrap();
        let packet2 = responder.encrypt(b"test", b"").unwrap();

        // First byte should differ (direction bit)
        assert_ne!(packet1.nonce[0], packet2.nonce[0]);
        assert_eq!(packet1.nonce[0], 0x00); // Initiator
        assert_eq!(packet2.nonce[0], 0x01); // Responder
    }

    #[test]
    fn test_initiator_nonces_cannot_collide_with_responder() {
        let key = [0x42u8; 32];
        let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
        let responder = TunnelCipher::new(key, TunnelDirection::Responder);

        // Generate many packets from each side
        let mut initiator_nonces = Vec::new();
        let mut responder_nonces = Vec::new();

        for _ in 0..100 {
            let packet = initiator.encrypt(b"test", b"").unwrap();
            initiator_nonces.push(packet.nonce);

            let packet = responder.encrypt(b"test", b"").unwrap();
            responder_nonces.push(packet.nonce);
        }

        // No initiator nonce should match any responder nonce
        for init_nonce in &initiator_nonces {
            for resp_nonce in &responder_nonces {
                assert_ne!(init_nonce, resp_nonce);
            }
        }
    }

    #[test]
    fn test_cross_direction_decryption() {
        let key = [0x42u8; 32];
        let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
        let responder = TunnelCipher::new(key, TunnelDirection::Responder);

        // Initiator encrypts, responder decrypts
        let packet = initiator.encrypt(b"hello from initiator", b"aad").unwrap();
        let decrypted = responder.decrypt(&packet, b"aad").unwrap();
        assert_eq!(decrypted, b"hello from initiator");

        // Responder encrypts, initiator decrypts
        let packet = responder.encrypt(b"hello from responder", b"aad").unwrap();
        let decrypted = initiator.decrypt(&packet, b"aad").unwrap();
        assert_eq!(decrypted, b"hello from responder");
    }

    #[test]
    fn test_direction_getter() {
        let initiator = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        let responder = TunnelCipher::new([0x42u8; 32], TunnelDirection::Responder);

        assert_eq!(initiator.direction(), TunnelDirection::Initiator);
        assert_eq!(responder.direction(), TunnelDirection::Responder);
    }
}

mod packet_tests {
    use super::*;

    #[test]
    fn test_packet_overhead() {
        assert_eq!(TunnelPacket::overhead(), 28); // 12 nonce + 16 tag
    }

    #[test]
    fn test_packet_serialization_roundtrip() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        let packet = cipher.encrypt(b"test data", b"").unwrap();

        let bytes = packet.to_bytes();
        let restored = TunnelPacket::from_bytes(&bytes).unwrap();

        assert_eq!(restored.nonce, packet.nonce);
        assert_eq!(restored.ciphertext, packet.ciphertext);
    }

    #[test]
    fn test_packet_from_bytes_too_short() {
        let short_bytes = [0u8; 20]; // Less than overhead
        let result = TunnelPacket::from_bytes(&short_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_plaintext_len() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);

        let plaintext = b"hello world"; // 11 bytes
        let packet = cipher.encrypt(plaintext, b"").unwrap();

        assert_eq!(packet.plaintext_len(), 11);
    }

    #[test]
    fn test_restored_packet_can_be_decrypted() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        let plaintext = b"test data";
        let aad = b"session";

        let packet = cipher.encrypt(plaintext, aad).unwrap();
        let bytes = packet.to_bytes();
        let restored = TunnelPacket::from_bytes(&bytes).unwrap();

        let decrypted = cipher.decrypt(&restored, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

mod encrypt_in_place_tests {
    use super::*;

    #[test]
    fn test_encrypt_in_place() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        let plaintext = b"secret data";
        let mut buffer = plaintext.to_vec();

        cipher.encrypt_in_place(&mut buffer, b"aad").unwrap();

        // Buffer should now contain nonce || ciphertext || tag
        assert_eq!(buffer.len(), plaintext.len() + TunnelPacket::overhead());

        // Should be able to parse and decrypt
        let packet = TunnelPacket::from_bytes(&buffer).unwrap();
        let decrypted = cipher.decrypt(&packet, b"aad").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_in_place_empty() {
        let cipher = TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator);
        let mut buffer = Vec::new();

        cipher.encrypt_in_place(&mut buffer, b"").unwrap();

        assert_eq!(buffer.len(), TunnelPacket::overhead());
    }
}

mod session_key_tests {
    use super::*;

    #[test]
    fn test_derive_produces_different_keys_for_directions() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys = TunnelKeys::derive(
            &shared_secret,
            &[0u8; 32],
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        assert_ne!(keys.initiator_key, keys.responder_key);
    }

    #[test]
    fn test_session_key_derivation_is_deterministic() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys1 = TunnelKeys::derive(
            &shared_secret,
            &[0u8; 32],
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        let keys2 = TunnelKeys::derive(
            &shared_secret,
            &[0u8; 32],
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        assert_eq!(keys1.initiator_key, keys2.initiator_key);
        assert_eq!(keys1.responder_key, keys2.responder_key);
    }

    #[test]
    fn test_different_session_ids_produce_different_keys() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys1 = TunnelKeys::derive(
            &shared_secret,
            &[0u8; 32],
            &[1u8; 32],
            &[0x01u8; 16],
        )
        .unwrap();

        let keys2 = TunnelKeys::derive(
            &shared_secret,
            &[0u8; 32],
            &[1u8; 32],
            &[0x02u8; 16],
        )
        .unwrap();

        assert_ne!(keys1.initiator_key, keys2.initiator_key);
        assert_ne!(keys1.responder_key, keys2.responder_key);
    }

    #[test]
    fn test_different_public_keys_produce_different_keys() {
        let responder_kp = HybridKeyPair::generate().unwrap();
        let (_, shared_secret) = hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        let keys1 = TunnelKeys::derive(
            &shared_secret,
            &[0u8; 32],
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        let keys2 = TunnelKeys::derive(
            &shared_secret,
            &[2u8; 32], // Different initiator public
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        assert_ne!(keys1.initiator_key, keys2.initiator_key);
    }

    #[test]
    fn test_different_shared_secrets_produce_different_keys() {
        let responder_kp1 = HybridKeyPair::generate().unwrap();
        let responder_kp2 = HybridKeyPair::generate().unwrap();

        let (_, shared_secret1) = hybrid_encapsulate(&responder_kp1.public_key()).unwrap();
        let (_, shared_secret2) = hybrid_encapsulate(&responder_kp2.public_key()).unwrap();

        let keys1 = TunnelKeys::derive(
            &shared_secret1,
            &[0u8; 32],
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        let keys2 = TunnelKeys::derive(
            &shared_secret2,
            &[0u8; 32],
            &[1u8; 32],
            &[0x42u8; 16],
        )
        .unwrap();

        assert_ne!(keys1.initiator_key, keys2.initiator_key);
        assert_ne!(keys1.responder_key, keys2.responder_key);
    }
}

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_tunnel_establishment() {
        // Simulate full tunnel establishment

        // 1. Generate keypairs
        let initiator_kp = HybridKeyPair::generate().unwrap();
        let responder_kp = HybridKeyPair::generate().unwrap();

        // 2. Initiator encapsulates to responder
        let (encapsulation, initiator_secret) =
            hybrid_encapsulate(&responder_kp.public_key()).unwrap();

        // 3. Responder decapsulates
        let responder_secret = responder_kp.decapsulate(&encapsulation).unwrap();

        // 4. Both derive the same shared secret
        assert_eq!(
            initiator_secret.as_bytes(),
            responder_secret.as_bytes()
        );

        // 5. Derive tunnel keys
        let session_id = [0x42u8; 16];
        let initiator_pub = initiator_kp.public_key().to_bytes();
        let responder_pub = responder_kp.public_key().to_bytes();

        let initiator_keys = TunnelKeys::derive(
            &initiator_secret,
            &initiator_pub,
            &responder_pub,
            &session_id,
        )
        .unwrap();

        let responder_keys = TunnelKeys::derive(
            &responder_secret,
            &initiator_pub,
            &responder_pub,
            &session_id,
        )
        .unwrap();

        // 6. Keys should match
        assert_eq!(initiator_keys.initiator_key, responder_keys.initiator_key);
        assert_eq!(initiator_keys.responder_key, responder_keys.responder_key);

        // 7. Create tunnel ciphers
        // Initiator uses initiator_key for sending, responder_key for receiving
        let initiator_send = TunnelCipher::new(initiator_keys.initiator_key, TunnelDirection::Initiator);
        let responder_recv = TunnelCipher::new(responder_keys.initiator_key, TunnelDirection::Initiator);

        let responder_send = TunnelCipher::new(responder_keys.responder_key, TunnelDirection::Responder);
        let initiator_recv = TunnelCipher::new(initiator_keys.responder_key, TunnelDirection::Responder);

        // 8. Test bidirectional communication
        let msg1 = b"Hello from initiator!";
        let packet1 = initiator_send.encrypt(msg1, &session_id).unwrap();
        let decrypted1 = responder_recv.decrypt(&packet1, &session_id).unwrap();
        assert_eq!(decrypted1, msg1);

        let msg2 = b"Hello from responder!";
        let packet2 = responder_send.encrypt(msg2, &session_id).unwrap();
        let decrypted2 = initiator_recv.decrypt(&packet2, &session_id).unwrap();
        assert_eq!(decrypted2, msg2);
    }

    #[test]
    fn test_tunnel_with_many_packets() {
        let key = [0x42u8; 32];
        let initiator = TunnelCipher::new(key, TunnelDirection::Initiator);
        let responder = TunnelCipher::new(key, TunnelDirection::Responder);

        // Send 1000 packets in each direction
        for i in 0..1000u32 {
            let msg = format!("Message {} from initiator", i);
            let packet = initiator.encrypt(msg.as_bytes(), b"").unwrap();
            let decrypted = responder.decrypt(&packet, b"").unwrap();
            assert_eq!(decrypted, msg.as_bytes());

            let msg = format!("Message {} from responder", i);
            let packet = responder.encrypt(msg.as_bytes(), b"").unwrap();
            let decrypted = initiator.decrypt(&packet, b"").unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }

        // Verify nonce counters
        assert_eq!(initiator.nonce_counter(), 1000);
        assert_eq!(responder.nonce_counter(), 1000);
    }
}

mod thread_safety_tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_concurrent_encryption() {
        let cipher = Arc::new(TunnelCipher::new([0x42u8; 32], TunnelDirection::Initiator));
        let mut handles = Vec::new();

        // Spawn 10 threads, each encrypting 100 messages
        for _ in 0..10 {
            let cipher_clone = Arc::clone(&cipher);
            let handle = thread::spawn(move || {
                let mut packets = Vec::new();
                for _ in 0..100 {
                    let packet = cipher_clone.encrypt(b"test", b"").unwrap();
                    packets.push(packet);
                }
                packets
            });
            handles.push(handle);
        }

        // Collect all packets
        let mut all_packets = Vec::new();
        for handle in handles {
            let packets = handle.join().unwrap();
            all_packets.extend(packets);
        }

        // Should have 1000 packets total
        assert_eq!(all_packets.len(), 1000);

        // All nonces should be unique
        let mut nonces: Vec<_> = all_packets.iter().map(|p| p.nonce).collect();
        nonces.sort();
        nonces.dedup();
        assert_eq!(nonces.len(), 1000);

        // Counter should be 1000
        assert_eq!(cipher.nonce_counter(), 1000);
    }
}
