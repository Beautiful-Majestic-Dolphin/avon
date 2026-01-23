//! Benchmarks for AVON cryptographic primitives.
//!
//! Run with: cargo bench -p avon-crypto

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use avon_crypto::ecdh::X25519KeyPair;
use avon_crypto::hybrid::key_exchange::{hybrid_encapsulate, HybridKeyPair};
use avon_crypto::hybrid::signature::HybridSigningKeyPair;
use avon_crypto::pqc::dilithium::DilithiumKeyPair;
use avon_crypto::pqc::kyber::KyberKeyPair;
use avon_crypto::signature::Ed25519KeyPair;

/// Benchmark classical X25519 key exchange.
fn bench_x25519_key_exchange(c: &mut Criterion) {
    let alice = X25519KeyPair::generate().unwrap();
    let bob = X25519KeyPair::generate().unwrap();

    c.bench_function("x25519_key_exchange", |b| {
        b.iter(|| {
            let _ = black_box(alice.diffie_hellman(bob.public_key()).unwrap());
        })
    });
}

/// Benchmark Kyber768 key encapsulation.
fn bench_kyber_encapsulate(c: &mut Criterion) {
    let keypair = KyberKeyPair::generate().unwrap();

    c.bench_function("kyber768_encapsulate", |b| {
        b.iter(|| {
            let _ = black_box(keypair.public_key().encapsulate().unwrap());
        })
    });
}

/// Benchmark Kyber768 key decapsulation.
fn bench_kyber_decapsulate(c: &mut Criterion) {
    let keypair = KyberKeyPair::generate().unwrap();
    let (ciphertext, _) = keypair.public_key().encapsulate().unwrap();

    c.bench_function("kyber768_decapsulate", |b| {
        b.iter(|| {
            let _ = black_box(keypair.decapsulate(&ciphertext).unwrap());
        })
    });
}

/// Benchmark hybrid key exchange (encapsulation side).
fn bench_hybrid_encapsulate(c: &mut Criterion) {
    let recipient = HybridKeyPair::generate().unwrap();

    c.bench_function("hybrid_encapsulate", |b| {
        b.iter(|| {
            let _ = black_box(hybrid_encapsulate(&recipient.public_key()).unwrap());
        })
    });
}

/// Benchmark hybrid key exchange (decapsulation side).
fn bench_hybrid_decapsulate(c: &mut Criterion) {
    let recipient = HybridKeyPair::generate().unwrap();
    let (encapsulation, _) = hybrid_encapsulate(&recipient.public_key()).unwrap();

    c.bench_function("hybrid_decapsulate", |b| {
        b.iter(|| {
            let _ = black_box(recipient.decapsulate(&encapsulation).unwrap());
        })
    });
}

/// Benchmark classical Ed25519 signing.
fn bench_ed25519_sign(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Hello, world! This is a test message for benchmarking.";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let _ = black_box(keypair.sign(black_box(message)));
        })
    });
}

/// Benchmark classical Ed25519 verification.
fn bench_ed25519_verify(c: &mut Criterion) {
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Hello, world! This is a test message for benchmarking.";
    let signature = keypair.sign(message);

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            let _ = black_box(
                keypair
                    .verifying_key()
                    .verify(black_box(message), black_box(&signature)),
            );
        })
    });
}

/// Benchmark Dilithium3 signing.
fn bench_dilithium_sign(c: &mut Criterion) {
    let keypair = DilithiumKeyPair::generate().unwrap();
    let message = b"Hello, world! This is a test message for benchmarking.";

    c.bench_function("dilithium3_sign", |b| {
        b.iter(|| {
            let _ = black_box(keypair.sign(black_box(message)));
        })
    });
}

/// Benchmark Dilithium3 verification.
fn bench_dilithium_verify(c: &mut Criterion) {
    let keypair = DilithiumKeyPair::generate().unwrap();
    let message = b"Hello, world! This is a test message for benchmarking.";
    let signature = keypair.sign(message);

    c.bench_function("dilithium3_verify", |b| {
        b.iter(|| {
            let _ = black_box(
                keypair
                    .verifying_key()
                    .verify(black_box(message), black_box(&signature)),
            );
        })
    });
}

/// Benchmark hybrid signing.
fn bench_hybrid_sign(c: &mut Criterion) {
    let keypair = HybridSigningKeyPair::generate().unwrap();
    let message = b"Hello, world! This is a test message for benchmarking.";

    c.bench_function("hybrid_sign", |b| {
        b.iter(|| {
            let _ = black_box(keypair.sign(black_box(message)));
        })
    });
}

/// Benchmark hybrid verification.
fn bench_hybrid_verify(c: &mut Criterion) {
    let keypair = HybridSigningKeyPair::generate().unwrap();
    let message = b"Hello, world! This is a test message for benchmarking.";
    let signature = keypair.sign(message);

    c.bench_function("hybrid_verify", |b| {
        b.iter(|| {
            let _ = black_box(
                keypair
                    .verifying_key()
                    .verify(black_box(message), black_box(&signature)),
            );
        })
    });
}

/// Benchmark key generation times.
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    group.bench_function("x25519", |b| {
        b.iter(|| {
            let _ = black_box(X25519KeyPair::generate().unwrap());
        })
    });

    group.bench_function("kyber768", |b| {
        b.iter(|| {
            let _ = black_box(KyberKeyPair::generate().unwrap());
        })
    });

    group.bench_function("hybrid_kex", |b| {
        b.iter(|| {
            let _ = black_box(HybridKeyPair::generate().unwrap());
        })
    });

    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let _ = black_box(Ed25519KeyPair::generate().unwrap());
        })
    });

    group.bench_function("dilithium3", |b| {
        b.iter(|| {
            let _ = black_box(DilithiumKeyPair::generate().unwrap());
        })
    });

    group.bench_function("hybrid_sign", |b| {
        b.iter(|| {
            let _ = black_box(HybridSigningKeyPair::generate().unwrap());
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_x25519_key_exchange,
    bench_kyber_encapsulate,
    bench_kyber_decapsulate,
    bench_hybrid_encapsulate,
    bench_hybrid_decapsulate,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_dilithium_sign,
    bench_dilithium_verify,
    bench_hybrid_sign,
    bench_hybrid_verify,
    bench_key_generation,
);

criterion_main!(benches);
