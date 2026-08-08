//! Client-side project key derivation, password verification, and secret encryption.
//!
//! Each project has a random salt and an encrypted verifier. Argon2id derives one
//! project master key from the password and salt. Purpose-specific encryption keys
//! are derived from it, and every encryption uses a fresh ChaCha20-Poly1305 nonce.

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::protocol::{KdfConfig, PROJECT_SALT_LEN, ProjectMetadata};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const VERIFIER_PLAINTEXT: &[u8] = b"keyben-project-verifier-v1";

/// A project master key derived locally from the project password.
pub struct ProjectKey([u8; KEY_LEN]);

struct EncryptionKey([u8; KEY_LEN]);

impl Drop for ProjectKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Create the KDF metadata and encrypted password verifier for a new project.
pub fn create_project_metadata(project: &str, password: &str) -> Result<ProjectMetadata> {
    if project.trim().is_empty() {
        bail!("Project name cannot be empty");
    }
    if password.is_empty() {
        bail!("Project password cannot be empty");
    }

    let salt: [u8; PROJECT_SALT_LEN] = rand::random();
    let kdf = KdfConfig::argon2id(B64.encode(salt));
    let project_key = derive_project_key(password, &kdf)?;
    let context = verifier_context(project);
    let encryption_key = derive_encryption_key(&project_key, &context);
    let verifier = encrypt_bytes(&encryption_key, VERIFIER_PLAINTEXT, &context)?;

    Ok(ProjectMetadata { kdf, verifier })
}

/// Derive and verify a project's key without sending the password to the server.
pub fn unlock_project(
    project: &str,
    password: &str,
    metadata: &ProjectMetadata,
) -> Result<ProjectKey> {
    if project.trim().is_empty() {
        bail!("Project name cannot be empty");
    }
    if password.is_empty() {
        bail!("Project password cannot be empty");
    }

    let project_key = derive_project_key(password, &metadata.kdf)?;
    let context = verifier_context(project);
    let encryption_key = derive_encryption_key(&project_key, &context);
    let plaintext = decrypt_bytes(&encryption_key, &metadata.verifier, &context)
        .map_err(|_| anyhow!("Invalid project password or corrupted project metadata"))?;

    if plaintext != VERIFIER_PLAINTEXT {
        bail!("Invalid project password or corrupted project metadata");
    }

    Ok(project_key)
}

/// Encrypt a secret with the verified project key and bind it to its location.
pub fn encrypt_secret(
    key: &ProjectKey,
    project: &str,
    env: &str,
    name: &str,
    plaintext: &str,
) -> Result<String> {
    let context = secret_context(project, env, name);
    let encryption_key = derive_encryption_key(key, &context);
    encrypt_bytes(&encryption_key, plaintext.as_bytes(), &context)
}

/// Decrypt a secret and verify that it belongs to the requested location.
pub fn decrypt_secret(
    key: &ProjectKey,
    project: &str,
    env: &str,
    name: &str,
    blob: &str,
) -> Result<String> {
    let context = secret_context(project, env, name);
    let encryption_key = derive_encryption_key(key, &context);
    let plaintext = decrypt_bytes(&encryption_key, blob, &context)
        .map_err(|_| anyhow!("Secret decryption failed: corrupted or misplaced ciphertext"))?;

    String::from_utf8(plaintext).context("Decrypted result is not valid UTF-8 text")
}

fn derive_project_key(password: &str, kdf: &KdfConfig) -> Result<ProjectKey> {
    if !kdf.is_supported() {
        bail!("Unsupported project KDF configuration");
    }

    let salt = B64
        .decode(&kdf.salt)
        .context("Project salt is not valid Base64")?;
    if salt.len() != PROJECT_SALT_LEN {
        bail!("Project salt must be {PROJECT_SALT_LEN} bytes");
    }

    let params = Params::new(
        kdf.memory_cost,
        kdf.time_cost,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| anyhow!("Invalid Argon2id parameters: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|err| anyhow!("Argon2id key derivation failed: {err}"))?;

    Ok(ProjectKey(key))
}

/// Derive a purpose- and location-specific encryption key from the project master key.
/// The length-prefixed context makes this a stable, unambiguous domain separation scheme.
fn derive_encryption_key(project_key: &ProjectKey, context: &[u8]) -> EncryptionKey {
    let mut input = Vec::with_capacity(32 + context.len());
    input.extend_from_slice(b"keyben-encryption-key-v1");
    input.extend_from_slice(&(context.len() as u64).to_be_bytes());
    input.extend_from_slice(context);
    EncryptionKey(hmac_sha256(&project_key.0, &input))
}

fn hmac_sha256(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; KEY_LEN] {
    const BLOCK_LEN: usize = 64;

    let mut inner_pad = [0x36_u8; BLOCK_LEN];
    let mut outer_pad = [0x5c_u8; BLOCK_LEN];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(input);
    let mut inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(&inner_hash);
    let output = outer.finalize().into();

    inner_pad.zeroize();
    outer_pad.zeroize();
    inner_hash.zeroize();
    output
}

fn encrypt_bytes(key: &EncryptionKey, plaintext: &[u8], aad: &[u8]) -> Result<String> {
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let ciphertext = cipher_for(key)
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(B64.encode(blob))
}

fn decrypt_bytes(key: &EncryptionKey, blob: &str, aad: &[u8]) -> Result<Vec<u8>> {
    let raw = B64
        .decode(blob.trim())
        .context("Ciphertext is not valid Base64")?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        bail!(
            "Ciphertext is shorter than {} bytes; the data is corrupted",
            NONCE_LEN + TAG_LEN
        );
    }

    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes).expect("length was validated as 12 bytes");
    cipher_for(key)
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("Authenticated decryption failed"))
}

fn cipher_for(key: &EncryptionKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(key.0))
}

fn verifier_context(project: &str) -> Vec<u8> {
    encode_context(&["project-verifier", project])
}

fn secret_context(project: &str, env: &str, name: &str) -> Vec<u8> {
    encode_context(&["secret", project, env, name])
}

fn encode_context(parts: &[&str]) -> Vec<u8> {
    let mut context = b"keyben-v1".to_vec();
    for part in parts {
        context.extend_from_slice(&(part.len() as u64).to_be_bytes());
        context.extend_from_slice(part.as_bytes());
    }
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ProjectKey {
        ProjectKey([0x42; KEY_LEN])
    }

    #[test]
    fn each_secret_location_gets_a_distinct_encryption_key() {
        let project_key = test_key();
        let first = derive_encryption_key(&project_key, &secret_context("app", "dev", "TOKEN"));
        let second = derive_encryption_key(&project_key, &secret_context("app", "dev", "OTHER"));
        let verifier = derive_encryption_key(&project_key, &verifier_context("app"));

        assert_ne!(first.0, second.0);
        assert_ne!(first.0, verifier.0);
    }

    #[test]
    fn hmac_sha256_matches_a_known_vector() {
        let key = [0x0b; KEY_LEN];
        assert_eq!(
            B64.encode(hmac_sha256(&key, b"Hi There")),
            "GYpgfrRL+8aZA6Dxzyu9xboKo/PZrjwcejsWlqC2jPc="
        );
    }

    #[test]
    fn project_password_unlocks_only_with_the_correct_password() {
        let metadata = create_project_metadata("myapp", "correct horse battery staple").unwrap();
        assert!(unlock_project("myapp", "correct horse battery staple", &metadata).is_ok());
        assert!(unlock_project("myapp", "wrong password", &metadata).is_err());
        assert!(
            unlock_project("another-project", "correct horse battery staple", &metadata).is_err()
        );
    }

    #[test]
    fn secret_roundtrip() {
        let key = test_key();
        let blob =
            encrypt_secret(&key, "myapp", "prod", "DB_URL", "postgres://user:pw@db/app").unwrap();
        assert_eq!(
            decrypt_secret(&key, "myapp", "prod", "DB_URL", &blob).unwrap(),
            "postgres://user:pw@db/app"
        );
    }

    #[test]
    fn ciphertext_is_bound_to_project_environment_and_name() {
        let key = test_key();
        let blob = encrypt_secret(&key, "myapp", "dev", "TOKEN", "secret").unwrap();
        assert!(decrypt_secret(&key, "other", "dev", "TOKEN", &blob).is_err());
        assert!(decrypt_secret(&key, "myapp", "prod", "TOKEN", &blob).is_err());
        assert!(decrypt_secret(&key, "myapp", "dev", "OTHER", &blob).is_err());
    }

    #[test]
    fn nonce_is_random_so_ciphertexts_differ() {
        let key = test_key();
        let a = encrypt_secret(&key, "app", "dev", "KEY", "same").unwrap();
        let b = encrypt_secret(&key, "app", "dev", "KEY", "same").unwrap();
        assert_ne!(a, b, "each encryption should use a fresh random nonce");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let blob = encrypt_secret(&key, "app", "dev", "KEY", "secret").unwrap();
        let mut raw = B64.decode(&blob).unwrap();
        *raw.last_mut().unwrap() ^= 0x01;
        assert!(decrypt_secret(&key, "app", "dev", "KEY", &B64.encode(raw)).is_err());
    }

    #[test]
    fn empty_and_unicode_values() {
        let key = test_key();
        for value in ["", "🔑 Unicode value", "multi\nline"] {
            let blob = encrypt_secret(&key, "app", "dev", "KEY", value).unwrap();
            assert_eq!(
                decrypt_secret(&key, "app", "dev", "KEY", &blob).unwrap(),
                value
            );
        }
    }
}
