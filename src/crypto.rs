//! Client-side end-to-end encryption: ChaCha20-Poly1305 with a SHA-256-derived key.
//!
//! Storage format (uploaded to the server after Base64 encoding):
//! `[12-byte nonce] + [ciphertext || 16-byte Poly1305 authentication tag]`
//!
//! The server sees only the Base64 string and never handles passwords or plaintext.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use sha2::{Digest, Sha256};

/// ChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 12;
/// Poly1305 authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Derive the project-bound verification value sent to the server.
pub fn project_password_hash(project: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"keyben-project-password-v1\0");
    hasher.update((project.len() as u64).to_be_bytes());
    hasher.update(project.as_bytes());
    hasher.update(password.as_bytes());
    B64.encode(hasher.finalize())
}

/// Hash a password of any length into a 32-byte symmetric key with SHA-256.
fn cipher_for(password: &str) -> ChaCha20Poly1305 {
    let key_bytes: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    ChaCha20Poly1305::new(&Key::from(key_bytes))
}

/// Encrypt plaintext and return the Base64-encoded `nonce || ciphertext || tag`.
pub fn encrypt(password: &str, plaintext: &str) -> Result<String> {
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();

    let ciphertext = cipher_for(password)
        .encrypt(&Nonce::from(nonce_bytes), plaintext.as_bytes())
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(B64.encode(blob))
}

/// Decrypt a Base64 string produced by [`encrypt`].
pub fn decrypt(password: &str, blob: &str) -> Result<String> {
    let raw = B64
        .decode(blob.trim())
        .context("Base64 decoding failed: the data was not written by this tool")?;

    if raw.len() < NONCE_LEN + TAG_LEN {
        bail!(
            "Ciphertext is shorter than {} bytes; the data is corrupted",
            NONCE_LEN + TAG_LEN
        );
    }

    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes).expect("length was validated as 12 bytes");

    let plaintext = cipher_for(password)
        .decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed: incorrect password or tampered data"))?;

    String::from_utf8(plaintext).context("Decrypted result is not valid UTF-8 text")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let blob = encrypt("hunter2", "postgres://user:pw@db/app").unwrap();
        assert_eq!(
            decrypt("hunter2", &blob).unwrap(),
            "postgres://user:pw@db/app"
        );
    }

    #[test]
    fn nonce_is_random_so_ciphertexts_differ() {
        let a = encrypt("pw", "same").unwrap();
        let b = encrypt("pw", "same").unwrap();
        assert_ne!(a, b, "each encryption should use a fresh random nonce");
        assert_eq!(decrypt("pw", &a).unwrap(), decrypt("pw", &b).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let blob = encrypt("right", "secret").unwrap();
        assert!(decrypt("wrong", &blob).is_err());
    }

    #[test]
    fn project_password_hash_is_bound_to_project_and_password() {
        let hash = project_password_hash("app", "right");
        assert_eq!(hash, project_password_hash("app", "right"));
        assert_ne!(hash, project_password_hash("other", "right"));
        assert_ne!(hash, project_password_hash("app", "wrong"));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let blob = encrypt("pw", "secret").unwrap();
        let mut raw = B64.decode(&blob).unwrap();
        *raw.last_mut().unwrap() ^= 0x01;
        assert!(decrypt("pw", &B64.encode(raw)).is_err());
    }

    #[test]
    fn empty_and_unicode_values() {
        for value in ["", "🔑 Unicode value", "multi\nline"] {
            let blob = encrypt("pw", value).unwrap();
            assert_eq!(decrypt("pw", &blob).unwrap(), value);
        }
    }
}
