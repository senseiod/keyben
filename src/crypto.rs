//! Client-side end-to-end encryption (v2): Argon2id key derivation + envelope encryption.
//!
//! Key schedule (all derivation happens on the client; the server never sees the password):
//! ```text
//! master_key  = Argon2id(password, salt, m=64MiB, t=3, p=4)      (32 bytes)
//! enc_key     = HKDF-SHA256(master_key, info="keyben v1 kek")    (wraps the DEK)
//! auth_secret = HKDF-SHA256(master_key, info="keyben v1 auth")   (sent to the server)
//! ```
//! Each project has one random 32-byte data-encryption key (DEK) that encrypts every
//! secret. The DEK is wrapped with `enc_key`, so changing the password only re-wraps the
//! DEK and leaves the secret ciphertext untouched.
//!
//! Blob format (Base64-encoded): `[24-byte XNonce] + [ciphertext || 16-byte Poly1305 tag]`.
//! Every AEAD operation binds associated data (project / env / name) so ciphertext cannot be
//! moved between locations.

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Argon2 salt length in bytes (public, stored alongside the project).
pub const SALT_LEN: usize = 16;
/// Symmetric key / DEK length in bytes.
const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 extended nonce length in bytes.
const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length in bytes.
const TAG_LEN: usize = 16;

/// Generate a random Argon2 salt for a new project or configuration file.
pub fn generate_salt() -> [u8; SALT_LEN] {
    rand::random()
}

/// Generate a random 32-byte data-encryption key for a new project.
pub fn generate_dek() -> [u8; KEY_LEN] {
    rand::random()
}

/// The per-project subkeys derived from a password and its salt.
pub struct ProjectKeys {
    /// Wraps and unwraps the project DEK; never leaves the client.
    enc_key: [u8; KEY_LEN],
    /// Proves knowledge of the password to the server.
    auth_secret: [u8; KEY_LEN],
}

impl ProjectKeys {
    /// Base64 `auth_secret` sent in the request header.
    pub fn auth_secret_b64(&self) -> String {
        B64.encode(self.auth_secret)
    }

    /// Base64 `SHA-256(auth_secret)` stored on the server for constant-time comparison.
    pub fn auth_hash_b64(&self) -> String {
        B64.encode(Sha256::digest(self.auth_secret))
    }
}

/// Derive the per-project subkeys from the password and its salt.
pub fn derive_project_keys(password: &str, salt: &[u8]) -> Result<ProjectKeys> {
    let master_key = argon2id_key(password, salt)?;
    // The two info labels domain-separate the subkeys: neither reveals the other.
    Ok(ProjectKeys {
        enc_key: hkdf_subkey(&master_key, b"keyben v1 kek"),
        auth_secret: hkdf_subkey(&master_key, b"keyben v1 auth"),
    })
}

/// Derive a raw 32-byte key from a password and salt with Argon2id.
///
/// Used directly for the local configuration file, and internally as the project master key.
pub fn argon2id_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    // m = 64 MiB, t = 3 iterations, p = 4 lanes.
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
        .map_err(|err| anyhow!("Invalid Argon2 parameters: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| anyhow!("Argon2 key derivation failed: {err}"))?;
    Ok(key)
}

/// Expand the master key into a domain-separated 32-byte subkey with HKDF-SHA256.
fn hkdf_subkey(master_key: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut subkey = [0u8; KEY_LEN];
    hkdf.expand(info, &mut subkey)
        .expect("32 is a valid HKDF-SHA256 output length");
    subkey
}

// -------------------------------------------------------------- AEAD primitives

/// Build the associated data for a wrapped DEK: `project || 0x00 || "wrap-v1"`.
fn wrap_aad(project: &str) -> Vec<u8> {
    aad(&[project.as_bytes(), b"wrap-v1"])
}

/// Build the associated data for a secret: `project || 0x00 || env || 0x00 || name || 0x00 || "secret-v1"`.
fn secret_aad(project: &str, env: &str, name: &str) -> Vec<u8> {
    aad(&[
        project.as_bytes(),
        env.as_bytes(),
        name.as_bytes(),
        b"secret-v1",
    ])
}

/// Join parts with a `0x00` separator; the separator keeps field boundaries unambiguous.
fn aad(parts: &[&[u8]]) -> Vec<u8> {
    parts.join(&0u8)
}

/// Encrypt `plaintext` under `key`, binding `associated_data`, into Base64 `nonce || ciphertext || tag`.
fn seal(key: &[u8; KEY_LEN], associated_data: &[u8], plaintext: &[u8]) -> Result<String> {
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(B64.encode(blob))
}

/// Decrypt a Base64 blob produced by [`seal`], verifying `associated_data`.
fn open(key: &[u8; KEY_LEN], associated_data: &[u8], blob: &str) -> Result<Vec<u8>> {
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
    let nonce = XNonce::try_from(nonce_bytes).expect("length was validated as 24 bytes");
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| anyhow!("Decryption failed: incorrect password or tampered data"))
}

// ----------------------------------------------------------------- Envelope API

/// Wrap a project DEK with the password-derived `enc_key`, bound to the project name.
pub fn wrap_dek(keys: &ProjectKeys, dek: &[u8; KEY_LEN], project: &str) -> Result<String> {
    seal(&keys.enc_key, &wrap_aad(project), dek)
}

/// Unwrap a project DEK previously produced by [`wrap_dek`].
pub fn unwrap_dek(keys: &ProjectKeys, wrapped: &str, project: &str) -> Result<[u8; KEY_LEN]> {
    let dek = open(&keys.enc_key, &wrap_aad(project), wrapped).context(
        "Failed to unwrap the project key; incorrect password or corrupted project metadata",
    )?;
    dek.try_into()
        .map_err(|_| anyhow!("Unwrapped project key has an invalid length"))
}

/// Encrypt a secret value with the project DEK, bound to `(project, env, name)`.
pub fn encrypt_secret(
    dek: &[u8; KEY_LEN],
    project: &str,
    env: &str,
    name: &str,
    plaintext: &str,
) -> Result<String> {
    seal(dek, &secret_aad(project, env, name), plaintext.as_bytes())
}

/// Decrypt a secret value produced by [`encrypt_secret`].
pub fn decrypt_secret(
    dek: &[u8; KEY_LEN],
    project: &str,
    env: &str,
    name: &str,
    blob: &str,
) -> Result<String> {
    let plaintext = open(dek, &secret_aad(project, env, name), blob)?;
    String::from_utf8(plaintext).context("Decrypted result is not valid UTF-8 text")
}

// -------------------------------------------------------- Local config-file API

/// Encrypt a single configuration field (server URL or token) with an Argon2id-derived key.
///
/// `role` (for example `"cfg-server-v2"`) is bound as associated data so one field's
/// ciphertext cannot be swapped into another field.
pub fn config_encrypt(key: &[u8; 32], role: &str, plaintext: &str) -> Result<String> {
    seal(key, role.as_bytes(), plaintext.as_bytes())
}

/// Decrypt a configuration field produced by [`config_encrypt`].
pub fn config_decrypt(key: &[u8; 32], role: &str, blob: &str) -> Result<String> {
    let plaintext = open(key, role.as_bytes(), blob)?;
    String::from_utf8(plaintext).context("Decrypted configuration value is not valid UTF-8 text")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    #[test]
    fn secret_roundtrip_through_envelope() {
        let keys = derive_project_keys("hunter2", &SALT).unwrap();
        let dek = generate_dek();
        let wrapped = wrap_dek(&keys, &dek, "app").unwrap();

        let unwrapped = unwrap_dek(&keys, &wrapped, "app").unwrap();
        assert_eq!(unwrapped, dek);

        let blob = encrypt_secret(&dek, "app", "dev", "DB_URL", "postgres://u:p@db/app").unwrap();
        assert_eq!(
            decrypt_secret(&dek, "app", "dev", "DB_URL", &blob).unwrap(),
            "postgres://u:p@db/app"
        );
    }

    #[test]
    fn nonce_is_random_so_ciphertexts_differ() {
        let dek = generate_dek();
        let a = encrypt_secret(&dek, "app", "dev", "K", "same").unwrap();
        let b = encrypt_secret(&dek, "app", "dev", "K", "same").unwrap();
        assert_ne!(a, b, "each encryption should use a fresh random nonce");
        assert_eq!(
            decrypt_secret(&dek, "app", "dev", "K", &a).unwrap(),
            decrypt_secret(&dek, "app", "dev", "K", &b).unwrap()
        );
    }

    #[test]
    fn wrong_password_cannot_unwrap_dek() {
        let dek = generate_dek();
        let right = derive_project_keys("right", &SALT).unwrap();
        let wrapped = wrap_dek(&right, &dek, "app").unwrap();
        let wrong = derive_project_keys("wrong", &SALT).unwrap();
        assert!(unwrap_dek(&wrong, &wrapped, "app").is_err());
    }

    #[test]
    fn secret_aad_binds_project_env_and_name() {
        let dek = generate_dek();
        let blob = encrypt_secret(&dek, "app", "dev", "DB_URL", "secret").unwrap();
        // Same DEK but a different location must fail authentication (anti copy-paste).
        assert!(decrypt_secret(&dek, "app", "prod", "DB_URL", &blob).is_err());
        assert!(decrypt_secret(&dek, "app", "dev", "OTHER", &blob).is_err());
        assert!(decrypt_secret(&dek, "other", "dev", "DB_URL", &blob).is_err());
        assert_eq!(
            decrypt_secret(&dek, "app", "dev", "DB_URL", &blob).unwrap(),
            "secret"
        );
    }

    #[test]
    fn wrap_aad_binds_project() {
        let keys = derive_project_keys("pw", &SALT).unwrap();
        let dek = generate_dek();
        let wrapped = wrap_dek(&keys, &dek, "app").unwrap();
        assert!(unwrap_dek(&keys, &wrapped, "other").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = generate_dek();
        let blob = encrypt_secret(&dek, "app", "dev", "K", "secret").unwrap();
        let mut raw = B64.decode(&blob).unwrap();
        *raw.last_mut().unwrap() ^= 0x01;
        assert!(decrypt_secret(&dek, "app", "dev", "K", &B64.encode(raw)).is_err());
    }

    #[test]
    fn auth_secret_matches_stored_hash_and_differs_by_salt() {
        let keys = derive_project_keys("pw", &SALT).unwrap();
        let sent = B64.decode(keys.auth_secret_b64()).unwrap();
        assert_eq!(B64.encode(Sha256::digest(&sent)), keys.auth_hash_b64());

        let other_salt = [9u8; SALT_LEN];
        let other = derive_project_keys("pw", &other_salt).unwrap();
        assert_ne!(keys.auth_hash_b64(), other.auth_hash_b64());
    }

    #[test]
    fn empty_and_unicode_values() {
        let dek = generate_dek();
        for value in ["", "🔑 Unicode value", "multi\nline"] {
            let blob = encrypt_secret(&dek, "app", "dev", "K", value).unwrap();
            assert_eq!(
                decrypt_secret(&dek, "app", "dev", "K", &blob).unwrap(),
                value
            );
        }
    }

    #[test]
    fn config_field_roundtrip_with_role_binding() {
        let key = argon2id_key("cfg-pw", &SALT).unwrap();
        let blob = config_encrypt(&key, "cfg-server-v2", "https://example.com").unwrap();
        assert_eq!(
            config_decrypt(&key, "cfg-server-v2", &blob).unwrap(),
            "https://example.com"
        );
        // Wrong role (field swap) must fail.
        assert!(config_decrypt(&key, "cfg-token-v2", &blob).is_err());
    }
}
