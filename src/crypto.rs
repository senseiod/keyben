//! 客户端侧的端到端加解密：ChaCha20-Poly1305 + SHA-256 派生密钥。
//!
//! 存储格式（Base64 编码后上传服务端）：
//! `[12 字节 Nonce] + [密文 || 16 字节 Poly1305 认证标签]`
//!
//! 服务端只看到 Base64 字符串，永远接触不到密码与明文。

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use sha2::{Digest, Sha256};

/// ChaCha20-Poly1305 的 Nonce 长度（字节）。
const NONCE_LEN: usize = 12;
/// Poly1305 认证标签长度（字节）。
const TAG_LEN: usize = 16;

/// 用 SHA-256 把任意长度的密码哈希成 32 字节对称密钥。
fn cipher_for(password: &str) -> ChaCha20Poly1305 {
    let key_bytes: [u8; 32] = Sha256::digest(password.as_bytes()).into();
    ChaCha20Poly1305::new(&Key::from(key_bytes))
}

/// 加密明文，返回 Base64 编码的 `Nonce || 密文 || Tag`。
pub fn encrypt(password: &str, plaintext: &str) -> Result<String> {
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();

    let ciphertext = cipher_for(password)
        .encrypt(&Nonce::from(nonce_bytes), plaintext.as_bytes())
        .map_err(|_| anyhow!("加密失败"))?;

    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(B64.encode(blob))
}

/// 解密 [`encrypt`] 产出的 Base64 字符串。
pub fn decrypt(password: &str, blob: &str) -> Result<String> {
    let raw = B64
        .decode(blob.trim())
        .context("Base64 解码失败：数据不是本工具写入的格式")?;

    if raw.len() < NONCE_LEN + TAG_LEN {
        bail!("密文长度不足 {} 字节，数据已损坏", NONCE_LEN + TAG_LEN);
    }

    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes).expect("已校验长度为 12 字节");

    let plaintext = cipher_for(password)
        .decrypt(&nonce, ciphertext)
        .map_err(|_| anyhow!("解密失败：密码错误或数据已被篡改"))?;

    String::from_utf8(plaintext).context("解密结果不是合法的 UTF-8 文本")
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
        assert_ne!(a, b, "每次加密都应使用新的随机 Nonce");
        assert_eq!(decrypt("pw", &a).unwrap(), decrypt("pw", &b).unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let blob = encrypt("right", "secret").unwrap();
        assert!(decrypt("wrong", &blob).is_err());
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
        for value in ["", "🔑 中文 值", "multi\nline"] {
            let blob = encrypt("pw", value).unwrap();
            assert_eq!(decrypt("pw", &blob).unwrap(), value);
        }
    }
}
