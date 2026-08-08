//! JSON types shared by the client and server.

use serde::{Deserialize, Serialize};

pub const KDF_ALGORITHM: &str = "argon2id";
pub const KDF_VERSION: u32 = 0x13;
pub const KDF_MEMORY_COST: u32 = 65_536;
pub const KDF_TIME_COST: u32 = 3;
pub const KDF_PARALLELISM: u32 = 1;
pub const PROJECT_SALT_LEN: usize = 16;
pub const PROJECT_VERIFIER_BLOB_LEN: usize = 54;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct KdfConfig {
    pub algorithm: String,
    pub version: u32,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub salt: String,
}

impl KdfConfig {
    pub fn argon2id(salt: String) -> Self {
        Self {
            algorithm: KDF_ALGORITHM.to_owned(),
            version: KDF_VERSION,
            memory_cost: KDF_MEMORY_COST,
            time_cost: KDF_TIME_COST,
            parallelism: KDF_PARALLELISM,
            salt,
        }
    }

    pub fn is_supported(&self) -> bool {
        self.algorithm == KDF_ALGORITHM
            && self.version == KDF_VERSION
            && self.memory_cost == KDF_MEMORY_COST
            && self.time_cost == KDF_TIME_COST
            && self.parallelism == KDF_PARALLELISM
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProjectMetadata {
    pub kdf: KdfConfig,
    pub verifier: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub kdf: KdfConfig,
    pub verifier: String,
}
