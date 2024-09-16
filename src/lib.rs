//
// Copyright (c) 2024 Nathan Fiedler
//
use std::fmt;

pub mod data;
pub mod domain;

///
/// This type represents various errors that can occur within this crate.
///
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error occurred during an I/O related operation.
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),
    /// Error occurred during an SQL related operation.
    #[error("SQL error: {0}")]
    SQLError(#[from] rusqlite::Error),
    /// Error occurred while (de)serializing JSON.
    #[error("JSON error: {0}")]
    JSONError(#[from] serde_json::Error),
    /// User record for given identifier was not found.
    #[error("no such user: {0}")]
    UserNotFound(String),
    /// Authentication failed for one reason or another.
    #[error("authentication failure")]
    AuthenticationFailure,
    /// Something happened when operating on the database.
    #[error("error resulting from database operation")]
    Database,
    /// Key derivation function in archive is not supported.
    #[error("unsupported key derivation function {0}")]
    UnsupportedKeyAlgo(u8),
    /// An unexpected error occurred that would otherwise have been a panic.
    #[error("something bad happened: {0}")]
    InternalError(String),
}

///
/// Algorithm for deriving a key from a passphrase.
///
#[derive(Clone, Debug, PartialEq)]
pub enum KeyDerivation {
    /// No derivation function, _default_
    None,
    /// Use the Argon2id KDF
    Argon2id,
}

impl fmt::Display for KeyDerivation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyDerivation::None => write!(f, "none"),
            KeyDerivation::Argon2id => write!(f, "Argon2id"),
        }
    }
}

impl Into<u8> for KeyDerivation {
    fn into(self) -> u8 {
        match self {
            KeyDerivation::None => 0,
            KeyDerivation::Argon2id => 1,
        }
    }
}

impl TryFrom<u8> for KeyDerivation {
    type Error = self::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyDerivation::None),
            1 => Ok(KeyDerivation::Argon2id),
            v => Err(self::Error::UnsupportedKeyAlgo(v)),
        }
    }
}

///
/// Parameters to be provided to the key derivation function. These are fairly
/// common to most such functions.
///
#[derive(Clone, Debug)]
pub struct KeyDerivationParams {
    /// Number of iterations for key derivation function
    time_cost: u32,
    /// Number of 1 kb memory blocks for key derivation function
    mem_cost: u32,
    /// Degree of parallelism for key derivation function
    para_cost: u32,
    /// Output length for key derivation function
    tag_length: u32,
}

impl KeyDerivationParams {
    ///
    /// Set the time cost from the optional value found in the archive.
    ///
    pub fn time_cost(mut self, time_cost: Option<u32>) -> Self {
        if let Some(tc) = time_cost {
            self.time_cost = tc;
        }
        self
    }

    ///
    /// Set the memory cost from the optional value found in the archive.
    ///
    pub fn mem_cost(mut self, mem_cost: Option<u32>) -> Self {
        if let Some(tc) = mem_cost {
            self.mem_cost = tc;
        }
        self
    }

    ///
    /// Set the degree of parallelism from the optional value found in the
    /// archive.
    ///
    pub fn para_cost(mut self, para_cost: Option<u32>) -> Self {
        if let Some(tc) = para_cost {
            self.para_cost = tc;
        }
        self
    }

    ///
    /// Set the output length from the optional value found in the archive.
    ///
    pub fn tag_length(mut self, tag_length: Option<u32>) -> Self {
        if let Some(tc) = tag_length {
            self.tag_length = tc;
        }
        self
    }
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            time_cost: 2,
            mem_cost: 19_456,
            para_cost: 1,
            tag_length: 32,
        }
    }
}

///
/// Generate a salt appropriate for the given key derivation function.
///
pub fn generate_salt(kd: &KeyDerivation) -> Result<Vec<u8>, Error> {
    if *kd == KeyDerivation::Argon2id {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        let mut buf: Vec<u8> = vec![0; salt.len()];
        let bytes = salt
            .decode_b64(&mut buf)
            .map_err(|e| Error::InternalError(format!("argon2 failed: {}", e)))?;
        Ok(bytes.to_vec())
    } else {
        // something went terribly wrong
        Err(Error::UnsupportedKeyAlgo(255))
    }
}

///
/// Produce a secret key from a passphrase and random salt.
///
pub fn derive_key(
    kd: &KeyDerivation,
    password: &str,
    salt: &[u8],
    params: &KeyDerivationParams,
) -> Result<Vec<u8>, Error> {
    if *kd == KeyDerivation::Argon2id {
        use argon2::{Algorithm, ParamsBuilder, Version};
        let mut output: Vec<u8> = vec![0; params.tag_length as usize];
        let mut builder: ParamsBuilder = ParamsBuilder::new();
        builder.t_cost(params.time_cost);
        builder.m_cost(params.mem_cost);
        builder.p_cost(params.para_cost);
        builder.output_len(params.tag_length as usize);
        let kdf = builder
            .context(Algorithm::Argon2id, Version::V0x13)
            .map_err(|e| Error::InternalError(format!("argon2 failed: {}", e)))?;
        kdf.hash_password_into(password.as_bytes(), salt, &mut output.as_mut_slice())
            .map_err(|e| Error::InternalError(format!("argon2 failed: {}", e)))?;
        Ok(output)
    } else {
        // something went terribly wrong
        Err(Error::UnsupportedKeyAlgo(255))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_argon2() -> Result<(), Error> {
        let password = "keyboard cat";
        let salt = generate_salt(&KeyDerivation::Argon2id)?;
        let params: KeyDerivationParams = Default::default();
        let secret = derive_key(&KeyDerivation::Argon2id, password, &salt, &params)?;
        assert_eq!(secret.len(), 32);
        assert_ne!(password.as_bytes(), secret.as_slice());
        Ok(())
    }
}
