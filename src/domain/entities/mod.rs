//
// Copyright (c) 2024 Nathan Fiedler
//
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp;
use std::collections::HashMap;
use std::fmt;

///
/// User entity.
///
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    /// Unique identifier for the user entity.
    pub username: String,
    /// Derived key from the plaintext passphrase, in base64.
    pub password: String,
    /// Random salt used to encrypt the password, in base64.
    pub salt: String,
    #[serde(flatten)]
    pub claims: HashMap<String, Value>,
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User({})", self.username)
    }
}

impl cmp::PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

impl cmp::Eq for User {}

///
/// Generated access token with expiration in seconds.
///
#[derive(Deserialize, Serialize)]
pub struct WebToken {
    /// Type of the access token (usually "bearer").
    pub token_type: String,
    /// Encoded access token.
    pub access_token: String,
    /// Expiration time in seconds.
    pub expires_in: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Error;

    #[test]
    fn test_user_equality() -> Result<(), Error> {
        let john1_json = r#"{
            "username": "johndoe",
            "password": "Q5FXw4pfZu7a9guz3/IL2iymfqr4DNCJlXyzVo/d26o",
            "salt": "XhsqF59GAF3aesbXwRybeQ",
            "purpose": "read"
        }"#;
        let john1: User = serde_json::from_str(&john1_json)?;
        let john2_json = r#"{
            "username": "johndoe",
            "password": "4+98tFPIAYN2IRmbJJ99eWnnXq/ptWdWw6u3GsD1qpk",
            "salt": "q9XQODnzdGP0QjJjn/IspA",
            "purpose": "read"
        }"#;
        let john2: User = serde_json::from_str(&john2_json)?;
        assert!(john1 == john2);
        assert!(john2 == john1);
        let jane1_json = r#"{
            "username": "janedoe",
            "password": "WChUFcOvZ2QN87OmyKE1Ohvqa5EZvgajXd2cwWqP5ec",
            "salt": "EzQBEhbg3RywcnI4coEzwQ",
            "purpose": "write"
        }"#;
        let jane1: User = serde_json::from_str(&jane1_json)?;
        assert!(john1 != jane1);

        Ok(())
    }
}
