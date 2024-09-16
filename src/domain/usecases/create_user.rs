//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::entities::User;
use crate::domain::repositories::EntityRepository;
use crate::{derive_key, generate_salt, KeyDerivation, KeyDerivationParams};
use anyhow::Error;
use base64::prelude::*;
use serde_json::Value;
use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

///
/// Use case to create a record for a user and add to the repository.
///
pub struct CreateUser {
    records: Arc<dyn EntityRepository>,
}

impl CreateUser {
    pub fn new(records: Arc<dyn EntityRepository>) -> Self {
        Self { records }
    }
}

impl super::UseCase<User, Params> for CreateUser {
    fn call(&self, params: Params) -> Result<User, Error> {
        let salt = generate_salt(&KeyDerivation::Argon2id)?;
        let kdparams: KeyDerivationParams = Default::default();
        let secret = derive_key(&KeyDerivation::Argon2id, &params.password, &salt, &kdparams)?;
        let user = User {
            username: params.username,
            password: BASE64_STANDARD_NO_PAD.encode(secret),
            salt: BASE64_STANDARD_NO_PAD.encode(salt),
            claims: params.claims,
        };
        self.records.insert_user(user.clone())?;
        Ok(user)
    }
}

#[derive(Clone)]
pub struct Params {
    /// Unique identifier for the user entity.
    pub username: String,
    /// Plaintext password.
    pub password: String,
    /// Additional fields associated with the user.
    pub claims: HashMap<String, Value>,
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params(user: {})", self.username)
    }
}

impl cmp::PartialEq for Params {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username
    }
}

impl cmp::Eq for Params {}

#[cfg(test)]
mod tests {
    use super::super::UseCase;
    use super::*;
    use crate::domain::repositories::MockEntityRepository;

    #[test]
    fn test_create_user_err() {
        // arrange
        let mut records = MockEntityRepository::new();
        records
            .expect_insert_user()
            .returning(|_| Err(crate::Error::InternalError("oh no".into())));
        let mut input_claims: HashMap<String, Value> = HashMap::new();
        input_claims.insert("purpose".into(), Value::String("read".into()));
        // act
        let usecase = CreateUser::new(Arc::new(records));
        let params = Params {
            username: "johndoe".into(),
            password: "keyboard cat".into(),
            claims: input_claims,
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "something bad happened: oh no"
        );
    }

    #[test]
    fn test_create_user_ok() {
        // arrange
        let mut records = MockEntityRepository::new();
        records.expect_insert_user().returning(|_| Ok(()));
        let mut input_claims: HashMap<String, Value> = HashMap::new();
        input_claims.insert("purpose".into(), Value::String("read".into()));
        // act
        let usecase = CreateUser::new(Arc::new(records));
        let params = Params {
            username: "johndoe".into(),
            password: "keyboard cat".into(),
            claims: input_claims,
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_ok());
        let new_user = result.unwrap();
        assert_eq!(new_user.username, "johndoe");
        let result = BASE64_STANDARD_NO_PAD.decode(new_user.salt);
        assert!(result.is_ok());
        let salt = result.unwrap();
        assert_eq!(salt.len(), 16);
        let result = BASE64_STANDARD_NO_PAD.decode(new_user.password);
        assert!(result.is_ok());
        let password = result.unwrap();
        assert_eq!(password.len(), 32);
    }
}
