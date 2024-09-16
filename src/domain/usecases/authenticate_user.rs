//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::entities::User;
use crate::domain::repositories::EntityRepository;
use crate::{derive_key, KeyDerivation, KeyDerivationParams};
use anyhow::Error;
use base64::prelude::*;
use std::cmp;
use std::fmt;
use std::sync::Arc;

///
/// Use case to fetch a user entity from the repository, if the provided
/// password matches the recorded value.
///
pub struct AuthenticateUser {
    records: Arc<dyn EntityRepository>,
}

impl AuthenticateUser {
    pub fn new(records: Arc<dyn EntityRepository>) -> Self {
        Self { records }
    }
}

impl super::UseCase<User, Params> for AuthenticateUser {
    fn call(&self, params: Params) -> Result<User, Error> {
        if let Ok(user) = self.records.get_user(&params.username) {
            let salt = BASE64_STANDARD_NO_PAD.decode(&user.salt)?;
            let kdparams: KeyDerivationParams = Default::default();
            let secret = derive_key(&KeyDerivation::Argon2id, &params.password, &salt, &kdparams)?;
            let en_secret = BASE64_STANDARD_NO_PAD.encode(secret);
            if en_secret == user.password {
                return Ok(user);
            }
        }
        // failure on get_user is treated as "auth failure", while the errors
        // caused by decoding and encryption should be surfaced as those are
        // programming errors that need to be fixed
        Err(crate::Error::AuthenticationFailure.into())
    }
}

#[derive(Clone)]
pub struct Params {
    pub username: String,
    pub password: String,
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params(username: {})", self.username)
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
    fn test_authenticate_user_get_user_err() {
        // arrange
        let mut records = MockEntityRepository::new();
        records
            .expect_get_user()
            .returning(|_| Err(crate::Error::UserNotFound("johndoe".into())));
        // act
        let usecase = AuthenticateUser::new(Arc::new(records));
        let params = Params {
            username: "johndoe".into(),
            password: "keyboard cat".into(),
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "authentication failure");
    }

    #[test]
    fn test_authenticate_user_auth_failure() {
        // arrange
        let mut records = MockEntityRepository::new();
        records.expect_get_user().returning(|username| {
            let user_json = r#"{
                "username": "replaceme",
                "password": "Q5FXw4pfZu7a9guz3/IL2iymfqr4DNCJlXyzVo/d26o",
                "salt": "XhsqF59GAF3aesbXwRybeQ",
                "purpose": "read"
            }"#;
            let mut user: User = serde_json::from_str(&user_json)?;
            user.username = username.to_string();
            Ok(user)
        });
        // act
        let usecase = AuthenticateUser::new(Arc::new(records));
        let params = Params {
            username: "johndoe".into(),
            password: "danger mouse".into(),
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "authentication failure");
    }

    #[test]
    fn test_authenticate_user_success() {
        // arrange
        let mut records = MockEntityRepository::new();
        records.expect_get_user().returning(|username| {
            let user_json = r#"{
                "username": "replaceme",
                "password": "Q5FXw4pfZu7a9guz3/IL2iymfqr4DNCJlXyzVo/d26o",
                "salt": "XhsqF59GAF3aesbXwRybeQ",
                "purpose": "read"
            }"#;
            let mut user: User = serde_json::from_str(&user_json)?;
            user.username = username.to_string();
            Ok(user)
        });
        // act
        let usecase = AuthenticateUser::new(Arc::new(records));
        let params = Params {
            username: "johndoe".into(),
            password: "keyboard cat".into(),
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "johndoe");
    }
}
