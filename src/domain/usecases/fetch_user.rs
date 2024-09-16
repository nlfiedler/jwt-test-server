//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::entities::User;
use crate::domain::repositories::EntityRepository;
use anyhow::Error;
use std::cmp;
use std::fmt;

///
/// Use case to retreive a user record from the repository.
///
pub struct FetchUser {
    records: Box<dyn EntityRepository>,
}

impl FetchUser {
    pub fn new(records: Box<dyn EntityRepository>) -> Self {
        Self { records }
    }
}

impl super::UseCase<User, Params> for FetchUser {
    fn call(&self, params: Params) -> Result<User, Error> {
        let user = self.records.get_user(&params.username)?;
        Ok(user)
    }
}

#[derive(Clone)]
pub struct Params {
    /// Identifier of user to be retrieved.
    pub username: String,
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
    fn test_fetch_user_err() {
        // arrange
        let mut records = MockEntityRepository::new();
        records
            .expect_get_user()
            .returning(|_| Err(crate::Error::InternalError("oh no".into())));
        // act
        let usecase = FetchUser::new(Box::new(records));
        let params = Params { username: "foobar".into() };
        let result = usecase.call(params);

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "something bad happened: oh no"
        );
    }

    #[test]
    fn test_fetch_user_ok() {
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
        let usecase = FetchUser::new(Box::new(records));
        let params = Params { username: "johndoe".into() };
        let result = usecase.call(params);

        // assert
        assert!(result.is_ok());
        let new_user = result.unwrap();
        assert_eq!(new_user.username, "johndoe");
    }
}
