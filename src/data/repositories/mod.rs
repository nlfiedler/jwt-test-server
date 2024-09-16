//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::data::sources::EntityDataSource;
use crate::domain::entities::User;
use crate::domain::repositories::EntityRepository;
use crate::Error;
use std::sync::Arc;

///
/// Default implementation of the entity repository.
///
pub struct EntityRepositoryImpl {
    datasource: Arc<dyn EntityDataSource>,
}

impl EntityRepositoryImpl {
    pub fn new(datasource: Arc<dyn EntityDataSource>) -> Self {
        Self { datasource }
    }
}

impl EntityRepository for EntityRepositoryImpl {
    fn count_users(&self) -> Result<u32, Error> {
        self.datasource.count_users()
    }

    fn get_user(&self, user_id: &str) -> Result<User, Error> {
        self.datasource.get_user(user_id)
    }

    fn insert_user(&self, user: User) -> Result<(), Error> {
        self.datasource.insert_user(user)
    }

    fn delete_user(&self, user_id: &str) -> Result<bool, Error> {
        self.datasource.delete_user(user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sources::MockEntityDataSource;
    use serde_json::Value;
    use std::collections::HashMap;

    #[test]
    fn test_count_users_err() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source
            .expect_count_users()
            .returning(|| Err(Error::InternalError("oh no".into())));

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.count_users();

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "something bad happened: oh no"
        );
    }

    #[test]
    fn test_count_users_ok() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source.expect_count_users().returning(|| Ok(10));

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.count_users();

        // assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn test_get_user_err() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source
            .expect_get_user()
            .returning(|_| Err(Error::InternalError("oh no".into())));

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.get_user("foobar");

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "something bad happened: oh no"
        );
    }

    #[test]
    fn test_get_user_ok() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source.expect_get_user().returning(|user_id| {
            let john_json = r#"{
                "username": "replaceme",
                "password": "Q5FXw4pfZu7a9guz3/IL2iymfqr4DNCJlXyzVo/d26o",
                "salt": "XhsqF59GAF3aesbXwRybeQ",
                "purpose": "read"
            }"#;
            let mut john: User = serde_json::from_str(&john_json)?;
            john.username = user_id.to_string();
            Ok(john)
        });

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.get_user("johndoe");

        // assert
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "johndoe");
        assert!(user.claims.contains_key("purpose"));
        assert_eq!(
            user.claims.get("purpose").map(|v| v.to_string()),
            Some("\"read\"".into())
        );
    }

    #[test]
    fn test_insert_user_err() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source
            .expect_insert_user()
            .returning(|_| Err(Error::InternalError("oh no".into())));
        let mut claims: HashMap<String, Value> = HashMap::new();
        claims.insert("purpose".into(), Value::String("read".into()));
        let user = User {
            username: "johndoe".into(),
            password: "keyboard cat".into(),
            salt: "random salt".into(),
            claims,
        };

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.insert_user(user);

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "something bad happened: oh no"
        );
    }

    #[test]
    fn test_insert_user_ok() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source.expect_insert_user().returning(|_| Ok(()));
        let mut claims: HashMap<String, Value> = HashMap::new();
        claims.insert("purpose".into(), Value::String("read".into()));
        let user = User {
            username: "johndoe".into(),
            password: "keyboard cat".into(),
            salt: "random salt".into(),
            claims,
        };

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.insert_user(user);

        // assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_user_err() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source
            .expect_delete_user()
            .returning(|_| Err(Error::InternalError("oh no".into())));

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.delete_user("foobar");

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "something bad happened: oh no"
        );
    }

    #[test]
    fn test_delete_user_false() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source.expect_delete_user().returning(|_| Ok(false));

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.delete_user("johndoe");

        // assert
        assert!(result.is_ok());
        let deleted = result.unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_delete_user_true() {
        // arrange
        let mut source = MockEntityDataSource::new();
        source.expect_delete_user().returning(|_| Ok(true));

        // act
        let repo = EntityRepositoryImpl::new(Arc::new(source));
        let result = repo.delete_user("johndoe");

        // assert
        assert!(result.is_ok());
        let deleted = result.unwrap();
        assert!(deleted);
    }
}
