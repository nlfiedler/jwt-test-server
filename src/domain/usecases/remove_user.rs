//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::repositories::EntityRepository;
use anyhow::Error;
use std::cmp;
use std::fmt;

///
/// Use case to remove a user record from the repository.
///
/// Returns `true` if a matching user record was removed.
///
pub struct RemoveUser {
    records: Box<dyn EntityRepository>,
}

impl RemoveUser {
    pub fn new(records: Box<dyn EntityRepository>) -> Self {
        Self { records }
    }
}

impl super::UseCase<bool, Params> for RemoveUser {
    fn call(&self, params: Params) -> Result<bool, Error> {
        let deleted = self.records.delete_user(&params.user_id)?;
        Ok(deleted)
    }
}

#[derive(Clone)]
pub struct Params {
    /// Identifier of user to be removed.
    pub user_id: String,
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params(user: {})", self.user_id)
    }
}

impl cmp::PartialEq for Params {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
    }
}

impl cmp::Eq for Params {}

#[cfg(test)]
mod tests {
    use super::super::UseCase;
    use super::*;
    use crate::domain::repositories::MockEntityRepository;

    #[test]
    fn test_remove_user_err() {
        // arrange
        let mut records = MockEntityRepository::new();
        records
            .expect_delete_user()
            .returning(|_| Err(crate::Error::InternalError("oh no".into())));
        // act
        let usecase = RemoveUser::new(Box::new(records));
        let params = Params {
            user_id: "foobar".into(),
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
    fn test_remove_user_false() {
        // arrange
        let mut records = MockEntityRepository::new();
        records.expect_delete_user().returning(|_| Ok(false));
        // act
        let usecase = RemoveUser::new(Box::new(records));
        let params = Params {
            user_id: "johndoe".into(),
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_remove_user_true() {
        // arrange
        let mut records = MockEntityRepository::new();
        records.expect_delete_user().returning(|_| Ok(true));
        // act
        let usecase = RemoveUser::new(Box::new(records));
        let params = Params {
            user_id: "johndoe".into(),
        };
        let result = usecase.call(params);

        // assert
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
