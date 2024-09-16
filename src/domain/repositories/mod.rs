//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::entities::User;
use crate::Error;
#[cfg(test)]
use mockall::{automock, predicate::*};

///
/// Repository for entities.
///
#[cfg_attr(test, automock)]
pub trait EntityRepository: Send {
    /// Return the number of user records.
    fn count_users(&self) -> Result<u32, Error>;

    /// Retrieve the user record with the given identifier.
    fn get_user(&self, user_id: &str) -> Result<User, Error>;

    /// Insert or update the given user entity.
    fn insert_user(&self, user: User) -> Result<(), Error>;

    /// Delete the user record with the given identifier.
    ///
    /// Returns `true` if the record was removed, `false` otherwise.
    fn delete_user(&self, user_id: &str) -> Result<bool, Error>;
}
