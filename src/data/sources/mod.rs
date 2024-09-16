//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::entities::User;
use crate::Error;
#[cfg(test)]
use mockall::{automock, predicate::*};
use std::sync::Arc;

mod sqlite;

///
/// Data source for entity objects.
///
#[cfg_attr(test, automock)]
pub trait EntityDataSource: Send + Sync {
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

///
/// Type for creating the desired type of data source.
///
pub enum DataSourceType {
    /// SQLite resident in memory, not persistent.
    SqliteMemory,
    /// SQLite stored persistently to the given file path.
    SqliteFile(String),
}

///
/// Construct a data source appripriate for the given type.
///
pub fn build_data_source(dstype: DataSourceType) -> Result<Arc<dyn EntityDataSource>, Error> {
    match dstype {
        DataSourceType::SqliteMemory => {
            let source: Arc<dyn EntityDataSource> =
                Arc::new(sqlite::SQLiteEntityDataSource::new_in_memory()?);
            Ok(source)
        }
        DataSourceType::SqliteFile(path) => {
            let source: Arc<dyn EntityDataSource> =
                Arc::new(sqlite::SQLiteEntityDataSource::new(path)?);
            Ok(source)
        }
    }
}
