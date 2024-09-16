//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::data::sources::EntityDataSource;
use crate::domain::entities::User;
use crate::Error;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

///
/// Data source implementation backed by an SQLite database.
///
pub struct SQLiteEntityDataSource {
    // database connection
    conn: Arc<Mutex<Connection>>,
}

impl SQLiteEntityDataSource {
    /// Construct an SQLite-based data source that will be stored at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let conn = Connection::open(path)?;
        create_tables(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Construct an SQLite-based data source that will be memory resident.
    pub fn new_in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory()?;
        create_tables(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl EntityDataSource for SQLiteEntityDataSource {
    fn count_users(&self) -> Result<u32, Error> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare("SELECT COUNT(*) FROM user")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            // mysterious failure
            Err(Error::Database)
        }
    }

    fn get_user(&self, user_id: &str) -> Result<User, Error> {
        let db = self.conn.lock().unwrap();
        let mut stmt =
            db.prepare("SELECT username, password, salt, claims FROM user WHERE username = ?")?;
        let mut rows = stmt.query([user_id])?;
        if let Some(row) = rows.next()? {
            let claims: String = row.get(3)?;
            let extra: HashMap<String, Value> = serde_json::from_str(&claims)?;
            Ok(User {
                username: row.get(0)?,
                password: row.get(1)?,
                salt: row.get(2)?,
                claims: extra,
            })
        } else {
            Err(Error::UserNotFound(user_id.to_owned()))
        }
    }

    fn insert_user(&self, user: User) -> Result<(), Error> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "INSERT OR REPLACE INTO user (username, password, salt, claims) VALUES (?, ?, ?, ?)",
        )?;
        let claims: String = serde_json::to_string(&user.claims)?;
        if stmt.execute([user.username, user.password, user.salt, claims])? == 1 {
            Ok(())
        } else {
            // mysterious failure
            Err(Error::Database)
        }
    }

    fn delete_user(&self, user_id: &str) -> Result<bool, Error> {
        let db = self.conn.lock().unwrap();
        // need 'RETURNING' otherwise the query rows will be empty
        let mut stmt = db.prepare("DELETE FROM user WHERE username = ? RETURNING username")?;
        let mut rows = stmt.query([user_id])?;
        if rows.next()?.is_some() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

//
// Create the database tables if they do not exist.
//
fn create_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            claims TEXT
        )",
        (),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_not_found() -> Result<(), Error> {
        // arrange
        // act
        let eds = SQLiteEntityDataSource::new_in_memory()?;
        let result = eds.get_user("nonesuch");
        // assert
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no such user: nonesuch"));
        Ok(())
    }

    #[test]
    fn test_count_users() -> Result<(), Error> {
        // zero
        let eds = SQLiteEntityDataSource::new_in_memory()?;
        let count = eds.count_users()?;
        assert_eq!(count, 0);

        // one
        let user_json = r#"{
            "username": "johndoe",
            "password": "secret123",
            "salt": "nacl123",
            "purpose": "read"
        }"#;
        let user: User = serde_json::from_str(&user_json)?;
        eds.insert_user(user)?;
        let count = eds.count_users()?;
        assert_eq!(count, 1);

        // two
        let user_json = r#"{
            "username": "janedoe",
            "password": "Passw0rd!",
            "salt": "nacl123",
            "purpose": "write"
        }"#;
        let user: User = serde_json::from_str(&user_json)?;
        eds.insert_user(user)?;
        let count = eds.count_users()?;
        assert_eq!(count, 2);

        Ok(())
    }

    #[test]
    fn test_insert_user_new() -> Result<(), Error> {
        // arrange
        let user_json = r#"{
            "username": "johndoe",
            "password": "secret123",
            "salt": "nacl123",
            "purpose": "read"
        }"#;
        let user: User = serde_json::from_str(&user_json)?;
        // act
        let eds = SQLiteEntityDataSource::new_in_memory()?;
        let result = eds.insert_user(user);
        // assert
        assert!(result.is_ok());
        let result = eds.get_user("johndoe");
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.password, "secret123");
        assert!(user.claims.contains_key("purpose"));
        Ok(())
    }

    #[test]
    fn test_insert_user_replace() -> Result<(), Error> {
        // insert a new user
        let user_json = r#"{
            "username": "johndoe",
            "password": "secret123",
            "salt": "nacl123",
            "purpose": "read"
        }"#;
        let user: User = serde_json::from_str(&user_json)?;
        let eds = SQLiteEntityDataSource::new_in_memory()?;
        let result = eds.insert_user(user);
        assert!(result.is_ok());

        // update the existing user record with new values
        let user_json = r#"{
            "username": "johndoe",
            "password": "Passw0rd!",
            "salt": "random456",
            "purpose": "write"
        }"#;
        let user: User = serde_json::from_str(&user_json)?;
        let result = eds.insert_user(user);
        assert!(result.is_ok());
        let result = eds.get_user("johndoe");
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.password, "Passw0rd!");
        assert!(user.claims.contains_key("purpose"));
        assert_eq!(
            user.claims.get("purpose").map(|v| v.to_string()),
            Some("\"write\"".into())
        );

        // ensure only one user record exists
        let count = eds.count_users()?;
        assert_eq!(count, 1);

        Ok(())
    }

    #[test]
    fn test_delete_user() -> Result<(), Error> {
        // delete when user does not exist
        let eds = SQLiteEntityDataSource::new_in_memory()?;
        let deleted = eds.delete_user("johndoe")?;
        assert!(!deleted);

        // insert a new user record
        let user_json = r#"{
            "username": "johndoe",
            "password": "secret123",
            "salt": "nacl123",
            "purpose": "read"
        }"#;
        let user: User = serde_json::from_str(&user_json)?;
        let result = eds.insert_user(user);
        assert!(result.is_ok());
        let result = eds.get_user("johndoe");
        assert!(result.is_ok());

        // delete the record and ensure it is gone
        let deleted = eds.delete_user("johndoe")?;
        assert!(deleted);
        let result = eds.get_user("johndoe");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no such user: johndoe"));
        let deleted = eds.delete_user("johndoe")?;
        assert!(!deleted);
        Ok(())
    }
}
