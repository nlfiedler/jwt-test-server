//
// Copyright (c) 2024 Nathan Fiedler
//
use anyhow::Error;
use std::cmp;
use std::fmt;

pub mod authenticate_user;
pub mod create_user;
pub mod fetch_user;
pub mod generate_token;
pub mod remove_user;

/// `UseCase` is the interface by which all use cases are invoked.
pub trait UseCase<Type, Params> {
    fn call(&self, params: Params) -> Result<Type, Error>;
}

/// `NoParams` is the type for use cases that do not take arguments.
pub struct NoParams {}

impl fmt::Display for NoParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NoParams()")
    }
}

impl cmp::PartialEq for NoParams {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl cmp::Eq for NoParams {}
