//
// Copyright (c) 2024 Nathan Fiedler
//
use crate::domain::entities::WebToken;
use anyhow::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

///
/// Use case to generate a JSON web token for a given subject.
///
pub struct GenerateToken {}

impl GenerateToken {
    pub fn new() -> Self {
        Self {}
    }
}

impl super::UseCase<WebToken, Params> for GenerateToken {
    fn call(&self, params: Params) -> Result<WebToken, Error> {
        let since_the_epoch = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards");
        let expires_at = since_the_epoch + Duration::from_secs(params.expires_in as u64);
        let my_claims = Claims {
            sub: params.subject,
            exp: expires_at.as_secs() as usize,
            iat: since_the_epoch.as_secs() as usize,
            iss: params.issuer,
            extra: params.claims,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(params.kid);
        let token = encode(&header, &my_claims, &params.encoder)?;
        Ok(WebToken {
            token_type: "bearer".into(),
            access_token: token,
            expires_in: params.expires_in,
        })
    }
}

#[derive(Clone)]
pub struct Params {
    /// Subject (typically user name) for which to generate a token.
    pub subject: String,
    /// Additional fields related to the subject that will be included in the
    /// token payload.
    pub claims: HashMap<String, Value>,
    /// Private key for encoding the web token.
    pub encoder: EncodingKey,
    /// Key identifier for the signing key.
    pub kid: String,
    /// URI of the token issuer.
    pub issuer: String,
    /// Number of seconds after which token should expire.
    pub expires_in: usize,
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Params(subject: {})", self.subject)
    }
}

impl cmp::PartialEq for Params {
    fn eq(&self, other: &Self) -> bool {
        self.subject == other.subject
    }
}

impl cmp::Eq for Params {}

///
/// Structure returned to the client as the token payload.
///
/// This type exists only for the sake of JSON serialization.
///
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::super::UseCase;
    use super::*;
    use base64::prelude::*;

    #[test]
    fn test_fetch_user_ok() -> anyhow::Result<()> {
        // arrange
        let mut claims: HashMap<String, Value> = HashMap::new();
        claims.insert("purpose".into(), Value::String("read".into()));
        let key_pem = std::fs::read("certs/key.pem")?;
        let encoder = EncodingKey::from_rsa_pem(&key_pem).expect("failed to create encoding key");
        let params = Params {
            subject: "johndoe".into(),
            claims,
            encoder,
            kid: "abc123".into(),
            issuer: "https://example.com".into(),
            expires_in: 3600,
        };
        // act
        let usecase = GenerateToken::new();
        let result = usecase.call(params);

        // assert
        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.token_type, "bearer");
        assert_eq!(token.expires_in, 3600);
        let mut iter = token.access_token.split('.');
        let header_raw = iter.next().unwrap();
        let header_bytes = BASE64_STANDARD_NO_PAD.decode(&header_raw)?;
        let header_str = str::from_utf8(&header_bytes)?;
        let header: Value = serde_json::from_str(header_str)?;
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "abc123");

        let payload_raw = iter.next().unwrap();
        let payload_bytes = BASE64_STANDARD_NO_PAD.decode(&payload_raw)?;
        let payload_str = str::from_utf8(&payload_bytes)?;
        let payload: Value = serde_json::from_str(payload_str)?;
        assert_eq!(payload["sub"], "johndoe");
        assert_eq!(payload["iss"], "https://example.com");
        assert_eq!(payload["purpose"], "read");

        let signature = iter.next().unwrap();
        assert!(signature.len() > 0);
        Ok(())
    }
}
