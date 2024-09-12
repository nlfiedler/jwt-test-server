//
// Copyright (c) 2024 Nathan Fiedler
//
use jsonwebtoken::{decode, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // retrieve an access token
    let client = reqwest::Client::new();
    let url = reqwest::Url::parse("https://localhost:3000/tokens")?;
    let res = client
        .post(url.clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(r#"grant_type=password&username=johndoe&password=tiger2"#)
        .send()
        .await?;
    if res.status() != 200 {
        let msg = "jwks request failed";
        return Err(Box::<dyn std::error::Error + Send + Sync + 'static>::from(
            msg,
        ));
    }
    let raw_text = res.text().await?;
    let raw_value: Value = serde_json::from_str(&raw_text)?;
    let token = raw_value.as_object().unwrap();
    let access_token = token["access_token"].as_str().unwrap();

    // retrieve the JSON web key set from the issuer
    let url = reqwest::Url::parse("https://localhost:3000/.well-known/jwks.json")?;
    let res = client.get(url.clone()).send().await?;
    if res.status() != 200 {
        let msg = "jwks request failed";
        return Err(Box::<dyn std::error::Error + Send + Sync + 'static>::from(
            msg,
        ));
    }
    let raw_text = res.text().await?;
    let jwks: JwkSet = serde_json::from_str(&raw_text)?;

    // extract the first key from the set and validate the token
    let decoder = DecodingKey::from_jwk(&jwks.keys[0])?;
    let token =
        decode::<Claims>(access_token, &decoder, &Validation::new(Algorithm::RS256)).unwrap();
    let purpose = token.claims.extra.get("purpose").to_owned().unwrap();
    println!("user {} with purpose {}", token.claims.sub, purpose);

    Ok(())
}
