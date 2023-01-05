//
// Copyright (c) 2022 Nathan Fiedler
//
use actix_web::web::Buf;
use hyper::{Body, Client, Method, Request};
use hyper_tls::HttpsConnector;
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
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    // retrieve an access token
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://127.0.0.1:3000/tokens")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            r#"grant_type=password&username=johndoe&password=tiger2"#,
        ))?;
    let resp = client.request(req).await?;
    if resp.status() != 200 {
        let msg = "tokens request failed";
        return Err(Box::<dyn std::error::Error + Send + Sync + 'static>::from(
            msg,
        ));
    }
    let body = hyper::body::to_bytes(resp.into_body()).await?;
    let buf = body.reader();
    let raw_value: Value = serde_json::from_reader(buf)?;
    let token = raw_value.as_object().unwrap();
    let access_token = token["access_token"].as_str().unwrap();

    // retrieve the JSON web key set from the issuer
    let uri = "https://127.0.0.1:3000/.well-known/jwks.json".parse()?;
    let resp = client.get(uri).await?;
    if resp.status() != 200 {
        let msg = "jwks request failed";
        return Err(Box::<dyn std::error::Error + Send + Sync + 'static>::from(
            msg,
        ));
    }
    let body = hyper::body::to_bytes(resp.into_body()).await?;
    let buf = body.reader();
    let raw_data = std::io::read_to_string(buf)?;
    let jwks: JwkSet = serde_json::from_str(&raw_data)?;

    // extract the first key from the set and validate the token
    let decoder = DecodingKey::from_jwk(&jwks.keys[0])?;
    let token =
        decode::<Claims>(access_token, &decoder, &Validation::new(Algorithm::RS256)).unwrap();
    let purpose = token.claims.extra.get("purpose").to_owned().unwrap();
    println!("user {} with purpose {}", token.claims.sub, purpose);

    Ok(())
}
