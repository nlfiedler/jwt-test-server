//
// Copyright (c) 2022 Nathan Fiedler
//
use actix_web::{
    body::BoxBody, get, http::header::ContentType, middleware, post, web, App, Either, HttpRequest,
    HttpResponse, HttpServer, Responder,
};
use anyhow::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::{error, info};
use once_cell::sync::Lazy;
use rsa::{
    pkcs8::{EncodePrivateKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::{
    env, fs,
    time::{Duration, SystemTime},
};

struct AppState {
    pub_key: RsaPublicKey,
    encoder: EncodingKey,
    kid: String,
}

static APP_STATE: Lazy<AppState> = Lazy::new(|| {
    let mut rng = rand::thread_rng();
    // n.b. more bits, lazy startup takes longer, and 2048 is already several seconds
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate private key");
    let pub_key = RsaPublicKey::from(&priv_key);
    // ideally EncodingKey would have a "from_rsa_raw_components()"
    let pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to convert to PEM")
        .to_string();
    let encoder = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("failed to create encoding key");
    let kid = uuid::Uuid::new_v4().to_string();
    AppState {
        pub_key,
        encoder,
        kid,
    }
});

static ISSUER_URI: Lazy<String> =
    Lazy::new(|| env::var("BASE_URI").unwrap_or_else(|_| "http://127.0.0.1:3000".to_owned()));

///
/// A single entity as read from the USERS_FILE (users.json) file.
///
#[derive(Debug, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
    #[serde(flatten)]
    claims: HashMap<String, Value>,
}

///
/// Full results from deserializing the USERS_FILE (users.json) file.
///
#[derive(Debug, Serialize, Deserialize)]
struct Users {
    users: Vec<User>,
}

///
/// Structure returned to the client as the token payload.
///
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    #[serde(flatten)]
    claims: HashMap<String, Value>,
}

///
/// Incoming form data for requesting a JSON web token.
///
#[derive(Deserialize)]
struct AuthRequest {
    grant_type: String,
    username: String,
    password: String,
    scope: Option<String>,
}

///
/// Generated JSON web token with optional scope.
///
#[derive(Serialize)]
struct AuthResponse {
    token_type: String,
    access_token: String,
    expires_in: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

fn authenticate_user(username: &str, password: &str) -> Result<Option<User>, Error> {
    let user_file = env::var("USERS_FILE").unwrap_or_else(|_| "users.json".to_owned());
    let user_data = fs::File::open(user_file)?;
    let user_list: Users = serde_json::from_reader(&user_data)?;
    for user in user_list.users {
        if user.username == username && user.password == password {
            return Ok(Some(user));
        }
    }
    Ok(None)
}

impl Responder for AuthResponse {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(body)
    }
}

type TokensResult = Either<AuthResponse, HttpResponse>;

#[post("/tokens")]
async fn post_tokens(form: web::Form<AuthRequest>) -> TokensResult {
    // use password grant type from RFC 6749 section 4.3 for simplicity
    if form.grant_type != "password" {
        Either::Right(HttpResponse::BadRequest().body("grant_type invalid"))
    } else {
        match authenticate_user(&form.username, &form.password) {
            Ok(Some(user)) => {
                let since_the_epoch = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time went backwards");
                let expires_at = since_the_epoch + Duration::from_secs(3600);
                let my_claims = Claims {
                    sub: user.username,
                    exp: expires_at.as_secs() as usize,
                    iat: since_the_epoch.as_secs() as usize,
                    iss: ISSUER_URI.clone(),
                    claims: user.claims,
                };
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some(APP_STATE.kid.clone());
                match encode(&header, &my_claims, &APP_STATE.encoder) {
                    Ok(token) => Either::Left(AuthResponse {
                        token_type: "bearer".into(),
                        access_token: token,
                        expires_in: 3600,
                        scope: form.scope.clone(),
                    }),
                    Err(err) => {
                        error!("failed to generate token: {:?}", err);
                        Either::Right(
                            HttpResponse::InternalServerError().body("error generating token"),
                        )
                    }
                }
            }
            Ok(None) => Either::Right(HttpResponse::Unauthorized().finish()),
            Err(err) => {
                error!("failed to authenticate user: {:?}", err);
                Either::Right(HttpResponse::InternalServerError().body("error authenticating user"))
            }
        }
    }
}

///
/// OpenID JSON web key set (RFC 7517)
///
#[get("/.well-known/jwks.json")]
async fn jwks_json() -> impl Responder {
    use rsa::PublicKeyParts;
    let e = base64::encode(APP_STATE.pub_key.e().to_bytes_le());
    let n = base64::encode(APP_STATE.pub_key.n().to_bytes_le());
    let kid = APP_STATE.kid.clone();
    let keys = serde_json::json!({
        "keys": [
            {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "n": n,
                "e": e,
                "kid": kid
            }
        ]
    });
    HttpResponse::Ok().body(keys.to_string())
}

#[get("/status")]
async fn app_status() -> impl Responder {
    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let addr = format!("{}:{}", host, port);
    info!("listening on http://{}/...", addr);
    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .service(post_tokens)
            .service(jwks_json)
            .service(app_status)
            .service(
                actix_files::Files::new("/", "static")
                    .use_etag(true)
                    .use_last_modified(true)
                    .index_file("index.html"),
            )
    })
    .bind(addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, http::header::ContentType, test};

    #[actix_web::test]
    async fn test_index_ok() {
        let app = test::init_service(
            App::new().service(
                actix_files::Files::new("/", "static")
                    .use_etag(true)
                    .use_last_modified(true)
                    .index_file("index.html"),
            ),
        )
        .await;
        let req = test::TestRequest::default().to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let bytes = test::read_body(resp).await;
        let expected = "<!DOCTYPE html>".as_bytes();
        let actual = bytes.slice(0..15);
        assert_eq!(actual, expected);
    }

    #[actix_web::test]
    async fn test_app_status_ok() {
        let app = test::init_service(App::new().service(app_status)).await;
        let req = test::TestRequest::get().uri("/status").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_jwks_json_ok() {
        let app = test::init_service(App::new().service(jwks_json)).await;
        let req = test::TestRequest::get()
            .uri("/.well-known/jwks.json")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        // too lazy to define a struct and use call_and_read_body_json()
        let body = resp.into_body();
        let chars = format!("{:?}", body);
        assert!(chars.contains("RS256"));
    }

    #[actix_web::test]
    async fn test_post_tokens_401() {
        let app = test::init_service(App::new().service(post_tokens)).await;
        let payload = r#"grant_type=password&username=scott&password=tiger"#.as_bytes();
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(payload)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_post_tokens_ok() {
        let app = test::init_service(App::new().service(post_tokens)).await;
        let payload = r#"grant_type=password&username=johndoe&password=tiger2"#.as_bytes();
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(payload)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        // too lazy to define a struct and use call_and_read_body_json()
        let body = resp.into_body();
        let chars = format!("{:?}", body);
        assert!(chars.contains("access_token"));
    }
}
