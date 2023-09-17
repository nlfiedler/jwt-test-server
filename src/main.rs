//
// Copyright (c) 2023 Nathan Fiedler
//
use actix_web::{
    body::BoxBody, get, http::header::ContentType, middleware, post, web, App, Either, HttpRequest,
    HttpResponse, HttpServer, Responder,
};
use anyhow::Error;
use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::{error, info};
use once_cell::sync::Lazy;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey, RsaPublicKey};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    io::BufReader,
    time::{Duration, SystemTime},
};

struct AppState {
    pub_key: RsaPublicKey,
    encoder: EncodingKey,
    kid: String,
}

static APP_STATE: Lazy<AppState> = Lazy::new(|| {
    // build an encoding key from the private key
    let key_path = env::var("KEY_FILE").unwrap_or_else(|_| "certs/key.pem".to_owned());
    let key_pem = fs::read(key_path).expect("failed to read key");
    let encoder = EncodingKey::from_rsa_pem(&key_pem).expect("failed to create encoding key");
    // extract the public certificate for serving via JWKS
    let key_pem_str = std::str::from_utf8(&key_pem).expect("failed to convert key bytes");
    let priv_key = RsaPrivateKey::from_pkcs8_pem(key_pem_str).expect("failed to parse key");
    let pub_key = RsaPublicKey::from(&priv_key);
    // compute a key id based on the public key n/e values
    use rsa::traits::PublicKeyParts;
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    let modulus = pub_key.n().to_bytes_be();
    hasher.update(modulus);
    let public_exponent = pub_key.e().to_bytes_be();
    hasher.update(public_exponent);
    let digest = hasher.finalize();
    let kid = format!("{:x}", digest);
    AppState {
        pub_key,
        encoder,
        kid,
    }
});

static ISSUER_URI: Lazy<String> =
    Lazy::new(|| env::var("BASE_URI").unwrap_or_else(|_| "https://127.0.0.1:3000".to_owned()));

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
    extra: HashMap<String, Value>,
}

///
/// Incoming form data for requesting a JSON web token.
///
#[derive(Deserialize)]
struct AuthRequest {
    grant_type: String,
    username: String,
    password: String,
}

///
/// Generated access token with expiration in seconds.
///
#[derive(Deserialize, Serialize)]
struct AuthResponse {
    token_type: String,
    access_token: String,
    expires_in: usize,
}

///
/// A JSON Web Key.
///
#[derive(Debug, Serialize, Deserialize)]
struct Jwk {
    alg: String,
    kty: String,
    #[serde(rename = "use")]
    use_: String,
    n: String,
    e: String,
    kid: String,
}

///
/// List of JSON Web Keys.
///
#[derive(Debug, Serialize, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
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
        let body = serde_json::to_string(&self)
            .unwrap_or_else(|err| format!("serialization error: {:?}", err));
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
                    extra: user.claims,
                };
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some(APP_STATE.kid.clone());
                match encode(&header, &my_claims, &APP_STATE.encoder) {
                    Ok(token) => Either::Left(AuthResponse {
                        token_type: "bearer".into(),
                        access_token: token,
                        expires_in: 3600,
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
/// OpenID discovery endpoint
///
#[get("/.well-known/openid-configuration")]
async fn openid_config() -> impl Responder {
    use serde_json::json;
    let issuer_uri = ISSUER_URI.to_string();
    let jwks_uri = format!("{}/.well-known/jwks.json", issuer_uri.clone());
    // authorization_endpoint should present a form
    let auth_endp = format!("{}/tokens", issuer_uri.clone());
    let configuration = json!({
        "issuer": issuer_uri.clone(),
        "jwks_uri": jwks_uri,
        "authorization_endpoint": auth_endp,
        "response_types_supported": ["code", "id_token", "token id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    });
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(configuration.to_string())
}

///
/// OpenID JSON web key set (RFC 7517)
///
#[get("/.well-known/jwks.json")]
async fn jwks_json() -> impl Responder {
    use rsa::traits::PublicKeyParts;
    // JWKS integers are big-endian and base64-url encoded w/o padding
    let e = general_purpose::URL_SAFE_NO_PAD.encode(APP_STATE.pub_key.e().to_bytes_be());
    let n = general_purpose::URL_SAFE_NO_PAD.encode(APP_STATE.pub_key.n().to_bytes_be());
    let kid = APP_STATE.kid.clone();
    let keys = Jwks {
        keys: vec![Jwk {
            alg: "RS256".into(),
            kty: "RSA".into(),
            use_: "sig".into(),
            n,
            e,
            kid,
        }],
    };
    HttpResponse::Ok().content_type(ContentType::json()).body(
        serde_json::to_string(&keys)
            .unwrap_or_else(|err| format!("serialization error: {:?}", err)),
    )
}

#[get("/status")]
async fn app_status() -> impl Responder {
    HttpResponse::Ok()
}

fn load_rustls_config() -> Result<rustls::ServerConfig, Error> {
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();
    let cert_path = env::var("CERT_FILE").unwrap_or_else(|_| "certs/cert.pem".to_owned());
    let key_path = env::var("KEY_FILE").unwrap_or_else(|_| "certs/key.pem".to_owned());
    let cert_file = &mut BufReader::new(File::open(cert_path)?);
    let key_file = &mut BufReader::new(File::open(key_path)?);
    let cert_chain = certs(cert_file)?.into_iter().map(Certificate).collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)?
        .into_iter()
        .map(PrivateKey)
        .collect();
    if keys.is_empty() {
        eprintln!("error: could not find PKCS 8 private keys");
        std::process::exit(1);
    }
    Ok(config.with_single_cert(cert_chain, keys.remove(0))?)
}

fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(post_tokens)
        .service(openid_config)
        .service(jwks_json)
        .service(app_status)
        .service(
            actix_files::Files::new("/", "static")
                .use_etag(true)
                .use_last_modified(true)
                .index_file("index.html"),
        );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    env_logger::init();
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let addr = format!("{}:{}", host, port);
    let protocol = env::var("PROTOCOL").unwrap_or_else(|_| "https".to_owned());
    if protocol == "https" {
        let rustls_config =
            load_rustls_config().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        info!("listening on https://{}/...", addr);
        HttpServer::new(|| {
            App::new()
                .wrap(middleware::Logger::default())
                .configure(config)
        })
        .bind_rustls(addr, rustls_config)?
        .run()
        .await
    } else {
        info!("listening on http://{}/...", addr);
        HttpServer::new(|| {
            App::new()
                .wrap(middleware::Logger::default())
                .configure(config)
        })
        .bind(addr)?
        .run()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http, http::header::ContentType, test};
    use jsonwebtoken::{decode, DecodingKey, Validation};

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
        let mut app = test::init_service(App::new().service(jwks_json)).await;
        let req = test::TestRequest::get()
            .uri("/.well-known/jwks.json")
            .to_request();
        let key_set: Jwks = test::call_and_read_body_json(&mut app, req).await;
        let key = &key_set.keys[0];
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.alg, "RS256");
        assert_eq!(key.use_, "sig");
    }

    #[actix_web::test]
    async fn test_openid_configuration_ok() {
        let mut app = test::init_service(App::new().service(openid_config)).await;
        let req = test::TestRequest::get()
            .uri("/.well-known/openid-configuration")
            .to_request();
        let configuration: HashMap<String, Value> =
            test::call_and_read_body_json(&mut app, req).await;
        assert!(configuration.contains_key("jwks_uri"));
        let option = configuration["id_token_signing_alg_values_supported"].as_array();
        assert!(option.is_some());
        let algorithms = option.unwrap();
        assert_eq!(algorithms[0], "RS256");
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
        let mut app = test::init_service(App::new().service(post_tokens)).await;
        let payload = r#"grant_type=password&username=johndoe&password=tiger2"#.as_bytes();
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(payload)
            .to_request();
        let token: AuthResponse = test::call_and_read_body_json(&mut app, req).await;
        assert_eq!(token.token_type, "bearer");
    }

    #[actix_web::test]
    async fn test_validate_ok() {
        let mut app = test::init_service(App::new().service(jwks_json).service(post_tokens)).await;
        // acquire an access token
        let payload = r#"grant_type=password&username=johndoe&password=tiger2"#.as_bytes();
        let req = test::TestRequest::post()
            .uri("/tokens")
            .insert_header(ContentType::form_url_encoded())
            .set_payload(payload)
            .to_request();
        let token: AuthResponse = test::call_and_read_body_json(&mut app, req).await;
        assert_eq!(token.token_type, "bearer");
        // fetch the key set
        let req = test::TestRequest::get()
            .uri("/.well-known/jwks.json")
            .to_request();
        let key_set: Jwks = test::call_and_read_body_json(&mut app, req).await;
        // validate using the (assumed) one key
        let jwk = &key_set.keys[0];
        let decoder = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).unwrap();
        let token = decode::<Claims>(
            &token.access_token,
            &decoder,
            &Validation::new(Algorithm::RS256),
        )
        .unwrap();
        assert_eq!(token.claims.sub, "johndoe");
        let purpose = token.claims.extra.get("purpose");
        let expected = Value::String("read".into());
        assert_eq!(purpose, Some(&expected));
    }
}
