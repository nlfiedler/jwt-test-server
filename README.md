# JWT Test Server

A simple authorization server that issues JSON Web Tokens as well as providing a JSON Web Key Set at the well known endpoint (`/.well-known/jwks.json`). Tokens are generated based on the credentials of users defined in a local file. This server is only suitable for testing purposes.

## Starting

```shell
cargo run
```

## Getting a Token

The authorization flow follows that of _Resource Owner Password Credentials Grant_ as described in [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) section 4.3 for the sake of simplicity. In this scenario, the resource owner and the client are effectively the same entity.

### Browser

Open the default web page in a browser, https://127.0.0.1:3000, and enter credentials matching those defined in the `users.json` file. The response body will contain JSON web token in JSON format.

### PowerShell

```ps1
$body = @{grant_type='password'
      username='johndoe'
      password='tiger2'}
$contentType = 'application/x-www-form-urlencoded' 
Invoke-WebRequest -Method POST -Uri https://127.0.0.1:3000/tokens -body $body -ContentType $contentType
```

### Rust

See the example in `examples/validate.rs` for how to use the `hyper` crate to retrieve a token.

## Configuring

By default the server will bind to the local address and listen on port 3000. The users are defined in a file named `users.json` that contains a list of objects which must have a `username` and `password` property, with the remaining fields copied directly into the token payload.

To modify the configuration, set any of the environment variables shown in the table below. The server will look for a file named `.env` and evaluate it using the `dotenv` crate. Any `name=value` pairs defined in that file will result in setting the named environment variable with the given value. Comment lines, which start with `#`, and blank lines, will be ignored.

| Name | Description | Default Value |
| ---- | ----------- | ------------- |
| `HOST` | address on which to bind | `127.0.0.1` |
| `PORT` | port on which to listen | `3000` |
| `RUST_LOG` | logging level such as `debug` or `info` | `error` (see https://docs.rs/env_logger/latest/env_logger/) |
| `BASE_URI` | value for the `iss` field in the token | `https://127.0.0.1:3000` |
| `USERS_FILE` | path of JSON-formatted file with list of valid users | `users.json` |
| `CERT_FILE` | path of PEM-encoded file containing public certificate | `certs/cert.pem` |
| `KEY_FILE` | path of PEM-encoded file containing private key | `certs/key.pem` |

## Certificates

The default self-signed TLS certificates in the `certs` directory, `cert.pem` and `key.pem`, where created using the [mkcert](https://github.com/FiloSottile/mkcert) utility, although `openssl` would also work. The advantage of `mkcert` is that it will install certificate authority certs to validate the certs created with `mkcert`.

## Validating

See the example in `examples/validate.rs` for how to validate a token using the JSON Web Key Set (JWKS) served by this authorization server. To run the example, start the server with the default configuration, and then in a separate shell, run this command:

```shell
cargo run --example validate
```

The example uses the `hyper` and `jsonwebtoken` crates to retrieve the JWKS served by this server (at the `/.well-known/jwks.json` endpoint) to validate the token generated by this server. This is a contrived example, as typically a trusted client would use the resource owner's credentials to get a token, pass that token to another service, and that other service would then validate the token against this authorization server. Ideally that service would validate the audience and issuer, and then utilize the claims provided to grant certain permissions to the service.
