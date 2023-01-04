# Overview

A simple authorization server that issues JSON Web Tokens as well as providing a JSON Web Key Set at the well known endpoint (`/.well-known/jwks.json`). Tokens are generated based on the credentials of users defined in a local file. This server is only suitable for testing purposes.

## Configuration

See the [project page](https://github.com/nlfiedler/jwt-test-server) for details on the configuration and use of this server image.

### User List

The image contains a set of users defined in a file named `users.json`, suitable for testing. To replace this file with your own, map a volume containing a JSON formatted list of users, as described on the [project page](https://github.com/nlfiedler/jwt-test-server) and change the `USERS_FILE` environment variable to reference this file.

The default users are as follows, where **Purpose** refers to a claim named `purpose`. By defining your own set of users, you can add whatever claims are needed.

| Name | Password | Purpose |
| ---- | -------- | ------- |
| `johndoe` | `tiger2` | `read` |
| `janedoe` | `tiger1` | `write` |

### SSL certificates

The image contains a set of self-signed certificates suitable for testing. To replace these certificates with your own, map a volume containing your PEM encoded public/private key pair and change the `CERT_FILE` and `KEY_FILE` environment variables to reference those files.

## License

[MIT License](https://opensource.org/licenses/MIT)
