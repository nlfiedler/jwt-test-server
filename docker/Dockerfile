#
# Docker container definition for publishing on Docker Hub.
#
# Build:
#
# $ docker build --pull -t jwt-test-server:latest -t jwt-test-server:0.2 -f docker/Dockerfile .
# $ docker tag jwt-test-server:latest nlfiedler/jwt-test-server:latest
# $ docker tag jwt-test-server:0.2 nlfiedler/jwt-test-server:0.2
# $ docker push --all-tags nlfiedler/jwt-test-server
#
# Run:
#
# $ docker run --restart unless-stopped -d -p 3000:3000 --name jwt-test-server jwt-test-server:latest
#

# build the server binary
FROM rust:latest AS builder
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -q update && \
    apt-get -q -y install clang
WORKDIR /build
COPY Cargo.toml .
COPY src src/
RUN cargo build --release

# build the final image
FROM debian:latest
WORKDIR /jwtserver
COPY --from=builder /build/target/release/jwt-test-server .
COPY certs certs
COPY static static
COPY users.json users.json
ENV HOST "0.0.0.0"
ENV RUST_LOG info
EXPOSE ${PORT}
ENTRYPOINT ["./jwt-test-server"]
