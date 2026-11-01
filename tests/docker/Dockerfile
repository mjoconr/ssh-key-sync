FROM rust:1.99-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --locked --release \
    -p ssh-key-sync-client \
    -p ssh-key-sync-server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl openssh-server \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ssh-key-sync-client /usr/local/bin/
COPY --from=builder /src/target/release/ssh-key-sync-server /usr/local/bin/
COPY tests/docker/run.sh /usr/local/bin/run-integration-test

ENTRYPOINT ["/usr/local/bin/run-integration-test"]

