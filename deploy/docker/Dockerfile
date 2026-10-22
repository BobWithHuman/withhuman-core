FROM rust:1.85-bookworm AS builder

ARG PACKAGE
ARG BINARY
WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY services ./services
COPY tests/fixtures ./tests/fixtures

RUN cargo build --locked --release --package "${PACKAGE}" --bin "${BINARY}" \
    && cp "/workspace/target/release/${BINARY}" /service

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /service /usr/local/bin/service

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/service"]
