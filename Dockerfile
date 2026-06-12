# Stage 1: Builder
FROM rust:1.83-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev cmake && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src/

COPY . .
RUN touch src/main.rs
RUN cargo build --release

# Stage 2: Runner
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/bash appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appuser /usr/src/app/target/release/auth-service-rust /app/auth-service-rust
COPY --from=builder --chown=appuser:appuser /usr/src/app/.env.example /app/.env

RUN chmod +x /app/auth-service-rust

EXPOSE 8001
ENV ENVIRONMENT=production

USER appuser

CMD ["/app/auth-service-rust"]
