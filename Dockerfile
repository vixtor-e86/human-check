# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm as builder

WORKDIR /usr/src/app

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy source to cache compiled dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy real project sources
COPY src ./src
COPY static ./static
COPY images ./images

# Ensure Cargo rebuilds with real sources
RUN touch src/main.rs
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/src/app/target/release/human-check /app/human-check
COPY static ./static
COPY images ./images

RUN mkdir -p /app/data /app/captures

ENV PORT=10000
EXPOSE 10000

CMD ["/app/human-check"]
