# syntax=docker/dockerfile:1.7
FROM rust:1.96-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bins
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iptables ipset && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/vpc-api /usr/local/bin/vpc-api
COPY --from=builder /src/target/release/vpc-controller /usr/local/bin/vpc-controller
COPY --from=builder /src/target/release/vpc-nat-guard /usr/local/bin/vpc-nat-guard
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/vpc-api"]
