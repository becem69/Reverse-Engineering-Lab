FROM rust:1.85-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY proto/ /proto/
COPY services/rust-analyzer/ .
ENV PROTO_PATH=/proto/analyzer.proto
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/rust-analyzer /rust-analyzer
ENV GRPC_PORT=50053
EXPOSE 50053
ENTRYPOINT ["/rust-analyzer"]
