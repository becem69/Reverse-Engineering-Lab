FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config protobuf-compiler-grpc libgrpc++-dev libprotobuf-dev libcapstone-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY proto/ /proto/
COPY services/shellcode-analyzer/ .
ENV PROTO_DIR=/proto
RUN mkdir build && cd build && cmake .. && make

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgrpc++1 libprotobuf32 libcapstone4 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/shellcode-analyzer /shellcode-analyzer
ENV GRPC_PORT=50060
EXPOSE 50060
ENTRYPOINT ["/shellcode-analyzer"]
