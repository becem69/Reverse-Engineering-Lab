FROM golang:1.25-bookworm AS protogen
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33.0 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
ENV PATH="/root/go/bin:${PATH}"
WORKDIR /gen
COPY proto/analyzer.proto ./proto/analyzer.proto
RUN mkdir -p out && protoc --go_out=out --go_opt=paths=source_relative \
    --go-grpc_out=out --go-grpc_opt=paths=source_relative -I proto proto/analyzer.proto

FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY shared/proto-gen/go/go.mod ./shared/proto-gen/go/go.mod
COPY --from=protogen /gen/out/ ./shared/proto-gen/go/
COPY services/go-analyzer/go.mod services/go-analyzer/go.sum* ./services/go-analyzer/
WORKDIR /src/services/go-analyzer
RUN go mod edit -replace malware-lab/shared/proto-gen/go=../../shared/proto-gen/go
COPY services/go-analyzer/cmd ./cmd
RUN go mod tidy && go build -o /go-analyzer ./cmd

FROM gcr.io/distroless/base-debian12
COPY --from=builder /go-analyzer /go-analyzer
ENV GRPC_PORT=50052
EXPOSE 50052
ENTRYPOINT ["/go-analyzer"]
