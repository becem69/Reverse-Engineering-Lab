FROM golang:1.22-bookworm AS protogen
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler && rm -rf /var/lib/apt/lists/*
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.33.0 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
ENV PATH="/root/go/bin:${PATH}"
WORKDIR /gen
COPY proto/analyzer.proto ./proto/analyzer.proto
RUN mkdir -p out && protoc --go_out=out --go_opt=paths=source_relative \
    --go-grpc_out=out --go-grpc_opt=paths=source_relative -I proto proto/analyzer.proto

FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY shared/proto-gen/go/go.mod ./shared/proto-gen/go/go.mod
COPY --from=protogen /gen/out/ ./shared/proto-gen/go/
COPY orchestrator/go.mod ./orchestrator/go.mod
COPY orchestrator/cmd ./orchestrator/cmd
COPY orchestrator/internal ./orchestrator/internal
WORKDIR /src/orchestrator
RUN go mod edit -replace malware-lab/shared/proto-gen/go=../shared/proto-gen/go
RUN go mod tidy && go build -o /orchestrator ./cmd

FROM ruby:3.3-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /orchestrator /orchestrator
COPY services/report-generator/ /services/report-generator/
ENV ORCHESTRATOR_PORT=9000
ENV REPORT_GENERATOR_PATH=/services/report-generator/generate.rb
EXPOSE 9000
ENTRYPOINT ["/orchestrator"]
