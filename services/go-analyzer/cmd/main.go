// Go-binary analyzer.
// Focuses on binaries that triage has already tagged as language=go.
// Uses Go's own debug/buildinfo package to recover build metadata
// (Go version, module path, dependencies) even from stripped binaries,
// since this info is embedded by the Go compiler itself.
package main

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	pb "malware-lab/shared/proto-gen/go"
)

const serviceName = "go-analyzer"

type server struct {
	pb.UnimplementedAnalyzerServer
}

func (s *server) Analyze(ctx context.Context, req *pb.SampleRequest) (*pb.AnalysisResult, error) {
	path := req.SamplePath
	log.Printf("received sample path=%s", path)

	result := &pb.AnalysisResult{
		AnalyzerName: serviceName,
		Extra:        map[string]string{},
	}

	info, err := buildinfo.ReadFile(path)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read Go build info: %v", err)
		log.Printf("buildinfo read failed: %v", err)
		return result, nil
	}

	result.Language = "go"
	result.Extra["go_version"] = info.GoVersion
	result.Extra["main_module"] = info.Main.Path
	result.Extra["main_module_version"] = info.Main.Version

	// List a handful of dependencies as a starting point — full dependency
	// graph can be added later once we decide how TTP correlation wants it.
	depCount := 0
	for _, dep := range info.Deps {
		if depCount >= 10 {
			break
		}
		result.Extra[fmt.Sprintf("dep_%d", depCount)] = fmt.Sprintf("%s@%s", dep.Path, dep.Version)
		depCount++
	}

	log.Printf("go analysis complete: go_version=%s main_module=%s deps_found=%d",
		info.GoVersion, info.Main.Path, len(info.Deps))

	return result, nil
}

func (s *server) Capabilities(ctx context.Context, req *pb.Empty) (*pb.CapabilitiesResponse, error) {
	return &pb.CapabilitiesResponse{
		SupportedFormats:   []string{"PE", "ELF"},
		SupportedLanguages: []string{"go"},
		ServiceName:        serviceName,
	}, nil
}

func main() {
	port := getenv("GRPC_PORT", "50052")

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAnalyzerServer(grpcServer, &server{})

	log.Printf("go-analyzer service listening on port %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
