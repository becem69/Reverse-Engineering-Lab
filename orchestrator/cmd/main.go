// Orchestrator entry point.
// Runs the full static-analysis pipeline for one sample:
//   1. Call triage (format/language/packed detection)
//   2. Route to the matching language analyzer based on triage's output
//   3. Merge findings and send them to the TTP correlation engine
//   4. Hand off aggregated results to the Ruby report generator
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"malware-lab/orchestrator/internal/registry"
	pb "malware-lab/shared/proto-gen/go"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func callAnalyzer(addr string, req *pb.SampleRequest) (*pb.AnalysisResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := pb.NewAnalyzerClient(conn)
	return client.Analyze(ctx, req)
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func resultToMap(r *pb.AnalysisResult) map[string]interface{} {
	if r == nil {
		return nil
	}
	ttps := []map[string]interface{}{}
	for _, t := range r.Ttps {
		ttps = append(ttps, map[string]interface{}{
			"technique_id":   t.TechniqueId,
			"technique_name": t.TechniqueName,
			"tactic":         t.Tactic,
			"evidence":       t.Evidence,
			"confidence":     t.Confidence,
		})
	}
	return map[string]interface{}{
		"analyzer_name":        r.AnalyzerName,
		"format":               r.Format,
		"language":             r.Language,
		"is_packed":            r.IsPacked,
		"packer_name":          r.PackerName,
		"imports":              r.Imports,
		"exports":              r.Exports,
		"strings_of_interest":  r.StringsOfInterest,
		"extra":                r.Extra,
		"ttps":                 ttps,
	}
}

func generateReport(samplePath string, triage, language, ttp *pb.AnalysisResult) {
	results := []map[string]interface{}{}
	if triage != nil {
		results = append(results, resultToMap(triage))
	}
	if language != nil {
		results = append(results, resultToMap(language))
	}
	if ttp != nil {
		results = append(results, resultToMap(ttp))
	}

	payload := map[string]interface{}{
		"sample_path":      samplePath,
		"analysis_results": results,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("failed to marshal report input: %v", err)
		return
	}

	inputPath := "/tmp/relab_report_input.json"
	outputPath := "/tmp/relab_report_output.json"

	if err := os.WriteFile(inputPath, payloadBytes, 0644); err != nil {
		log.Printf("failed to write report input: %v", err)
		return
	}

	reportGeneratorPath := getenv("REPORT_GENERATOR_PATH", "../services/report-generator/generate.rb")
	cmd := exec.Command("ruby", reportGeneratorPath, inputPath, outputPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("report generator failed: %v\noutput: %s", err, string(out))
		return
	}
	log.Printf("%s", string(out))
	log.Printf("final report available at: %s", outputPath)
}

func main() {
	samplePath := getenv("DEMO_SAMPLE_PATH", "/tmp/fake_sample.exe")

	reg := registry.New()
	reg.Register("triage", getenv("TRIAGE_ADDR", "localhost:50051"), []string{"*"}, []string{"*"})
	reg.Register("go-analyzer", getenv("GO_ANALYZER_ADDR", "localhost:50052"), []string{"PE", "ELF"}, []string{"go"})
	reg.Register("rust-analyzer", getenv("RUST_ANALYZER_ADDR", "localhost:50053"), []string{"PE", "ELF"}, []string{"rust"})
	reg.Register("cpp-analyzer", getenv("CPP_ANALYZER_ADDR", "localhost:50054"), []string{"PE", "ELF"}, []string{"cpp", "c"})
	reg.Register("dotnet-analyzer", getenv("DOTNET_ANALYZER_ADDR", "localhost:50057"), []string{"PE", "ELF"}, []string{"dotnet"})
	reg.Register("python-analyzer", getenv("PYTHON_ANALYZER_ADDR", "localhost:50058"), []string{"PE", "ELF"}, []string{"python"})
	reg.Register("delphi-analyzer", getenv("DELPHI_ANALYZER_ADDR", "localhost:50059"), []string{"PE", "ELF"}, []string{"delphi"})
	reg.Register("shellcode-analyzer", getenv("SHELLCODE_ANALYZER_ADDR", "localhost:50060"), []string{"PE", "ELF", "raw", "unknown"}, []string{"shellcode", "unknown"})
	reg.Register("ttp-engine", getenv("TTP_ENGINE_ADDR", "localhost:50056"), []string{"*"}, []string{"*"})

	// --- Step 1: Triage ---
	triageAddr := reg.ResolveByName("triage")
	if triageAddr == "" {
		log.Fatal("no triage service registered")
	}

	log.Printf("[1/3] calling triage at %s", triageAddr)
	triageResult, err := callAnalyzer(triageAddr, &pb.SampleRequest{
		SamplePath: samplePath,
		Metadata:   map[string]string{},
	})
	if err != nil {
		log.Fatalf("triage call failed: %v", err)
	}
	log.Printf("triage result: format=%s language=%s packed=%v packer=%s",
		triageResult.Format, triageResult.Language, triageResult.IsPacked, triageResult.PackerName)

	// --- Step 2: Route to language-specific analyzer, if one matches ---
	// For raw/headerless blobs (format=unknown or language=unknown) the
	// shellcode-analyzer is attempted as a fallback before giving up.
	var languageResult *pb.AnalysisResult
	langAddrs := reg.Resolve(triageResult.Format, triageResult.Language)
	var specificAddr string
	for _, addr := range langAddrs {
		if addr != triageAddr {
			specificAddr = addr
			break
		}
	}

	// Shellcode fallback: if triage could not identify the format/language,
	// try the shellcode-analyzer — it handles raw, headerless blobs.
	if specificAddr == "" && (triageResult.Format == "unknown" || triageResult.Language == "unknown" || triageResult.Format == "") {
		if scAddr := reg.ResolveByName("shellcode-analyzer"); scAddr != "" {
			log.Printf("[2/3] no language analyzer matched, falling back to shellcode-analyzer")
			specificAddr = scAddr
		}
	}

	if specificAddr != "" {
		log.Printf("[2/3] calling language analyzer at %s (language=%s)", specificAddr, triageResult.Language)
		languageResult, err = callAnalyzer(specificAddr, &pb.SampleRequest{
			SamplePath: samplePath,
			Metadata:   map[string]string{},
		})
		if err != nil {
			log.Printf("language analyzer call failed (continuing without it): %v", err)
		} else {
			log.Printf("language analyzer result: language=%s extra=%v", languageResult.Language, languageResult.Extra)
		}
	} else {
		log.Printf("[2/3] no specific language analyzer registered for language=%s, skipping", triageResult.Language)
	}

	// --- Step 3: TTP correlation ---
	ttpAddr := reg.ResolveByName("ttp-engine")
	if ttpAddr == "" {
		log.Fatal("no ttp-engine service registered")
	}

	ttpMetadata := map[string]string{
		"is_packed":   boolToStr(triageResult.IsPacked),
		"packer_name": triageResult.PackerName,
		"language":    triageResult.Language,
	}

	log.Printf("[3/3] calling ttp-engine at %s", ttpAddr)
	ttpResult, err := callAnalyzer(ttpAddr, &pb.SampleRequest{
		SamplePath: samplePath,
		Metadata:   ttpMetadata,
	})
	if err != nil {
		log.Fatalf("ttp-engine call failed: %v", err)
	}

	log.Printf("=== FINAL RESULT ===")
	log.Printf("format=%s language=%s packed=%v packer=%s",
		triageResult.Format, triageResult.Language, triageResult.IsPacked, triageResult.PackerName)
	log.Printf("TTPs found: %d", len(ttpResult.Ttps))
	for _, ttp := range ttpResult.Ttps {
		log.Printf("  - %s: %s (%s) confidence=%.2f", ttp.TechniqueId, ttp.TechniqueName, ttp.Tactic, ttp.Confidence)
	}

	generateReport(samplePath, triageResult, languageResult, ttpResult)
}
