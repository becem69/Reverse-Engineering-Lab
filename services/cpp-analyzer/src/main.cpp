// C/C++ binary analyzer.
// First pass: detect C++-specific signals via string/symbol scanning
// (Itanium-mangled symbols like _ZN, _ZSt, libstdc++ markers, vtable
// symbols). Full disassembly (Capstone) and import table analysis can
// be layered on once this skeleton is confirmed working end-to-end.

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <grpcpp/grpcpp.h>
#include "analyzer.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using malwarelab::Analyzer;
using malwarelab::SampleRequest;
using malwarelab::AnalysisResult;
using malwarelab::CapabilitiesResponse;
using malwarelab::Empty;

const std::string SERVICE_NAME = "cpp-analyzer";

std::string readFile(const std::string& path, bool& ok) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        ok = false;
        return "";
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    ok = true;
    return ss.str();
}

int countOccurrences(const std::string& haystack, const std::string& needle) {
    int count = 0;
    size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        count++;
        pos += needle.length();
    }
    return count;
}

class AnalyzerServiceImpl final : public Analyzer::Service {
    Status Analyze(ServerContext* context, const SampleRequest* request,
                   AnalysisResult* response) override {
        std::cout << "received sample path=" << request->sample_path() << std::endl;

        bool ok = false;
        std::string raw = readFile(request->sample_path(), ok);
        response->set_analyzer_name(SERVICE_NAME);

        if (!ok) {
            response->set_error("failed to read file: " + request->sample_path());
            return Status::OK;
        }

        int mangledSymbols = countOccurrences(raw, "_ZN");
        int stdSymbols = countOccurrences(raw, "_ZSt");
        int vtableRefs = countOccurrences(raw, "vtable for");
        int glibcxxRefs = countOccurrences(raw, "GLIBCXX");

        bool isCpp = (mangledSymbols > 0) || (stdSymbols > 0) || (vtableRefs > 0) || (glibcxxRefs > 0);

        response->set_language(isCpp ? "cpp" : "c");

        auto* extra = response->mutable_extra();
        (*extra)["mangled_symbol_count"] = std::to_string(mangledSymbols);
        (*extra)["std_symbol_count"] = std::to_string(stdSymbols);
        (*extra)["vtable_reference_count"] = std::to_string(vtableRefs);
        (*extra)["glibcxx_reference_count"] = std::to_string(glibcxxRefs);

        std::cout << "cpp analysis complete: language=" << response->language()
                   << " mangled_symbols=" << mangledSymbols << std::endl;

        return Status::OK;
    }

    Status Capabilities(ServerContext* context, const Empty* request,
                         CapabilitiesResponse* response) override {
        response->add_supported_formats("PE");
        response->add_supported_formats("ELF");
        response->add_supported_languages("cpp");
        response->add_supported_languages("c");
        response->set_service_name(SERVICE_NAME);
        return Status::OK;
    }
};

void RunServer() {
    std::string port = std::getenv("GRPC_PORT") ? std::getenv("GRPC_PORT") : "50054";
    std::string server_address = "0.0.0.0:" + port;

    AnalyzerServiceImpl service;
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "cpp-analyzer service listening on port " << port << std::endl;
    server->Wait();
}

int main() {
    RunServer();
    return 0;
}
