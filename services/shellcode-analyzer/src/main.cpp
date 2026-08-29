// Shellcode/assembly analyzer.
// Treats the sample as a raw headerless blob (no PE/ELF expected) and
// disassembles it directly with Capstone in x86-64 mode. Flags signals
// common in real shellcode: syscall/interrupt instructions, NOP sleds,
// and GetPC patterns (call immediately followed by pop — the classic
// technique shellcode uses to find its own address without relocations).

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <capstone/capstone.h>
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

const std::string SERVICE_NAME = "shellcode-analyzer";

std::vector<uint8_t> readFileBytes(const std::string& path, bool& ok) {
    std::ifstream file(path, std::ios::binary);
    if (!file) { ok = false; return {}; }
    ok = true;
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
}

class AnalyzerServiceImpl final : public Analyzer::Service {
    Status Analyze(ServerContext* context, const SampleRequest* request,
                   AnalysisResult* response) override {
        std::cout << "received sample path=" << request->sample_path() << std::endl;

        bool ok = false;
        std::vector<uint8_t> raw = readFileBytes(request->sample_path(), ok);
        response->set_analyzer_name(SERVICE_NAME);

        if (!ok) {
            response->set_error("failed to read file: " + request->sample_path());
            return Status::OK;
        }

        csh handle;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            response->set_error("failed to initialize capstone");
            return Status::OK;
        }

        cs_insn* insn;
        size_t count = cs_disasm(handle, raw.data(), raw.size(), 0x1000, 0, &insn);

        int syscall_count = 0;
        int int_count = 0;
        int nop_count = 0;
        int getpc_pattern_count = 0;
        size_t valid_instructions = count;

        for (size_t i = 0; i < count; i++) {
            std::string mnemonic = insn[i].mnemonic;

            if (mnemonic == "syscall") syscall_count++;
            if (mnemonic == "int3" || mnemonic == "int") int_count++;
            if (mnemonic == "nop") nop_count++;

            if (mnemonic == "call" && i + 1 < count) {
                std::string next_mnemonic = insn[i + 1].mnemonic;
                if (next_mnemonic == "pop") {
                    getpc_pattern_count++;
                }
            }
        }

        bool looksLikeShellcode = (syscall_count > 0) || (getpc_pattern_count > 0) ||
                                   (nop_count > 10) || (valid_instructions > 0 && count * 4 >= raw.size());

        response->set_language(looksLikeShellcode ? "shellcode" : "unknown");

        auto* extra = response->mutable_extra();
        (*extra)["instructions_decoded"] = std::to_string(count);
        (*extra)["syscall_count"] = std::to_string(syscall_count);
        (*extra)["interrupt_count"] = std::to_string(int_count);
        (*extra)["nop_count"] = std::to_string(nop_count);
        (*extra)["getpc_pattern_count"] = std::to_string(getpc_pattern_count);
        (*extra)["sample_size_bytes"] = std::to_string(raw.size());

        std::cout << "shellcode analysis complete: instructions=" << count
                   << " syscalls=" << syscall_count
                   << " getpc_patterns=" << getpc_pattern_count << std::endl;

        if (count > 0) {
            cs_free(insn, count);
        }
        cs_close(&handle);

        return Status::OK;
    }

    Status Capabilities(ServerContext* context, const Empty* request,
                         CapabilitiesResponse* response) override {
        response->add_supported_formats("raw");
        response->add_supported_languages("shellcode");
        response->set_service_name(SERVICE_NAME);
        return Status::OK;
    }
};

void RunServer() {
    std::string port = std::getenv("GRPC_PORT") ? std::getenv("GRPC_PORT") : "50060";
    std::string server_address = "0.0.0.0:" + port;

    AnalyzerServiceImpl service;
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "shellcode-analyzer listening on port " << port << std::endl;
    server->Wait();
}

int main() {
    RunServer();
    return 0;
}
