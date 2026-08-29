# RELab - Reverse Engineering Lab

RELab is a modular, Dockerized static-analysis pipeline for binary samples. You hand it a file - an ELF, a PE, a raw shellcode blob, or anything in between - and it automatically triages the format, routes the sample to the right language-specific analyzer, correlates findings against MITRE ATT&CK, and writes a structured JSON report. Everything runs locally in containers, no cloud dependencies.

The project is deliberately polyglot: each analyzer is written in the language best suited to the job (Python for signature matching, Go for build-info extraction, Rust for symbol demangling, C++ for disassembly, C# for CLR metadata, Ruby for report generation), all stitched together by a Go orchestrator over gRPC.

---

## Requirements

Only **Docker** and **Docker Compose** are required to run RELab. All language toolchains (Go, Rust, .NET, C++, Python, Ruby) are installed inside the build containers, nothing needs to be installed on the host.

| Dependency | Purpose |
|---|---|
| Docker Engine | Build and run all service containers |
| Docker Compose (v2, `docker compose`) | Orchestrate the multi-container stack |

Native (non-Docker) development is also possible for iterating on a single service, see **Local Development** below.

---

## Setup

```bash
git clone Reverse-Engineering-Lab RELab
cd RELab
docker compose build
```

The first build takes several minutes (compiling Go, Rust, C++, and .NET services from source). Subsequent builds are cached and much faster.

---

## How to Use

Run the full pipeline against a sample on the shared volume:

```bash
docker compose run --rm orchestrator
```

The orchestrator reads the sample path from the `DEMO_SAMPLE_PATH` environment variable (defaults to `/tmp/fake_sample.exe`). To analyze your own sample, mount it into the `samples` volume or override the path:

```bash
docker compose run --rm -e DEMO_SAMPLE_PATH=/samples/mysample.exe orchestrator
```

To bring up all analyzer services persistently (so the orchestrator can be run repeatedly without cold-starting every container):

```bash
docker compose up -d
docker compose run --rm orchestrator
```

The final report is written to `/tmp/relab_report_output.json` inside the orchestrator container. Use a bind mount if you want it accessible on the host.

---

## How It Works

RELab is built around one simple idea: every component speaks the same gRPC interface defined in `proto/analyzer.proto`, so any language can host any stage of the pipeline without any stage needing to know what language another is written in.

### The shared contract - `analyzer.proto`

Every service exposes two RPCs:
- `Analyze(SampleRequest) -> AnalysisResult`, the main analysis call.
- `Capabilities(Empty) -> CapabilitiesResponse`, declares which formats and languages this service handles.

`SampleRequest` carries the file path and an optional `metadata` map for passing findings between stages. `AnalysisResult` carries format, language, packer info, imports, exports, strings of interest, a list of `TTP` structs, and a free-form `extra` map for service-specific data.

Protobuf generates bindings for every language automatically from the single source-of-truth `.proto` file, so the wire format is identical regardless of whether the sender is Go, Rust, C#, Python, or C++.

### The orchestrator (Go)

`orchestrator/cmd/main.go` is the only piece with a global view of the pipeline. It:

1. **Registers all services** in an internal registry that maps `(format, language)` pairs to gRPC addresses (resolved via Docker Compose service names on the shared network).
2. **Calls triage first**, sends the sample path and gets back a format (`PE`, `ELF`, `MachO`, `unknown`) and a language (`go`, `rust`, `dotnet`, `cpp`, `delphi`, `python`, `unknown`).
3. **Routes to the language analyzer**, looks up the registry for a service matching both the detected format and language. If triage returned `unknown`, it falls back to the shellcode-analyzer.
4. **Calls the TTP engine**, passes triage findings (packed status, packer name, language) as metadata for rule-based MITRE ATT&CK correlation.
5. **Calls the report generator**, serializes all results to JSON and shells out to the Ruby report generator to produce the final report.

### Stage 1 - Triage (Python)

`services/triage/server.py` reads the raw bytes of the sample and performs:
- **Format detection**: magic bytes (`MZ` -> PE, `\x7fELF` -> ELF, Mach-O magic values).
- **Language detection**: scans for known byte-string markers per language (`.gopclntab` for Go, `.rustc` for Rust, `mscorlib`/`System.Runtime` for .NET, `_ZN`/`GLIBCXX` for C++, `Borland`/`Vcl.Forms` for Delphi, PyInstaller's bootloader magic for Python). Assigns the language with the most marker hits.
- **Packer detection**: known packer section signatures (UPX, ASPack, Themida, PECompact, MPRESS), falling back to Shannon entropy analysis.
- **LIEF metadata**: structured PE/ELF metadata (section count, import count, compile timestamp, PIE flag) via the `lief` library.

### Stage 2 - Language analyzers

**Go analyzer (Go)**: uses `debug/buildinfo` to extract the embedded build manifest (Go version, module path, dependency graph). Works even on stripped binaries since Go embeds this unconditionally.

**Rust analyzer (Rust)**: parses the binary with `goblin`, walks the real symbol table, and demangles Itanium-mangled Rust symbols (`_ZN` prefix) via `rustc-demangle`.

**C++ analyzer (C++)**: scans for Itanium-mangled symbols (`_ZN`, `_ZSt`), vtable strings, and `GLIBCXX` version strings, reporting counts of each.

**Shellcode analyzer (C++)**: disassembles raw, headerless bytes with Capstone (x86-64) and flags `syscall` instructions, software interrupts, NOP sleds, and call-then-pop GetPC patterns.

**.NET analyzer (C#)**: uses `System.Reflection.Metadata` to read CLR metadata directly (module name, referenced assemblies, type names) without loading or executing the assembly.

**Python analyzer (Python)**: detects PyInstaller's bootloader magic bytes and extracts bundled module name strings as evidence.

**Delphi analyzer (Python)**: detects Borland/VCL compiler marker strings and known Delphi unit name patterns.

### Stage 3 - TTP correlation engine (Python)

`services/ttp-engine/rules.py` maps signals from earlier stages to MITRE ATT&CK techniques via simple, independent rule functions (packed binary -> Defense Evasion, suspicious API strings -> Process Injection / Command Execution, etc.). Adding coverage means adding a rule function, not touching pipeline code.

### Stage 4 - Report generator (Ruby)

`services/report-generator/report.rb` merges all analyzer outputs into one JSON report, de-duplicating TTPs found by multiple analyzers. `generate.rb` is the CLI entry point the orchestrator shells out to.

---

## Known Limitations

**Packer OEP recovery was attempted and removed.** An earlier version of this project included a dedicated packer/unpacking service (C + Unicorn Engine) that attempted to emulate a packer's unpacking stub to recover the Original Entry Point. Signature-based packer *detection* worked reliably and still lives in the triage service, but full stub emulation required faithfully emulating the Linux syscall/ABI environment (`mmap`, `mprotect`, TLS setup, etc.), which a hand-rolled set of syscall hooks could not do reliably, emulation would drift off the real code path after a few hundred thousand instructions. Rather than ship broken/unreliable OEP recovery, the service was removed. Revisiting this properly would mean building on a full userland-emulation framework (e.g. **Qiling**) rather than raw Unicorn Engine.

**Dynamic analysis (sandboxed detonation) is out of scope for this version.** RELab is currently a purely static-analysis pipeline. A future phase could add an isolated dynamic sandbox (network-faked, syscall-traced) to complement the static findings here.

---

## Project Structure

```
RELab/
|
├── docker-compose.yml               # Full multi-service stack definition
├── .dockerignore
|
├── proto/
│   └── analyzer.proto               # Single shared gRPC contract for every service
|
├── shared/
│   └── proto-gen/go/                # Go protobuf/gRPC generated stubs (go.mod only; generated at build time)
|
├── orchestrator/                    # Go - pipeline coordinator
│   ├── cmd/main.go                  # Entry point: triage -> route -> TTP -> report
│   ├── internal/registry/           # Service registry: maps (format, language) -> address
│   ├── go.mod
│   └── Dockerfile
|
├── services/
│   ├── triage/                      # Python - format/language/packer detection
│   │   ├── server.py
│   │   ├── pb/                      # Python gRPC stubs
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   │
│   ├── go-analyzer/                 # Go - Go build metadata extraction
│   │   ├── cmd/main.go
│   │   ├── go.mod
│   │   └── Dockerfile
│   │
│   ├── rust-analyzer/               # Rust - symbol demangling via goblin
│   │   ├── src/main.rs
│   │   ├── Cargo.toml
│   │   ├── build.rs
│   │   └── Dockerfile
│   │
│   ├── cpp-analyzer/                # C++ - Itanium symbol / GLIBCXX scanning
│   │   ├── src/main.cpp
│   │   ├── CMakeLists.txt
│   │   └── Dockerfile
│   │
│   ├── shellcode-analyzer/          # C++ - Capstone x86-64 disassembly
│   │   ├── src/main.cpp
│   │   ├── CMakeLists.txt
│   │   └── Dockerfile
│   │
│   ├── dotnet-analyzer/             # C# - CLR metadata via Reflection.Metadata
│   │   ├── Services/AnalyzerService.cs
│   │   ├── Program.cs
│   │   ├── Protos/analyzer.proto
│   │   ├── dotnet-analyzer.csproj
│   │   └── Dockerfile
│   │
│   ├── python-analyzer/             # Python - PyInstaller magic detection
│   │   ├── server.py
│   │   ├── pb/
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   │
│   ├── delphi-analyzer/             # Python - Borland/VCL marker detection
│   │   ├── server.py
│   │   ├── pb/
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   │
│   ├── ttp-engine/                  # Python - MITRE ATT&CK rule correlator
│   │   ├── server.py
│   │   ├── rules.py                 # Add new TTP rules here
│   │   ├── pb/
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   │
│   └── report-generator/            # Ruby - JSON report builder
│       ├── report.rb                # Core aggregation and dedup logic
│       ├── generate.rb              # CLI entry point
│       └── Dockerfile
```

### Port assignments

| Service | Port |
|---|---|
| triage | 50051 |
| go-analyzer | 50052 |
| rust-analyzer | 50053 |
| cpp-analyzer | 50054 |
| ttp-engine | 50056 |
| dotnet-analyzer | 50057 |
| python-analyzer | 50058 |
| delphi-analyzer | 50059 |
| shellcode-analyzer | 50060 |
| orchestrator | 9000 |

Inside Docker Compose, services reach each other by service name (e.g. `triage:50051`), configured via environment variables in `docker-compose.yml`.

---

## Local Development (without Docker)

Each service can also be run natively for faster iteration on a single component. This requires the language toolchain for that specific service (Go, Rust + Cargo, .NET 8 SDK, CMake + a C++ compiler + gRPC/Protobuf/Capstone system libraries, Python 3, or Ruby, depending on the service). See each service's `Dockerfile` for the exact build steps its container performs, replicate the same steps locally, then run the resulting binary/script directly and point the orchestrator's environment variables (`TRIAGE_ADDR`, `GO_ANALYZER_ADDR`, etc.) at `localhost:<port>` instead of the Docker service names.
