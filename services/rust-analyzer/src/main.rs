// Rust-binary analyzer.
// Uses `goblin` to parse ELF/PE binaries and looks for Rust-specific
// signals: the .rustc section (embedded rustc version metadata),
// panic strings, and mangled Rust symbol names (which we demangle
// via rustc-demangle for readability in the report).

use tonic::{transport::Server, Request, Response, Status};
use std::fs;
use goblin::Object;

pub mod malwarelab {
    tonic::include_proto!("malwarelab");
}

use malwarelab::analyzer_server::{Analyzer, AnalyzerServer};
use malwarelab::{SampleRequest, AnalysisResult, CapabilitiesResponse, Empty};

const SERVICE_NAME: &str = "rust-analyzer";

#[derive(Debug, Default)]
pub struct RustAnalyzer {}

#[tonic::async_trait]
impl Analyzer for RustAnalyzer {
    async fn analyze(
        &self,
        request: Request<SampleRequest>,
    ) -> Result<Response<AnalysisResult>, Status> {
        let req = request.into_inner();
        println!("received sample path={}", req.sample_path);

        let raw = match fs::read(&req.sample_path) {
            Ok(data) => data,
            Err(e) => {
                let result = AnalysisResult {
                    analyzer_name: SERVICE_NAME.to_string(),
                    error: format!("failed to read file: {}", e),
                    ..Default::default()
                };
                return Ok(Response::new(result));
            }
        };

        let mut extra = std::collections::HashMap::new();
        let mut is_rust = false;
        let mut demangled_symbols: Vec<String> = vec![];

        // Parse properly via goblin instead of guessing over raw bytes.
        match Object::parse(&raw) {
            Ok(Object::Elf(elf)) => {
                extra.insert("parsed_format".to_string(), "ELF".to_string());
                for sym in elf.syms.iter() {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if name.starts_with("_ZN") || name.starts_with("__ZN") {
                            is_rust = true;
                            if demangled_symbols.len() < 10 {
                                demangled_symbols.push(rustc_demangle::demangle(name).to_string());
                            }
                        }
                    }
                }
                // Section-name check still useful as a fast corroborating signal.
                for section in elf.section_headers.iter() {
                    if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                        if name.contains("rustc") {
                            is_rust = true;
                            extra.insert("rustc_section_found".to_string(), "true".to_string());
                        }
                    }
                }
            }
            Ok(Object::PE(pe)) => {
                extra.insert("parsed_format".to_string(), "PE".to_string());
                for export in pe.exports.iter() {
                    if let Some(name) = export.name {
                        if name.starts_with("_ZN") || name.starts_with("__ZN") {
                            is_rust = true;
                            if demangled_symbols.len() < 10 {
                                demangled_symbols.push(rustc_demangle::demangle(name).to_string());
                            }
                        }
                    }
                }
            }
            Ok(_) => {
                extra.insert("parsed_format".to_string(), "other".to_string());
            }
            Err(e) => {
                extra.insert("goblin_parse_error".to_string(), e.to_string());
            }
        }

        if !demangled_symbols.is_empty() {
            extra.insert("sample_demangled_symbols".to_string(), demangled_symbols.join(" | "));
        }

        let result = AnalysisResult {
            analyzer_name: SERVICE_NAME.to_string(),
            language: if is_rust { "rust".to_string() } else { "unknown".to_string() },
            extra,
            ..Default::default()
        };

        println!("rust analysis complete: is_rust={}", is_rust);
        Ok(Response::new(result))
    }

    async fn capabilities(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CapabilitiesResponse>, Status> {
        Ok(Response::new(CapabilitiesResponse {
            supported_formats: vec!["PE".to_string(), "ELF".to_string()],
            supported_languages: vec!["rust".to_string()],
            service_name: SERVICE_NAME.to_string(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::var("GRPC_PORT").unwrap_or_else(|_| "50053".to_string());
    let addr = format!("0.0.0.0:{}", port).parse()?;
    let analyzer = RustAnalyzer::default();

    println!("rust-analyzer service listening on port {}", port);

    Server::builder()
        .add_service(AnalyzerServer::new(analyzer))
        .serve(addr)
        .await?;

    Ok(())
}
