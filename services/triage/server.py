"""
Triage Service
==============
First stage of the pipeline. Every sample passes through here before being
routed to a language-specific analyzer.

Responsibilities:
  1. File format detection (PE / ELF / Mach-O / unknown)
  2. Language fingerprinting (Go / Rust / C++ / .NET / Python / unknown)
  3. Packer detection (entropy-based + signature-based)
  4. Hashing (sha256 already assumed provided by orchestrator, but we verify)
"""

import hashlib
import logging
import math
import os
import re
from concurrent import futures

import grpc
import lief

from pb import analyzer_pb2, analyzer_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [triage] %(levelname)s %(message)s")
log = logging.getLogger("triage")

SERVICE_NAME = "triage"

PACKER_SECTION_SIGNATURES = {
    "UPX": [b"UPX0", b"UPX1", b"UPX!"],
    "ASPack": [b".aspack", b".adata"],
    "Themida": [b".themida", b".winlice"],
    "PECompact": [b"PEC2"],
    "MPRESS": [b".MPRESS1", b".MPRESS2"],
}

GO_MARKERS = [b"Go build ID:", b".gopclntab", b"golang.org/", b"runtime.main"]
RUST_MARKERS = [b".rustc", b"rust_begin_unwind", b"rust_panic", b"cargo/registry"]
DOTNET_MARKERS = [b"mscorlib", b"System.Runtime", b"_CorExeMain"]
CPP_MARKERS = [b"_ZN", b"_ZSt", b"std::", b"GLIBCXX", b"vtable for"]
PYTHON_MARKERS = [b"MEI\x0c\x0b\x0a\x0b\x0e", b"PyInstaller", b"python3", b"Py_Initialize"]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    entropy = 0.0
    length = len(data)
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def detect_format(raw: bytes) -> str:
    if raw[:2] == b"MZ":
        return "PE"
    if raw[:4] == b"\x7fELF":
        return "ELF"
    if raw[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "MachO"
    return "unknown"


def detect_language(raw: bytes) -> str:
    def hits(markers):
        return sum(1 for m in markers if m in raw)

    scores = {
        "go": hits(GO_MARKERS),
        "rust": hits(RUST_MARKERS),
        "dotnet": hits(DOTNET_MARKERS),
        "cpp": hits(CPP_MARKERS),
        "python": hits(PYTHON_MARKERS),
    }
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "unknown"
    return best


def detect_packer(raw: bytes, fmt: str):
    for name, sigs in PACKER_SECTION_SIGNATURES.items():
        if any(sig in raw for sig in sigs):
            return True, name, 0.9

    entropy = shannon_entropy(raw)
    printable_ratio = len(re.findall(rb"[ -~]{5,}", raw)) / max(len(raw) // 200, 1)

    if entropy > 7.2 and printable_ratio < 1.0:
        return True, "unknown_packer", min(0.5 + (entropy - 7.2), 0.85)

    return False, "", 0.0


def try_lief_metadata(path: str, fmt: str) -> dict:
    extra = {}
    try:
        binary = lief.parse(path)
        if binary is None:
            return extra
        if fmt == "PE":
            extra["compile_timestamp"] = str(getattr(binary.header, "time_date_stamps", ""))
            extra["num_sections"] = str(len(binary.sections))
            extra["imported_functions_count"] = str(len(binary.imported_functions))
        elif fmt == "ELF":
            extra["num_sections"] = str(len(binary.sections))
            extra["is_pie"] = str(binary.is_pie)
    except Exception as e:
        extra["lief_parse_error"] = str(e)
    return extra


class AnalyzerServicer(analyzer_pb2_grpc.AnalyzerServicer):
    def Analyze(self, request, context):
        path = request.sample_path
        log.info("received sample sha256=%s path=%s", request.sha256, path)

        if not os.path.isfile(path):
            return analyzer_pb2.AnalysisResult(
                analyzer_name=SERVICE_NAME,
                error=f"sample not found at {path}",
            )

        with open(path, "rb") as f:
            raw = f.read()

        actual_hash = hashlib.sha256(raw).hexdigest()
        if request.sha256 and actual_hash != request.sha256:
            log.warning("hash mismatch: expected=%s actual=%s", request.sha256, actual_hash)

        fmt = detect_format(raw)
        language = detect_language(raw)
        is_packed, packer_name, confidence = detect_packer(raw, fmt)
        extra = try_lief_metadata(path, fmt)
        extra["file_size"] = str(len(raw))
        extra["entropy"] = f"{shannon_entropy(raw):.3f}"

        result = analyzer_pb2.AnalysisResult(
            analyzer_name=SERVICE_NAME,
            format=fmt,
            language=language,
            is_packed=is_packed,
            packer_name=packer_name,
            packer_confidence=confidence,
            extra=extra,
        )
        log.info(
            "triage result sha256=%s format=%s language=%s packed=%s packer=%s",
            request.sha256, fmt, language, is_packed, packer_name,
        )
        return result

    def Capabilities(self, request, context):
        return analyzer_pb2.CapabilitiesResponse(
            supported_formats=["PE", "ELF", "MachO", "unknown"],
            supported_languages=["*"],
            service_name=SERVICE_NAME,
        )


def serve():
    port = os.environ.get("GRPC_PORT", "50051")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    analyzer_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    log.info("triage service listening on port %s", port)
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
