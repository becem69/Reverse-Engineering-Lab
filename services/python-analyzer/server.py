"""
Python-binary analyzer.
Detects PyInstaller-frozen executables (the dominant way Python malware
gets distributed as a standalone binary) via PyInstaller's embedded
archive magic bytes, and extracts bundled module names as evidence.
"""

import logging
import os
import re
from concurrent import futures

import grpc

from pb import analyzer_pb2, analyzer_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [python-analyzer] %(levelname)s %(message)s")
log = logging.getLogger("python-analyzer")

SERVICE_NAME = "python-analyzer"

# PyInstaller embeds this magic marker (its "cookie") near the end of the
# frozen executable, used by its own bootloader to locate the archive.
PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def detect_pyinstaller(raw: bytes) -> bool:
    return PYINSTALLER_MAGIC in raw


def extract_module_names(raw: bytes) -> list:
    # PyInstaller's archive stores module names as readable strings
    # alongside compiled bytecode; a simple pattern catches typical
    # dotted Python module paths without needing full archive parsing.
    pattern = re.compile(rb"[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*){1,4}")
    candidates = set()
    for match in pattern.findall(raw):
        name = match.decode("ascii", errors="ignore")
        if 4 < len(name) < 60:
            candidates.add(name)
        if len(candidates) >= 25:
            break
    return sorted(candidates)


class AnalyzerServicer(analyzer_pb2_grpc.AnalyzerServicer):
    def Analyze(self, request, context):
        path = request.sample_path
        log.info("received sample path=%s", path)

        result = analyzer_pb2.AnalysisResult(analyzer_name=SERVICE_NAME)

        if not os.path.isfile(path):
            result.error = f"sample not found at {path}"
            return result

        with open(path, "rb") as f:
            raw = f.read()

        is_pyinstaller = detect_pyinstaller(raw)
        result.language = "python" if is_pyinstaller else "unknown"

        extra = {}
        extra["is_pyinstaller"] = str(is_pyinstaller)

        if is_pyinstaller:
            modules = extract_module_names(raw)
            extra["sample_module_names"] = ",".join(modules[:20])
            extra["module_count_sampled"] = str(len(modules))

        result.extra.update(extra)

        log.info("python analysis complete: is_pyinstaller=%s", is_pyinstaller)
        return result

    def Capabilities(self, request, context):
        return analyzer_pb2.CapabilitiesResponse(
            supported_formats=["PE", "ELF"],
            supported_languages=["python"],
            service_name=SERVICE_NAME,
        )


def serve():
    port = os.environ.get("GRPC_PORT", "50058")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    analyzer_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    log.info("python-analyzer service listening on port %s", port)
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
