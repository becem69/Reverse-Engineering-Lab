"""
Delphi-binary analyzer.
Detects Delphi/Borland-compiled executables via VCL/RTL signature strings
and known Delphi unit names, and extracts a sample of referenced units
as evidence.
"""

import logging
import os
import re
from concurrent import futures

import grpc

from pb import analyzer_pb2, analyzer_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [delphi-analyzer] %(levelname)s %(message)s")
log = logging.getLogger("delphi-analyzer")

SERVICE_NAME = "delphi-analyzer"

DELPHI_MARKERS = [
    b"Borland",
    b"Delphi",
    b"SysUtils",
    b"Vcl.Forms",
    b"Vcl.Controls",
    b"System.Classes",
    b"FastMM",
    b"madExcept",
    # Linux/cross-platform Delphi via Free Pascal / Lazarus uses LCL instead of VCL.
    b"LCLBase",
    b"LCLIntf",
    b"LCLType",
    b"lazarus",
]

KNOWN_UNIT_PATTERN = re.compile(
    rb"(?:Vcl|System|Data|Web|Soap|Xml)\.[A-Za-z_][A-Za-z0-9_.]{2,40}"
)


def detect_delphi(raw: bytes):
    hits = [m.decode() for m in DELPHI_MARKERS if m in raw]
    return len(hits) > 0, hits


def extract_units(raw: bytes) -> list:
    matches = set()
    for m in KNOWN_UNIT_PATTERN.findall(raw):
        matches.add(m.decode("ascii", errors="ignore"))
        if len(matches) >= 20:
            break
    return sorted(matches)


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

        is_delphi, marker_hits = detect_delphi(raw)
        result.language = "delphi" if is_delphi else "unknown"

        extra = {"is_delphi": str(is_delphi)}
        if is_delphi:
            extra["matched_markers"] = ",".join(marker_hits)
            units = extract_units(raw)
            extra["sample_units"] = ",".join(units)
            extra["unit_count_sampled"] = str(len(units))

        result.extra.update(extra)

        log.info("delphi analysis complete: is_delphi=%s markers=%s", is_delphi, marker_hits)
        return result

    def Capabilities(self, request, context):
        return analyzer_pb2.CapabilitiesResponse(
            supported_formats=["PE", "ELF"],
            supported_languages=["delphi"],
            service_name=SERVICE_NAME,
        )


def serve():
    port = os.environ.get("GRPC_PORT", "50059")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    analyzer_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    log.info("delphi-analyzer service listening on port %s", port)
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
