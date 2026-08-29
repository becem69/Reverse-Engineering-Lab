"""
TTP Correlation Engine — gRPC server.
Takes an already-computed AnalysisResult (from triage or a language
analyzer) and runs it through the rule engine to produce ATT&CK TTP
matches. This service doesn't re-analyze the raw sample; it correlates
signals that earlier pipeline stages already extracted.
"""

import logging
import os
from concurrent import futures

import grpc

from pb import analyzer_pb2, analyzer_pb2_grpc
from rules import run_all_rules

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ttp-engine] %(levelname)s %(message)s")
log = logging.getLogger("ttp-engine")

SERVICE_NAME = "ttp-engine"


class AnalyzerServicer(analyzer_pb2_grpc.AnalyzerServicer):
    def Analyze(self, request, context):
        log.info("received sample sha256=%s metadata_keys=%s", request.sha256, list(request.metadata.keys()))

        # This service expects the caller to have populated `metadata` with
        # prior-stage findings (is_packed, packer_name, language, etc.) since
        # it correlates rather than re-analyzes raw bytes. This is a simple
        # convention for now; a dedicated message type can replace it later
        # if the metadata map gets unwieldy.
        analysis_input = {
            "is_packed": request.metadata.get("is_packed", "false").lower() == "true",
            "packer_name": request.metadata.get("packer_name", ""),
            "language": request.metadata.get("language", ""),
            "strings_of_interest": request.metadata.get("strings_of_interest", "").split("|") if request.metadata.get("strings_of_interest") else [],
        }

        ttp_matches = run_all_rules(analysis_input)

        result = analyzer_pb2.AnalysisResult(analyzer_name=SERVICE_NAME)
        for match in ttp_matches:
            ttp = result.ttps.add()
            ttp.technique_id = match["technique_id"]
            ttp.technique_name = match["technique_name"]
            ttp.tactic = match["tactic"]
            ttp.evidence = match["evidence"]
            ttp.confidence = match["confidence"]

        log.info("ttp correlation complete: %d matches found", len(ttp_matches))
        return result

    def Capabilities(self, request, context):
        return analyzer_pb2.CapabilitiesResponse(
            supported_formats=["*"],
            supported_languages=["*"],
            service_name=SERVICE_NAME,
        )


def serve():
    port = os.environ.get("GRPC_PORT", "50056")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    analyzer_pb2_grpc.add_AnalyzerServicer_to_server(AnalyzerServicer(), server)
    server.add_insecure_port(f"[::]:{port}")
    log.info("ttp-engine service listening on port %s", port)
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
