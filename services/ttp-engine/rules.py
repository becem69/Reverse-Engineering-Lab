"""
TTP Rules
=========
Maps signals we already have from triage/analyzers (packed status, language,
detected strings/imports, etc.) to MITRE ATT&CK techniques. Intentionally
simple and data-driven — extending coverage should mean adding a rule here,
not writing new code paths.

Each rule is a function that inspects an AnalysisResult-like dict and
returns zero or more TTP matches, so rules can be combined arbitrarily
and added independently.
"""

TTPMatch = dict  # {technique_id, technique_name, tactic, evidence, confidence}


def rule_packed_binary(extra: dict, is_packed: bool, packer_name: str) -> list:
    """A packed binary is itself a defense-evasion signal."""
    if not is_packed:
        return []
    return [{
        "technique_id": "T1027.002",
        "technique_name": "Software Packing",
        "tactic": "Defense Evasion",
        "evidence": f"binary is packed with {packer_name or 'an unidentified packer'}",
        "confidence": 0.85,
    }]


def rule_go_language(language: str, extra: dict) -> list:
    """Go binaries are common in modern malware (Cobalt Strike loaders,
    cross-platform botnets) partly because of easy cross-compilation and
    static linking — itself worth flagging as a mild signal."""
    if language != "go":
        return []
    return [{
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "evidence": "written in Go; statically-linked Go binaries are commonly used "
                    "to evade signature-based detection and simplify cross-platform deployment",
        "confidence": 0.3,
    }]


def rule_suspicious_strings(strings_of_interest: list) -> list:
    """Look for strings that commonly indicate specific ATT&CK techniques."""
    matches = []
    joined = " ".join(strings_of_interest).lower()

    indicators = [
        (["cmd.exe", "/c ", "powershell"], "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", 0.6),
        (["reg add", "hkey_", "run\\"], "T1547.001", "Registry Run Keys / Startup Folder", "Persistence", 0.6),
        (["schtasks", "crontab"], "T1053", "Scheduled Task/Job", "Persistence", 0.6),
        (["socket", "connect(", "recv(", "send("], "T1071", "Application Layer Protocol", "Command and Control", 0.4),
        (["createremotethread", "virtualallocex", "writeprocessmemory"], "T1055", "Process Injection", "Defense Evasion", 0.7),
    ]

    for keywords, tid, tname, tactic, confidence in indicators:
        if any(kw in joined for kw in keywords):
            matches.append({
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "evidence": f"one or more indicator strings found: {[k for k in keywords if k in joined]}",
                "confidence": confidence,
            })

    return matches


def run_all_rules(analysis_result: dict) -> list:
    """Runs every rule against a merged analysis result dict and returns
    the combined list of TTP matches."""
    matches = []
    matches += rule_packed_binary(
        analysis_result.get("extra", {}),
        analysis_result.get("is_packed", False),
        analysis_result.get("packer_name", ""),
    )
    matches += rule_go_language(
        analysis_result.get("language", ""),
        analysis_result.get("extra", {}),
    )
    matches += rule_suspicious_strings(
        analysis_result.get("strings_of_interest", [])
    )
    return matches
