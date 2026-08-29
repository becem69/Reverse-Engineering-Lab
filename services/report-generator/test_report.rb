require_relative 'report'

fake_triage_result = {
  analyzer_name: "triage",
  format: "PE",
  language: "go",
  is_packed: true,
  packer_name: "UPX",
  extra: { entropy: "7.8", file_size: "204800" }
}

fake_ttp_result = {
  analyzer_name: "ttp-engine",
  ttps: [
    {
      technique_id: "T1027.002",
      technique_name: "Software Packing",
      tactic: "Defense Evasion",
      evidence: "binary is packed with UPX",
      confidence: 0.85
    },
    {
      technique_id: "T1055",
      technique_name: "Process Injection",
      tactic: "Defense Evasion",
      evidence: "indicator string found: VirtualAllocEx",
      confidence: 0.7
    }
  ]
}

report = ReportGenerator.build_report("/tmp/fake_sample.exe", [fake_triage_result, fake_ttp_result])
ReportGenerator.write_report(report, "/tmp/test_report.json")

puts "Report written to /tmp/test_report.json"
puts JSON.pretty_generate(report)
