# Report Generator
# ================
# Aggregates results from all analyzer stages (triage, language analyzers,
# TTP correlation) into a single structured report. JSON is the base
# format; other formats (PDF, STIX) can be built as renderers on top of
# this same aggregated structure later.

require 'json'
require 'time'

module ReportGenerator
  def self.build_report(sample_path, analysis_results)
    report = {
      report_version: "1.0",
      generated_at: Time.now.utc.iso8601,
      sample: { path: sample_path },
      findings: {
        format: nil,
        language: nil,
        is_packed: false,
        packer_name: "",
        imports: [],
        exports: [],
        strings_of_interest: [],
        extra: {}
      },
      ttps: [],
      analyzers_run: []
    }

    analysis_results.each do |result|
      report[:analyzers_run] << (result[:analyzer_name] || "unknown")

      # Merge findings — later analyzers can add detail without
      # overwriting earlier confirmed fields, unless still unset.
      report[:findings][:format] ||= result[:format] if result[:format] && !result[:format].empty?
      report[:findings][:language] ||= result[:language] if result[:language] && !result[:language].empty?
      report[:findings][:is_packed] = true if result[:is_packed]
      if result[:packer_name] && !result[:packer_name].empty? && report[:findings][:packer_name].empty?
        report[:findings][:packer_name] = result[:packer_name]
      end

      report[:findings][:imports].concat(result[:imports] || [])
      report[:findings][:exports].concat(result[:exports] || [])
      report[:findings][:strings_of_interest].concat(result[:strings_of_interest] || [])
      report[:findings][:extra].merge!(result[:extra] || {})

      report[:ttps].concat(result[:ttps] || [])
    end

    # De-duplicate TTPs that might be found by multiple analyzers.
    seen = {}
    deduped_ttps = []
    report[:ttps].each do |ttp|
      key = ttp[:technique_id]
      unless seen[key]
        seen[key] = true
        deduped_ttps << ttp
      end
    end
    report[:ttps] = deduped_ttps

    report
  end

  def self.write_report(report, output_path)
    File.write(output_path, JSON.pretty_generate(report))
  end
end
