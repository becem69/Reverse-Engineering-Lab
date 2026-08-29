# CLI entrypoint: reads aggregated analyzer results from a JSON file
# (written by the orchestrator), builds the final report, writes it out.
# Usage: ruby generate.rb <input_results.json> <output_report.json>

require_relative 'report'
require 'json'

input_path = ARGV[0]
output_path = ARGV[1]

raise "usage: ruby generate.rb <input.json> <output.json>" unless input_path && output_path

data = JSON.parse(File.read(input_path), symbolize_names: true)

report = ReportGenerator.build_report(data[:sample_path], data[:analysis_results])
ReportGenerator.write_report(report, output_path)

puts "Report written to #{output_path}"
