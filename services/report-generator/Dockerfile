FROM ruby:3.3-slim
WORKDIR /app
COPY services/report-generator/report.rb services/report-generator/generate.rb .
ENTRYPOINT ["ruby", "generate.rb"]
