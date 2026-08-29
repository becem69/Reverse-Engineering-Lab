FROM python:3.12-slim
WORKDIR /app
COPY services/ttp-engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/ttp-engine/pb/ ./pb/
COPY services/ttp-engine/server.py services/ttp-engine/rules.py .
ENV GRPC_PORT=50056
EXPOSE 50056
CMD ["python", "server.py"]
