FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*
COPY services/triage/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/triage/pb/ ./pb/
COPY services/triage/server.py .
ENV GRPC_PORT=50051
EXPOSE 50051
CMD ["python", "server.py"]
