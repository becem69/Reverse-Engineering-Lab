FROM python:3.12-slim
WORKDIR /app
COPY services/delphi-analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/delphi-analyzer/pb/ ./pb/
COPY services/delphi-analyzer/server.py .
ENV GRPC_PORT=50059
EXPOSE 50059
CMD ["python", "server.py"]
