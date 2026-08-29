FROM python:3.12-slim
WORKDIR /app
COPY services/python-analyzer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/python-analyzer/pb/ ./pb/
COPY services/python-analyzer/server.py .
ENV GRPC_PORT=50058
EXPOSE 50058
CMD ["python", "server.py"]
