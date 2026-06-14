FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN groupadd -r scanner && useradd -r -g scanner scanner && \
    mkdir -p /data && chown scanner:scanner /data

ENV PYTHONPATH=/app/src
ENV SCANNER_DB_TYPE=sqlite
ENV SCANNER_DB_PATH=/data/iot_scanner.db

EXPOSE 5000

USER scanner

# Gunicorn for production (replaces the Flask dev server). Sized for a
# t3.micro (1 vCPU, 1GB): 2 gthread workers x 4 threads. Threads suit this
# I/O-bound (network/DB) workload and keep the long-lived SSE stream alive
# without spawning memory-hungry processes. Scan state lives in the DB, so
# any worker can serve /api/scan/status and /api/scan/stream.
CMD ["gunicorn", "--workers", "2", "--threads", "4", \
     "--bind", "0.0.0.0:5000", "--timeout", "120", \
     "api.app:create_app()"]
