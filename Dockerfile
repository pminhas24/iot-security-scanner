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

EXPOSE 5000

USER scanner

CMD ["python", "src/cli.py", "--web", "--db-path", "/data/iot_scanner.db"]
