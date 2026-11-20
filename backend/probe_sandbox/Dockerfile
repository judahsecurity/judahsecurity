# Image for probe-egress (relay + scope proxy) and probe-runner (script executor).
# Build context: backend/. Neither service gets backend code, secrets or volumes.
FROM python:3.11-slim

RUN pip install --no-cache-dir httpx==0.25.2 cryptography==41.0.7 \
    && useradd --system --no-create-home --uid 10001 egress

COPY probe_sandbox/egress.py probe_sandbox/runner.py /app/

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
CMD ["python", "-I", "/app/runner.py"]
