# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Sondagem é só sockets/TLS/asyncio stdlib -- ao contrário de
# invariant_assessment, este container não precisa de docker-cli nem do
# socket do host, só de rede de saída até os endpoints cadastrados.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "invariant_discovery.api:app", "--host", "0.0.0.0", "--port", "8000"]
