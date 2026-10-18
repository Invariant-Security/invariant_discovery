# syntax=docker/dockerfile:1
# python:3.12.14-slim fixado por digest do índice -- atualizar
# conscientemente (README, "Locked dependencies").
ARG BASE=python:3.12.14-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
FROM ${BASE}

WORKDIR /app

# Sondagem é só sockets/TLS/asyncio stdlib -- ao contrário de
# invariant_assessment, este container não precisa de docker-cli nem do
# socket do host, só de rede de saída até os endpoints cadastrados.

# Dependências antes do código: mudar README/src não reinstala nada.
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps . && pip check

EXPOSE 8000
CMD ["uvicorn", "invariant_discovery.api:app", "--host", "0.0.0.0", "--port", "8000"]
