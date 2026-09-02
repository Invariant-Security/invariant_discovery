"""Thin FastAPI wrapper over ranges.expand + probe.probe_host +
classify.classify. Sem Postgres aqui, ever -- invariant_api é quem
persiste os resultados (ver clients/discovery_client.py e
routes/endpoints.py lá). POST /discover é síncrono, sem fila -- mesmo
precedente de invariant_assessment's /assessment/run (um round-trip),
justificado pela concorrência interna (asyncio.Semaphore) manter até um
/24 dentro de um timeout razoável.
"""

import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from invariant_discovery import classify, probe, ranges

app = FastAPI(title="Invariant Discovery")

# Limite de hosts sondados ao mesmo tempo -- não por CIDR, mas no total de
# uma chamada (um /24 inteiro cabe tranquilo, um /20 também).
_MAX_CONCURRENT_PROBES = 50


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


class DiscoverRequest(BaseModel):
    addresses: list[str]


class DiscoveryResultItem(BaseModel):
    ip: str
    classification: str
    confidence: float
    evidence: dict
    scanned_at: str


class DiscoverResponse(BaseModel):
    results: list[DiscoveryResultItem]


@app.post("/discover", response_model=DiscoverResponse)
async def discover(payload: DiscoverRequest) -> DiscoverResponse:
    ips: list[str] = []
    for address in payload.addresses:
        try:
            ips.extend(ranges.expand(address))
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    semaphore = asyncio.Semaphore(_MAX_CONCURRENT_PROBES)
    evidences = await asyncio.gather(*(probe.probe_host(ip, semaphore=semaphore) for ip in ips))

    scanned_at = datetime.now(timezone.utc).isoformat()
    results = []
    for ip, evidence in zip(ips, evidences):
        classification, confidence = classify.classify(evidence)
        results.append(
            DiscoveryResultItem(
                ip=ip,
                classification=classification,
                confidence=confidence,
                evidence=evidence,
                scanned_at=scanned_at,
            )
        )
    return DiscoverResponse(results=results)
