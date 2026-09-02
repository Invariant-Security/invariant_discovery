# invariant_discovery

Fingerprints network endpoints (a single IP or a CIDR range) as one of
`windows`/`linux`/`docker`/`waf`/`firewall`/`vmware`/`unknown`, without
nmap or elevated privileges: a curated set of TCP ports, banner/HTTP
header/TLS-cert signals, and a weighted heuristic (see `classify.py`).
Part of the appliance pivot's "discovery & identify" first step -- running
actual CIS checks against a discovered endpoint is out of scope here, see
`invariant_assessment/preocupacoes.md` for where that would plug in.

No Postgres access, ever -- `invariant_api` is the only service that
persists a `DiscoveryResult` (via `invariant_contracts`); this service only
knows "which IPs, which signals, which guess".

## Endpoints

- `GET /healthz`
- `POST /discover` -- body `{"addresses": ["10.0.0.5", "10.0.0.0/24"]}`,
  returns `{"results": [{"ip", "classification", "confidence", "evidence",
  "scanned_at"}, ...]}`. Synchronous, no job queue -- see `api.py`'s
  docstring for why that's fine at today's expected range sizes.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q                 # unit tests, no sockets needed
pytest tests/ -q -m integration  # needs the fixture containers, see tests/fixtures/
uvicorn invariant_discovery.api:app --reload
```
