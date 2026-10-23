# invariant_discovery

Network discovery for [Invariant](https://invariantsec.org), an open-source
CIS compliance assessment toolkit for Linux hosts and containers.

Give it a single IP or a CIDR range and it fingerprints each endpoint as
`windows`, `linux`, `docker`, `waf`, `firewall`, `vmware` or `unknown`:

- no nmap and no elevated privileges, only plain TCP connects;
- a curated set of ports, plus banner, HTTP header and TLS certificate signals;
- a weighted heuristic that returns a classification, a confidence score and
  the evidence behind it (see `classify.py`).

It answers "what is out there?" before an assessment runs. It does not run
compliance checks itself, and it keeps no state.

> Discovery is planned to move into
> [`invariant_assessment`](https://github.com/Invariant-Security/invariant_assessment),
> next to the command-line tool.

## Quick start

```bash
pip install -e .
uvicorn invariant_discovery.api:app
curl -s localhost:8000/discover \
  -H 'content-type: application/json' \
  -d '{"addresses": ["192.0.2.10", "192.0.2.0/28"]}'
```

Only scan networks you own or are authorized to test.

## API

- `GET /healthz`
- `POST /discover`, body `{"addresses": ["10.0.0.5", "10.0.0.0/24"]}`,
  returns `{"results": [{"ip", "classification", "confidence", "evidence",
  "scanned_at"}, ...]}`. It is synchronous, with no job queue; see the
  docstring in `api.py`.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q                 # unit tests, no sockets needed
pytest tests/ -q -m integration  # needs the fixture containers, see tests/fixtures/
uvicorn invariant_discovery.api:app --reload
```

### Locked dependencies

`requirements.lock` (hashed) is what the image and CI install; `pyproject.toml` keeps the loose ranges.
Regenerate (add/bump a dep): in `python:3.12.14-slim@<digest>`, `pip install pip-tools && pip-compile --generate-hashes --strip-extras --allow-unsafe -o requirements.lock` with the deps from `pyproject.toml` as input.
Bump the base: `docker buildx imagetools inspect python:3.12.14-slim` (or the new tag) → put the index `Digest:` in the Dockerfile `ARG BASE`, then rebuild and run `pip check`.

## Contributing

Contributions are welcome under the DCO, with no CLA. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE).
