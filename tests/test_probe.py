"""Exercita probe.py contra sockets de verdade (containers em
tests/fixtures/docker-compose.yml), não dicts sintéticos -- isso é o que
test_classify.py cobre. Windows/VMware/RDP reais não são containerizáveis;
silent-port só confirma o sinal "porta aberta sem banner" que RDP/VMware
também produziriam.
"""

import asyncio
import subprocess

import pytest

from invariant_discovery.probe import probe_host

pytestmark = pytest.mark.integration


def _container_ip(name: str) -> str:
    try:
        output = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"fixture container {name!r} not reachable via docker inspect: {exc}")
    if not output:
        pytest.skip(f"fixture container {name!r} has no IP -- is it running? (see tests/fixtures/docker-compose.yml)")
    return output


async def _probe(ip: str) -> dict:
    return await probe_host(ip, semaphore=asyncio.Semaphore(10))


async def test_probe_detects_real_ssh_banner():
    ip = _container_ip("invariant-discovery-test-sshd")

    evidence = await _probe(ip)

    assert 22 in evidence["open_ports"]
    assert "OpenSSH" in evidence["banners"]["22"]


async def test_probe_only_reports_actually_open_ports():
    """Regression: probe_host() must not include ports that timed out /
    refused as "open" -- confirmed this broke once (every probed port
    ended up in open_ports regardless of whether it answered).
    """
    ip = _container_ip("invariant-discovery-test-sshd")

    evidence = await _probe(ip)

    assert evidence["open_ports"] == [22]


async def test_probe_detects_real_http_body_signal():
    ip = _container_ip("invariant-discovery-test-http-waf-like")

    evidence = await _probe(ip)

    assert 80 in evidence["open_ports"]
    assert "cloudflare" in evidence["banners"]["80"].lower()


async def test_probe_detects_silent_open_port():
    ip = _container_ip("invariant-discovery-test-silent-port")

    evidence = await _probe(ip)

    assert 3389 in evidence["open_ports"]
