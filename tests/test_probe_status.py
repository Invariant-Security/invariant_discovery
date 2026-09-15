"""Testa o mapeamento de status de port_attempts de forma determinística --
monkeypatch em asyncio.open_connection (probe.py chama via
`asyncio.open_connection(...)`, então patchar o atributo no módulo asyncio
pega as 10 portas de uma vez, sem depender de rede real nem de sleeps
reais). Os casos de porta realmente aberta contra sockets de verdade
continuam em test_probe.py -- este arquivo cobre só a tradução
exceção -> status, sem pytestmark.integration.
"""

import asyncio
import errno

import pytest

from invariant_discovery import probe as probe_mod
from invariant_discovery.probe import PORTS, probe_host


async def _probe_with_connect_error(monkeypatch, exc):
    async def fake_open_connection(*args, **kwargs):
        raise exc

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return await probe_host("203.0.113.1", semaphore=asyncio.Semaphore(10))


async def test_connection_refused_is_reported_as_refused(monkeypatch):
    exc = ConnectionRefusedError()
    exc.errno = errno.ECONNREFUSED

    result = await _probe_with_connect_error(monkeypatch, exc)

    assert result["open_ports"] == []
    assert result["banners"] == {}
    assert len(result["port_attempts"]) == len(PORTS)
    assert all(a["status"] == "refused" for a in result["port_attempts"])


async def test_network_unreachable_is_reported(monkeypatch):
    exc = OSError()
    exc.errno = errno.ENETUNREACH

    result = await _probe_with_connect_error(monkeypatch, exc)

    assert all(a["status"] == "network_unreachable" for a in result["port_attempts"])


async def test_host_unreachable_is_reported(monkeypatch):
    exc = OSError()
    exc.errno = errno.EHOSTUNREACH

    result = await _probe_with_connect_error(monkeypatch, exc)

    assert all(a["status"] == "host_unreachable" for a in result["port_attempts"])


async def test_unmapped_oserror_is_reported_as_error(monkeypatch):
    exc = OSError()
    exc.errno = errno.EACCES  # não está em _STATUS_BY_ERRNO de propósito

    result = await _probe_with_connect_error(monkeypatch, exc)

    assert all(a["status"] == "error" for a in result["port_attempts"])


async def test_unexpected_exception_is_reported_as_error_not_raised(monkeypatch):
    async def fake_open_connection(*args, **kwargs):
        raise ValueError("algo inesperado, não é nem OSError nem TimeoutError")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = await probe_host("203.0.113.1", semaphore=asyncio.Semaphore(10))

    assert all(a["status"] == "error" for a in result["port_attempts"])


async def test_timeout_is_reported_without_a_real_wait(monkeypatch):
    # Encolhe os timeouts pra não esperar 1.5s reais por porta -- ainda
    # exercita o except asyncio.TimeoutError de verdade, só rápido.
    monkeypatch.setattr(probe_mod, "_CONNECT_TIMEOUT", 0.02)
    monkeypatch.setattr(probe_mod, "_READ_TIMEOUT", 0.02)

    async def hang_forever(*args, **kwargs):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", hang_forever)

    result = await probe_host("203.0.113.1", semaphore=asyncio.Semaphore(10))

    assert result["open_ports"] == []
    assert all(a["status"] == "timeout" for a in result["port_attempts"])


async def test_open_port_is_excluded_from_port_attempts(monkeypatch):
    """Mistura: porta 22 abre de verdade (fake), o resto falha -- confirma
    que port_attempts só lista o que NÃO abriu, sem duplicar com
    open_ports.
    """

    async def fake_open_connection(host, port, **kwargs):
        if port == 22:
            reader = asyncio.StreamReader()
            reader.feed_data(b"SSH-2.0-OpenSSH_9.6\r\n")
            reader.feed_eof()

            class _FakeWriter:
                def close(self):
                    pass

                async def wait_closed(self):
                    pass

            return reader, _FakeWriter()
        raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = await probe_host("203.0.113.1", semaphore=asyncio.Semaphore(10))

    assert result["open_ports"] == [22]
    assert "OpenSSH" in result["banners"]["22"]
    assert all(a["port"] != 22 for a in result["port_attempts"])
    assert len(result["port_attempts"]) == len(PORTS) - 1
    assert all(a["status"] == "refused" for a in result["port_attempts"])
