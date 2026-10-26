"""netguard: alvos internos recusados antes de qualquer conexão."""

import asyncio
import subprocess
import sys
from unittest import mock

import pytest

from invariant_discovery import netguard, probe, ranges
from invariant_discovery.netguard import BlockedTargetError, check_target_ip, is_blocked

BLOCKED = [
    "127.0.0.1", "127.255.0.9", "::1", "::ffff:127.0.0.1", "169.254.169.254", "0.0.0.0",
    "fe80::1", "64:ff9b::7f00:1", "2002:7f00:1::", "fd00:ec2::254", "224.0.0.1", "255.255.255.255",
    "::", "ff02::1", "::ffff:169.254.169.254",
]


@pytest.fixture(autouse=True)
def strict(monkeypatch):
    monkeypatch.delenv("INVARIANT_ALLOW_LOOPBACK_TARGETS", raising=False)
    monkeypatch.delenv("INVARIANT_BLOCKED_CIDRS", raising=False)


@pytest.mark.parametrize("ip", BLOCKED)
def test_blocked_ips_refused_by_expand_and_probe_before_any_connection(ip):
    with pytest.raises(BlockedTargetError):
        check_target_ip(ip)
    with pytest.raises(ValueError):
        ranges.expand(ip)
    with mock.patch("asyncio.open_connection") as conn:
        with pytest.raises(BlockedTargetError):
            asyncio.run(probe.probe_host(ip, semaphore=asyncio.Semaphore(1)))
    conn.assert_not_called()


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "172.16.0.1", "64:ff9b::a00:5", "::ffff:10.0.0.5", "2002:a00:5::"])
def test_client_rfc1918_passes(ip):
    assert not is_blocked(ip)


def test_expand_rfc1918_cidr_passes():
    assert len(ranges.expand("10.0.0.0/24")) == 254


def test_extra_cidrs_are_added(monkeypatch):
    monkeypatch.setenv("INVARIANT_BLOCKED_CIDRS", "10.42.0.0/16, 10.43.0.1/32")
    assert is_blocked("10.42.7.7") and is_blocked("10.43.0.1")
    assert not is_blocked("10.43.0.2") and not is_blocked("10.0.0.5")
    with pytest.raises(ValueError):
        ranges.expand("10.43.0.1")
    assert is_blocked("127.0.0.1")  # soma ao fixo


def test_cidr_crossing_block_drops_only_blocked():
    hosts = ranges.expand("169.254.0.0/20")
    assert hosts == []
    hosts = ranges.expand("0.0.0.0/20")
    assert hosts == []


def test_cidr_partially_blocked(monkeypatch):
    monkeypatch.setenv("INVARIANT_BLOCKED_CIDRS", "10.0.0.128/25")
    hosts = ranges.expand("10.0.0.0/24")
    assert "10.0.0.1" in hosts and "10.0.0.127" in hosts
    assert "10.0.0.128" not in hosts and "10.0.0.200" not in hosts
    assert len(hosts) == 127  # .1 a .127


def test_loopback_allowed_only_loopback(monkeypatch):
    monkeypatch.setenv("INVARIANT_ALLOW_LOOPBACK_TARGETS", "1")
    assert not is_blocked("127.0.0.1") and not is_blocked("::1")
    assert ranges.expand("127.0.0.1") == ["127.0.0.1"]
    for ip in ("169.254.169.254", "fe80::1", "0.0.0.0", "fd00:ec2::254", "224.0.0.1"):
        assert is_blocked(ip)


def _start(env_extra):
    env = {"PATH": "/usr/bin:/bin", "INVARIANT_INTERNAL_DISCOVERY_TOKEN": "t" * 20, **env_extra}
    return subprocess.run(
        [sys.executable, "-c",
         "import asyncio; from invariant_discovery.api import app\n"
         "async def go():\n async with app.router.lifespan_context(app): pass\n"
         "asyncio.run(go())"],
        env=env, capture_output=True, text=True, timeout=60,
    )


@pytest.mark.parametrize("env", ["", "prod", "appliance"])
def test_startup_refuses_loopback_allowance_outside_test_ci(env):
    proc = _start({"INVARIANT_ALLOW_LOOPBACK_TARGETS": "1", "INVARIANT_ENVIRONMENT": env})
    assert proc.returncode != 0
    assert "INVARIANT_ALLOW_LOOPBACK_TARGETS" in proc.stderr


@pytest.mark.parametrize("env", ["test", "ci"])
def test_startup_accepts_loopback_allowance_in_test_ci(env):
    assert _start({"INVARIANT_ALLOW_LOOPBACK_TARGETS": "1", "INVARIANT_ENVIRONMENT": env}).returncode == 0


def test_startup_refuses_invalid_blocked_cidrs():
    proc = _start({"INVARIANT_BLOCKED_CIDRS": "10.0.0.0/8,nao-e-cidr"})
    assert proc.returncode != 0
    assert "INVARIANT_BLOCKED_CIDRS" in proc.stderr


def test_startup_ok_without_config():
    assert _start({}).returncode == 0


def test_validate_startup_in_process(monkeypatch):
    monkeypatch.setenv("INVARIANT_BLOCKED_CIDRS", "bogus")
    with pytest.raises(RuntimeError):
        netguard.validate_startup()
