"""Bloqueio de alvos internos (SSRF) -- stdlib only, idêntico em discovery,
assessment e api. Não usa `is_private`: RFC1918 do cliente é o caso normal.
"""

import ipaddress
import os
from functools import lru_cache

_LOOPBACK = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128"))
_FIXED = _LOOPBACK + tuple(
    ipaddress.ip_network(n)
    for n in ("0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
              "::/128", "fe80::/10", "ff00::/8", "fd00:ec2::254/128")
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class BlockedTargetError(ValueError):
    pass


@lru_cache(maxsize=8)
def _extra(raw: str) -> tuple:
    try:
        return tuple(ipaddress.ip_network(c.strip(), strict=False) for c in raw.split(",") if c.strip())
    except ValueError as e:
        raise RuntimeError(f"INVARIANT_BLOCKED_CIDRS inválida: {e}") from e


def validate_startup() -> None:
    """Chamar no startup: CIDR inválido ou liberação de loopback fora de
    test/ci recusam a partida."""
    _extra(os.environ.get("INVARIANT_BLOCKED_CIDRS", ""))
    if _allow_loopback() and os.environ.get("INVARIANT_ENVIRONMENT", "") not in ("test", "ci"):
        raise RuntimeError("INVARIANT_ALLOW_LOOPBACK_TARGETS só é permitido com INVARIANT_ENVIRONMENT=test ou ci")


def _allow_loopback() -> bool:
    return os.environ.get("INVARIANT_ALLOW_LOOPBACK_TARGETS") == "1"


def _candidates(ip: ipaddress._BaseAddress) -> list:
    if ip.version == 4:
        return [ip]
    embedded = ip.ipv4_mapped
    if embedded is None and ip in _NAT64:
        embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if embedded is None and ip.sixtofour is not None:
        embedded = ip.sixtofour
    return [ip, embedded] if embedded else [ip]


def is_blocked(ip: str) -> bool:
    nets = _FIXED + _extra(os.environ.get("INVARIANT_BLOCKED_CIDRS", ""))
    if _allow_loopback():
        nets = tuple(n for n in nets if n not in _LOOPBACK)
    return any(c in n for c in _candidates(ipaddress.ip_address(ip)) for n in nets if c.version == n.version)


def check_target_ip(ip: str) -> None:
    if is_blocked(ip):
        raise BlockedTargetError(f"target {ip} is not allowed")
