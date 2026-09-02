"""Expande um endereço cadastrado (IP único ou CIDR) numa lista de IPs a
sondar -- stdlib ipaddress, sem dependência nova (nmap/scapy não entram
aqui, ver o plano de discovery pro porquê).
"""

import ipaddress

# Maior range aceito de uma vez -- guarda simples contra escanear uma rede
# inteira sem querer (um /24 = 254 hosts é um range SMB/home-lab realista;
# um /8 não é pra isso). Não é uma fila de jobs, só um limite direto.
MIN_PREFIX_LENGTH = 20


class RangeTooLargeError(ValueError):
    pass


def expand(address: str) -> list[str]:
    """address é um IP único ("10.0.0.5") ou um CIDR ("10.0.0.0/24").
    Um IP único sempre expande pra ele mesmo, mesmo que `strict=False`
    normalize a entrada.
    """
    network = ipaddress.ip_network(address, strict=False)
    if network.num_addresses == 1:
        return [str(network.network_address)]
    if network.prefixlen < MIN_PREFIX_LENGTH:
        max_addresses = 2 ** (32 - MIN_PREFIX_LENGTH)
        raise RangeTooLargeError(
            f"{address!r} has {network.num_addresses} addresses -- refusing anything "
            f"larger than a /{MIN_PREFIX_LENGTH} ({max_addresses} addresses)"
        )
    return [str(ip) for ip in network.hosts()]
