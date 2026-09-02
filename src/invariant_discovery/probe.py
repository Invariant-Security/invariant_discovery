"""Sonda leve de portas por host -- sem nmap, sem privilégio elevado. Um
round-trip TCP por porta candidata via asyncio, timeout curto, concorrência
por host limitada externamente por um Semaphore (ver api.py). Produz só os
sinais brutos (portas abertas + banners/headers) -- classify.py decide o
que eles significam.
"""

import asyncio
import ssl
from email import message_from_bytes

# Portas reveladoras o bastante pra valer a pena sondar -- ver
# classify.py pro porquê de cada uma.
PORTS: list[int] = [22, 80, 443, 8443, 445, 3389, 902, 903, 2375, 2376]

_HTTP_PORTS = {80, 8443}  # 8443 quase sempre é HTTPS na prática, mas sem TLS aqui evita 2 tentativas
_HTTPS_PORTS = {443}
_CONNECT_TIMEOUT = 1.5
_READ_TIMEOUT = 1.5
_READ_BYTES = 4096

# Sub-string crua procurada nos bytes do certificado quando a conexão TLS
# não devolve uma resposta HTTP reconhecível (serviço TLS não-HTTP, ex.
# vCenter/ESXi em 443 que não fala HTTP puro na raiz) -- fallback
# deliberadamente simples.
# ponytail: cert grepado cru (bytes DER), não parseado como X.509; trocar
# por `cryptography` se algum vendor precisar de um campo específico do
# certificado em vez de só aparecer nos bytes.
_CERT_VENDOR_KEYWORDS = [b"VMware", b"ESXi", b"vCenter", b"Fortinet", b"pfSense", b"Palo Alto Networks"]


async def probe_host(ip: str, *, semaphore: asyncio.Semaphore) -> dict:
    """Returns {"open_ports": [int, ...], "banners": {"<port>": "<text>"}}."""
    results = await asyncio.gather(*(_probe_port(ip, port, semaphore) for port in PORTS))
    open_ports = [port for port, _ in results if port is not None]
    banners = {str(port): banner for port, banner in results if port is not None and banner}
    return {"open_ports": open_ports, "banners": banners}


async def _probe_port(ip: str, port: int, semaphore: asyncio.Semaphore) -> tuple[int, str] | tuple[None, str]:
    async with semaphore:
        try:
            if port in _HTTP_PORTS:
                banner = await asyncio.wait_for(_probe_http(ip, port, tls=False), _CONNECT_TIMEOUT + _READ_TIMEOUT)
            elif port in _HTTPS_PORTS:
                banner = await asyncio.wait_for(_probe_http(ip, port, tls=True), _CONNECT_TIMEOUT + _READ_TIMEOUT)
            elif port == 22:
                banner = await asyncio.wait_for(_probe_banner(ip, port), _CONNECT_TIMEOUT + _READ_TIMEOUT)
            else:
                banner = await asyncio.wait_for(_probe_open(ip, port), _CONNECT_TIMEOUT)
        except (asyncio.TimeoutError, OSError):
            return None, ""
    return port, banner


async def _probe_open(ip: str, port: int) -> str:
    """Só confirma que a porta abre -- pra portas de sinal binário (SMB,
    RDP, VMware agent, Docker remote API) o open/closed já é o sinal
    inteiro, não precisa de payload nenhum.
    """
    reader, writer = await asyncio.open_connection(ip, port)
    writer.close()
    await writer.wait_closed()
    return ""


async def _probe_banner(ip: str, port: int) -> str:
    """SSH manda o banner antes de qualquer coisa ser enviada -- só ler."""
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        data = await asyncio.wait_for(reader.read(_READ_BYTES), _READ_TIMEOUT)
    finally:
        writer.close()
        await writer.wait_closed()
    return data.decode("utf-8", errors="replace")


def _parse_http_signal(raw_response: str) -> str:
    """Extrai um texto de sinal (headers + início do corpo) de uma
    resposta HTTP crua -- usa email.message_from_bytes (stdlib) pra
    parsear os headers em vez de escrever um parser à mão.
    """
    header_block, _, body = raw_response.partition("\r\n\r\n")
    # header_block começa com a status line ("HTTP/1.1 200 OK"), que não é
    # um header -- pula ela antes de parsear o resto como RFC822.
    _, _, headers_only = header_block.partition("\r\n")
    headers = message_from_bytes(headers_only.encode("utf-8", errors="replace"))
    header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
    return f"{header_text} {body[:500]}".strip()


async def _probe_http(ip: str, port: int, *, tls: bool) -> str:
    ssl_context = None
    if tls:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.open_connection(ip, port, ssl=ssl_context)
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        cert_bytes = ssl_object.getpeercert(binary_form=True) if ssl_object else None

        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        writer.write(request)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(_READ_BYTES), _READ_TIMEOUT)
    finally:
        writer.close()
        await writer.wait_closed()

    raw_response = data.decode("utf-8", errors="replace")
    if raw_response.startswith("HTTP/"):
        return _parse_http_signal(raw_response)

    # Handshake TLS ok, mas não veio nada parecido com HTTP -- serviço TLS
    # não-HTTP na porta. Único fallback: grepar os bytes crus do cert.
    if cert_bytes:
        for keyword in _CERT_VENDOR_KEYWORDS:
            if keyword in cert_bytes:
                return keyword.decode()
    return ""
