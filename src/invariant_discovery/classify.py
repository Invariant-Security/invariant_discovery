"""Classifica um IP como windows/linux/docker/waf/firewall/vmware/unknown a
partir de sinais leves (porta aberta + banner/header), sem nmap. Pontuação
ponderada, não if/elif rígido -- um Linux rodando Samba (445 aberto) não
deve virar "windows" só por isso; a soma de sinais decide, e um único
sinal fraco (ex: só 445 aberto) produz confiança baixa em vez de 100%.

# ponytail: pesos e keywords calibrados a mão, sem ML -- teto real é a
# diversidade de rede de clientes de verdade não coberta pelo fixture set
# de testes; revisitar quando houver dado real de falso-positivo/negativo.
"""

from collections import Counter

MIN_CONFIDENCE = 0.4
# diferença mínima (como fração do total) entre os 2 melhores candidatos
# pra não virar "unknown" -- evita apresentar um empate como certeza.
_TIE_MARGIN = 0.15
# score de um sinal "decisivo" (ex: só o banner Cloudflare, ou só a porta
# VMware) -- usado pra não deixar um sinal único e fraco (ex: só 445
# aberto) virar confiança 1.0 mesmo sem nenhum concorrente.
_STRONG_SCORE = 5

# porta aberta -> {classificação: peso}. Só portas cujo simples "está
# aberta" já é um sinal razoável entram aqui -- 80/443/8443/22 não têm
# peso próprio, o sinal deles vem do banner/header, não da porta em si.
_PORT_WEIGHTS: dict[int, dict[str, int]] = {
    445: {"windows": 2},  # fraco -- Samba em Linux também abre 445
    3389: {"windows": 4},
    902: {"vmware": 5},
    903: {"vmware": 5},
    2375: {"docker": 5},
    2376: {"docker": 5},
}

# substring (lowercased) encontrada num banner/header -> (classificação, peso)
_BANNER_KEYWORDS: dict[str, tuple[str, int]] = {
    "ubuntu": ("linux", 4),
    "debian": ("linux", 4),
    "openssh": ("linux", 1),  # fraco -- Windows também pode expor OpenSSH
    "cloudflare": ("waf", 5),
    "akamai": ("waf", 5),
    "sucuri": ("waf", 5),
    "imperva": ("waf", 5),
    "aws waf": ("waf", 5),
    "pfsense": ("firewall", 5),
    "fortigate": ("firewall", 5),
    "fortios": ("firewall", 5),
    "pan-os": ("firewall", 5),
    "sonicwall": ("firewall", 5),
    "cisco asa": ("firewall", 5),
    "meraki": ("firewall", 5),
    "opnsense": ("firewall", 5),
    "watchguard": ("firewall", 5),
    "esxi": ("vmware", 5),
    "vsphere": ("vmware", 5),
    "vmware": ("vmware", 4),
}


def classify(evidence: dict) -> tuple[str, float]:
    """evidence: {"open_ports": [int, ...], "banners": {"<port>": "<text>"}}.
    Returns (classification, confidence) -- classification is "unknown"
    when nothing responded, the top two candidates are too close to call,
    or the winning signal is too weak on its own to trust.
    """
    if not evidence.get("open_ports"):
        return "unknown", 0.0

    scores: Counter[str] = Counter()

    for port in evidence["open_ports"]:
        for classification, weight in _PORT_WEIGHTS.get(port, {}).items():
            scores[classification] += weight

    for text in evidence.get("banners", {}).values():
        lowered = text.lower()
        for keyword, (classification, weight) in _BANNER_KEYWORDS.items():
            if keyword in lowered:
                scores[classification] += weight

    if not scores:
        return "unknown", 0.0

    ranked = scores.most_common()
    top_classification, top_score = ranked[0]
    total = sum(scores.values())

    # Confiança combina duas coisas: quão forte é o sinal vencedor em
    # termos absolutos (top_score / _STRONG_SCORE) e quão dominante ele é
    # sobre o resto (top_score / total) -- um único sinal fraco isolado
    # (score baixo, mas sem concorrente) não deve sair com confiança 1.0.
    confidence = min(1.0, top_score / _STRONG_SCORE) * (top_score / total)

    if len(ranked) > 1:
        _, second_score = ranked[1]
        if (top_score - second_score) / total < _TIE_MARGIN:
            return "unknown", confidence

    if confidence < MIN_CONFIDENCE:
        return "unknown", confidence

    return top_classification, confidence
