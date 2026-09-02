from invariant_discovery.classify import MIN_CONFIDENCE, classify


def test_no_open_ports_returns_unknown_zero_confidence():
    assert classify({"open_ports": [], "banners": {}}) == ("unknown", 0.0)


def test_open_port_with_no_matching_signal_returns_unknown():
    # porta 80 aberta não tem peso próprio (só o header/corpo decide) --
    # sem banner nenhum, não há sinal pra classificar.
    assert classify({"open_ports": [80], "banners": {}}) == ("unknown", 0.0)


def test_rdp_and_smb_open_classifies_windows_high_confidence():
    classification, confidence = classify({"open_ports": [445, 3389], "banners": {}})

    assert classification == "windows"
    assert confidence == 1.0


def test_smb_alone_classifies_windows_with_low_confidence():
    """445 sozinho é um sinal fraco (Samba em Linux também abre essa
    porta) -- deve passar do piso de confiança, mas raspando nele, não
    100%.
    """
    classification, confidence = classify({"open_ports": [445], "banners": {}})

    assert classification == "windows"
    assert MIN_CONFIDENCE <= confidence < 0.6


def test_vmware_agent_port_classifies_vmware_high_confidence():
    classification, confidence = classify({"open_ports": [902], "banners": {}})

    assert classification == "vmware"
    assert confidence == 1.0


def test_docker_remote_api_port_classifies_docker():
    classification, confidence = classify({"open_ports": [2375], "banners": {}})

    assert classification == "docker"
    assert confidence == 1.0


def test_ssh_banner_with_debian_classifies_linux_high_confidence():
    evidence = {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2 Debian-2"}}

    classification, confidence = classify(evidence)

    assert classification == "linux"
    assert confidence == 1.0


def test_bare_openssh_banner_alone_is_too_weak_to_classify():
    """OpenSSH puro (sem "Ubuntu"/"Debian" no banner) não é decisivo --
    Windows também pode expor OpenSSH -- deve cair pra unknown.
    """
    evidence = {"open_ports": [22], "banners": {"22": "SSH-2.0-OpenSSH_9.2"}}

    classification, _ = classify(evidence)

    assert classification == "unknown"


def test_cloudflare_header_classifies_waf():
    evidence = {"open_ports": [443], "banners": {"443": "Server: cloudflare Connection: close"}}

    classification, confidence = classify(evidence)

    assert classification == "waf"
    assert confidence == 1.0


def test_pfsense_login_page_classifies_firewall():
    evidence = {"open_ports": [443], "banners": {"443": "<title>pfSense - Login</title>"}}

    classification, _ = classify(evidence)

    assert classification == "firewall"


def test_esxi_banner_classifies_vmware():
    evidence = {"open_ports": [443], "banners": {"443": "Server: VMware ESXi"}}

    classification, _ = classify(evidence)

    assert classification == "vmware"


def test_close_tie_between_two_candidates_returns_unknown():
    """Um sinal Linux (banner "ubuntu") e um sinal VMware (banner "esxi")
    quase empatados -- não dá pra confiar num só, deve virar unknown em
    vez de escolher o levemente maior.
    """
    evidence = {
        "open_ports": [22, 443],
        "banners": {"22": "ubuntu ssh server", "443": "esxi management"},
    }

    classification, _ = classify(evidence)

    assert classification == "unknown"
