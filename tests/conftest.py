"""Liberação explícita de loopback para a suíte (testes sobem servidores em
127.0.0.1). Só vale com INVARIANT_ENVIRONMENT=test; os testes de netguard
controlam as variáveis por conta própria (monkeypatch)."""

import os

os.environ["INVARIANT_ENVIRONMENT"] = "test"
os.environ["INVARIANT_ALLOW_LOOPBACK_TARGETS"] = "1"
