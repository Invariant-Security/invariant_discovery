# RDP/VMware-agent alvos reais não são containerizáveis de verdade -- este
# fixture só confirma o sinal "porta aberta, sem banner" (o caminho
# _probe_open() em probe.py) sobre um socket real, ligando netcat na porta
# RDP (3389) sem falar protocolo nenhum. O conteúdo do banner de RDP/VMware
# de verdade só tem cobertura ao nível de test_classify.py (evidência
# sintética) -- gap de cobertura documentado, não escondido, ver README.md.
FROM alpine:3.20
RUN apk add --no-cache netcat-openbsd
EXPOSE 3389
CMD ["nc", "-lk", "-p", "3389"]
