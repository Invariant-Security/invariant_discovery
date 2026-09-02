# Debian real com sshd de verdade -- pra test_probe.py confirmar o banner
# grab real (SSH-2.0-OpenSSH_... Debian-...) sobre um socket de verdade,
# não um dict sintético (isso quem cobre é test_classify.py).
FROM debian:11

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && mkdir -p /run/sshd \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
