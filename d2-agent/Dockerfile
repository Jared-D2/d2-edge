FROM python:3.11-slim

# Refresh base distro packages first to pick up Debian security updates
# (openssl, libssl3t64, libgdk-pixbuf*, libtiff6, etc.)
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    iperf3 iputils-ping curl traceroute mtr gnupg lsb-release psmisc procps nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install ca-certificates + D2 internal root CA
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Install D2 internal root CA at build time so TLS to the controller validates
# without relying on runtime bind mounts.
COPY d2-internal-root.crt /usr/local/share/ca-certificates/d2-internal-root.crt
RUN update-ca-certificates

RUN curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash \
    && apt-get install -y speedtest \
    && rm -rf /var/lib/apt/lists/*

# Accept license at build time so it never prompts at runtime
RUN speedtest --accept-license --accept-gdpr > /dev/null 2>&1 || true

WORKDIR /app
COPY requirements.txt .
# Refresh pip toolchain (fixes wheel CVE-2026-24049, jaraco.context CVE-2026-23949)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

CMD ["python", "app.py"]
