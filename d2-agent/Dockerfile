FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iperf3 iputils-ping curl traceroute mtr gnupg lsb-release psmisc procps nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Ookla official speedtest CLI
RUN curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash \
    && apt-get install -y speedtest \
    && rm -rf /var/lib/apt/lists/*

# Accept license at build time so it never prompts at runtime
RUN speedtest --accept-license --accept-gdpr > /dev/null 2>&1 || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

CMD ["python", "app.py"]
