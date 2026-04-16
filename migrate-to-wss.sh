#!/bin/bash
# Migrate a d2-edge Pi from ws:// to wss://. Run as root on the affected Pi.
set -e
if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi

cd /opt/d2-edge
# 1. Install D2 internal root CA
cat > /usr/local/share/ca-certificates/d2-internal-root.crt <<CAEOF
-----BEGIN CERTIFICATE-----
MIIB5TCCAYqgAwIBAgIRAOPSKvG1eBTmQzTSD+1Fw/gwCgYIKoZIzj0EAwIwUDEi
MCAGA1UEChMZRDIgVGVjaG5vbG9neSBJbnRlcm5hbCBDQTEqMCgGA1UEAxMhRDIg
VGVjaG5vbG9neSBJbnRlcm5hbCBDQSBSb290IENBMB4XDTI2MDQxMDA2MjMxOVoX
DTM2MDQwNzA2MjMxOVowUDEiMCAGA1UEChMZRDIgVGVjaG5vbG9neSBJbnRlcm5h
bCBDQTEqMCgGA1UEAxMhRDIgVGVjaG5vbG9neSBJbnRlcm5hbCBDQSBSb290IENB
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+164O9mQaAtjGLkblSyORVX255Xu
o4FibgJiAW78gBxiy8/0DuPY9JVZYbDe3vvIh/0IPdAmzF1o80bPnr7MyqNFMEMw
DgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFEVe
/gZOEX62En48gFTxeBTnrvA9MAoGCCqGSM49BAMCA0kAMEYCIQCF7zf/se+AD/4D
4CkctnfcQFkPQHjfoA4UJEjpCTJ/nQIhAIX3q/LrUGCd1ErGo15mGyKktsTwIztu
MGtmDAkUuA0z
-----END CERTIFICATE-----
CAEOF
update-ca-certificates

# 2. Mount CA into d2-agent container
python3 - <<PY
import pathlib, re
p = pathlib.Path("/opt/d2-edge/docker-compose.yml")
src = p.read_text()
m = re.search(r"(  d2-agent:.*?)(?=\n  [a-z][a-z0-9-]*:|\Z)", src, re.DOTALL)
block = m.group(1)
if "d2-internal-root.crt" not in block:
    new_block = block.replace(
        "./d2-agent/app.py:/app/app.py",
        "/usr/local/share/ca-certificates/d2-internal-root.crt:/usr/local/share/ca-certificates/d2-internal-root.crt:ro\n      - ./d2-agent/app.py:/app/app.py"
    )
    src = src.replace(block, new_block)
    p.write_text(src)
PY

# 3. Dockerfile: ensure ca-certificates installed
grep -q "ca-certificates" /opt/d2-edge/d2-agent/Dockerfile ||   sed -i "0,/apt-get install -y/s|apt-get install -y|apt-get install -y ca-certificates|" /opt/d2-edge/d2-agent/Dockerfile

# 4. .env: switch to wss://
sed -i "s|^CONTROLLER_URL=ws://|CONTROLLER_URL=wss://|" /opt/d2-edge/.env
grep "^CONTROLLER_URL" /opt/d2-edge/.env

# 5. Rebuild and recreate
docker compose build d2-agent --pull
docker compose up -d d2-agent --force-recreate
sleep 3
docker exec d2-agent update-ca-certificates
docker restart d2-agent
sleep 10
docker logs d2-agent --since 15s 2>&1 | grep -iE "connected|ssl|fail" | tail -5
