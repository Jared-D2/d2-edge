# D2 Edge Appliance

MSP edge stack for customer sites. Runs on Raspberry Pi 5.

## Services

| Service | Purpose | LAN Port |
|---|---|---|
| tailscale | Secure tunnel to Azure | — |
| syslog-proxy | Forwards syslog to Graylog | UDP/TCP 514 |
| zabbix-proxy | Monitoring proxy | — |
| freeradius-proxy | RADIUS proxy | UDP 1812/1813 |
| auvik | Network discovery | — |

## New customer deployment

### Prerequisites
- Raspberry Pi 5 (4GB+ RAM, 32GB+ SD card)
- Fresh Raspberry Pi OS Lite 64-bit
- SSH access

### Step 1 — Bootstrap
```bash
curl -sSL https://raw.githubusercontent.com/Jared-D2/d2-edge/main/shared/scripts/bootstrap.sh | sudo bash
```

### Step 2 — Configure
```bash
nano /opt/d2-edge/.env
```

| Variable | Description | Example |
|---|---|---|
| EDGE_HOSTNAME | Unique Pi hostname | d2-customer-site01 |
| EDGE_SITE_ID | Short site ID, no spaces | northsyd |
| TENANT_ID | Customer ID | d2002 |
| TENANT_NAME | Customer name, no spaces | Acme_Corp |
| TS_AUTHKEY | Tailscale auth key | tskey-auth-xxx |
| RADIUS_SHARED_SECRET | RADIUS proxy secret | (generate randomly) |
| LOCAL_CLIENT_SECRET | LAN RADIUS client secret | (generate randomly) |
| LOCAL_CLIENT_SUBNET | Customer LAN subnet | 10.0.0.0/8 |
| AUVIK_API_KEY | From Auvik portal | — |

### Step 3 — Deploy
```bash
sudo bash /opt/d2-edge/shared/scripts/deploy-all.sh
```

## Updating an existing deployment
```bash
sudo bash /opt/d2-edge/shared/scripts/update.sh
```

## Useful commands
```bash
# Container status
docker ps

# Tailscale status
docker exec tailscale tailscale status

# NTP sync
chronyc tracking

# Test syslog pipeline
logger -n 127.0.0.1 -P 514 "TEST $(date)"

# View logs
bash /opt/d2-edge/shared/scripts/logs-all.sh
```
