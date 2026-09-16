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
| d2-agent | Network test agent | TCP 8080, TCP 5201 (iperf3) |

## New customer deployment

### Prerequisites
- Raspberry Pi 5 (4GB+ RAM, 32GB+ SD card)
- Fresh Raspberry Pi OS Lite 64-bit
- SSH access

### Step 1 — Bootstrap
The repo is private. Open the onboarding portal → **New Edge Pi** tab, fill in the
site, and paste the generated **bootstrap block** into the Pi's shell. It installs the
fleet read-only deploy key, pins github.com, clones `/opt/d2-edge` as `admin`, then runs
`shared/scripts/bootstrap.sh`.

Hand-building without the portal: the repo is private, so there is no way to fetch
`bootstrap.sh` anonymously. Create the files the clone reads, paste in their contents,
then clone — same steps the portal block performs:

```bash
sudo install -d -m 700 -o admin -g admin /home/admin/.ssh
sudo install -m 600 -o admin -g admin /dev/null /home/admin/.ssh/id_d2edge_deploy   # then paste the key into it
sudo install -m 644 -o admin -g admin /dev/null /home/admin/.ssh/known_hosts_github  # then paste GitHub's host keys (gh api meta --jq '.ssh_keys[] | "github.com " + .')
sudo install -d -m 755 -o admin -g admin /opt/d2-edge
sudo -u admin git clone \
    -c core.sshCommand="ssh -i '/home/admin/.ssh/id_d2edge_deploy' -o IdentitiesOnly=yes -o UserKnownHostsFile='/home/admin/.ssh/known_hosts_github' -o StrictHostKeyChecking=yes -o BatchMode=yes" \
    git@github.com:Jared-D2/d2-edge.git /opt/d2-edge
sudo bash /opt/d2-edge/shared/scripts/bootstrap.sh
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
