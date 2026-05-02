"""
D2 Edge Agent - Runs on each Raspberry Pi
"""
import asyncio
import errno
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import defusedxml.ElementTree as ET
import uvicorn
import websockets
from fastapi import FastAPI, Header, HTTPException, Query

_log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level_name, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("edge-agent")

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "")
AGENT_ID = os.getenv("AGENT_ID", socket.gethostname())
TENANT_ID = os.getenv("TENANT_ID", "unknown")
TENANT_NAME = os.getenv("TENANT_NAME", "")
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
# Optional command allowlist. Empty env = allow all (default).
# Example: ALLOWED_COMMANDS=ping,traceroute,dns to lock a site-specific Pi down.
_allowed_env = os.getenv("ALLOWED_COMMANDS", "").strip()
ALLOWED_COMMANDS = set(c.strip() for c in _allowed_env.split(",") if c.strip()) if _allowed_env else None
NETBOX_SITE_SLUG = os.getenv("NETBOX_SITE_SLUG", "")
GIT_SHA = os.getenv("GIT_SHA", "unknown").strip() or "unknown"

if not AGENT_TOKEN or AGENT_TOKEN == "change-me":
    log.critical("AGENT_TOKEN is not set. Refusing to start.")
    sys.exit(1)

BUFFER_DB = "/app/buffer/buffer.db"

BUFFER_MAX_ROWS = int(os.getenv("BUFFER_MAX_ROWS", "20000"))
BUFFER_RETENTION_DAYS = int(os.getenv("BUFFER_RETENTION_DAYS", "7"))


@dataclass(frozen=True)
class MonitorConfig:
    """Snapshot of controller-pushed monitor targets.

    Frozen + tuple fields so `_monitor_config = new_cfg` is a single
    atomic pointer swap (GIL-safe in CPython). Monitor loops read the
    module-level reference once per iteration and never see a torn
    snapshot across traceroute_targets / http_targets / received.
    """
    traceroute_targets: tuple = ()
    http_targets: tuple = ()
    received: bool = False


_monitor_config = MonitorConfig()


def _set_monitor_config(cfg: MonitorConfig) -> None:
    global _monitor_config
    _monitor_config = cfg


def init_buffer_db() -> None:
    """Initialize local SQLite buffer for outage data retention."""
    conn = sqlite3.connect(BUFFER_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS buffered_results (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        command   TEXT NOT NULL,
        result    TEXT NOT NULL,
        timestamp REAL NOT NULL,
        flushed   INTEGER DEFAULT 0
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_flushed_ts ON buffered_results(flushed, timestamp)")
    conn.commit()
    conn.close()
    log.info("Buffer DB initialised at %s", BUFFER_DB)


def cleanup_buffer_db() -> None:
    """Delete flushed rows older than retention window; enforce max row count."""
    try:
        cutoff = time.time() - (BUFFER_RETENTION_DAYS * 86400)
        conn = sqlite3.connect(BUFFER_DB)
        c1 = conn.execute("DELETE FROM buffered_results WHERE flushed=1 AND timestamp<?", (cutoff,))
        deleted_old = c1.rowcount
        total = conn.execute("SELECT COUNT(*) FROM buffered_results").fetchone()[0]
        deleted_cap = 0
        if total > BUFFER_MAX_ROWS:
            excess = total - BUFFER_MAX_ROWS
            c2 = conn.execute(
                "DELETE FROM buffered_results WHERE id IN (SELECT id FROM buffered_results ORDER BY timestamp ASC LIMIT ?)",
                (excess,))
            deleted_cap = c2.rowcount
        conn.commit()
        conn.close()
        if deleted_old or deleted_cap:
            log.info("Buffer cleanup: %d aged + %d over-cap rows removed", deleted_old, deleted_cap)
    except Exception as e:
        log.warning("Buffer cleanup error: %s", e)


async def buffer_cleanup_loop() -> None:
    """Run cleanup every hour."""
    while True:
        await asyncio.sleep(3600)
        cleanup_buffer_db()

def buffer_result(command: str, result: dict) -> None:
    """Store a monitoring result locally when controller is unreachable."""
    try:
        conn = sqlite3.connect(BUFFER_DB)
        conn.execute("INSERT INTO buffered_results (command, result, timestamp) VALUES (?,?,?)",
                     (command, json.dumps(result), result.get("timestamp", time.time())))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("Buffer write error: %s", e)

def get_buffered_results(limit: int = 500) -> list:
    """Retrieve unflushed buffered results."""
    try:
        conn = sqlite3.connect(BUFFER_DB)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM buffered_results WHERE flushed=0 ORDER BY timestamp LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        log.warning("Buffer read error: %s", e)
        return []

def mark_buffered_flushed(ids: list) -> None:
    """Mark buffered records as flushed."""
    if not ids:
        return
    try:
        conn = sqlite3.connect(BUFFER_DB)
        conn.execute("UPDATE buffered_results SET flushed=1 WHERE id IN ({})".format(
            ",".join("?" * len(ids))), ids)
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("Buffer flush mark error: %s", e)

# Initialise buffer DB immediately at module load
try:
    init_buffer_db()
except Exception as _e:
    log.warning("Buffer DB init failed: %s", _e)


def get_default_gateway() -> str:
    """Read default gateway from /proc/net/route."""
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000" and parts[7] == "00000000":
                    # Gateway is in hex little-endian
                    gw_hex = parts[2]
                    gw = ".".join(str(int(gw_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
                    return gw
    except Exception:
        pass
    return ""

# Hostname / IP targets: must start + end with alnum, no leading hyphen (argv
# injection defense: blocks "-f", "--iflist", etc. being mistaken for flags by
# ping/traceroute/nmap/dig). Max label length 63, max total 253.
TARGET_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$')
# nmap port spec: digits, comma, dash. Max 32 comma-separated entries, each
# up to a 5-digit-dash-5-digit range. Blocks "-" (all ports) and option-form.
PORT_SPEC_RE = re.compile(r'^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?){0,31}$')
DNS_RECORD_TYPES = frozenset({
    "A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA",
})


def validate_target(target: str) -> str:
    if not isinstance(target, str) or not TARGET_RE.match(target):
        raise HTTPException(status_code=400, detail="Invalid target")
    return target


def validate_port_spec(port: str) -> str:
    if not isinstance(port, str) or not PORT_SPEC_RE.match(port):
        raise HTTPException(status_code=400, detail="Invalid port spec")
    return port


def validate_dns_record_type(record_type: str) -> str:
    rt = (record_type or "").upper()
    if rt not in DNS_RECORD_TYPES:
        raise HTTPException(status_code=400, detail="Invalid DNS record_type")
    return rt


def require_auth(authorization: Optional[str]) -> None:
    expected = f"Bearer {AGENT_TOKEN}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


class SpawnFailureError(RuntimeError):
    """Kernel/runtime refused to clone a process or start a thread.

    Raised when fork/clone returns EAGAIN/ENOMEM, or threading reports
    "can't start new thread" — i.e. the host has hit its PID/thread cap.
    The probe wasn't actually attempted, so its result is meaningless and
    the controller must NOT store it as a real failure.
    """


def _is_spawn_exhaustion(exc: BaseException) -> bool:
    if isinstance(exc, BlockingIOError):
        return True
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in (errno.EAGAIN, errno.ENOMEM):
        return True
    if isinstance(exc, RuntimeError) and "can't start new thread" in str(exc).lower():
        return True
    return False


def _spawn_failure_result(cmd: str, params: dict, exc: BaseException) -> dict:
    """Result dict for a probe that never ran due to host exhaustion.

    `spawn_failure=True` is the contract with the controller: rows tagged
    this way must NOT be stored as real probe results. Includes the
    target/host/url so the controller can correlate without inferring
    "unknown".
    """
    out = {
        "success": False,
        "spawn_failure": True,
        "error": f"{type(exc).__name__}: {exc}",
        "command": cmd,
        "timestamp": time.time(),
    }
    for key in ("target", "host", "url", "gateway"):
        val = (params or {}).get(key)
        if val:
            out[key] = val
            break
    return out


def run_cmd(cmd: list, timeout: int = 60) -> tuple[bool, str]:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return True, out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except subprocess.CalledProcessError as e:
        return False, e.output.decode(errors="replace")
    except Exception as e:
        if _is_spawn_exhaustion(e):
            raise SpawnFailureError(f"{type(e).__name__}: {e}") from e
        return False, str(e)


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


# Public IP is expensive to look up (3 sequential HTTP probes, up to 15s).
# Cached with a 5-minute TTL so /info and register() don't block the handler.
_public_ip_cache: dict = {"ip": "unknown", "ts": 0.0}
_PUBLIC_IP_TTL = 300


def get_public_ip() -> str:
    """Fetch public IP via lightweight echo service. Cached with 5-min TTL."""
    now = time.time()
    if now - _public_ip_cache["ts"] < _PUBLIC_IP_TTL and _public_ip_cache["ip"] != "unknown":
        return _public_ip_cache["ip"]
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip:
                    _public_ip_cache["ip"] = ip
                    _public_ip_cache["ts"] = now
                    return ip
        except Exception:
            continue
    _public_ip_cache["ts"] = now  # avoid thundering-herd retries during full outage
    return "unknown"


def get_dns_servers() -> list:
    """Read DNS servers from /etc/resolv.conf."""
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except Exception:
        pass
    return servers


def get_dns_search_domains() -> list:
    """Read DNS search domains from /etc/resolv.conf."""
    domains = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("search") or line.startswith("domain"):
                    parts = line.split()
                    domains.extend(parts[1:])
    except Exception:
        pass
    return domains


def get_tailscale_ip() -> str:
    """Read current Tailscale IPv4 from tailscale0 interface."""
    try:
        out = subprocess.check_output(
            ['ip', '-4', '-o', 'addr', 'show', 'tailscale0'],
            timeout=5, stderr=subprocess.DEVNULL,
        ).decode()
        # Example shape: 'N: tailscale0    inet 100.64.0.1/32 scope global ...'
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
        return m.group(1) if m else ''
    except Exception:
        return ''


def system_info() -> dict:
    ok, uptime = run_cmd(["cat", "/proc/uptime"])
    uptime_seconds = float(uptime.split()[0]) if ok else None
    return {
        "agent_id": AGENT_ID,
        "tenant_id": TENANT_ID,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "ip": get_local_ip(),
        "tailscale_ip": get_tailscale_ip(),
        "netbox_site_slug": NETBOX_SITE_SLUG,
        "public_ip": get_public_ip(),
        "gateway": get_default_gateway(),
        "tenant_name": TENANT_NAME,
        "dns_servers": get_dns_servers(),
        "python": platform.python_version(),
        "git_sha": GIT_SHA,
        "version": GIT_SHA[:7] if GIT_SHA != "unknown" else "unknown",
        "uptime_seconds": uptime_seconds,
        "timestamp": time.time(),
    }


def run_speedtest() -> dict:
    ok, raw = run_cmd(["speedtest", "--format=json", "--accept-license", "--accept-gdpr"], timeout=120)
    if not ok:
        return {"error": raw}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Failed to parse speedtest output", "raw": raw[:500]}


def run_iperf(target: str, duration: int = 10, reverse: bool = False,
              protocol: str = "tcp", streams: int = 1, window: str = "",
              bitrate: str = "", omit: int = 0) -> dict:
    cmd = ["iperf3", "-c", target, "-J", "-t", str(duration)]
    if reverse:
        cmd.append("-R")
    if protocol == "udp":
        cmd.append("-u")
        if bitrate:
            cmd += ["-b", bitrate]
    if streams > 1:
        cmd += ["-P", str(streams)]
    if window:
        cmd += ["-w", window]
    if omit > 0:
        cmd += ["-O", str(omit)]
    ok, raw = run_cmd(cmd, timeout=duration + 15)
    if not ok:
        return {"error": raw}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"error": "Failed to parse iperf3 output", "raw": raw[:500]}


def run_iperf_server(duration: int = 15) -> dict:
    """Start iperf3 in server mode for one connection, return this agent IP.

    Schedules a background cleanup: if no client connects within
    (duration + 30)s, kill the iperf3 process to avoid port leak."""
    local_ip = get_local_ip()
    # Kill any existing iperf3 server holding port 5201
    try:
        subprocess.run(["fuser", "-k", "5201/tcp"], capture_output=True)
    except Exception as e:
        if _is_spawn_exhaustion(e):
            raise SpawnFailureError(f"iperf_server fuser fork failed: {e}") from e
        log.debug("fuser cleanup before iperf_server failed: %s", e)
    time.sleep(0.3)
    cmd = ["iperf3", "-s", "--one-off", "-J"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        if _is_spawn_exhaustion(e):
            raise SpawnFailureError(f"iperf_server iperf3 fork failed: {e}") from e
        log.warning("iperf_server start failed: %s", e)
        return {"error": "iperf server start failed"}
    time.sleep(1.0)

    def _reaper(p: subprocess.Popen, deadline: float) -> None:
        try:
            p.wait(timeout=deadline)
        except subprocess.TimeoutExpired:
            try:
                p.kill()
                log.warning("iperf_server PID %d killed - no client connected", p.pid)
            except Exception as kill_e:
                log.warning("iperf_server reap kill failed: %s", kill_e)

    try:
        threading.Thread(target=_reaper, args=(proc, duration + 30), daemon=True).start()
    except Exception as e:
        # Reaper thread couldn't start — kill the listener so we don't leak it,
        # then signal exhaustion upstream.
        try:
            proc.kill()
        except Exception:
            pass
        if _is_spawn_exhaustion(e):
            raise SpawnFailureError(f"iperf_server reaper thread failed: {e}") from e
        log.warning("iperf_server reaper thread spawn failed: %s", e)
        return {"error": "iperf server reaper failed"}
    return {"status": "listening", "ip": local_ip}


def run_ping(target: str, count: int = 10, size: int = 0, df: bool = False, interval: float = 1.0) -> dict:
    cmd = ["ping", "-c", str(count), "-i", str(interval)]
    if size > 0:
        cmd += ["-s", str(size)]
    if df:
        cmd += ["-M", "do"]
    cmd.append(target)
    ok, raw = run_cmd(cmd, timeout=count * interval + 10)
    lines = raw.splitlines()
    result = {"raw": raw, "success": ok}
    for line in lines:
        if "rtt" in line or "round-trip" in line:
            try:
                stats = line.split("=")[1].strip().split("/")
                result["rtt_min_ms"] = float(stats[0])
                result["rtt_avg_ms"] = float(stats[1])
                result["rtt_max_ms"] = float(stats[2])
                result["rtt_mdev_ms"] = float(stats[3].split()[0])
            except Exception:
                pass
        if "packet loss" in line:
            try:
                result["packet_loss_pct"] = float(line.split("%")[0].split()[-1])
            except Exception:
                pass
    return result


def run_mtu_test(target: str, max_size: int = 1500) -> dict:
    """Binary-search the largest IPv4 MTU that reaches target with DF set.

    Sends single `ping -M do -c 1 -W 2 -s <payload>` probes where
    payload = mtu_total - 28 (20 B IP header + 8 B ICMP header).
    Returns {"target", "mtu_size", "success", "raw", "attempts"}.
    mtu_size is the total IPv4 MTU (incl. headers); None if unreachable.
    """
    lo = 576
    hi = max(lo, int(max_size))
    attempts = []

    def probe(total_mtu: int) -> bool:
        payload = max(0, total_mtu - 28)
        ok, _ = run_cmd(
            ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), target],
            timeout=5,
        )
        attempts.append({"mtu": total_mtu, "payload": payload, "success": ok})
        return ok

    # If the lowest MTU doesn't work, target is unreachable (or not ICMP-responsive).
    if not probe(lo):
        return {"target": target, "mtu_size": None, "success": False,
                "raw": "target unreachable at lo MTU", "attempts": attempts}

    # Fast path: usually the full MTU works.
    if probe(hi):
        return {"target": target, "mtu_size": hi, "success": True,
                "raw": f"pmtu={hi} (max)", "attempts": attempts}

    # Binary search between lo (works) and hi (fails).
    best = lo
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if probe(mid):
            lo = mid
            best = mid
        else:
            hi = mid
    return {"target": target, "mtu_size": best, "success": True,
            "raw": f"pmtu={best}", "attempts": attempts}


def parse_traceroute(raw: str) -> list:
    """Parse traceroute -n output into structured hops."""
    hops = []
    for line in raw.strip().splitlines()[1:]:  # skip header
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        try:
            hop_num = int(parts[0])
        except ValueError:
            continue
        ip = None
        rtts = []
        for part in parts[1:]:
            if part == "*":
                rtts.append(None)
            elif part == "ms":
                continue
            else:
                try:
                    rtts.append(float(part))
                except ValueError:
                    if "." in part:
                        ip = part
        hops.append({
            "hop": hop_num,
            "ip": ip,
            "rtts": rtts,
            "loss_pct": round(sum(1 for r in rtts if r is None) / max(len(rtts), 1) * 100, 1) if rtts else 100
        })
    return hops


def run_traceroute(target: str, use_mtr: bool = False, count: int = 10) -> dict:
    """Run traceroute or mtr and return structured hop data."""
    if use_mtr:
        ok, raw = run_cmd(["mtr", "--json", "-c", str(count), "-n", target], timeout=count * 2 + 30)
        if ok:
            try:
                mtr_data = json.loads(raw)
                hops = []
                for hub in mtr_data.get("report", {}).get("hubs", []):
                    hops.append({
                        "hop": hub.get("count", 0),
                        "ip": hub.get("host", "*"),
                        "loss_pct": hub.get("Loss%", 0),
                        "sent": hub.get("Snt", 0),
                        "avg": hub.get("Avg", None),
                        "best": hub.get("Best", None),
                        "worst": hub.get("Wrst", None),
                        "stdev": hub.get("StDev", None),
                        "last": hub.get("Last", None),
                    })
                return {"hops": hops, "target": target, "success": True, "type": "mtr", "raw": raw}
            except json.JSONDecodeError:
                pass
        return {"raw": raw, "success": False, "type": "mtr", "target": target, "hops": []}
    else:
        ok, raw = run_cmd(["traceroute", "-n", "-m", "20", target], timeout=60)
        hops = parse_traceroute(raw) if ok else []
        return {"hops": hops, "target": target, "success": ok, "type": "traceroute", "raw": raw}


URL_ALLOWED_SCHEMES = ("http://", "https://")
# Cloud instance-metadata endpoints across providers. All resolve over HTTP
# and can leak IAM tokens / instance data. Match by literal name AND by
# resolved IP (see _resolve_and_check below — DNS rebinding mitigation).
METADATA_HOSTS = frozenset({
    "169.254.169.254",          # AWS / Azure / DigitalOcean / OpenStack
    "metadata.google.internal", # GCP
    "fd00:ec2::254",            # AWS IMDSv2 IPv6
    "192.0.0.192",              # Oracle Cloud
    "100.100.100.200",          # Alibaba Cloud
})
METADATA_IPS = frozenset({
    "169.254.169.254",
    "192.0.0.192",
    "100.100.100.200",
    "fd00:ec2::254",
})


def _ip_is_blocked(ip_str: str) -> bool:
    """True if IP is link-local, loopback, multicast, reserved, or metadata."""
    if ip_str in METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified)


def _looks_like_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolve_and_check(host: str) -> tuple[bool, list]:
    """Resolve host to every IP; return (blocked?, [ips]).

    Customer LAN (RFC1918) is intentionally permitted because probing
    customer infra is this agent's purpose. We only block:
      - literal metadata hostnames / IPs
      - loopback / link-local / multicast / reserved / unspecified
    """
    if not host:
        return True, []
    if host.lower() in METADATA_HOSTS:
        return True, []
    # If host is already an IP literal, skip DNS.
    try:
        ipaddress.ip_address(host)
        return _ip_is_blocked(host), [host]
    except ValueError:
        pass
    # Hostname — resolve every A/AAAA record and check each.
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return True, []  # unresolvable — block defensively
    def _ip_sort_key(ip_str):
        try:
            return (ipaddress.ip_address(ip_str).version == 6, ip_str)
        except ValueError:
            return (True, ip_str)
    ips = sorted({info[4][0] for info in infos}, key=_ip_sort_key)
    for ip in ips:
        if _ip_is_blocked(ip):
            return True, ips
    return False, ips


def run_http_test(url: str, follow_redirects: bool = True, timeout: int = 15) -> dict:
    """HTTP/HTTPS response time test using curl timing metrics."""
    # Default scheme: https
    if not url.lower().startswith(URL_ALLOWED_SCHEMES):
        if "://" in url:
            return {"url": url, "success": False, "error": "Only http(s) URLs allowed"}
        url = "https://" + url
    # Resolve host and block metadata / loopback / link-local IPs. Pin curl to
    # the resolved IP with --resolve to prevent DNS re-resolution (rebinding)
    # between our check and curl's own lookup.
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or scheme_port
    except Exception:
        return {"url": url, "success": False, "error": "Invalid URL"}
    blocked, ips = _resolve_and_check(host)
    if blocked:
        return {"url": url, "success": False,
                "error": "Host blocked (metadata / loopback / link-local / unresolvable)"}
    # Use seconds-based variables (compatible with all curl versions), convert to ms
    fmt = (
        "dns_s=%{time_namelookup}\n"
        "connect_s=%{time_connect}\n"
        "tls_s=%{time_appconnect}\n"
        "ttfb_s=%{time_starttransfer}\n"
        "total_s=%{time_total}\n"
        "http_code=%{http_code}\n"
        "redirect_count=%{num_redirects}\n"
        "size_bytes=%{size_download}\n"
        "url_final=%{url_effective}\n"
    )
    cmd = ["curl", "-o", "/dev/null", "-s", "-w", fmt,
           "--max-time", str(timeout),
           "--connect-timeout", "5"]
    # Pin to a resolved IP so curl cannot re-resolve to a blocked address.
    if ips and host and not _looks_like_ip_literal(host):
        cmd += ["--resolve", f"{host}:{port}:{ips[0]}"]
    if follow_redirects:
        cmd.append("-L")
    cmd.append(url)
    ok, raw = run_cmd(cmd, timeout=timeout + 5)
    result = {"url": url, "success": ok, "timestamp": time.time()}
    if ok:
        parsed = {}
        for line in raw.strip().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                try:
                    parsed[k] = float(v)
                except ValueError:
                    parsed[k] = v
        # Convert seconds to ms
        result["dns_ms"] = round(parsed.get("dns_s", 0) * 1000, 2)
        result["connect_ms"] = round(parsed.get("connect_s", 0) * 1000, 2)
        tls_s = parsed.get("tls_s", 0)
        result["tls_ms"] = round(tls_s * 1000, 2)
        result["tls_handshake_ms"] = round((tls_s - parsed.get("connect_s", 0)) * 1000, 2) if tls_s > 0 else None
        result["ttfb_ms"] = round(parsed.get("ttfb_s", 0) * 1000, 2)
        result["total_ms"] = round(parsed.get("total_s", 0) * 1000, 2)
        result["http_code"] = int(parsed.get("http_code", 0))
        result["redirect_count"] = int(parsed.get("redirect_count", 0))
        result["size_bytes"] = int(parsed.get("size_bytes", 0))
        result["url_final"] = parsed.get("url_final", url)
        result["success"] = result["http_code"] > 0
    else:
        result["error"] = raw[:200]
    return result


def run_tcp_time(host: str, port: int = 443, timeout: int = 5) -> dict:
    """Measure TCP connection establishment time.

    Resolves host first and refuses on link-local / metadata / loopback
    IPs, then pins the connect to the resolved IP so DNS rebinding can't
    swap the target mid-syscall.
    """
    result = {"host": host, "port": port, "timestamp": time.time()}
    blocked, ips = _resolve_and_check(host)
    if blocked or not ips:
        result["success"] = False
        result["connect_ms"] = None
        result["error"] = "Target resolves to a blocked IP"
        return result
    target_ip = ips[0]
    try:
        # AF-agnostic so IPv6 resolutions still work. getaddrinfo returned
        # sorted IPs, so target_ip is deterministic across calls.
        family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        err = s.connect_ex((target_ip, port))
        elapsed = round((time.time() - t0) * 1000, 2)
        s.close()
        result["success"] = err == 0
        result["connect_ms"] = elapsed if err == 0 else None
        result["resolved_ip"] = target_ip
        result["error"] = None if err == 0 else f"Connection failed (code {err})"
    except Exception as e:
        result["success"] = False
        result["connect_ms"] = None
        result["error"] = str(e)
    return result


# Bounds for nmap parameters exposed to the controller. Clamp here rather
# than reject so a slightly-off-by-one controller request still executes.
_NMAP_TIMING_MIN, _NMAP_TIMING_MAX = 0, 5
_NMAP_TOP_PORTS_MAX = 1000
_NMAP_TIMEOUT_MAX = 120


def run_port_check(host: str, port: str = "443", scan_type: str = "tcp",
                   service_detection: bool = False, timing: int = 4,
                   top_ports: int = 0, timeout: int = 10) -> dict:
    """Port check using nmap with optional service detection.

    Resolves host first and refuses on link-local / metadata / loopback
    IPs. Pins nmap and the socket fallback to the resolved IP so DNS
    rebinding can't swap the target between the check and the scan.
    """
    # Clamp numeric params: caller-supplied, must be bounded.
    timing = max(_NMAP_TIMING_MIN, min(int(timing), _NMAP_TIMING_MAX))
    top_ports = max(0, min(int(top_ports), _NMAP_TOP_PORTS_MAX))
    timeout = max(1, min(int(timeout), _NMAP_TIMEOUT_MAX))
    scan_type = scan_type if scan_type in ("tcp", "udp") else "tcp"
    # Validate port spec unless top_ports takes precedence.
    if top_ports == 0:
        validate_port_spec(str(port))
    blocked, ips = _resolve_and_check(host)
    if blocked or not ips:
        return {"host": host, "port": port, "scan_type": scan_type,
                "reachable": False, "error": "Target resolves to a blocked IP"}
    target_ip = ips[0]
    # Build nmap command; scan the resolved IP, not the hostname.
    cmd = ["nmap", "-oX", "-"]  # XML output to stdout
    if scan_type == "udp":
        cmd.append("-sU")
    else:
        cmd.append("-sT")  # TCP connect scan (no root needed)
    cmd.append(f"-T{timing}")
    if service_detection:
        cmd.append("-sV")
    if top_ports > 0:
        cmd += ["--top-ports", str(top_ports)]
    elif port:
        cmd += ["-p", str(port)]
    cmd.append(target_ip)
    ok, raw = run_cmd(cmd, timeout=timeout + 30)
    result = {"host": host, "resolved_ip": target_ip, "port": port,
              "scan_type": scan_type, "raw_xml": raw[:2000] if ok else None}
    if not ok:
        # Fallback to socket check on first requested port, also pinned
        # to the already-resolved IP.
        try:
            ports = [int(p.strip()) for p in str(port).replace("-", " ").split(",") if p.strip().isdigit()]
            if not ports:
                ports = [443]
            family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(5)
            start = time.time()
            r = s.connect_ex((target_ip, ports[0]))
            elapsed = round((time.time() - start) * 1000, 2)
            s.close()
            result["reachable"] = r == 0
            result["latency_ms"] = elapsed if r == 0 else None
            result["error"] = raw[:200]
        except Exception as e:
            result["reachable"] = False
            result["error"] = str(e)
        return result
    # Parse nmap XML (defusedxml, already imported at top).
    try:
        root = ET.fromstring(raw)
        ports_found = []
        for host_el in root.findall("host"):
            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                port_info = {
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "reason": state_el.get("reason") if state_el is not None else "",
                }
                if service_el is not None:
                    port_info["service"] = service_el.get("name", "")
                    if service_detection:
                        port_info["version"] = " ".join(filter(None, [
                            service_el.get("product", ""),
                            service_el.get("version", ""),
                            service_el.get("extrainfo", "")
                        ])).strip()
                ports_found.append(port_info)
        open_ports = [p for p in ports_found if p["state"] == "open"]
        result["ports"] = ports_found
        result["open_count"] = len(open_ports)
        result["reachable"] = len(open_ports) > 0
        result["success"] = True
    except Exception as e:
        result["parse_error"] = str(e)
        result["reachable"] = "open" in raw.lower()
    return result


def run_dns(target: str = "google.com", server: str = "", record_type: str = "A") -> dict:
    """DNS resolution test using dig if available, fallback to socket."""
    results = {}
    dig_cmd = ["dig", "+stats", "+noall", "+answer", "+time=3", "+tries=1"]
    if server:
        dig_cmd.append(f"@{server}")
    dig_cmd += [target, record_type]
    try:
        ok, raw = run_cmd(dig_cmd, timeout=10)
    except SpawnFailureError as e:
        # Host PID/thread exhaustion — fall through to in-process getaddrinfo
        # so DNS health stays observable without needing to fork dig.
        log.warning("dig spawn failed (%s); falling back to getaddrinfo", e)
        ok, raw = False, str(e)
    if ok and raw:
        results["raw"] = raw
        for line in raw.splitlines():
            if "Query time:" in line:
                try:
                    results["query_ms"] = int(line.split(":")[1].strip().split()[0])
                except Exception:
                    pass
            if "SERVER:" in line:
                try:
                    results["server_used"] = line.split("(")[1].rstrip(")")
                except Exception:
                    pass
        answers = [l.strip() for l in raw.splitlines() if l.strip() and not l.startswith(";")]
        results["answers"] = answers
        results["success"] = len(answers) > 0
    else:
        start = time.time()
        try:
            addrs = socket.getaddrinfo(target, None)
            elapsed = round((time.time() - start) * 1000, 2)
            results["query_ms"] = elapsed
            results["answers"] = list({a[4][0] for a in addrs})
            results["success"] = True
        except Exception as e:
            results["query_ms"] = None
            results["answers"] = []
            results["success"] = False
            results["error"] = str(e)
    results["target"] = target
    results["record_type"] = record_type
    results["server"] = server or "default"
    results["timestamp"] = time.time()
    return results


_current_ws = None


def get_current_ws():
    return _current_ws


@asynccontextmanager
async def lifespan(app: FastAPI):
    if CONTROLLER_URL:
        asyncio.create_task(controller_ws_loop())
        asyncio.create_task(buffer_cleanup_loop())
        asyncio.create_task(dns_monitor_loop(get_current_ws))
        asyncio.create_task(gateway_monitor_loop(get_current_ws))
        asyncio.create_task(traceroute_monitor_loop(get_current_ws))
        asyncio.create_task(http_monitor_loop(get_current_ws))
        log.info("WebSocket push loop started -> %s", CONTROLLER_URL)
    else:
        log.warning("CONTROLLER_URL not set - running in standalone REST mode only")
    yield


app = FastAPI(title="D2 Edge Agent", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    """Unauthenticated liveness probe (for Docker healthcheck). No sensitive info."""
    return {"status": "ok"}


@app.get("/info")
def info(authorization: str = Header(None)):
    """Full system info — authenticated."""
    require_auth(authorization)
    return system_info()


@app.post("/tests/speedtest")
def speedtest(authorization: str = Header(None)):
    require_auth(authorization)
    return run_speedtest()


@app.post("/tests/iperf")
def iperf(
    target: str = Query(...),
    duration: int = Query(10, ge=1, le=60),
    reverse: bool = Query(False),
    authorization: str = Header(None),
):
    require_auth(authorization)
    validate_target(target)
    return run_iperf(target, duration, reverse)


@app.post("/tests/ping")
def ping(
    target: str = Query(...),
    count: int = Query(10, ge=1, le=50),
    authorization: str = Header(None),
):
    require_auth(authorization)
    validate_target(target)
    return run_ping(target, count)


@app.post("/tests/traceroute")
def traceroute(
    target: str = Query(...),
    use_mtr: bool = Query(False),
    count: int = Query(10, ge=1, le=100),
    authorization: str = Header(None),
):
    require_auth(authorization)
    validate_target(target)
    return run_traceroute(target, use_mtr=use_mtr, count=count)


async def controller_ws_loop():
    global _current_ws
    backoff = 5
    while True:
        try:
            log.info("Connecting to controller at %s", CONTROLLER_URL)
            async with websockets.connect(
                CONTROLLER_URL,
                extra_headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
                ping_interval=20,
                ping_timeout=10,
            ) as ws:
                backoff = 5
                _current_ws = ws
                log.info("Connected to controller")

                await ws.send(json.dumps({
                    "type": "register",
                    "agent_id": AGENT_ID,
                    "tenant_id": TENANT_ID,
                    "info": system_info(),
                }))

                # Flush buffered results from outage
                buffered = get_buffered_results()
                if buffered:
                    log.info("Flushing %d buffered results to controller", len(buffered))
                    flushed_ids = []
                    for rec in buffered:
                        try:
                            result = json.loads(rec["result"])
                            await ws.send(json.dumps({
                                "type": "result",
                                "job_id": str(uuid.uuid4()),
                                "agent_id": AGENT_ID,
                                "tenant_id": TENANT_ID,
                                "command": rec["command"],
                                "result": result,
                                "timestamp": rec["timestamp"],
                                "buffered": True,
                            }))
                            flushed_ids.append(rec["id"])
                        except Exception as e:
                            log.warning("Buffer flush error: %s", e)
                    mark_buffered_flushed(flushed_ids)
                    log.info("Flushed %d buffered results", len(flushed_ids))

                async def heartbeat():
                    last_ts_ip = get_tailscale_ip()
                    while True:
                        await asyncio.sleep(HEARTBEAT_INTERVAL)
                        try:
                            await ws.send(json.dumps({
                                "type": "heartbeat",
                                "agent_id": AGENT_ID,
                                "timestamp": time.time(),
                            }))
                            # Detect Tailscale IP change and report it
                            cur_ts_ip = get_tailscale_ip()
                            if cur_ts_ip and cur_ts_ip != last_ts_ip:
                                log.info("Tailscale IP changed: %s -> %s", last_ts_ip, cur_ts_ip)
                                await ws.send(json.dumps({
                                    "type": "ip_change",
                                    "agent_id": AGENT_ID,
                                    "tailscale_ip": cur_ts_ip,
                                    "previous": last_ts_ip,
                                    "timestamp": time.time(),
                                }))
                                last_ts_ip = cur_ts_ip
                        except Exception:
                            break

                hb_task = asyncio.create_task(heartbeat())

                try:
                    async for raw in ws:
                        await handle_command(ws, raw)
                finally:
                    hb_task.cancel()

        except Exception as e:
            _current_ws = None
            log.warning("Controller connection failed: %s. Retrying in %ds", e, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)


async def handle_command(ws, raw: str):
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("Received non-JSON from controller: %s", raw[:100])
        return

    cmd = msg.get("command")
    job_id = msg.get("job_id")
    params = msg.get("params", {})

    log.info("Received command: %s (job_id=%s)", cmd, job_id)

    if ALLOWED_COMMANDS is not None and cmd not in ALLOWED_COMMANDS and cmd != "config_update":
        log.warning("Command %s rejected by ALLOWED_COMMANDS allowlist", cmd)
        await ws.send(json.dumps({
            "type": "result",
            "job_id": job_id,
            "agent_id": AGENT_ID,
            "tenant_id": TENANT_ID,
            "command": cmd,
            "result": {"error": "Command not permitted on this agent"},
            "timestamp": time.time(),
        }))
        return

    loop = asyncio.get_running_loop()
    result = {}
    try:
        if cmd == "speedtest":
            result = await loop.run_in_executor(None, run_speedtest)
        elif cmd == "ping":
            target = validate_target(params.get("target", ""))
            count = int(params.get("count", 10))
            size = int(params.get("size", 0))
            df = bool(params.get("df", False))
            interval = float(params.get("interval", 1.0))
            result = await loop.run_in_executor(
                None, run_ping, target, count, size, df, interval)
        elif cmd == "iperf":
            target = validate_target(params.get("target", ""))
            duration = int(params.get("duration", 10))
            reverse = bool(params.get("reverse", False))
            protocol = params.get("protocol", "tcp")
            streams = int(params.get("streams", 1))
            window = params.get("window", "")
            bitrate = params.get("bitrate", "")
            omit = int(params.get("omit", 0))
            result = await loop.run_in_executor(
                None, run_iperf, target, duration, reverse, protocol, streams, window, bitrate, omit)
        elif cmd == "iperf_server":
            duration = int(params.get("duration", 15))
            result = await loop.run_in_executor(None, run_iperf_server, duration)
        elif cmd == "traceroute":
            target = validate_target(params.get("target", ""))
            use_mtr = bool(params.get("use_mtr", False))
            count = int(params.get("count", 10))
            result = await loop.run_in_executor(
                None, run_traceroute, target, use_mtr, count)
        elif cmd == "http_test":
            url = params.get("url", "")
            follow_redirects = bool(params.get("follow_redirects", True))
            timeout = int(params.get("timeout", 15))
            result = await loop.run_in_executor(
                None, run_http_test, url, follow_redirects, timeout)
        elif cmd == "tcp_time":
            host = validate_target(params.get("host", ""))
            port = int(params.get("port", 443))
            timeout = int(params.get("timeout", 5))
            result = await loop.run_in_executor(
                None, run_tcp_time, host, port, timeout)
        elif cmd == "port_check":
            host = validate_target(params.get("host", ""))
            port = params.get("port", "443")
            scan_type = params.get("scan_type", "tcp")
            service_detection = bool(params.get("service_detection", False))
            timing = int(params.get("timing", 4))
            top_ports = int(params.get("top_ports", 0))
            result = await loop.run_in_executor(
                None, run_port_check, host, str(port), scan_type, service_detection, timing, top_ports)
        elif cmd == "dns":
            target = validate_target(params.get("target", "google.com"))
            server = params.get("server", "")
            if server:
                validate_target(server)
            record_type = validate_dns_record_type(params.get("record_type", "A"))
            result = await loop.run_in_executor(
                None, run_dns, target, server, record_type)
        elif cmd == "mtu_test":
            target = validate_target(params.get("target", ""))
            max_size = int(params.get("max_size", 1500))
            max_size = max(576, min(max_size, 9000))
            result = await loop.run_in_executor(
                None, run_mtu_test, target, max_size)
        elif cmd == "config_update":
            # Atomic replace: build a new MonitorConfig and swap the module
            # reference. Read by the monitor loops as a single pointer deref,
            # so callers never see a torn snapshot of the three fields.
            new_cfg = MonitorConfig(
                traceroute_targets=tuple(params.get("traceroute_targets", [])),
                http_targets=tuple(params.get("http_targets", [])),
                received=True,
            )
            _set_monitor_config(new_cfg)
            log.info("Config update: %d traceroute, %d http targets",
                     len(new_cfg.traceroute_targets), len(new_cfg.http_targets))
            # No result to send back for config updates
            return
        else:
            result = {"error": f"Unknown command: {cmd}"}
    except HTTPException as e:
        result = {"error": e.detail}
    except SpawnFailureError as e:
        log.error("Command %s aborted - host PID/thread exhaustion: %s", cmd, e)
        result = _spawn_failure_result(cmd, params, e)
    except Exception as e:
        if _is_spawn_exhaustion(e):
            log.error("Command %s aborted - host PID/thread exhaustion (raw %s): %s",
                      cmd, type(e).__name__, e)
            result = _spawn_failure_result(cmd, params, e)
        else:
            log.warning("Command %s failed (%s): %s", cmd, type(e).__name__, e, exc_info=True)
            result = {"error": f"{cmd} failed"}

    await ws.send(json.dumps({
        "type": "result",
        "job_id": job_id,
        "agent_id": AGENT_ID,
        "tenant_id": TENANT_ID,
        "command": cmd,
        "result": result,
        "timestamp": time.time(),
    }))


DNS_TARGETS = [
    {"target": "google.com",     "server": "8.8.8.8", "record_type": "A"},
    {"target": "cloudflare.com", "server": "1.1.1.1", "record_type": "A"},
    {"target": "google.com",     "server": "",         "record_type": "A"},
]
DNS_INTERVAL = 30


async def gateway_monitor_loop(get_ws_func):
    """Ping default gateway every 30s and push results."""
    await asyncio.sleep(15)  # offset from DNS loop
    while True:
        try:
            gw = get_default_gateway()
            if gw:
                loop = asyncio.get_running_loop()
                try:
                    result = await loop.run_in_executor(
                        None, run_ping, gw, 3, 0, False, 1.0
                    )
                except SpawnFailureError as e:
                    log.error("Gateway monitor aborted - host PID/thread exhaustion: %s", e)
                    result = _spawn_failure_result("gateway_monitor", {"gateway": gw}, e)
                except Exception as e:
                    if _is_spawn_exhaustion(e):
                        log.error("Gateway monitor aborted - exhaustion (raw %s): %s",
                                  type(e).__name__, e)
                        result = _spawn_failure_result("gateway_monitor", {"gateway": gw}, e)
                    else:
                        raise
                result["gateway"] = gw
                result["timestamp"] = time.time()
                ws = get_ws_func()
                payload = json.dumps({
                    "type": "result",
                    "job_id": str(uuid.uuid4()),
                    "agent_id": AGENT_ID,
                    "tenant_id": TENANT_ID,
                    "command": "gateway_monitor",
                    "result": result,
                    "timestamp": time.time(),
                })
                if ws is not None:
                    await ws.send(payload)
                elif not result.get("spawn_failure"):
                    # Buffer locally during outage. Skip spawn-failure stubs —
                    # they're meaningless once the host recovers.
                    buffer_result("gateway_monitor", result)
            else:
                log.debug("No default gateway found")
        except Exception as e:
            log.warning("Gateway monitor error: %s", e)
        await asyncio.sleep(30)


async def dns_monitor_loop(get_ws_func):
    """Continuously run DNS checks and push results to controller."""
    await asyncio.sleep(10)
    while True:
        loop = asyncio.get_running_loop()
        try:
            ws = get_ws_func()
            if ws is not None:
                for t in DNS_TARGETS:
                    try:
                        try:
                            result = await loop.run_in_executor(
                                None, run_dns, t["target"], t["server"], t["record_type"]
                            )
                        except SpawnFailureError as e:
                            log.error("DNS monitor aborted - host exhaustion: %s", e)
                            result = _spawn_failure_result(
                                "dns_monitor", {"target": t["target"]}, e)
                        except Exception as e:
                            if _is_spawn_exhaustion(e):
                                log.error("DNS monitor aborted - exhaustion: %s", e)
                                result = _spawn_failure_result(
                                    "dns_monitor", {"target": t["target"]}, e)
                            else:
                                raise
                        result["label"] = t.get("label", "external")
                        await ws.send(json.dumps({
                            "type": "result",
                            "job_id": str(uuid.uuid4()),
                            "agent_id": AGENT_ID,
                            "tenant_id": TENANT_ID,
                            "command": "dns_monitor",
                            "result": result,
                            "timestamp": time.time(),
                        }))
                    except Exception as e:
                        log.warning("DNS monitor send error: %s", e)
        except Exception as e:
            log.warning("DNS monitor loop error: %s", e)
        # Buffer DNS results when offline
        if get_ws_func() is None:
            try:
                for t in DNS_TARGETS:
                    try:
                        result = await loop.run_in_executor(
                            None, run_dns, t["target"], t["server"], t["record_type"]
                        )
                    except SpawnFailureError:
                        continue
                    except Exception as e:
                        if _is_spawn_exhaustion(e):
                            continue
                        raise
                    buffer_result("dns_monitor", result)
            except Exception:
                pass
        await asyncio.sleep(DNS_INTERVAL)



TRACEROUTE_TARGETS = ["8.8.8.8", "1.1.1.1"]
_tr_env = os.getenv("TRACEROUTE_TARGETS", "")
if _tr_env:
    TRACEROUTE_TARGETS = [t.strip() for t in _tr_env.split(",") if t.strip()]
TRACEROUTE_INTERVAL = int(os.getenv("TRACEROUTE_INTERVAL", "120"))

async def traceroute_monitor_loop(get_ws_func):
    """Periodically run mtr to configured targets and push results."""
    await asyncio.sleep(20)
    while True:
        # Read once per iteration so a config_update mid-loop can't
        # split the snapshot between `received` and `traceroute_targets`.
        cfg = _monitor_config
        try:
            if cfg.received and cfg.traceroute_targets:
                targets = cfg.traceroute_targets
            else:
                targets = tuple({"target": t.strip(), "interval": TRACEROUTE_INTERVAL}
                                for t in TRACEROUTE_TARGETS if t.strip())

            loop = asyncio.get_running_loop()
            for t in targets:
                target = t.get("target", t) if isinstance(t, dict) else t
                try:
                    try:
                        result = await loop.run_in_executor(
                            None, run_traceroute, target, True, 5
                        )
                    except SpawnFailureError as e:
                        log.error("Traceroute monitor aborted for %s - host exhaustion: %s",
                                  target, e)
                        result = _spawn_failure_result(
                            "traceroute_monitor", {"target": target}, e)
                    except Exception as e:
                        if _is_spawn_exhaustion(e):
                            log.error("Traceroute monitor aborted for %s - exhaustion: %s",
                                      target, e)
                            result = _spawn_failure_result(
                                "traceroute_monitor", {"target": target}, e)
                        else:
                            raise
                    result["timestamp"] = time.time()
                    ws = get_ws_func()
                    payload = json.dumps({
                        "type": "result",
                        "job_id": str(uuid.uuid4()),
                        "agent_id": AGENT_ID,
                        "tenant_id": TENANT_ID,
                        "command": "traceroute_monitor",
                        "result": result,
                        "timestamp": time.time(),
                    })
                    if ws is not None:
                        await ws.send(payload)
                    elif not result.get("spawn_failure"):
                        buffer_result("traceroute_monitor", result)
                except Exception as e:
                    log.warning("Traceroute monitor error for %s: %s", target, e)
        except Exception as e:
            log.warning("Traceroute monitor loop error: %s", e)

        min_interval = TRACEROUTE_INTERVAL
        if cfg.received and cfg.traceroute_targets:
            intervals = [t.get("interval", TRACEROUTE_INTERVAL)
                         for t in cfg.traceroute_targets if isinstance(t, dict)]
            if intervals:
                min_interval = min(intervals)
        await asyncio.sleep(min_interval)


HTTP_TARGETS_DEFAULT = [
    {"url": "https://www.google.com", "label": "Google"},
    {"url": "https://login.microsoftonline.com", "label": "Microsoft 365"},
    {"url": "https://1.1.1.1", "label": "Cloudflare"},
]
_http_env = os.getenv("HTTP_TARGETS", "")
if _http_env:
    try:
        HTTP_TARGETS = json.loads(_http_env)
    except json.JSONDecodeError:
        HTTP_TARGETS = HTTP_TARGETS_DEFAULT
else:
    HTTP_TARGETS = HTTP_TARGETS_DEFAULT
HTTP_MONITOR_INTERVAL = int(os.getenv("HTTP_MONITOR_INTERVAL", "300"))


async def http_monitor_loop(get_ws_func):
    """Periodically run HTTP tests to configured targets and push results."""
    await asyncio.sleep(25)
    while True:
        cfg = _monitor_config
        try:
            if cfg.received and cfg.http_targets:
                targets = cfg.http_targets
            else:
                targets = HTTP_TARGETS

            loop = asyncio.get_running_loop()
            for target in targets:
                try:
                    url = target.get("url", target) if isinstance(target, dict) else target
                    label = target.get("label", url) if isinstance(target, dict) else url
                    try:
                        result = await loop.run_in_executor(
                            None, run_http_test, url
                        )
                    except SpawnFailureError as e:
                        log.error("HTTP monitor aborted for %s - host exhaustion: %s", url, e)
                        result = _spawn_failure_result("http_monitor", {"url": url}, e)
                    except Exception as e:
                        if _is_spawn_exhaustion(e):
                            log.error("HTTP monitor aborted for %s - exhaustion: %s", url, e)
                            result = _spawn_failure_result("http_monitor", {"url": url}, e)
                        else:
                            raise
                    result["label"] = label
                    result["timestamp"] = time.time()
                    ws = get_ws_func()
                    payload = json.dumps({
                        "type": "result",
                        "job_id": str(uuid.uuid4()),
                        "agent_id": AGENT_ID,
                        "tenant_id": TENANT_ID,
                        "command": "http_monitor",
                        "result": result,
                        "timestamp": time.time(),
                    })
                    if ws is not None:
                        await ws.send(payload)
                    elif not result.get("spawn_failure"):
                        buffer_result("http_monitor", result)
                except Exception as e:
                    log.warning("HTTP monitor error for %s: %s", target, e)
        except Exception as e:
            log.warning("HTTP monitor loop error: %s", e)

        min_interval = HTTP_MONITOR_INTERVAL
        if cfg.received and cfg.http_targets:
            intervals = [t.get("interval", HTTP_MONITOR_INTERVAL)
                         for t in cfg.http_targets if isinstance(t, dict)]
            if intervals:
                min_interval = min(intervals)
        await asyncio.sleep(min_interval)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080, log_config=None)