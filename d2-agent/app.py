"""
D2 Edge Agent - Runs on each Raspberry Pi
"""
import asyncio
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
import websockets
from fastapi import FastAPI, Header, HTTPException, Query

logging.basicConfig(
    level=logging.INFO,
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

if not AGENT_TOKEN or AGENT_TOKEN == "change-me":
    log.critical("AGENT_TOKEN is not set. Refusing to start.")
    sys.exit(1)

BUFFER_DB = "/app/buffer.db"

def init_buffer_db():
    """Initialize local SQLite buffer for outage data retention."""
    import sqlite3 as _sql
    conn = _sql.connect(BUFFER_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS buffered_results (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        command   TEXT NOT NULL,
        result    TEXT NOT NULL,
        timestamp REAL NOT NULL,
        flushed   INTEGER DEFAULT 0
    )""")
    conn.commit()
    conn.close()
    log.info("Buffer DB initialised at %s", BUFFER_DB)

def buffer_result(command: str, result: dict):
    """Store a monitoring result locally when controller is unreachable."""
    import sqlite3 as _sql
    try:
        conn = _sql.connect(BUFFER_DB)
        conn.execute("INSERT INTO buffered_results (command, result, timestamp) VALUES (?,?,?)",
                     (command, json.dumps(result), result.get("timestamp", time.time())))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("Buffer write error: %s", e)

def get_buffered_results(limit: int = 500):
    """Retrieve unflushed buffered results."""
    import sqlite3 as _sql
    try:
        conn = _sql.connect(BUFFER_DB)
        conn.row_factory = _sql.Row
        rows = conn.execute(
            "SELECT * FROM buffered_results WHERE flushed=0 ORDER BY timestamp LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def mark_buffered_flushed(ids: list):
    """Mark buffered records as flushed."""
    import sqlite3 as _sql
    if not ids:
        return
    try:
        conn = _sql.connect(BUFFER_DB)
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

TARGET_RE = re.compile(r'^[\w.\-]{1,253}$')


def validate_target(target: str) -> str:
    if not TARGET_RE.match(target):
        raise HTTPException(status_code=400, detail="Invalid target")
    return target


def require_auth(authorization: Optional[str]):
    if authorization != f"Bearer {AGENT_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")


def run_cmd(cmd: list, timeout: int = 60):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return True, out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except subprocess.CalledProcessError as e:
        return False, e.output.decode(errors="replace")
    except Exception as e:
        return False, str(e)


def get_local_ip() -> str:
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def get_public_ip() -> str:
    """Fetch public IP via lightweight echo service."""
    import urllib.request as _req
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]:
        try:
            with _req.urlopen(url, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            continue
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


def system_info() -> dict:
    ok, uptime = run_cmd(["cat", "/proc/uptime"])
    uptime_seconds = float(uptime.split()[0]) if ok else None
    return {
        "agent_id": AGENT_ID,
        "tenant_id": TENANT_ID,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "ip": get_local_ip(),
        "public_ip": get_public_ip(),
        "gateway": get_default_gateway(),
        "tenant_name": TENANT_NAME,
        "dns_servers": get_dns_servers(),
        "python": platform.python_version(),
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
    """Start iperf3 in server mode for one connection, return this agent IP."""
    import subprocess as sp
    import socket as _socket
    local_ip = get_local_ip()
    # Kill any existing iperf3 server holding port 5201
    try:
        sp.run(["fuser", "-k", "5201/tcp"], capture_output=True)
    except Exception:
        pass
    time.sleep(0.3)
    cmd = ["iperf3", "-s", "--one-off", "-J"]
    try:
        proc = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE)
        # Wait for iperf3 to bind - just sleep, don't connect (connecting would consume the one-off slot)
        time.sleep(1.0)
        return {"status": "listening", "ip": local_ip, "pid": proc.pid}
    except Exception as e:
        return {"error": str(e)}


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


def run_traceroute(target: str) -> dict:
    ok, raw = run_cmd(["traceroute", "-n", "-m", "20", target], timeout=60)
    return {"raw": raw, "success": ok}


def run_http_test(url: str, follow_redirects: bool = True, timeout: int = 15) -> dict:
    """HTTP/HTTPS response time test using curl timing metrics."""
    if not url.startswith("http"):
        url = "https://" + url
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
    """Measure TCP connection establishment time."""
    import socket as _socket
    result = {"host": host, "port": port, "timestamp": time.time()}
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        err = s.connect_ex((host, port))
        elapsed = round((time.time() - t0) * 1000, 2)
        s.close()
        result["success"] = err == 0
        result["connect_ms"] = elapsed if err == 0 else None
        result["error"] = None if err == 0 else f"Connection failed (code {err})"
    except Exception as e:
        result["success"] = False
        result["connect_ms"] = None
        result["error"] = str(e)
    return result


def run_port_check(host: str, port: str = "443", scan_type: str = "tcp",
                   service_detection: bool = False, timing: int = 4,
                   top_ports: int = 0, timeout: int = 10) -> dict:
    """Port check using nmap with optional service detection."""
    # Build nmap command
    cmd = ["nmap", "-oX", "-"]  # XML output to stdout
    # Scan type
    if scan_type == "udp":
        cmd.append("-sU")
    else:
        cmd.append("-sT")  # TCP connect scan (no root needed)
    # Timing
    cmd.append(f"-T{timing}")
    # Service detection
    if service_detection:
        cmd.append("-sV")
    # Port specification
    if top_ports > 0:
        cmd += ["--top-ports", str(top_ports)]
    elif port:
        cmd += ["-p", str(port)]
    cmd.append(host)
    ok, raw = run_cmd(cmd, timeout=timeout + 30)
    result = {"host": host, "port": port, "scan_type": scan_type, "raw_xml": raw[:2000] if ok else None}
    if not ok:
        # Fallback to socket check
        import socket as _socket
        try:
            ports = [int(p.strip()) for p in str(port).replace("-", " ").split(",") if p.strip().isdigit()]
            if not ports:
                ports = [443]
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(5)
            start = time.time()
            r = s.connect_ex((host, ports[0]))
            elapsed = round((time.time() - start) * 1000, 2)
            s.close()
            result["reachable"] = r == 0
            result["latency_ms"] = elapsed if r == 0 else None
            result["error"] = raw[:200]
        except Exception as e:
            result["reachable"] = False
            result["error"] = str(e)
        return result
    # Parse nmap XML
    try:
        import xml.etree.ElementTree as ET
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
    import socket as _socket
    results = {}
    dig_cmd = ["dig", "+stats", "+noall", "+answer", "+time=3", "+tries=1"]
    if server:
        dig_cmd.append(f"@{server}")
    dig_cmd += [target, record_type]
    ok, raw = run_cmd(dig_cmd, timeout=10)
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
            addrs = _socket.getaddrinfo(target, None)
            elapsed = round((time.time() - start) * 1000, 2)
            results["query_ms"] = elapsed
            results["answers"] = list(set(a[4][0] for a in addrs))
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
        asyncio.create_task(dns_monitor_loop(get_current_ws))
        asyncio.create_task(gateway_monitor_loop(get_current_ws))
        log.info("WebSocket push loop started -> %s", CONTROLLER_URL)
    else:
        log.warning("CONTROLLER_URL not set - running in standalone REST mode only")
    yield


app = FastAPI(title="D2 Edge Agent", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", **system_info()}


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
def traceroute(target: str = Query(...), authorization: str = Header(None)):
    require_auth(authorization)
    validate_target(target)
    return run_traceroute(target)


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
                    import uuid as _buuid
                    for rec in buffered:
                        try:
                            result = json.loads(rec["result"])
                            await ws.send(json.dumps({
                                "type": "result",
                                "job_id": str(_buuid.uuid4()),
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
                    while True:
                        await asyncio.sleep(HEARTBEAT_INTERVAL)
                        try:
                            await ws.send(json.dumps({
                                "type": "heartbeat",
                                "agent_id": AGENT_ID,
                                "timestamp": time.time(),
                            }))
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

    result = {}
    try:
        if cmd == "speedtest":
            result = await asyncio.get_event_loop().run_in_executor(None, run_speedtest)
        elif cmd == "ping":
            target = validate_target(params.get("target", ""))
            count = int(params.get("count", 10))
            size = int(params.get("size", 0))
            df = bool(params.get("df", False))
            interval = float(params.get("interval", 1.0))
            result = await asyncio.get_event_loop().run_in_executor(
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
            result = await asyncio.get_event_loop().run_in_executor(
                None, run_iperf, target, duration, reverse, protocol, streams, window, bitrate, omit)
        elif cmd == "iperf_server":
            duration = int(params.get("duration", 15))
            result = await asyncio.get_event_loop().run_in_executor(None, run_iperf_server, duration)
        elif cmd == "traceroute":
            target = validate_target(params.get("target", ""))
            result = await asyncio.get_event_loop().run_in_executor(None, run_traceroute, target)
        elif cmd == "http_test":
            url = params.get("url", "")
            follow_redirects = bool(params.get("follow_redirects", True))
            timeout = int(params.get("timeout", 15))
            result = await asyncio.get_event_loop().run_in_executor(
                None, run_http_test, url, follow_redirects, timeout)
        elif cmd == "tcp_time":
            host = validate_target(params.get("host", ""))
            port = int(params.get("port", 443))
            timeout = int(params.get("timeout", 5))
            result = await asyncio.get_event_loop().run_in_executor(
                None, run_tcp_time, host, port, timeout)
        elif cmd == "port_check":
            host = validate_target(params.get("host", ""))
            port = params.get("port", "443")
            scan_type = params.get("scan_type", "tcp")
            service_detection = bool(params.get("service_detection", False))
            timing = int(params.get("timing", 4))
            top_ports = int(params.get("top_ports", 0))
            result = await asyncio.get_event_loop().run_in_executor(
                None, run_port_check, host, str(port), scan_type, service_detection, timing, top_ports)
        elif cmd == "dns":
            target = params.get("target", "google.com")
            server = params.get("server", "")
            record_type = params.get("record_type", "A")
            result = await asyncio.get_event_loop().run_in_executor(
                None, run_dns, target, server, record_type)
        else:
            result = {"error": f"Unknown command: {cmd}"}
    except HTTPException as e:
        result = {"error": e.detail}
    except Exception as e:
        result = {"error": str(e)}

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
    import uuid as _uuid
    await asyncio.sleep(15)  # offset from DNS loop
    while True:
        try:
            gw = get_default_gateway()
            if gw:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, run_ping, gw, 3, 0, False, 1.0
                )
                result["gateway"] = gw
                result["timestamp"] = time.time()
                ws = get_ws_func()
                payload = json.dumps({
                    "type": "result",
                    "job_id": str(_uuid.uuid4()),
                    "agent_id": AGENT_ID,
                    "tenant_id": TENANT_ID,
                    "command": "gateway_monitor",
                    "result": result,
                    "timestamp": time.time(),
                })
                if ws is not None:
                    await ws.send(payload)
                else:
                    # Buffer locally during outage
                    buffer_result("gateway_monitor", result)
            else:
                log.debug("No default gateway found")
        except Exception as e:
            log.warning("Gateway monitor error: %s", e)
        await asyncio.sleep(30)


async def dns_monitor_loop(get_ws_func):
    """Continuously run DNS checks and push results to controller."""
    import uuid as _uuid
    await asyncio.sleep(10)
    while True:
        try:
            ws = get_ws_func()
            if ws is not None:
                for t in DNS_TARGETS:
                    try:
                        result = await asyncio.get_event_loop().run_in_executor(
                            None, run_dns, t["target"], t["server"], t["record_type"]
                        )
                        result["label"] = t.get("label", "external")
                        await ws.send(json.dumps({
                            "type": "result",
                            "job_id": str(_uuid.uuid4()),
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
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, run_dns, t["target"], t["server"], t["record_type"]
                    )
                    buffer_result("dns_monitor", result)
            except Exception:
                pass
        await asyncio.sleep(DNS_INTERVAL)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_config=None)