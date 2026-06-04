# d2-edge Hardening & Reliability — Implementation Plan

> **For agentic workers / Codex review:** This plan targets the **`d2-edge`** repo
> (`git@github.com:Jared-D2/d2-edge.git`), **not** the msp-dashboard repo. Steps use
> checkbox (`- [ ]`) syntax. Each task is independently shippable as one PR. Tasks
> include **Rationale / Risk / Rollback / Acceptance** so a reviewer can judge each
> change in isolation. Code tasks are TDD (failing test → implement → green → commit);
> infra/bash tasks use validation commands (`bash -n`, `shellcheck`, `docker compose
> config`, `ufw status`) as their "test".

**Goal:** Close the security and reliability findings from the 2026-06-03 line-by-line
review of d2001-nw-pi01 / the d2-edge appliance, without regressing its existing
(strong) SSRF, auth, and exhaustion-handling behavior.

**Architecture:** d2-edge is a docker-compose appliance: a FastAPI probe agent
(`d2-agent/app.py`, ~2.7k LOC) plus syslog/zabbix/freeradius/netflow/auvik/cert proxies,
provisioned by idempotent bash (`bootstrap.sh`, `update.sh`, `preflight.sh`,
`render-configs.sh`) and self-healed on every `update.sh`. Fixes are grouped into:
Phase 0 (CI foundation), Phase 1 (safe in-repo fixes), Phase 2 (higher-touch hardening),
Phase 3 (cross-repo / policy design proposals).

**Tech Stack:** Python 3.12 (FastAPI, uvicorn, websockets, defusedxml, pytest), Bash,
Docker / docker-compose, ufw, systemd, nginx, FreeRADIUS, syslog-ng, GitHub Actions (new).

---

## Conventions & Prerequisites

**Repo root** in all paths below is the d2-edge checkout root (on a Pi: `/opt/d2-edge`).

**Branching:** one branch + PR per task, e.g. `fix/netflow-firewall-ports`. Do **not**
push to `main`. Keep PRs small so Codex can review each in isolation.

**Running the Python tests** (Linux dev box, CI, or the Pi host — host Python is 3.13,
container is 3.12; either runs the suite):

```bash
cd d2-agent
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
AGENT_TOKEN=test-token .venv/bin/python -m pytest tests -v
```

> `AGENT_TOKEN` must be set in the environment — `app.py` calls `sys.exit(1)` at import
> if it is unset. (`tests/test_security.py` sets a dummy via `os.environ.setdefault`,
> but don't rely on import order; always export it.)

**Bash validation** for every script touched: `bash -n <script>` and `shellcheck <script>`.

**Compose validation:** `COMPOSE_PROFILES=enabled DOCKER_GID=999 docker compose config >/dev/null`.

**Baseline (do this first):**

- [ ] Establish a green baseline: run the test command above and confirm all existing
      tests pass. Record the count. If any fail on a clean checkout, stop and report —
      do not build on a red baseline.
- [ ] Add `d2-agent/.venv/` to `.gitignore` so the test venv is never committed.

---

# PHASE 0 — CI Foundation

## Task 0: Add GitHub Actions CI (pytest + shellcheck)

**Why first:** every subsequent PR should be gated by automated tests + lint. This also
underpins Phase 3 S2 (require green CI + review before code can reach the fleet).

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `.gitignore` (add `d2-agent/.venv/`)

- [ ] **Step 1: Create the workflow**

```yaml
# .github/workflows/ci.yml
name: ci
on:
  pull_request:
  push:
    branches: [main]
jobs:
  python-tests:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: d2-agent
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt pytest
      - env:
          AGENT_TOKEN: ci-test-token
        run: python -m pytest tests -v
  shellcheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: shellcheck all scripts
        run: |
          sudo apt-get update -qq && sudo apt-get install -y -qq shellcheck
          find . -name '*.sh' -not -path './d2-agent/.venv/*' -print0 \
            | xargs -0 -r shellcheck --severity=warning
```

- [ ] **Step 2: Add the venv ignore**

Append to `.gitignore`:

```
d2-agent/.venv/
```

- [ ] **Step 3: Validate locally**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: no error (valid YAML).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .gitignore
git commit -m "ci: run pytest + shellcheck on PRs"
```

**Risk:** Low. CI may surface pre-existing shellcheck warnings — triage them (fix or
`# shellcheck disable=` with justification) in this PR or a fast-follow.
**Rollback:** delete the workflow file.
**Acceptance:** PR shows two green checks; a deliberately-broken test makes CI red.

---

# PHASE 1 — Safe, in-repo fixes

## Task 1: Remove dead code `_run_dhcp_test_helper` (C1)

**Files:** Modify `d2-agent/app.py` (delete the function, currently ~lines 1016-1026);
Modify `d2-agent/tests/test_security.py` (add guard test).

**Rationale:** `_run_dhcp_test_helper` is never called (verified: single occurrence in
the file). The real path is `run_dhcp_test` / `run_dhcp_test_for_sensor`. Dead code is a
maintenance trap.

- [ ] **Step 1: Write the failing test** — append to `tests/test_security.py`:

```python
class TestNoDeadCode:
    def test_run_dhcp_test_helper_removed(self):
        assert not hasattr(app, "_run_dhcp_test_helper")
```

- [ ] **Step 2: Run it — expect FAIL**

Run: `AGENT_TOKEN=t .venv/bin/python -m pytest tests/test_security.py::TestNoDeadCode -v`
Expected: FAIL (attribute still exists).

- [ ] **Step 3: Delete the function** from `app.py` — remove the whole block:

```python
def _run_dhcp_test_helper(iface: str) -> dict:
    """Stub for dhcp_test until the run_dhcp_test agent function exists.
    ...
    """
    fn = globals().get("run_dhcp_test")
    if fn is None:
        return {"success": False, "interface": iface, "error": "run_dhcp_test not implemented"}
    return fn(iface)
```

- [ ] **Step 4: Run the FULL suite — expect PASS** (confirms nothing referenced it)

Run: `AGENT_TOKEN=t .venv/bin/python -m pytest tests -v`
Expected: PASS, count == baseline + 1.

- [ ] **Step 5: Commit**

```bash
git add d2-agent/app.py d2-agent/tests/test_security.py
git commit -m "refactor(agent): remove dead _run_dhcp_test_helper"
```

**Risk:** Very low. **Rollback:** revert commit. **Acceptance:** suite green; symbol gone.

---

## Task 2: Re-validate redirect target in `run_http_test` (S4 — SSRF defense-in-depth)

**Files:** Modify `d2-agent/app.py` (`run_http_test`, ~lines 1814-1849);
Modify `d2-agent/tests/test_security.py`.

**Rationale:** `-L` follows redirects, but `--resolve` pins only the *original* host. A
3xx to a different host (cloud metadata, loopback, link-local) is re-resolved by curl
with no SSRF check. Real-world impact on a LAN Pi is low (no cloud metadata; loopback
agent API is auth-gated) but the code comments claim rebinding protection it doesn't
provide across redirects, and `http`/`zoom_test` steps hit controller-supplied URLs.

- [ ] **Step 1: Write failing tests** — append to `tests/test_security.py`:

```python
class TestHttpRedirectSsrf:
    def _curl_output(self, url_final):
        return ("dns_s=0.01\nconnect_s=0.02\ntls_s=0.0\nttfb_s=0.05\n"
                "total_s=0.06\nhttp_code=200\nredirect_count=1\n"
                f"size_bytes=10\nurl_final={url_final}\n")

    def test_redirect_to_metadata_is_rejected(self, monkeypatch):
        monkeypatch.setattr(app.socket, "getaddrinfo",
                            lambda *_a, **_k: [(0, 0, 0, "", ("203.0.113.5", 0))])
        monkeypatch.setattr(app, "run_cmd",
                            lambda cmd, timeout=60: (True, self._curl_output(
                                "http://169.254.169.254/latest/meta-data/")))
        r = app.run_http_test("http://safe.example.com")
        assert r["success"] is False
        assert "blocked" in r["error"].lower()

    def test_same_host_redirect_is_allowed(self, monkeypatch):
        monkeypatch.setattr(app.socket, "getaddrinfo",
                            lambda *_a, **_k: [(0, 0, 0, "", ("203.0.113.5", 0))])
        monkeypatch.setattr(app, "run_cmd",
                            lambda cmd, timeout=60: (True, self._curl_output(
                                "https://safe.example.com/landing")))
        r = app.run_http_test("https://safe.example.com")
        assert r["success"] is True
```

- [ ] **Step 2: Run — expect the metadata test to FAIL**

Run: `AGENT_TOKEN=t .venv/bin/python -m pytest tests/test_security.py::TestHttpRedirectSsrf -v`
Expected: `test_redirect_to_metadata_is_rejected` FAILS (currently returns success).

- [ ] **Step 3: Implement.** In `run_http_test`, (a) bound redirects, (b) re-validate the
      final host. Change the follow-redirects line from:

```python
    if follow_redirects and not _looks_like_ip_literal(host):
        cmd.append("-L")
```

to:

```python
    if follow_redirects and not _looks_like_ip_literal(host):
        cmd += ["-L", "--max-redirs", "5"]
```

Then, inside the `if ok:` block, **after** `result["url_final"] = parsed.get("url_final", url)`
and before `result["success"] = result["http_code"] > 0`, insert:

```python
        # Defense-in-depth: -L can follow a redirect to a host we never pinned
        # (--resolve covers only the original host), so a 3xx to a blocked IP
        # would be fetched unchecked. Re-validate the effective final host and
        # fail closed if it landed on a blocked address.
        final_url = result["url_final"] or url
        try:
            final_host = urlparse(final_url).hostname or ""
        except Exception:
            final_host = ""
        if final_host and final_host.lower() != (host or "").lower():
            final_blocked, _ = _resolve_and_check(final_host)
            if final_blocked:
                return {"url": url, "success": False, "url_final": final_url,
                        "error": "Redirect landed on a blocked host "
                                 "(metadata / loopback / link-local / unresolvable)"}
```

- [ ] **Step 4: Run — expect PASS**

Run: `AGENT_TOKEN=t .venv/bin/python -m pytest tests/test_security.py -v`
Expected: PASS (both new tests + all existing).

- [ ] **Step 5: Commit**

```bash
git add d2-agent/app.py d2-agent/tests/test_security.py
git commit -m "fix(agent): re-validate redirect target in run_http_test (SSRF defense-in-depth)"
```

**Risk:** Low. Could reject a legitimate cross-host redirect that resolves to RFC1918
(allowed) — but `_resolve_and_check` permits RFC1918, so only metadata/loopback/link-local
final hosts are rejected. **Rollback:** revert commit. **Acceptance:** metadata-redirect
rejected; same-host and public-host redirects still succeed.

---

## Task 3: Clamp WebSocket command params inside `run_*` (S5)

**Files:** Modify `d2-agent/app.py` (`run_ping`, `run_iperf`, `run_traceroute`);
Modify `d2-agent/tests/test_security.py`.

**Rationale:** REST endpoints clamp via `Query(ge=,le=)`, but `handle_command`'s WS path
passes `count/size/interval/duration/streams` through raw `int()/float()`. A buggy or
compromised controller could request `ping count=10_000_000`. Clamp at the **function**
level (single source of truth) so both REST and WS are bounded — matching the pattern
`run_mtu_test`/`run_port_check` already use.

- [ ] **Step 1: Write failing tests** — append to `tests/test_security.py`:

```python
class TestParamClamping:
    def test_run_ping_clamps_count_and_interval(self, monkeypatch):
        seen = {}
        def fake(cmd, timeout=60):
            seen["cmd"] = cmd
            return True, "1 packets transmitted, 1 received, 0% packet loss"
        monkeypatch.setattr(app, "run_cmd", fake)
        app.run_ping("8.8.8.8", count=10_000_000, interval=0.0001)
        assert "100" in seen["cmd"]   # count clamped to 100
        assert "0.2" in seen["cmd"]   # interval floored to 0.2

    def test_run_iperf_clamps_duration_and_streams(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(app, "run_cmd",
                            lambda cmd, timeout=60: seen.update(cmd=cmd) or (True, "{}"))
        app.run_iperf("10.0.0.1", duration=99999, streams=999)
        assert "60" in seen["cmd"]    # -t clamped to 60
        assert "32" in seen["cmd"]    # -P clamped to 32

    def test_run_traceroute_clamps_count(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(app, "run_cmd",
                            lambda cmd, timeout=60: seen.update(cmd=cmd) or (True, ""))
        app.run_traceroute("8.8.8.8", use_mtr=True, count=99999)
        assert "100" in seen["cmd"]
```

- [ ] **Step 2: Run — expect FAIL** (`AGENT_TOKEN=t .venv/bin/python -m pytest tests/test_security.py::TestParamClamping -v`).

- [ ] **Step 3: Implement.** Add a clamp at the top of each function:

In `run_ping`, immediately after the `def run_ping(...):` line:

```python
    count = max(1, min(int(count), 100))
    size = max(0, min(int(size), 65500))
    interval = max(0.2, min(float(interval), 10.0))
```

In `run_iperf`, immediately after the `def run_iperf(...):` line:

```python
    duration = max(1, min(int(duration), 60))
    streams = max(1, min(int(streams), 32))
    omit = max(0, min(int(omit), 60))
```

In `run_traceroute`, immediately after the `def run_traceroute(...):` line:

```python
    count = max(1, min(int(count), 100))
```

- [ ] **Step 4: Run full suite — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git add d2-agent/app.py d2-agent/tests/test_security.py
git commit -m "fix(agent): clamp ping/iperf/traceroute params server-side (WS path)"
```

**Risk:** Low — clamps are wider than existing REST limits, so legitimate calls are
unaffected. **Rollback:** revert commit. **Acceptance:** oversized params are capped in
the built command; normal params unchanged.

---

## Task 4: Reset `_cycle_in_flight` if task scheduling fails (R3)

**Files:** Modify `d2-agent/app.py` (`handle_command`, `run_cycle`/`run_triage` branches,
~lines 2432-2451); Modify `d2-agent/tests/test_security.py`.

**Rationale:** `_cycle_in_flight` is set `True` before `asyncio.create_task` and reset
only in the task's `finally`. If `create_task` raises (or the task never runs), the flag
stays `True` and blocks **all** future cycles/triage until the agent restarts.

- [ ] **Step 1: Write failing test** — append to `tests/test_security.py`:

```python
import asyncio as _asyncio

class TestCycleInFlightGuard:
    def test_flag_resets_if_scheduling_fails(self, monkeypatch):
        app._cycle_in_flight = False

        class FakeWS:
            async def send(self, _):  # noqa: D401
                pass

        def boom(coro):
            coro.close()  # avoid "never awaited" warning
            raise RuntimeError("scheduler down")
        monkeypatch.setattr(app.asyncio, "create_task", boom)

        raw = app.json.dumps({"command": "run_cycle", "job_id": "j1", "params": {}})
        _asyncio.run(app.handle_command(FakeWS(), raw))
        assert app._cycle_in_flight is False
```

- [ ] **Step 2: Run — expect FAIL** (flag stays True).

- [ ] **Step 3: Implement.** In `handle_command`, change the `run_cycle` branch from:

```python
                _cycle_in_flight = True
                asyncio.create_task(_run_cycle_and_send(ws, params))
                return  # cycle_result follows asynchronously from the task.
```

to:

```python
                _cycle_in_flight = True
                try:
                    asyncio.create_task(_run_cycle_and_send(ws, params))
                except Exception:
                    _cycle_in_flight = False
                    raise
                return  # cycle_result follows asynchronously from the task.
```

Apply the **same** try/except wrapping to the `run_triage` branch
(`asyncio.create_task(_run_triage_and_send(ws, params))`).

- [ ] **Step 4: Run full suite — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git add d2-agent/app.py d2-agent/tests/test_security.py
git commit -m "fix(agent): reset _cycle_in_flight when task scheduling fails"
```

**Risk:** Low. **Rollback:** revert commit. **Acceptance:** simulated scheduling failure
leaves the flag clear; normal cycles still set/clear it via the task `finally`.

---

## Task 5: Redact Wi-Fi password from `association_test` error output (S6)

**Files:** Modify `d2-agent/app.py` (`run_association_test`, ~lines 664-694);
Modify `d2-agent/tests/test_security.py`.

**Rationale:** The PSK is passed on the `nmcli` argv (visible in `ps`/`/proc/<pid>/cmdline`)
and nmcli failure text (`raw[:500]`) is returned to the controller, potentially echoing
the secret. Only reachable in `active`/`lab` mode. This task removes the **return-path**
leak; the residual argv exposure to local processes is documented below as a follow-up.

- [ ] **Step 1: Write failing test** — append to `tests/test_security.py`:

```python
class TestAssociationPasswordRedaction:
    def test_password_not_in_error(self, monkeypatch):
        monkeypatch.setattr(app.shutil, "which", lambda _x: "/usr/bin/nmcli")
        monkeypatch.setattr(app, "run_cmd",
                            lambda cmd, timeout=60: (False,
                                "Error: activation failed: secret 'hunter2-secret'"))
        monkeypatch.setattr(app, "run_ssid_check",
                            lambda *a, **k: {"bssids": [], "strongest_rssi": None,
                                             "interface": "wlan0", "tool": "nmcli"})
        r = app.run_association_test("MyNet", "wlan0", 10, "hunter2-secret")
        assert "hunter2-secret" not in (r.get("error") or "")
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement.** In `run_association_test`, after the line
      `ok, raw = run_cmd(cmd, timeout=timeout + 5)`, insert:

```python
    if password and not ok and isinstance(raw, str):
        raw = raw.replace(password, "***REDACTED***")
```

(The existing `"error": None if ok else raw[:500]` then uses the scrubbed `raw`.)

- [ ] **Step 4: Run full suite — expect PASS.**

- [ ] **Step 5: Commit**

```bash
git add d2-agent/app.py d2-agent/tests/test_security.py
git commit -m "fix(agent): redact Wi-Fi PSK from association_test error output"
```

**Risk:** Very low. **Rollback:** revert commit. **Residual / follow-up (track as issue):**
the PSK is still on the `nmcli` argv (visible to local processes during the call). Full
fix = create an nmcli connection profile with `802-11-wireless-security.psk` set via a
`nmcli --ask`/stdin flow, or a secret-agent, instead of inline `password <pw>`. Defer
unless `active`/`lab` Pis are multi-tenant.
**Acceptance:** PSK never appears in the returned `error` string.

---

## Task 6: Pin mutable container images by digest (C3)

**Files:** Modify `docker-compose.yml` (zabbix-agent2, netflow-proxy);
Modify `d2-agent/Dockerfile` (base image).

**Rationale:** Most compose images are digest-pinned (good); these three use mutable tags
(`ubuntu-7.4-latest`, `1.27-alpine`, `python:3.12-slim`), defeating reproducibility and
supply-chain integrity. Digests below are the **currently-deployed** values on
d2001-nw-pi01 (2026-06-03) — confirm they match a known-good image before merging.

- [ ] **Step 1: zabbix-agent2** — in `docker-compose.yml` change:

```yaml
    image: zabbix/zabbix-agent2:ubuntu-7.4-latest
```
to:
```yaml
    image: zabbix/zabbix-agent2:ubuntu-7.4-latest@sha256:c3946e0a524fb1798eed12db92cf2a49ceaaa409971c7d2c92bfd6e48b60100e
```

- [ ] **Step 2: netflow-proxy** — change:

```yaml
    image: nginx:1.27-alpine
```
to:
```yaml
    image: nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10
```

- [ ] **Step 3: Dockerfile base.** Fetch the current arm64 digest, then pin it:

```bash
docker buildx imagetools inspect python:3.12-slim --format '{{.Manifest.Digest}}'
```
In `d2-agent/Dockerfile` change `FROM python:3.12-slim` to
`FROM python:3.12-slim@sha256:<DIGEST-FROM-ABOVE>`.

- [ ] **Step 4: Validate compose parses**

Run: `COMPOSE_PROFILES=enabled DOCKER_GID=999 docker compose config >/dev/null && echo OK`
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml d2-agent/Dockerfile
git commit -m "build: pin zabbix-agent2 / nginx / python base by digest"
```

**Risk:** Low — pins to the exact images already running. Future updates become a
deliberate digest bump (the intent). **Rollback:** revert commit. **Acceptance:**
`docker compose config` shows `@sha256:` for all images; a Pi `docker compose up -d`
pulls the same images (no re-pull churn).

---

## Task 7: Widen `.gitignore` for backup files + clean stray secrets-bearing backups (C2)

**Files:** Modify `.gitignore`. Plus a one-time **ops cleanup** on each Pi (not a repo change).

**Rationale:** `.gitignore` has `*.bak`/`*.bak2`, but stray files like
`.env.bak.20260511-pre-netflow`, `app.py.bak-codex-...`, `docker-compose.yml.bak-pre-iw-...`
have suffixes that slip past those globs and show as untracked. On-disk perms were verified
safe (600/640 root|admin, not world-readable) so this is hygiene, not a live leak — but a
plaintext `.env.bak` containing secrets shouldn't linger.

- [ ] **Step 1: Replace** the two lines `*.bak` and `*.bak2` in `.gitignore` with:

```
*.bak*
```

- [ ] **Step 2: Confirm nothing currently tracked matches** (must print nothing):

Run: `git ls-files | grep -E '\.bak' || echo "none tracked - good"`
Expected: `none tracked - good`.

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore all .bak* variants"
```

- [ ] **Step 4: Ops cleanup (run on each Pi, NOT a repo change).** Document this in the PR
      description for the operator to run fleet-wide (e.g. via the Ansible account):

```bash
cd /opt/d2-edge
ls -la .env.bak.* *.bak-* d2-agent/*.bak-* freeradius-proxy/certs/*.bak* 2>/dev/null
# After confirming they are stale backups:
sudo rm -f .env.bak.* docker-compose.yml.bak-* docker-compose.yml.bak.* \
           d2-agent/app.py.bak-* d2-agent/Dockerfile.bak-* \
           freeradius-proxy/certs/*.bak*
```

**Risk:** Low (only untracked backups removed; verify list before `rm`). **Rollback:**
backups are disposable by definition. **Acceptance:** `git status` clean of `.bak*`;
no `.env.bak*` left on the Pi.

---

## Task 8: Fix `deploy-all.sh` mojibake in banner text (C4)

**Files:** Modify `shared/scripts/deploy-all.sh`.

**Rationale:** Several `echo` lines contain an invalid (non-UTF-8) em-dash byte rendering
as `�` (e.g. `" D2 Edge Appliance � Deploy"`, `"OK � offset:"`). Cosmetic (banner output
only) but signals a broken-encoding edit; replace with ASCII `-`.

- [ ] **Step 1: Replace** the affected lines (currently ~16, 41, 43, 57) so the non-ASCII
      separator becomes a plain ` - `:

```bash
echo " D2 Edge Appliance - Deploy"
```
```bash
    echo "  OK - offset: ${OFFSET}s"
```
```bash
    echo "  WARNING: chrony not running - time may be unreliable"
```
```bash
        echo "  OK - Tailscale IP: $TSIP"
```

- [ ] **Step 2: Verify the file is now clean UTF-8 / ASCII**

Run: `grep -nP '[^\x00-\x7F]' shared/scripts/deploy-all.sh || echo "ASCII clean"`
Expected: `ASCII clean` (or only intentional box chars if any remain).
Run: `bash -n shared/scripts/deploy-all.sh && shellcheck shared/scripts/deploy-all.sh`

- [ ] **Step 3: Commit**

```bash
git add shared/scripts/deploy-all.sh
git commit -m "chore: fix non-UTF-8 banner characters in deploy-all.sh"
```

**Risk:** None (output text). **Rollback:** revert. **Acceptance:** no `�` in deploy output.

---

## Task 9: De-duplicate `FakeSock` dunder methods in tests (C5)

**Files:** Modify `d2-agent/tests/test_security.py` (`TestTcpTimeSsrf.test_pins_to_resolved_ip_on_success`).

**Rationale:** `FakeSock` defines `__enter__`/`__exit__` twice. Harmless but sloppy.

- [ ] **Step 1: Remove the duplicate pair** so the class has exactly one
      `__enter__`/`__exit__`:

```python
        class FakeSock:
            def settimeout(self, _): pass
            def connect_ex(self, addr):
                seen["addr"] = addr
                return 0
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *a): self.close()
```

- [ ] **Step 2: Run that test — expect PASS**

Run: `AGENT_TOKEN=t .venv/bin/python -m pytest tests/test_security.py::TestTcpTimeSsrf -v`

- [ ] **Step 3: Commit**

```bash
git add d2-agent/tests/test_security.py
git commit -m "test: drop duplicate FakeSock dunder methods"
```

**Risk:** None. **Rollback:** revert. **Acceptance:** test still passes.

---

## Task 10: NetFlow firewall ports + LAN-scoped rules from `.env` (R1 + C6)

**Files:** Create `scripts/heal-firewall.sh`; Modify `shared/scripts/update.sh`
(invoke the heal); Modify `shared/scripts/bootstrap.sh` (add 6343/4739; stop hardcoding
the LAN subnet for cert-server/RadSec).

**Rationale (R1 — verified live):** `netflow-proxy/nginx.conf.template` listens on UDP
2055 (NetFlow), 6343 (sFlow), 4739 (IPFIX) — all confirmed bound via `ss`. But `bootstrap.sh`
ufw opens only 2055 (plus 9995/9996 which nothing listens on). So inbound **sFlow/6343 and
IPFIX/4739 are silently dropped**. **(C6):** the cert-server (80) and RadSec (2083) ufw
rules hardcode `192.168.0.0/16`, but `LOCAL_CLIENT_SUBNET` examples use `10.0.0.0/8` — on a
10.x site, onboarding and RadSec are firewalled. Because `.env` isn't populated at bootstrap
time, the LAN-scoped rules belong in a heal that runs after `preflight` validates `.env`
(matching the existing auvik-watchdog / oxidized / svc-ansible heal pattern).

- [ ] **Step 1: Create `scripts/heal-firewall.sh`**

```bash
#!/usr/bin/env bash
# Idempotent ufw heal. Two jobs:
#  1. (R1) Open the sFlow/IPFIX ports the netflow-proxy actually listens on
#     (nginx.conf.template: 2055/6343/4739). bootstrap.sh's original block
#     predated the sFlow/IPFIX listeners and only opened 2055, so 6343/4739
#     inbound were dropped on already-bootstrapped Pis. Gated on the netflow
#     profile so non-relay Pis don't open unused ports.
#  2. (C6) Scope cert-server (80) + RadSec (2083) to the customer LAN(s) from
#     LOCAL_CLIENT_SUBNET instead of a hardcoded 192.168.0.0/16, so 10.x sites
#     work. `ufw allow` is a no-op when the rule already exists.
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="${ENV_FILE:-$EDGE_DIR/.env}"

if [[ $EUID -ne 0 ]]; then echo "[heal-fw] must run as root" >&2; exit 1; fi
command -v ufw >/dev/null 2>&1 || { echo "[heal-fw] ufw not installed; skip"; exit 0; }
ufw status 2>/dev/null | grep -q "Status: active" || { echo "[heal-fw] ufw inactive; skip"; exit 0; }

# shellcheck disable=SC1090
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE" 2>/dev/null || true; set +a; }

add_rule() {  # add_rule <ufw-args...> <grep-key>
    local key="${!#}"; set -- "${@:1:$#-1}"
    if ! ufw status | grep -qF "$key"; then
        ufw allow "$@" >/dev/null && echo "[heal-fw] added: ufw allow $* ($key)"
    fi
}

# 1. NetFlow relay ports (only on flow-exporter Pis)
if [[ "${DEPLOY_NETFLOW_PROXY:-enabled}" == "enabled" ]]; then
    if ! ufw status | grep -q '^6343/udp'; then
        ufw allow 6343/udp comment 'sFlow relay' >/dev/null; echo "[heal-fw] opened 6343/udp"; fi
    if ! ufw status | grep -q '^4739/udp'; then
        ufw allow 4739/udp comment 'IPFIX relay' >/dev/null; echo "[heal-fw] opened 4739/udp"; fi
fi

# 2. LAN-scoped onboarding + RadSec from each configured customer subnet
SUBNETS="${LOCAL_CLIENT_SUBNET//,/ }"
for subnet in $SUBNETS; do
    [[ "$subnet" == "REPLACE_ME" || -z "$subnet" ]] && continue
    if ! ufw status | grep -qF "$subnet 80/tcp"; then
        ufw allow from "$subnet" to any port 80 proto tcp comment 'cert-server onboarding' >/dev/null
        echo "[heal-fw] cert-server allowed from $subnet"; fi
    if ! ufw status | grep -qF "$subnet 2083/tcp"; then
        ufw allow from "$subnet" to any port 2083 proto tcp comment 'RadSec' >/dev/null
        echo "[heal-fw] RadSec allowed from $subnet"; fi
done

echo "[heal-fw] OK"
```

> Note: `ufw status` rule-text matching is approximate; the `grep -qF "$subnet 80/tcp"`
> guard mirrors how ufw renders `from <subnet> ... 80/tcp`. Re-running is safe even if a
> guard mis-matches (ufw dedupes identical rules). Reviewer: confirm the grep keys against
> `ufw status` output format on the target Debian/ufw version.

- [ ] **Step 2: Make it executable and wire into `update.sh`.** After the svc-ansible /
      weekly-upgrade heal blocks in `shared/scripts/update.sh` (step `[3/6]`), add:

```bash
# Firewall heal: open netflow-proxy's sFlow/IPFIX ports and LAN-scope
# cert-server/RadSec from LOCAL_CLIENT_SUBNET. Idempotent. (R1 + C6)
if [[ -x "$EDGE_DIR/scripts/heal-firewall.sh" ]]; then
    bash "$EDGE_DIR/scripts/heal-firewall.sh"
fi
```

- [ ] **Step 3: Fresh-install path in `bootstrap.sh`.** In the ufw block, add the relay
      ports next to the existing `ufw allow 2055 ...`:

```bash
ufw allow 6343/udp comment 'Auvik sFlow relay' >/dev/null
ufw allow 4739/udp comment 'Auvik IPFIX relay' >/dev/null
```

And **replace** the two hardcoded LAN lines:

```bash
ufw allow from 192.168.0.0/16 to any port 80 proto tcp comment 'cert-server (LAN onboarding)' >/dev/null
ufw allow from 192.168.0.0/16 to any port 2083 proto tcp comment 'RadSec from customer devices' >/dev/null
```

with a forward-reference comment (the LAN subnet isn't known until `.env` is filled in):

```bash
# cert-server (80) + RadSec (2083) are LAN-scoped to LOCAL_CLIENT_SUBNET by
# scripts/heal-firewall.sh after .env is configured (see deploy-all.sh / update.sh).
```

- [ ] **Step 4: Mark the new script executable + add it to deploy-all.sh too** (first
      deploy, before any update). In `shared/scripts/deploy-all.sh`, after `render-configs.sh`:

```bash
if [[ -x "$EDGE_DIR/scripts/heal-firewall.sh" ]]; then
    bash "$EDGE_DIR/scripts/heal-firewall.sh"
fi
```

- [ ] **Step 5: Validate**

Run: `chmod +x scripts/heal-firewall.sh && bash -n scripts/heal-firewall.sh && shellcheck scripts/heal-firewall.sh`
Run on a **staging Pi**: `sudo bash scripts/heal-firewall.sh && sudo ufw status | grep -E '6343|4739|2083|80/'`
Expected: 6343/udp + 4739/udp present; 80/2083 scoped to the configured subnet.
Then confirm flow data lands centrally (Graylog/Zabbix flow dashboards) after applying.

- [ ] **Step 6: Commit**

```bash
git add scripts/heal-firewall.sh shared/scripts/update.sh shared/scripts/deploy-all.sh shared/scripts/bootstrap.sh
git commit -m "fix(firewall): open sFlow/IPFIX relay ports + scope LAN rules to LOCAL_CLIENT_SUBNET"
```

**Risk:** Medium-low. Opening 6343/4739 is the intended behavior; LAN-scoping change could,
on a misconfigured `.env`, fail to open 80/2083 (onboarding) — but preflight requires
`LOCAL_CLIENT_SUBNET` non-empty, so it will be set. Existing 192.168.0.0/16 rules on
already-bootstrapped Pis remain until manually removed (harmless superset).
**Rollback:** `sudo ufw delete allow 6343/udp` etc.; revert commit.
**Acceptance:** sFlow/IPFIX no longer dropped (verified by central flow ingest); 10.x-site
onboarding/RadSec reachable from the customer LAN.

---

# PHASE 2 — Higher-touch hardening (stage before fleet rollout)

## Task 11: SSH hardening — disable password auth + restrict root login (S7)

**Files:** Modify `shared/scripts/bootstrap.sh` (the `sshd_config.d/hardening.conf`
heredoc). Plus a **manual, per-Pi** rollout procedure (NOT an auto-heal).

**Rationale:** Current hardening only sets `X11Forwarding no` + `MaxAuthTries 3`. A
key-authenticated fleet should disable password auth and restrict root login. fail2ban
already mitigates brute force; this removes the attack surface entirely.

**⚠️ Safety:** Flipping `PasswordAuthentication no` fleet-wide can lock you out if any Pi
lacks a working key. This task changes **bootstrap (new installs) only**; existing Pis get
a **manual, verified** rollout. Do **not** add this to an auto-heal.

- [ ] **Step 1:** In `bootstrap.sh`, change the hardening heredoc from:

```bash
cat > /etc/ssh/sshd_config.d/hardening.conf << 'SSHCONF'
X11Forwarding no
MaxAuthTries 3
SSHCONF
```

to:

```bash
cat > /etc/ssh/sshd_config.d/hardening.conf << 'SSHCONF'
X11Forwarding no
MaxAuthTries 3
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
SSHCONF
sshd -t   # validate config before reload; aborts (set -e) on syntax error
```

- [ ] **Step 2:** Update the echo line to reflect the new policy:

```bash
echo "  SSH: X11 off, MaxAuthTries=3, password auth disabled, root key-only"
```

- [ ] **Step 3: Validate** `bash -n shared/scripts/bootstrap.sh && shellcheck shared/scripts/bootstrap.sh`.

- [ ] **Step 4: Commit**

```bash
git add shared/scripts/bootstrap.sh
git commit -m "harden(ssh): disable password auth + restrict root login on new installs"
```

- [ ] **Step 5: Document the manual existing-Pi rollout** in the PR body (operator runs
      per Pi, after confirming key login works):

```bash
# 1. Confirm key-only login works from a SECOND terminal BEFORE closing the first.
sudo install -m 644 /dev/stdin /etc/ssh/sshd_config.d/hardening.conf <<'EOF'
X11Forwarding no
MaxAuthTries 3
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
sudo sshd -t && sudo systemctl reload ssh
sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin|kbdinteractive'
# Rollback if locked-risk: delete the file + reload (keep first session open!).
```

**Risk:** **Medium (lockout)** for existing Pis — hence manual + two-session verification.
New installs: low (operator is on console). **Rollback:** remove hardening.conf, reload.
**Acceptance:** `sshd -T` shows `passwordauthentication no` / `permitrootlogin prohibit-password`;
key login still works.

---

## Task 12: Run the d2-agent container as non-root with file caps (S8)

**Files:** Modify `d2-agent/Dockerfile`. (Compose already grants `cap_add: NET_ADMIN`;
default caps include `NET_RAW`.) **Requires staging validation** (integration, not unit).

**Rationale:** The agent runs as `uid=0` (verified). `dhcp_test` (AF_PACKET) needs
`CAP_NET_RAW` and `iw scan` needs `CAP_NET_ADMIN`, but those can be granted to a non-root
user via **file capabilities** on the interpreter, so a container escape doesn't land as
host-uid-0-equivalent.

- [ ] **Step 1:** In `d2-agent/Dockerfile`, before the `CMD`, add libcap, a non-root user,
      and file caps on the interpreter; then switch user:

```dockerfile
# Run as non-root. dhcp_test (AF_PACKET) needs CAP_NET_RAW; iw scan needs
# CAP_NET_ADMIN. Grant them as file caps on the interpreter so a non-root
# UID gets them in its permitted+effective+inheritable set (ambient via +eip),
# instead of running the whole process as root.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap 'cap_net_raw,cap_net_admin,cap_net_bind_service=+eip' "$(readlink -f "$(command -v python3)")" \
    && useradd -r -u 10001 -s /usr/sbin/nologin d2agent \
    && mkdir -p /app/buffer && chown -R d2agent:d2agent /app
USER d2agent
```

> Reviewer notes: (a) file caps must survive the final image layer — verify with
> `getcap`. (b) the compose bind-mount `./d2-agent/buffer:/app/buffer` must be writable by
> uid 10001 — see Step 3. (c) if `setcap` on the symlinked python doesn't take effect at
> runtime, fall back to `cap_add: [NET_RAW, NET_ADMIN]` in compose **and** keep the file
> caps (Docker won't grant caps to non-root without ambient/file caps).

- [ ] **Step 2: Build**

Run: `docker compose build d2-agent --pull`
Run: `docker run --rm --cap-add NET_ADMIN --entrypoint sh d2-agent -c 'id && getcap "$(readlink -f "$(command -v python3)")"'`
Expected: non-root `uid=10001`, and `cap_net_admin,cap_net_bind_service,cap_net_raw=eip`.

- [ ] **Step 3: Fix buffer mount ownership** (host side). The bind-mounted
      `d2-agent/buffer` must be writable by uid 10001. Add to `shared/scripts/update.sh`
      and `deploy-all.sh` near the other chown heals:

```bash
# d2-agent now runs as non-root uid 10001; its buffer dir must be writable.
[[ -d "$EDGE_DIR/d2-agent/buffer" ]] && chown -R 10001:10001 "$EDGE_DIR/d2-agent/buffer" 2>/dev/null || true
```

- [ ] **Step 4: Staging integration test — on a non-production Pi:**

```bash
docker compose up -d --force-recreate d2-agent
docker exec d2-agent id            # expect uid=10001
# Drive a dhcp_test + ap_scan via the controller (or local curl with AGENT_TOKEN)
# and confirm both still succeed (AF_PACKET + nl80211 require the caps).
docker logs d2-agent --since 2m | grep -iE 'permission|EPERM|operation not permitted' && echo "CAP PROBLEM" || echo "caps OK"
curl -fs http://127.0.0.1:8080/health   # healthcheck still green
```

- [ ] **Step 5: Commit (only after staging passes)**

```bash
git add d2-agent/Dockerfile shared/scripts/update.sh shared/scripts/deploy-all.sh
git commit -m "harden(agent): run container as non-root uid 10001 with file caps"
```

**Risk:** **Medium** — could break `dhcp_test`/`ap_scan` if caps don't propagate; buffer
writes fail if ownership not fixed. Hence staging gate. **Rollback:** revert Dockerfile
(`USER root` default) + rebuild. **Acceptance:** agent runs as uid 10001; dhcp_test +
ap_scan succeed; buffer writes work; healthcheck green.

---

# PHASE 3 — Cross-repo / policy design proposals (need decisions before task-level plans)

> These are **design proposals**, not bite-sized tasks, because they need the controller
> codebase (not in scope for this review) and/or product/ops decisions. Each lists the
> decision, the proposed approach, and acceptance criteria. Promote to a full task-level
> plan once the decision is made.

## Proposal A: Per-agent authentication / mTLS (S1)

**Problem:** One fleet-wide `AGENT_TOKEN`; agents self-assert `agent_id`/`tenant_id` with
no per-agent credential, and the token never rotates. Compromise of any Pi's `.env` →
impersonate any agent/tenant, inject false monitoring data, or register rogue agents.

**Decision needed (pick one):**
1. **mTLS client certs (recommended).** You already run an internal CA (`cert-server`,
   `d2-internal-root.crt`) and RadSec mTLS — reuse it. Issue a per-Pi client cert at
   bootstrap; the controller terminates the WSS with `verify_mode=CERT_REQUIRED` and
   derives the agent identity from the cert CN/SAN, ignoring the self-reported `agent_id`.
2. **Per-agent bearer tokens.** Mint a unique token per Pi (store server-side, hashed);
   `update.sh`/onboarding fetches it; controller maps token→agent_id and rejects mismatched
   self-reported ids. Simpler, but no transport-level identity and still a shared-secret
   class.

**Agent-side changes (either option):** `controller_ws_loop` already sends
`Authorization: Bearer`; for mTLS, pass an `ssl.SSLContext` with the client cert to
`websockets.connect`. Bind nothing to the self-reported `agent_id` for trust.
**Controller-side changes (separate repo/plan):** enforce identity from the
connection, not the payload; add a registration allow-list; support rotation.
**Migration:** dual-accept (old token AND new credential) during rollout; cut over per
tenant; then disable the shared token.
**Acceptance:** a Pi presenting tenant A's credential cannot post results as tenant B;
revoking one Pi's credential doesn't affect others; rotation is possible without a fleet
`.env` edit.

## Proposal B: Signed/pinned release pipeline instead of `git pull main` (S2)

**Problem:** `update.sh` does `git pull` of the default branch then runs repo-shipped
scripts as root, fleet-wide, unattended (weekly timer + Ansible self-arm). No signing,
no pinned release, no review gate ⇒ a GitHub compromise is fleet root RCE.

**Proposed approach (concrete, mostly in-repo):**
1. **GitHub:** protect `main` (required PR review + green CI from Task 0; require signed
   commits; enforce 2FA/passkeys on the org/account).
2. **Release tags:** cut signed annotated tags (`git tag -s vYYYY.MM.DD ...`).
3. **`update.sh` verifies + pins.** Replace `sudo -u admin git pull` with a fetch +
   verify + checkout of the latest **signed** tag:

   ```bash
   sudo -u admin git -C "$EDGE_DIR" fetch --tags --force origin
   latest_tag=$(sudo -u admin git -C "$EDGE_DIR" tag -l 'v*' --sort=-version:refname | head -1)
   if ! sudo -u admin git -C "$EDGE_DIR" verify-tag "$latest_tag"; then
       echo "ERROR: tag $latest_tag failed signature verification — refusing to deploy" >&2
       exit 1
   fi
   sudo -u admin git -C "$EDGE_DIR" checkout --quiet "$latest_tag"
   ```

   Requires the signer's public key in the `admin` user's GPG keyring (provision at
   bootstrap). Keep a `lab`/`canary` override env to track `main` on test Pis.
**Decision needed:** who holds the signing key + where (hardware token recommended); tag
cadence; canary cohort.
**Acceptance:** a tampered/unsigned tag is refused by `update.sh`; production Pis only ever
run signed, reviewed tags; `main` can't be pushed without review + CI.

**Related (S3 — quick win that can ship now, in this repo):** `svc_ansible` is in the
`docker` group "for read-only `docker ps`", but docker-group = full root (mount host `/`
in a container), defeating its `from=`-locked key + single-command sudoers. **Recommend a
standalone PR:** in `scripts/setup-svc-ansible.sh`, remove the `usermod -aG docker`
(lines ~27-30) and instead grant a narrow sudoers entry for status only:
`svc_ansible ALL=(root) NOPASSWD: /usr/bin/docker ps, /usr/bin/docker inspect *`
(validate with `visudo -cf`). Acceptance: `id svc_ansible` shows no `docker` group; Ansible
status checks still work via sudo.

## Proposal C: Decouple `run_cycle` IP layer from the RF chain (R2)

**Problem:** Core cycle is a linear chain
`ap_scan(10)→ssid(20)→association(30)→dhcp(40)→gateway(50)→dns(60/70)/internet(80)`.
`no_rf_capability`/`no_expected_ssid` skips propagate, so on a wired / no-SSID sensor the
**entire IP/connectivity/DNS/internet chain is skipped** (all-skipped cycle), even though
`dhcp_test` defaults to the **wired** interface.

**Decision needed:** are cycles ever dispatched to wired / non-Wi-Fi sensors? (Confirm with
the controller's dispatch logic.) If yes, this is a real gap; if cycles only ever target
active/lab Wi-Fi sensors, it's lower priority.

**Proposed change (small, testable — promote to a task if confirmed):** in
`CORE_CYCLE_STEPS`, decouple the IP layer from the RF/association layer by changing
`dhcp_test`'s dependency from `[30]` to `[]` (and document that the RF chain `10→20→30`
remains independent). Then a wired Pi runs dhcp/gateway/dns/internet regardless of RF.
Add tests asserting that with `caps.rf_scan == False` (no wifi), steps 40-80 still execute
(not `skipped`). **Acceptance:** wired-sensor cycle exercises the IP/connectivity layers;
Wi-Fi-sensor behavior unchanged for the RF chain.

## Proposal D: Stage the weekly third-party `full-upgrade` (R4)

**Problem:** `weekly-full-upgrade.service` runs unattended `apt full-upgrade` across all
repos including Docker & Tailscale, fleet-wide, Saturday 01:00 — a bad upstream release
ships everywhere at once (the exact lockout risk `update.sh`'s own comments worry about).

**Decision needed:** acceptable patch latency vs. blast radius.
**Options:**
1. **Canary cohort:** a `WEEKLY_UPGRADE_COHORT` env (`canary`/`fleet`); canary Pis run the
   timer Saturday, fleet runs Sunday only if canary stayed healthy (gated by a controller
   check). Most robust.
2. **Hold the risky packages:** keep the weekly timer for OS packages but exclude
   Docker/Tailscale — e.g. `apt-mark hold docker-ce docker-ce-cli tailscale` (bump them
   deliberately via a reviewed change). Simplest; recommended interim.
**Acceptance:** a regression in docker/tailscale cannot reach the whole fleet in one
unattended window.

---

## Suggested PR / merge order

1. Task 0 (CI) — gates everything after.
2. Phase 1 quick wins, each its own PR: Tasks 1, 5, 8, 9, 7 (trivial) → 2, 3, 4 (agent
   logic) → 6 (digests) → 10 (firewall; stage-verify flow ingest).
3. S3 docker-group fix (under Proposal B) — small, ship early.
4. Phase 2: Task 11 (SSH) and Task 12 (non-root container) — **staging-gated**, one Pi
   first, then cohort, then fleet.
5. Phase 3 proposals A/B/C/D — decide, then write follow-up task-level plans (A and B span
   the controller repo).

## Self-review (writing-plans checklist)

- **Spec coverage:** every review finding is mapped — S1→Prop A, S2→Prop B, S3→Prop B
  rider, S4→Task 2, S5→Task 3, S6→Task 5, S7→Task 11, S8→Task 12; R1→Task 10, R2→Prop C,
  R3→Task 4, R4→Prop D; C1→Task 1, C2→Task 7, C3→Task 6, C4→Task 8, C5→Task 9, C6→Task 10.
  Plus Task 0 (CI) as new foundation.
- **Placeholder scan:** no `TODO`/"handle edge cases"; the only deliberately-deferred value
  is the `python:3.12-slim` digest, supplied as an exact fetch command (digests are chosen
  at implementation time by design). Controller-side specifics in Prop A/B are explicitly
  out-of-scope pending that repo.
- **Type/name consistency:** `heal-firewall.sh` referenced consistently across
  update.sh/deploy-all.sh/bootstrap.sh; test class names unique; clamp constants inline.
- **Known constraint:** `AGENT_TOKEN` must be exported for every pytest run (documented in
  Conventions and in each test command).
