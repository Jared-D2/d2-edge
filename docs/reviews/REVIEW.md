# d2-edge code/security/reliability review — d2001-nw-pi01 (192.168.166.34)

Reviewed: 2026-06-03. Source: `/opt/d2-edge` @ HEAD (`git@github.com:Jared-D2/d2-edge.git`),
49 tracked files (~6k LOC). Live verifications run on the Pi (container caps, listeners,
ufw, secret-file perms, git secret history).

## Verdict
High-quality, unusually security-conscious codebase. No critical/exploitable bug found in
the code itself. Findings are mostly hardening / defense-in-depth, a few concrete reliability
bugs, and some cleanup. Git history is clean of secrets (verified); on-disk secret perms are 600/640.

---
## SECURITY (ranked)

S1 (Med-High, design) — Fleet-wide shared AGENT_TOKEN + unauthenticated agent identity.
  .env.template:76-80; app.py:40,350-353,2138-2143. One bearer token for the whole fleet;
  agents self-assert agent_id/tenant_id with no per-agent credential and the token never rotates.
  Compromise of any Pi's .env → impersonate any agent_id/tenant_id, inject false data, register
  rogue agents. Fix: per-agent tokens or mTLS client certs (internal CA + RadSec mTLS plumbing
  already exists); controller should bind WS-authenticated identity to agent_id, not trust the
  self-reported field. Support rotation.

S2 (Med-High, supply chain) — Auto-pull of `main` → unattended root code execution.
  bootstrap.sh:64,155; update.sh:66; weekly timer + svc_ansible self-arm. `git pull` of default
  branch then runs repo scripts as root, fleet-wide, unattended. No signing, no pinned release,
  no review gate. GitHub compromise = fleet root RCE. Fix: branch protection + 2FA, deploy from
  signed tags and verify before running, pin a release ref. (Also unpinned `curl|sh`/`|bash`.)

S3 (Med) — docker group makes "least-privilege" svc_ansible (and admin) root-equivalent.
  setup-svc-ansible.sh:27-30. docker group = full root (mount host / via a container), defeats
  the from=-locked key + single-command sudoers. Fix: drop svc_ansible from docker group; grant
  a specific sudoers line for `docker ps`/`inspect` if status is needed.

S4 (Low-Med) — run_http_test follows redirects (-L) with only the initial host pinned → SSRF
  guard bypass on redirect. app.py:1818-1822. 3xx to another host re-resolves with no check.
  Low real impact on a LAN Pi (no cloud metadata; loopback API is auth-gated) but comments claim
  protection not delivered across redirects. Fix: do not auto-follow with curl -L; follow redirects
  in agent code with a small redirect loop that validates each Location host via _resolve_and_check
  before making the next request.

S5 (Low-Med, robustness) — WebSocket command params not bounded server-side. handle_command
  app.py:2347-2431. REST clamps via Query(ge/le); WS path takes count/size/duration/streams/etc
  raw. Buggy/compromised controller → unbounded ping/iperf. Fix: clamp inside run_* functions
  (mtu/port_check already do).

S6 (Low) — association_test Wi-Fi password on nmcli argv. app.py:677-681. Visible in ps/cmdline;
  may echo in raw[:500] error. active/lab only. Fix: nmcli profile/stdin; scrub error text.

S7 (Low, hardening) — SSH still allows password auth / root login. bootstrap.sh:92-96 only sets
  X11Forwarding/MaxAuthTries. Add PasswordAuthentication no + PermitRootLogin prohibit-password.

S8 (Low, hardening) — d2-agent runs as root (verified uid=0, CapEff has NET_ADMIN+NET_RAW).
  Dockerfile has no USER. dhcp_test needs NET_RAW only — run as non-root UID with file/ambient caps.

Minor: .env.template hardcodes personal email as Auvik username; .env sourced as code by root in
several scripts (treat as code); Graylog/Zabbix transport is plaintext but rides Tailscale (note dep).

---
## RELIABILITY / CORRECTNESS

R1 (Med, VERIFIED) — Firewall ports don't match NetFlow relay listeners. nginx.conf.template:18-20
  listens UDP 2055/6343/4739 (all confirmed bound live); ufw (bootstrap.sh:108-111) opens 2055/9995/
  9996 only. → sFlow/6343 + IPFIX/4739 inbound are DROPPED; 9995/9996 opened for nothing (no listener).
  Fix: open 6343/4739; drop 9995/9996 unless actually used.

R2 (Med, verify vs controller) — run_cycle chain short-circuits whole core cycle on wired/no-SSID
  sensors. app.py:830-839,1064-1095. Linear chain ap_scan→ssid→association→dhcp→gateway→dns/internet;
  no_rf_capability/no_expected_ssid skips propagate, so dhcp(depends [30]) and everything after is
  skipped on a non-Wi-Fi Pi → all-skipped cycle. Fix: make dhcp/gateway/dns/internet not depend on
  RF/association steps.

R3 (Low) — _cycle_in_flight can wedge permanently if create_task fails. app.py:2432-2451. Reset only
  in task finally. Fix: set flag inside task or guard scheduling with try/except reset; consider Lock.

R4 (Low-Med, availability) — Weekly unattended `apt full-upgrade` incl Docker/Tailscale fleet-wide.
  weekly-full-upgrade.service:10. Bad upstream release ships Saturday 01:00 (the lockout risk update.sh
  itself worries about). Fix: canary first, or hold docker/tailscale from unattended full-upgrade.

R5 (Low) — locale-dependent ping/traceroute parsing; all blocking probes share ~8-thread default
  executor (120s speedtest ties up a worker). Minor.

---
## CODE QUALITY / CLEANUP
C1 Dead code: _run_dhcp_test_helper (app.py:1016-1026) never called (verified). Remove.
C2 Stray *.bak*/.env.bak.* clutter in /opt/d2-edge not matched by `*.bak` gitignore (perms safe:
   600/640 root|admin). Delete or widen gitignore to *.bak*.
C3 Inconsistent image pinning: zabbix-agent2 ubuntu-7.4-latest, netflow-proxy nginx:1.27-alpine,
   Dockerfile python:3.12-slim use mutable tags; others digest-pinned. Pin by digest.
C4 deploy-all.sh mojibake in echo banners (non-UTF-8 em-dashes). Cosmetic.
C5 Duplicate __enter__/__exit__ in test FakeSock (test_security.py:304-307). Harmless.
C6 ufw LAN rules hardcode 192.168.0.0/16 (bootstrap.sh:112-113) but .env examples use 10.0.0.0/8;
   on a 10.x site cert-server(80)/RadSec(2083) get firewalled. Derive from LOCAL_CLIENT_SUBNET.

## DONE WELL (don't regress)
SSRF/argv defenses (TARGET_RE, allowlists, _resolve_and_check + --resolve, defusedxml, metadata block);
hmac.compare_digest auth; refuses default token; thread/PID-exhaustion handling (SpawnFailureError, mtr
semaphore); atomic MonitorConfig swap; disk-buffered offline results; exponential backoff; excellent
preflight.sh; idempotent self-healing deploys; least-privilege service accounts (from= keys, single-cmd
sudoers, nologin bastion); RadSec mTLS; RADIUS require_message_authenticator (Blast-RADIUS); cert-server
nginx hardening; clean git history.
