# Private Repo Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Jared-D2/d2-edge` private on GitHub without breaking new-Pi bootstrap, fleet `update.sh` pulls, or the Ansible deploy path.

**Architecture:** One fleet-wide **read-only GitHub deploy key** replaces both anonymous HTTPS access and the over-privileged full-account SSH key currently sitting on the office Pi. A new idempotent heal script (`scripts/setup-git-deploy-key.sh`) installs the key from `GIT_DEPLOY_KEY_B64` in `.env`, pins GitHub's host keys, sets the repo's `core.sshCommand`, and rewrites `origin` to the SSH URL. `update.sh` calls it as a host-heal; `bootstrap.sh` and the onboarding portal's "New Edge Pi" block use the same key pre-clone. The fleet converts **while the repo is still public**; the visibility flip is the last step.

**Tech Stack:** bash (Pi scripts), plain-assert Python tests (repo convention, no pytest), `gh` CLI (GitHub admin), Ansible on `192.168.166.3` (`d2-deploy` wrapper), Flask onboarding portal on NetBox `192.168.166.5` (`/opt/netbox/onboarding/app.py`, not in git).

---

## Facts established 2026-09-14 (do not re-derive)

| Item | Value |
|---|---|
| Public repo | `Jared-D2/d2-edge` (0 forks, 0 stars, no `.github/` workflows, no deploy keys) |
| Already private | `Jared-D2/msp-dashboard-source` (unaffected) |
| `origin/main` HEAD | `2471ace` |
| Office Pi `192.168.166.34` | origin = `git@github.com:Jared-D2/d2-edge.git`, **no** `core.sshCommand`, key `/home/admin/.ssh/id_ed25519` authenticates as user **Jared-D2** (full account key, comment `d2-raspberry-pe`, fingerprint `SHA256:WMXhnyfZoZx7CqpOMnSaW9jUqE+rYJGRk8RinRDErtc`) |
| Home/lab Pi `192.168.21.20` | unreachable today; previously noted as **https** origin |
| 8 customer Pis (nib001 ×7, hom001 ×1) | unknown remote type; **Claude must never SSH to them** |
| Ansible `.3` | `group_vars` already uses the SSH URL; `deploy-edge.yml` wraps `update.sh`; `edge-status.yml` does no fetch |
| Anonymous consumers that break on flip | `README.md:25` curl one-liner, `bootstrap.sh:4-5` raw URL + HTTPS clone, portal "New Edge Pi" bootstrap block |
| `update.sh` self-mod lag | a change to `update.sh` executes on the **second** run after it lands |
| GitHub host keys | fetched via `gh api meta --jq '.ssh_keys[]'` on 2026-09-14, embedded in Task 2 |

**Ownership legend:** 🤖 = implementer (Opus) does it. 🧑 = **Jared must do it** (access Claude does not have, or a decision only Jared can make). Every 🧑 step names the exact command or click.

---

## File Structure

| Path | Responsibility | Action |
|---|---|---|
| `scripts/setup-git-deploy-key.sh` | Idempotent heal: install deploy key, pin host keys, set `core.sshCommand`, rewrite origin, report legacy key | Create |
| `tests/test_setup_git_deploy_key.py` | Sandbox tests for the heal (runs on any Linux box) | Create |
| `shared/scripts/update.sh` | Call the heal in the `[3/6]` host-heal block | Modify (after the `setup-svc-ansible.sh` block, ~line 194) |
| `shared/scripts/bootstrap.sh` | SSH clone as `admin` with the deploy key; fail loud if key absent | Modify lines 4-5 and 190-203 |
| `.env.template` | Document optional `GIT_DEPLOY_KEY_B64` | Modify (append section) |
| `README.md` | Replace curl one-liner with the portal-driven flow | Modify lines 23-26 |
| `/opt/netbox/onboarding/app.py` (on `.5`, NOT git) | Emit `GIT_DEPLOY_KEY_B64` in `.env` and the pre-clone bootstrap block | Modify |
| `/opt/netbox/onboarding/.env` (on `.5`) | Holds `EDGE_GIT_DEPLOY_KEY_B64` fleet secret | Modify |
| `/opt/ansible/playbooks/edge-status.yml` (on `.3`, NOT git) | Report origin URL + deploy-key wiring per Pi | Modify |

---

## Task 0: Working tree

- [ ] **Step 1: Use the prepared worktree** 🤖

The plan author already created it. Confirm:

```bash
cd C:/Users/JaredCooper/Claude/d2-edge-wt-private-repo && git status -sb && git log --oneline -1
```
Expected: `## feat/private-repo-deploy-key` and HEAD `2471ace` (plus this plan file once committed). Do **not** touch `C:/Users/JaredCooper/Claude/d2-edge` (stale branch, dirty).

- [ ] **Step 2: Commit the plan** 🤖

```bash
git add docs/superpowers/plans/2026-09-14-private-repo-migration.md
git commit -m "docs: plan for private repo migration (fleet read-only deploy key)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 1: Generate the fleet deploy key and register it on GitHub

The private key must live where fleet secrets already live: `/opt/netbox/onboarding/.env` on NetBox `.5`. Generate it **there** so it never sits on a laptop.

- [ ] **Step 1: Check reachability of `.5`** 🤖

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes -o ConnectTimeout=8 -o BatchMode=yes jaredc@192.168.166.5 'echo ok'
```
If this times out (it did on 2026-09-14), hand Steps 2-3 to Jared verbatim and wait for the `.pub` line back.

- [ ] **Step 2: Generate the key on `.5`** 🤖 (or 🧑 if unreachable — run exactly this on `.5`)

```bash
sudo install -d -m 700 /opt/netbox/onboarding/keys
sudo ssh-keygen -t ed25519 -N "" -C "d2-edge-fleet-readonly" -f /opt/netbox/onboarding/keys/d2-edge-deploy
sudo chmod 600 /opt/netbox/onboarding/keys/d2-edge-deploy
sudo cat /opt/netbox/onboarding/keys/d2-edge-deploy.pub
```
Expected: one line `ssh-ed25519 AAAA... d2-edge-fleet-readonly`.

- [ ] **Step 3: Append the base64 private key to the portal `.env`** 🤖 (or 🧑)

```bash
sudo cp /opt/netbox/onboarding/.env /opt/netbox/onboarding/.env.pre-2026-09-14-deploy-key
echo "EDGE_GIT_DEPLOY_KEY_B64=$(sudo base64 -w0 /opt/netbox/onboarding/keys/d2-edge-deploy)" | sudo tee -a /opt/netbox/onboarding/.env >/dev/null
sudo grep -c '^EDGE_GIT_DEPLOY_KEY_B64=' /opt/netbox/onboarding/.env
```
Expected: `1`.

- [ ] **Step 4: Register the public key as a READ-ONLY deploy key** 🤖

Save the `.pub` line to a temp file, then (no `--allow-write` = read-only):

```bash
gh repo deploy-key add "$SCRATCH/d2-edge-deploy.pub" --repo Jared-D2/d2-edge --title "d2-edge-fleet-readonly (edge Pis)"
gh repo deploy-key list --repo Jared-D2/d2-edge
```
Expected: one key, `read-only`.

- [ ] **Step 5: Store the private key in the password manager** 🧑

Copy the output of `sudo cat /opt/netbox/onboarding/keys/d2-edge-deploy` on `.5` into the D2 password manager under "d2-edge fleet deploy key (read-only)". This is the recovery copy if `.5` is ever rebuilt.

---

## Task 2: The heal script (TDD)

**Files:**
- Create: `scripts/setup-git-deploy-key.sh`
- Create: `tests/test_setup_git_deploy_key.py`

Tests run on Linux only (they exercise `install -o`, `git`, `base64`). Run them on the Ansible control node as `jaredc` (python3 3.12 + git 2.43 present, no pytest needed):

```bash
# from the worktree root
rsync -a --delete -e "ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes" ./ jaredc@192.168.166.3:/tmp/d2-edge-test/
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.3 'cd /tmp/d2-edge-test && python3 tests/test_setup_git_deploy_key.py'
```
(If `rsync` is missing on Windows, `scp -r` the `scripts/`, `shared/`, `tests/` directories instead.)

- [ ] **Step 1: Write the failing test** 🤖

`tests/test_setup_git_deploy_key.py`:

```python
#!/usr/bin/env python3
"""Plain-assert tests for scripts/setup-git-deploy-key.sh (no pytest dep).

Linux only (install -o, git, base64). Run on the Ansible control node:
    python3 tests/test_setup_git_deploy_key.py
"""
import base64, os, pathlib, pwd, stat, subprocess, tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "setup-git-deploy-key.sh"
ME = pwd.getpwuid(os.getuid()).pw_name
FAKE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nnotarealkey\n-----END OPENSSH PRIVATE KEY-----\n"
FAKE_B64 = base64.b64encode(FAKE_KEY.encode()).decode()
SSH_ORIGIN = "git@github.com:Jared-D2/d2-edge.git"
HTTPS_ORIGIN = "https://github.com/Jared-D2/d2-edge.git"


def sandbox(td, origin=HTTPS_ORIGIN, env_line=None):
    edge = pathlib.Path(td, "edge"); edge.mkdir()
    subprocess.run(["git", "-C", str(edge), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(edge), "remote", "add", "origin", origin], check=True)
    home = pathlib.Path(td, "home"); home.mkdir()
    if env_line is not None:
        pathlib.Path(edge, ".env").write_text(env_line + "\n")
    return edge, home


def run(edge, home, extra_env=None):
    env = dict(os.environ, EDGE_DIR=str(edge), ADMIN_USER=ME, ADMIN_HOME=str(home))
    env.pop("GIT_DEPLOY_KEY_B64", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True)


def git_cfg(edge, key):
    r = subprocess.run(["git", "-C", str(edge), "config", "--get", key],
                       capture_output=True, text=True)
    return r.stdout.strip()


# 1. key from .env: installs 0600 key, pins host keys, rewrites origin, sets sshCommand
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    r = run(edge, home)
    assert r.returncode == 0, r.stderr
    key = home / ".ssh" / "id_d2edge_deploy"
    assert key.read_text() == FAKE_KEY
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE((home / ".ssh").stat().st_mode) == 0o700
    assert "github.com ssh-ed25519" in (home / ".ssh" / "known_hosts_github").read_text()
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN
    sshcmd = git_cfg(edge, "core.sshCommand")
    assert "IdentitiesOnly=yes" in sshcmd and str(key) in sshcmd and "StrictHostKeyChecking=yes" in sshcmd
    # idempotent: second run changes nothing
    r2 = run(edge, home)
    assert r2.returncode == 0, r2.stderr
    assert "installed" not in r2.stdout and "origin:" not in r2.stdout and "set core" not in r2.stdout, r2.stdout

# 2. environment beats .env (bootstrap path: no .env yet)
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td)
    r = run(edge, home, {"GIT_DEPLOY_KEY_B64": FAKE_B64})
    assert r.returncode == 0, r.stderr
    assert (home / ".ssh" / "id_d2edge_deploy").read_text() == FAKE_KEY
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN

# 3. already-SSH origin, no key anywhere: exit 0, no warning, origin untouched
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, origin=SSH_ORIGIN)
    r = run(edge, home)
    assert r.returncode == 0 and "WARNING" not in r.stdout, r.stdout

# 4. no key + https origin: exit 0 with WARNING, origin untouched, nothing installed
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td)
    r = run(edge, home)
    assert r.returncode == 0, r.stderr
    assert "WARNING" in r.stdout, r.stdout
    assert git_cfg(edge, "remote.origin.url") == HTTPS_ORIGIN
    assert not (home / ".ssh" / "id_d2edge_deploy").exists()

# 5. garbage key material: exit 1, nothing installed
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line="GIT_DEPLOY_KEY_B64=bm90LWEta2V5")  # "not-a-key"
    r = run(edge, home)
    assert r.returncode == 1, (r.returncode, r.stderr)
    assert "not a base64 OpenSSH private key" in r.stderr
    assert not (home / ".ssh" / "id_d2edge_deploy").exists()

# 6. no checkout yet (pre-clone): key + known_hosts installed, exit 0
with tempfile.TemporaryDirectory() as td:
    home = pathlib.Path(td, "home"); home.mkdir()
    r = run(pathlib.Path(td, "nope"), home, {"GIT_DEPLOY_KEY_B64": FAKE_B64})
    assert r.returncode == 0, r.stderr
    assert (home / ".ssh" / "id_d2edge_deploy").exists()
    assert (home / ".ssh" / "known_hosts_github").exists()

# 7. legacy full-account key present: reported by fingerprint line, never deleted
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    sshdir = home / ".ssh"; sshdir.mkdir(mode=0o700)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "legacy",
                    "-f", str(sshdir / "id_ed25519")], check=True)
    r = run(edge, home)
    assert r.returncode == 0, r.stderr
    assert "legacy key still present" in r.stdout and "SHA256:" in r.stdout, r.stdout
    assert (sshdir / "id_ed25519").exists()

print("ok")
```

- [ ] **Step 2: Run the test, confirm it fails** 🤖

Run (on `.3`, per the rsync recipe above): `python3 tests/test_setup_git_deploy_key.py`
Expected: `AssertionError` from case 1 with stderr `bash: .../scripts/setup-git-deploy-key.sh: No such file or directory`.

- [ ] **Step 3: Write the script** 🤖

`scripts/setup-git-deploy-key.sh`:

```bash
#!/usr/bin/env bash
# Point this Pi's /opt/d2-edge checkout at the PRIVATE GitHub repo using the
# fleet READ-ONLY deploy key. Idempotent -- runs on every update.sh (host-
# heal [3/6]) and at the end of bootstrap.sh.
#
# Why: the d2-edge repo is private; anonymous https:// pulls 404. Every Pi
# needs (a) the deploy key and (b) an SSH origin. The key is fleet-shared
# (one read-only deploy key on the repo -- same pattern as TS_AUTHKEY and
# AGENT_TOKEN) and arrives as GIT_DEPLOY_KEY_B64 in .env (root-only 0600),
# or as the same name in the ENVIRONMENT, which is how bootstrap supplies it
# before .env exists. Environment wins over .env.
#
# Never touches the operator's legacy ~admin/.ssh/id_ed25519 (the full-
# account key from imaging) -- it only REPORTS its fingerprint so the key
# can be revoked on GitHub once the fleet has converted.
#
# Env overrides (test harness only): EDGE_DIR, ENV_FILE, ADMIN_USER, ADMIN_HOME.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="${ENV_FILE:-$EDGE_DIR/.env}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_HOME="${ADMIN_HOME:-/home/$ADMIN_USER}"
SSH_DIR="$ADMIN_HOME/.ssh"
KEY_FILE="$SSH_DIR/id_d2edge_deploy"
KNOWN_HOSTS="$SSH_DIR/known_hosts_github"
SSH_ORIGIN="git@github.com:Jared-D2/d2-edge.git"
SSH_CMD="ssh -i $KEY_FILE -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=yes"

# GitHub's published host keys (gh api meta --jq '.ssh_keys[]', 2026-09-14).
# Pinned, NOT ssh-keyscan'd: trust-on-first-use over a customer WAN is not
# acceptable for the key that pulls code onto every appliance.
GITHUB_HOST_KEYS='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk='

# shellcheck source=../shared/scripts/lib/envfile.sh
. "$SCRIPT_DIR/../shared/scripts/lib/envfile.sh"

log() { echo "[git-deploy-key] $*"; }

# Run git as the user who owns the checkout (update.sh runs as root).
as_admin() {
    if [[ $EUID -eq 0 && "$ADMIN_USER" != "$(id -un)" ]]; then
        sudo -u "$ADMIN_USER" "$@"
    else
        "$@"
    fi
}

# install_file MODE SRC DST -- write only when absent or content differs.
# Returns 0 if it wrote, 1 if already current.
install_file() {
    local mode="$1" src="$2" dst="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then return 1; fi
    install -m "$mode" -o "$ADMIN_USER" -g "$ADMIN_USER" "$src" "$dst"
    return 0
}

tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

# 1. Key material: environment wins (bootstrap, pre-.env), then .env.
key_b64="${GIT_DEPLOY_KEY_B64:-$(env_get GIT_DEPLOY_KEY_B64 "$ENV_FILE")}"
if [[ -n "$key_b64" ]]; then
    if ! printf '%s' "$key_b64" | base64 -d > "$tmp" 2>/dev/null \
       || ! grep -q -- '-----BEGIN OPENSSH PRIVATE KEY-----' "$tmp"; then
        echo "[git-deploy-key] ERROR: GIT_DEPLOY_KEY_B64 is not a base64 OpenSSH private key" >&2
        exit 1
    fi
    install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$SSH_DIR"
    if install_file 600 "$tmp" "$KEY_FILE"; then log "installed $KEY_FILE"; fi
fi

# 2. Without a key there is nothing to wire -- but shout if the pull will break.
if [[ ! -f "$KEY_FILE" ]]; then
    if [[ -d "$EDGE_DIR/.git" ]] \
       && as_admin git -C "$EDGE_DIR" remote get-url origin 2>/dev/null | grep -q '^https://'; then
        log "WARNING: origin is https:// and no deploy key is configured -- git pull fails once the repo is private. Add GIT_DEPLOY_KEY_B64 to $ENV_FILE."
    fi
    exit 0
fi

# 3. Pinned GitHub host keys.
printf '%s\n' "$GITHUB_HOST_KEYS" > "$tmp"
if install_file 644 "$tmp" "$KNOWN_HOSTS"; then log "pinned GitHub host keys in $KNOWN_HOSTS"; fi

# 4. Repo wiring (only once a checkout exists).
if [[ -d "$EDGE_DIR/.git" ]]; then
    if [[ "$(as_admin git -C "$EDGE_DIR" config --get core.sshCommand || true)" != "$SSH_CMD" ]]; then
        as_admin git -C "$EDGE_DIR" config core.sshCommand "$SSH_CMD"
        log "set core.sshCommand -> $KEY_FILE"
    fi
    origin="$(as_admin git -C "$EDGE_DIR" remote get-url origin 2>/dev/null || true)"
    if [[ "$origin" != "$SSH_ORIGIN" ]]; then
        as_admin git -C "$EDGE_DIR" remote set-url origin "$SSH_ORIGIN"
        log "origin: ${origin:-<none>} -> $SSH_ORIGIN"
    fi
fi

# 5. Legacy full-account key: report, never delete.
if [[ -f "$SSH_DIR/id_ed25519.pub" ]]; then
    log "NOTICE: legacy key still present: $(ssh-keygen -lf "$SSH_DIR/id_ed25519.pub" 2>/dev/null || echo "$SSH_DIR/id_ed25519.pub") -- revoke on GitHub once the fleet is converted, then delete it"
fi
```

- [ ] **Step 4: Mark executable (the `update.sh` hook checks `-x`)** 🤖

```bash
git add scripts/setup-git-deploy-key.sh tests/test_setup_git_deploy_key.py
git update-index --chmod=+x scripts/setup-git-deploy-key.sh
git ls-files -s scripts/setup-git-deploy-key.sh
```
Expected: mode `100755`.

- [ ] **Step 5: Run the tests, confirm they pass** 🤖

Re-rsync, then: `python3 tests/test_setup_git_deploy_key.py`
Expected: `ok`. Also `bash -n scripts/setup-git-deploy-key.sh` exits 0.

- [ ] **Step 6: Commit** 🤖

```bash
git commit -m "feat(git): fleet read-only deploy key heal for the private repo

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 3: Wire the heal into `update.sh` and document the `.env` key

**Files:**
- Modify: `shared/scripts/update.sh` (insert after the `setup-svc-ansible.sh` block ending at line 194)
- Modify: `.env.template` (append before the `# --- OOB console` section)

- [ ] **Step 1: Add the hook to `update.sh`** 🤖

Insert directly after this existing block:

```bash
if [[ -x "$EDGE_DIR/scripts/setup-svc-ansible.sh" ]]; then
    bash "$EDGE_DIR/scripts/setup-svc-ansible.sh"
fi
```

the new block:

```bash
# Private-repo git auth: installs the fleet READ-ONLY deploy key from
# GIT_DEPLOY_KEY_B64 (.env) and switches origin https:// -> SSH with pinned
# GitHub host keys. Self-mod lag applies: the first update.sh after this
# landed pulls the code, the SECOND executes this hook -- so the fleet must
# convert (two pushes) BEFORE the repo flips private, because the [1/6]
# pull above is what breaks on an unconverted https:// Pi. On such a Pi
# with no key this only warns. Fail-loud on purpose (no || true): a bad
# key value means the next pull would fail anyway.
if [[ -x "$EDGE_DIR/scripts/setup-git-deploy-key.sh" ]]; then
    bash "$EDGE_DIR/scripts/setup-git-deploy-key.sh"
fi
```

- [ ] **Step 2: Add the `.env.template` entry** 🤖

Insert before `# --- OOB console (4G HAT) ---`:

```bash
# --- Git (private repo) ---------------------------------------------------
# GIT_DEPLOY_KEY_B64: base64 (one line) of the fleet READ-ONLY GitHub deploy
# key. update.sh installs it to /home/admin/.ssh/id_d2edge_deploy and points
# origin at git@github.com:Jared-D2/d2-edge.git. Fleet-wide value -- fetch
# from /opt/netbox/onboarding/.env (EDGE_GIT_DEPLOY_KEY_B64). Optional on a
# Pi that already has the key file; REQUIRED on any Pi still on an https://
# origin or git pull fails once the repo is private.
GIT_DEPLOY_KEY_B64=
```

- [ ] **Step 3: Syntax-check and confirm preflight is untouched** 🤖

```bash
bash -n shared/scripts/update.sh && grep -c "setup-git-deploy-key" shared/scripts/update.sh && grep -c GIT_DEPLOY_KEY_B64 shared/scripts/preflight.sh
```
Expected: `1` then `0` (the key is deliberately NOT in preflight's `required=` list — the key file path is an equally valid source, and pre-flip Pis must keep deploying).

- [ ] **Step 4: Commit** 🤖

```bash
git add shared/scripts/update.sh .env.template
git commit -m "feat(update): self-heal git deploy key + SSH origin on every update

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 4: `bootstrap.sh` clones the private repo with the deploy key

**Files:**
- Modify: `shared/scripts/bootstrap.sh:4-5` and `:190-203`

- [ ] **Step 1: Replace the URL constants (lines 4-5)** 🤖

Old:
```bash
REPO_URL="https://raw.githubusercontent.com/Jared-D2/d2-edge"
REPO_GIT="https://github.com/Jared-D2/d2-edge.git"
```
New (`REPO_URL` was never used):
```bash
# The repo is PRIVATE. Clones/pulls authenticate with the fleet read-only
# deploy key; the onboarding portal's "New Edge Pi" block installs the key
# and the pinned GitHub host keys and clones BEFORE running this script.
REPO_GIT="git@github.com:Jared-D2/d2-edge.git"
DEPLOY_KEY=/home/admin/.ssh/id_d2edge_deploy
DEPLOY_KNOWN_HOSTS=/home/admin/.ssh/known_hosts_github
```

- [ ] **Step 2: Replace the clone block (lines 190-203)** 🤖

Old:
```bash
# ─── Clone repo ───────────────────────────────────────────────────────────
echo ""
echo "[7/8] Cloning d2-edge repo..."
if [[ -d "${EDGE_DIR}/.git" ]]; then
    echo "  Repo already exists, pulling latest..."
    cd "${EDGE_DIR}" && git pull
else
    git clone "${REPO_GIT}" "${EDGE_DIR}"
fi

# Repo cloned as root; chown everything to admin so update.sh (git pull
# runs as admin) can write .git state. Keep .env at root:root 600 — secrets.
chown -R admin:admin "${EDGE_DIR}"
[[ -f "${EDGE_DIR}/.env" ]] && chown root:root "${EDGE_DIR}/.env" && chmod 600 "${EDGE_DIR}/.env"
```
New:
```bash
# ─── Clone repo ───────────────────────────────────────────────────────────
echo ""
echo "[7/8] Cloning d2-edge repo..."
if [[ -d "${EDGE_DIR}/.git" ]]; then
    # Normal path: the portal bootstrap block already cloned as admin with
    # core.sshCommand set, so a plain pull as admin authenticates.
    echo "  Repo already exists, pulling latest..."
    chown -R admin:admin "${EDGE_DIR}/.git"
    sudo -u admin git -C "${EDGE_DIR}" pull
else
    # Hand-build fallback: the operator must have dropped the key + pinned
    # host keys in place (both come from the portal's New Edge Pi tab).
    if [[ ! -f "$DEPLOY_KEY" || ! -f "$DEPLOY_KNOWN_HOSTS" ]]; then
        echo "ERROR: ${EDGE_DIR} is missing and ${DEPLOY_KEY} / ${DEPLOY_KNOWN_HOSTS} are not both present." >&2
        echo "  The d2-edge repo is private. Run the bootstrap block from the onboarding" >&2
        echo "  portal (New Edge Pi tab) -- it installs the key, pins github.com, clones," >&2
        echo "  then runs this script." >&2
        exit 1
    fi
    install -d -m 755 -o admin -g admin "${EDGE_DIR}"
    sudo -u admin git clone \
        -c core.sshCommand="ssh -i ${DEPLOY_KEY} -o IdentitiesOnly=yes -o UserKnownHostsFile=${DEPLOY_KNOWN_HOSTS} -o StrictHostKeyChecking=yes" \
        "${REPO_GIT}" "${EDGE_DIR}"
fi

# Everything under the checkout belongs to admin (update.sh pulls as admin).
# Keep .env at root:root 600 — secrets.
chown -R admin:admin "${EDGE_DIR}"
[[ -f "${EDGE_DIR}/.env" ]] && chown root:root "${EDGE_DIR}/.env" && chmod 600 "${EDGE_DIR}/.env"

# Normalise the git auth wiring (pinned host keys, core.sshCommand, SSH
# origin) now that the repo content is on disk. Idempotent.
bash "${EDGE_DIR}/scripts/setup-git-deploy-key.sh"
```

- [ ] **Step 3: Syntax check** 🤖

```bash
bash -n shared/scripts/bootstrap.sh && grep -c "raw.githubusercontent\|https://github.com/Jared-D2" shared/scripts/bootstrap.sh
```
Expected: `0`.

- [ ] **Step 4: Commit** 🤖

```bash
git add shared/scripts/bootstrap.sh
git commit -m "feat(bootstrap): clone the private repo as admin via the deploy key

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 5: README

**Files:**
- Modify: `README.md:23-26`

- [ ] **Step 1: Replace the Step 1 block** 🤖

Old:
````markdown
### Step 1 � Bootstrap
```bash
curl -sSL https://raw.githubusercontent.com/Jared-D2/d2-edge/main/shared/scripts/bootstrap.sh | sudo bash
```
````
New:
````markdown
### Step 1 — Bootstrap
The repo is private. Open the onboarding portal → **New Edge Pi** tab, fill in the
site, and paste the generated **bootstrap block** into the Pi's shell. It installs the
fleet read-only deploy key, pins github.com, clones `/opt/d2-edge` as `admin`, then runs
`shared/scripts/bootstrap.sh`. (Hand-building without the portal: place the key at
`/home/admin/.ssh/id_d2edge_deploy` and the pinned host keys at
`/home/admin/.ssh/known_hosts_github` first, then `sudo bash bootstrap.sh`.)
````
Also fix the two other mojibake `�` headings in the same file to `—` while there (Step 2, Step 3) — cosmetic, same commit.

- [ ] **Step 2: Commit** 🤖

```bash
git add README.md
git commit -m "docs: bootstrap via the portal block now that the repo is private

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Task 6: Push the branch and merge to `main` (repo still public)

- [ ] **Step 1: Push** 🤖

```bash
git push -u origin feat/private-repo-deploy-key
```

- [ ] **Step 2: Merge** 🤖 (`--no-ff` merge commit into `main`, matching the repo's existing `Merge feat/...:` convention; `main` is not checked out in any other worktree, so `checkout -B` is safe)

```bash
git fetch origin && git checkout -B main origin/main && git merge --no-ff feat/private-repo-deploy-key -m "Merge feat/private-repo-deploy-key: fleet read-only deploy key for the private repo" && git push origin main && git checkout feat/private-repo-deploy-key
```
Expected: `origin/main` now contains `scripts/setup-git-deploy-key.sh`. Verify: `git ls-tree origin/main scripts/setup-git-deploy-key.sh` shows `100755`.

---

## Task 7: Onboarding portal emits the key and the pre-clone bootstrap block

**Files (on NetBox `192.168.166.5`, NOT in git):**
- Modify: `/opt/netbox/onboarding/app.py` — the `/api/onboard-pi` handler
- Already modified in Task 1: `/opt/netbox/onboarding/.env`

Convention (from memory): back up to `/opt/netbox-onboarding-app.py.pre-<date>`, edit as root, `sudo systemctl restart netbox-onboarding.service`. If `.5` is unreachable from Claude's box, every step here becomes 🧑 — hand Jared the exact diff below.

- [ ] **Step 1: Locate the emitters** 🤖

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.5 'sudo grep -nE "onboard-pi|raw\.githubusercontent|bootstrap\.sh|EDGE_TS_AUTHKEY|AGENT_TOKEN=" /opt/netbox/onboarding/app.py'
```
Expected: the route decorator, the line building the `.env` text (where `AGENT_TOKEN=` is emitted from `EDGE_AGENT_TOKEN`), and the line(s) building the bootstrap command block containing the `raw.githubusercontent.com` curl.

- [ ] **Step 2: Back up** 🤖

```bash
sudo cp /opt/netbox/onboarding/app.py /opt/netbox-onboarding-app.py.pre-2026-09-14-deploy-key
```

- [ ] **Step 3: Emit `GIT_DEPLOY_KEY_B64` in the generated `.env`** 🤖

Next to where `AGENT_TOKEN={os.environ.get("EDGE_AGENT_TOKEN", "")}` (or equivalent) is emitted, add the same pattern for the new key so the rendered `.env` gains:

```
# Fleet read-only GitHub deploy key (base64). update.sh installs it; keeps git pull working on the private repo.
GIT_DEPLOY_KEY_B64=<value of EDGE_GIT_DEPLOY_KEY_B64>
```

- [ ] **Step 4: Replace the bootstrap block** 🤖

Replace the curl one-liner with this block (Python f-string / template — keep the file's existing style; `{key_b64}` is `EDGE_GIT_DEPLOY_KEY_B64` from the portal env):

```bash
# --- D2 Edge bootstrap (private repo) ---
sudo apt-get update -qq && sudo apt-get install -y -qq git
sudo install -d -m 700 -o admin -g admin /home/admin/.ssh
sudo install -m 600 -o admin -g admin /dev/null /home/admin/.ssh/id_d2edge_deploy
echo '{key_b64}' | base64 -d | sudo tee /home/admin/.ssh/id_d2edge_deploy >/dev/null
sudo install -m 644 -o admin -g admin /dev/null /home/admin/.ssh/known_hosts_github
echo 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' | sudo tee /home/admin/.ssh/known_hosts_github >/dev/null
sudo install -d -m 755 -o admin -g admin /opt/d2-edge
sudo -u admin git clone -c core.sshCommand='ssh -i /home/admin/.ssh/id_d2edge_deploy -o IdentitiesOnly=yes -o UserKnownHostsFile=/home/admin/.ssh/known_hosts_github -o StrictHostKeyChecking=yes' git@github.com:Jared-D2/d2-edge.git /opt/d2-edge
sudo bash /opt/d2-edge/shared/scripts/bootstrap.sh
```

(The `install /dev/null` lines create the files with the right mode *before* content is written, so the private key is never world-readable even momentarily. `bootstrap.sh` then runs `setup-git-deploy-key.sh`, which pins the full three-key set.)

- [ ] **Step 5: Restart and smoke-test** 🤖

```bash
sudo python3 -m py_compile /opt/netbox/onboarding/app.py && sudo systemctl restart netbox-onboarding.service && sleep 2 && systemctl is-active netbox-onboarding.service
```
Expected: `active`. Then in the portal UI (🧑 or via the browser tools): New Edge Pi tab → generate for a throwaway hostname → confirm the `.env` pane contains `GIT_DEPLOY_KEY_B64=` with a long value and the bootstrap pane contains `git clone -c core.sshCommand=` and **no** `raw.githubusercontent.com`. Do not create a NetBox site for the throwaway if the form offers a dry-run; otherwise delete the site afterwards.

---

## Task 8: Ansible `edge-status.yml` reports private-repo readiness

**Files (on `192.168.166.3`, NOT in git):**
- Modify: `/opt/ansible/playbooks/edge-status.yml`

- [ ] **Step 1: Read the play** 🤖

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.3 'sudo cat /opt/ansible/playbooks/edge-status.yml'
```

- [ ] **Step 2: Add two read-only tasks + extend the summary** 🤖

Back up first: `sudo cp /opt/ansible/playbooks/edge-status.yml /opt/ansible/playbooks/edge-status.yml.pre-2026-09-14`. Then add, after the existing `rev-parse --short HEAD` task (same style, svc_ansible can read the admin-owned `.git/config` because `safe.directory` is set system-wide):

```yaml
    - name: git origin URL
      ansible.builtin.command: git -C {{ edge_dir }} remote get-url origin
      register: git_origin
      changed_when: false

    - name: git core.sshCommand (deploy-key wiring)
      ansible.builtin.command: git -C {{ edge_dir }} config --get core.sshCommand
      register: git_sshcmd
      changed_when: false
      failed_when: false
```

and extend the existing `debug`/summary message with:

```yaml
        origin={{ git_origin.stdout }} deploy_key={{ 'yes' if 'id_d2edge_deploy' in git_sshcmd.stdout else 'NO' }}
```

- [ ] **Step 3: Verify on the D2 tenant** 🤖

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.3 'd2-deploy status'
```
Expected: both D2 Pis report `origin=git@github.com:Jared-D2/d2-edge.git deploy_key=NO` (not converted yet) and `failed=0`. Note `d2001-nw-pi01` already shows the SSH origin; the lab Pi may be offline — record which.

---

## Task 9: Convert the fleet (repo STILL public)

Order matters: `.env` gets the key line → **two** `d2-deploy push` runs (self-mod lag) → audit shows `deploy_key=yes` everywhere reachable. Only then Task 10.

The one-line append (same for every Pi; value from `sudo grep '^EDGE_GIT_DEPLOY_KEY_B64=' /opt/netbox/onboarding/.env | cut -d= -f2-` on `.5`):

```bash
echo 'GIT_DEPLOY_KEY_B64=<paste value>' | sudo tee -a /opt/d2-edge/.env >/dev/null && sudo grep -c '^GIT_DEPLOY_KEY_B64=' /opt/d2-edge/.env
```
Expected: `1`. (`update.sh` dedups an accidental double paste of the same value.)

- [ ] **Step 1: D2 Pis — append the key line** 🤖 (allowlisted: `admin@192.168.166.34`, `admin@192.168.21.20`)

Run the append above on each via `ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes admin@<ip> '<append command>'`. If `.20` is unreachable, mark it 🧑 and move on.

- [ ] **Step 2: D2 Pis — deploy twice** 🤖 (Jared's standing rule is that he runs deployed Pis himself; he has authorised this migration, so run it, but stop and report if `failed≠0`)

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.3 'd2-deploy push && d2-deploy push'
```
Expected in the second run's output per Pi: `[git-deploy-key] installed /home/admin/.ssh/id_d2edge_deploy`, `pinned GitHub host keys`, `set core.sshCommand -> ...`, and on `.34` the line `NOTICE: legacy key still present: 256 SHA256:WMXhnyfZoZx7CqpOMnSaW9jUqE+rYJGRk8RinRDErtc ...`. Then `d2-deploy status` shows `deploy_key=yes` for both.

- [ ] **Step 3: Prove the deploy key alone can pull** 🤖

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes admin@192.168.166.34 'cd /opt/d2-edge && git fetch -v origin 2>&1 | tail -2 && ssh -i ~/.ssh/id_d2edge_deploy -o IdentitiesOnly=yes -o UserKnownHostsFile=~/.ssh/known_hosts_github -o StrictHostKeyChecking=yes -T git@github.com 2>&1 | head -1'
```
Expected: fetch succeeds and the greeting reads `Hi Jared-D2/d2-edge! You've successfully authenticated` (a deploy key greets with the **repo** name, not the user — that is the proof it is the new key).

- [ ] **Step 4: Customer Pis — append the key line** 🧑

Claude cannot SSH to these. For each of the 8 customer Pis (nib001 ×7, hom001 ×1 — `d2-deploy status device_roles_edge_pi` lists them with reachability), run the append command above as `admin`. Any Pi that is offline: skip and note it for the straggler runbook (Task 10 Step 4).

- [ ] **Step 5: Customer Pis — deploy twice** 🧑 (or 🤖 on explicit go — it is the same `d2-deploy` wrapper)

```bash
d2-deploy push tenants_nib_health_funds && d2-deploy push tenants_nib_health_funds
d2-deploy push tenants_home_in_place && d2-deploy push tenants_home_in_place
```
Expected: `failed=0`; second-run output shows `[git-deploy-key] installed ...` per Pi.

- [ ] **Step 6: Fleet audit gate** 🤖

```bash
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.3 'd2-deploy status device_roles_edge_pi' | grep -E "origin=|UNREACHABLE"
```
**Gate:** every reachable Pi shows `origin=git@github.com:Jared-D2/d2-edge.git deploy_key=yes`. List any unreachable Pi by name — they go into the straggler runbook and do NOT block the flip (their running containers are unaffected; only their next `update.sh` is).

---

## Task 10: Flip the repo private and verify

- [ ] **Step 1: Go/no-go** 🧑

Jared confirms the Task 9 audit output and says "flip". This is the one irreversible-feeling step (it is reversible, but a public→private→public bounce would be noisy).

- [ ] **Step 2: Flip** 🤖 (on Jared's go)

```bash
gh repo edit Jared-D2/d2-edge --visibility private --accept-visibility-change-consequences && gh repo view Jared-D2/d2-edge --json visibility --jq .visibility
```
Expected: `PRIVATE`.

- [ ] **Step 3: Verify the three consumers** 🤖

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://raw.githubusercontent.com/Jared-D2/d2-edge/main/README.md
git ls-remote https://github.com/Jared-D2/d2-edge.git 2>&1 | head -1
ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes jaredc@192.168.166.3 'd2-deploy push'
```
Expected: `404`; an authentication error (or a credential prompt that you Ctrl-C) on the anonymous ls-remote; and the D2-tenant push succeeds with `failed=0` and `[1/6] Pulling latest from Git... OK`. Then 🧑 runs (or authorises) `d2-deploy push tenants_nib_health_funds` / `tenants_home_in_place` once more as the post-flip proof.

- [ ] **Step 4: Straggler runbook (for any Pi that missed Task 9)** — record in this plan under "Outcome"

On a Pi that never pulled the new code before the flip, `update.sh` fails at `[1/6]` before the heal can run. Manual recovery as `admin` on that Pi (🧑 for customer Pis):

```bash
echo 'GIT_DEPLOY_KEY_B64=<value>' | sudo tee -a /opt/d2-edge/.env >/dev/null
sudo install -d -m 700 -o admin -g admin /home/admin/.ssh
sudo install -m 600 -o admin -g admin /dev/null /home/admin/.ssh/id_d2edge_deploy
echo '<value>' | base64 -d | sudo tee /home/admin/.ssh/id_d2edge_deploy >/dev/null
sudo -u admin git -C /opt/d2-edge remote set-url origin git@github.com:Jared-D2/d2-edge.git
sudo -u admin git -C /opt/d2-edge config core.sshCommand 'ssh -i /home/admin/.ssh/id_d2edge_deploy -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new'
sudo bash /opt/d2-edge/shared/scripts/update.sh && sudo bash /opt/d2-edge/shared/scripts/update.sh
```
The second `update.sh` runs the heal, which replaces `accept-new` with the pinned host keys.

---

## Task 11: Retire the full-account key

- [ ] **Step 1: Revoke on GitHub** 🧑 — only after every Pi shows `deploy_key=yes` (Task 9 Step 6) and the post-flip pushes passed (Task 10 Step 3)

GitHub → Settings → **SSH and GPG keys** → delete the key whose fingerprint is `SHA256:WMXhnyfZoZx7CqpOMnSaW9jUqE+rYJGRk8RinRDErtc` (title likely `d2-raspberry-pe`). If the same fingerprint appears in the `[git-deploy-key] NOTICE: legacy key still present` line on **other** Pis' deploy output, that confirms the fleet shared one imaged key and this single revocation covers them all. If a *different* fingerprint appears on any Pi, revoke that one too.

**Consequence to accept:** you can no longer `git push` from `d2001-nw-pi01` (`.34`). Push from this laptop instead (`gh auth status` here is already `Jared-D2`).

- [ ] **Step 2: Remove the dead key files from the D2 Pis** 🤖 (after Step 1)

```bash
for ip in 192.168.166.34 192.168.21.20; do ssh -i ~/.ssh/id_claude -o IdentitiesOnly=yes admin@$ip 'rm -f ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub && ls ~/.ssh'; done
```
Expected: listing shows `id_d2edge_deploy` and `known_hosts_github`, no `id_ed25519`. Customer Pis: 🧑 same `rm` as `admin`, or leave them — a revoked key is inert.

- [ ] **Step 3: Update memory** 🤖

Update `reference_d2_edge_stack.md` (Repo section: private, deploy key path, bootstrap-via-portal) and `project_fleet_rollout_ansible.md` (the "admin has the GitHub deploy key" sentence now means `id_d2edge_deploy`, read-only). Add a `MEMORY.md` line for this plan's outcome.

---

## Not in scope (decided 2026-09-14)

- **Scrubbing internal IPs from git history.** Going private stops further exposure; a history rewrite would break every Pi's checkout. Treat the 10.255.255.x / 192.168.x addresses in the public history as already disclosed.
- **UXI controller resolving the expected agent SHA via GitHub.** Still the pinned `EXPECTED_AGENT_GIT_SHA` in `/opt/d2-controller/.env`. If the `git ls-remote` design is ever built it will need this same deploy key (read-only is sufficient).
- **Per-Pi deploy keys.** One fleet key matches the existing TS_AUTHKEY / AGENT_TOKEN model. Rotate by adding a second deploy key, rolling the `.env` value, then deleting the first.

## Self-review (author, 2026-09-14)

- Spec coverage: bootstrap (T4, T7), existing Pis (T2, T3, T9), over-privileged key (T2 notice, T11), flip (T10), portal (T7), Ansible visibility (T8), README (T5). ✔
- Placeholder scan: only `<value>` / `<paste value>` / `<ip>` for secrets or per-host substitution, each defined where it is obtained. ✔
- Name consistency: `id_d2edge_deploy`, `known_hosts_github`, `GIT_DEPLOY_KEY_B64` (Pi `.env`), `EDGE_GIT_DEPLOY_KEY_B64` (portal `.env`) used identically across T1–T11. ✔
