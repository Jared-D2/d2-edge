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
