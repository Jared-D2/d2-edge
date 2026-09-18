#!/usr/bin/env python3
"""Plain-assert tests for scripts/setup-git-deploy-key.sh (no pytest dep).

Linux only (install -o, git, base64). Run on the Ansible control node:
    python3 tests/test_setup_git_deploy_key.py

Assumes the runner's primary group name equals its username: the script chowns
to "$ADMIN_USER:$ADMIN_USER" and the harness sets ADMIN_USER to the runner.
"""
import atexit, base64, os, pathlib, pwd, re, shutil, stat, subprocess, tempfile, time

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "setup-git-deploy-key.sh"
BOOTSTRAP = REPO / "shared" / "scripts" / "bootstrap.sh"
ME = pwd.getpwuid(os.getuid()).pw_name

# The script validates the key with `ssh-keygen -y`, so the fixture must be a
# REAL unencrypted ed25519 key. Generated once per run; lives for the module.
_KEYDIR = tempfile.mkdtemp(prefix="d2edge-testkey-")
atexit.register(shutil.rmtree, _KEYDIR, True)
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test",
                "-f", str(pathlib.Path(_KEYDIR, "id_fixture"))], check=True)
FAKE_KEY = pathlib.Path(_KEYDIR, "id_fixture").read_text()
FAKE_B64 = base64.b64encode(FAKE_KEY.encode()).decode()
# Same key, last 40 chars lopped off: decodes cleanly, parses as nothing.
BAD_KEY_B64 = base64.b64encode(FAKE_KEY[:-40].encode()).decode()
SSH_ORIGIN = "ssh://git@ssh.github.com:443/Jared-D2/d2-edge.git"
# The pre-443 SSH origin (port 22). Still on Pis that converted before the
# switch to ssh.github.com:443; the heal must rewrite it like any other.
LEGACY_SSH_ORIGIN = "git@github.com:Jared-D2/d2-edge.git"
HTTPS_ORIGIN = "https://github.com/Jared-D2/d2-edge.git"
KEY_ERR = "not a base64 OpenSSH private key"


def expected_sshcmd(home):
    return (f"ssh -i '{home}/.ssh/id_d2edge_deploy' -o IdentitiesOnly=yes"
            f" -o UserKnownHostsFile='{home}/.ssh/known_hosts_github'"
            f" -o StrictHostKeyChecking=yes -o BatchMode=yes"
            f" -o ConnectTimeout=20")


def sandbox(td, origin=HTTPS_ORIGIN, env_line=None):
    edge = pathlib.Path(td, "edge"); edge.mkdir()
    subprocess.run(["git", "-C", str(edge), "init", "-q"], check=True)
    if origin is not None:  # None = fresh `git init`, no origin remote at all
        subprocess.run(["git", "-C", str(edge), "remote", "add", "origin", origin], check=True)
    home = pathlib.Path(td, "home"); home.mkdir()
    if env_line is not None:
        pathlib.Path(edge, ".env").write_text(env_line + "\n")
    return edge, home


def run(edge, home, extra_env=None, remote_check=False, timeout=None):
    """Run the heal against a sandbox.

    The harness must stay offline-safe, so the script's `git ls-remote` probe
    is suppressed by default; remote_check=True re-enables it for the cases
    that drive it through a fake ssh.
    """
    env = dict(os.environ, EDGE_DIR=str(edge), ADMIN_USER=ME, ADMIN_HOME=str(home))
    env.pop("GIT_DEPLOY_KEY_B64", None)
    # A GIT_SSH_COMMAND/GIT_SSH in the runner's environment outranks the
    # core.sshCommand under test, which would route the probe past the fake ssh.
    env.pop("GIT_SSH_COMMAND", None)
    env.pop("GIT_SSH", None)
    if remote_check:
        env.pop("GIT_DEPLOY_KEY_NO_REMOTE_CHECK", None)
    else:
        env["GIT_DEPLOY_KEY_NO_REMOTE_CHECK"] = "1"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True,
                          text=True, timeout=timeout)


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
    assert "[ssh.github.com]:443 ssh-ed25519" in (home / ".ssh" / "known_hosts_github").read_text()
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN
    sshcmd = git_cfg(edge, "core.sshCommand")
    assert "IdentitiesOnly=yes" in sshcmd and str(key) in sshcmd and "StrictHostKeyChecking=yes" in sshcmd
    assert "BatchMode=yes" in sshcmd, sshcmd
    # never echo key material
    out = r.stdout + r.stderr
    assert FAKE_B64 not in out, out
    assert FAKE_KEY.splitlines()[1] not in out, out
    # idempotent: second run changes nothing and says nothing
    r2 = run(edge, home)
    assert r2.returncode == 0, r2.stderr
    assert r2.stdout == "", r2.stdout

# 2. environment beats .env (bootstrap path: no .env yet)
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td)
    r = run(edge, home, {"GIT_DEPLOY_KEY_B64": FAKE_B64})
    assert r.returncode == 0, r.stderr
    assert (home / ".ssh" / "id_d2edge_deploy").read_text() == FAKE_KEY
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN

# 3. already-converted origin (443 form), no key anywhere: exit 0, no warning,
#    origin untouched
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

# 8. metadata drift only (portal wrote the key 0644 into a 0755 .ssh):
#    perms converge, but content is unchanged so nothing is "installed"
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    sshdir = home / ".ssh"; sshdir.mkdir(); os.chmod(sshdir, 0o755)
    key = sshdir / "id_d2edge_deploy"
    key.write_text(FAKE_KEY); os.chmod(key, 0o644)
    r = run(edge, home)
    assert r.returncode == 0, r.stderr
    assert stat.S_IMODE(key.stat().st_mode) == 0o600, oct(key.stat().st_mode)
    assert stat.S_IMODE(sshdir.stat().st_mode) == 0o700, oct(sshdir.stat().st_mode)
    assert "installed" not in r.stdout, r.stdout
    assert key.read_text() == FAKE_KEY

# 9. checkout with NO origin remote at all (fresh git init): remote is added
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, origin=None)
    r = run(edge, home, {"GIT_DEPLOY_KEY_B64": FAKE_B64})
    assert r.returncode == 0, r.stderr
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN

# 10. stale core.sshCommand is rewritten to exactly the wanted string
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    subprocess.run(["git", "-C", str(edge), "config", "core.sshCommand", "ssh -o Foo=bar"],
                   check=True)
    r = run(edge, home)
    assert r.returncode == 0, r.stderr
    assert git_cfg(edge, "core.sshCommand") == expected_sshcmd(home), git_cfg(edge, "core.sshCommand")

# 11. truncated key: decodes, but ssh-keygen cannot parse it -> exit 1
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={BAD_KEY_B64}")
    r = run(edge, home)
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert KEY_ERR in r.stderr, r.stderr
    assert not (home / ".ssh" / "id_d2edge_deploy").exists()

# 12. undecodable base64: exit 1, same message
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td)
    r = run(edge, home, {"GIT_DEPLOY_KEY_B64": "!!!!"})
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert KEY_ERR in r.stderr, r.stderr
    assert not (home / ".ssh" / "id_d2edge_deploy").exists()

# 13. ADMIN_HOME does not exist (misprovisioned Pi): exit 1, create nothing
with tempfile.TemporaryDirectory() as td:
    edge, _ = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    home = pathlib.Path(td, "no-such-home")
    r = run(edge, home)
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert "ERROR" in r.stderr, r.stderr
    assert not home.exists()
    assert git_cfg(edge, "remote.origin.url") == HTTPS_ORIGIN

# 14. reachability probe ON: a failing ssh makes `git ls-remote` fail -> WARNING,
#     still exit 0. A fake ssh on PATH (git resolves core.sshCommand's `ssh`
#     through PATH) keeps this deterministic and offline.
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    bindir = pathlib.Path(td, "bin"); bindir.mkdir()
    fake_ssh = bindir / "ssh"
    fake_ssh.write_text("#!/bin/sh\nexit 255\n"); os.chmod(fake_ssh, 0o755)
    r = run(edge, home, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"},
            remote_check=True)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "ls-remote origin' failed" in r.stdout, r.stdout
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN

# 15. pre-existing key file that is NOT a usable private key, no .env value:
#     warn that the next pull will fail, but still exit 0 (operator fixes .env)
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td)
    sshdir = home / ".ssh"; sshdir.mkdir(mode=0o700)
    key = sshdir / "id_d2edge_deploy"
    key.write_text("garbage"); os.chmod(key, 0o600)
    r = run(edge, home)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "does not parse" in r.stdout, r.stdout
    assert key.read_text() == "garbage"

# 16. parity: bootstrap.sh's clone -c core.sshCommand must equal the heal's
#     wanted string, or every bootstrapped Pi gets it rewritten on first update
bs = BOOTSTRAP.read_text()
m = re.search(r'-c core\.sshCommand="([^"]*)"', bs)
assert m, "no -c core.sshCommand= literal in bootstrap.sh"
literal = m.group(1)
for var in ("DEPLOY_KEY", "DEPLOY_KNOWN_HOSTS"):
    vm = re.search(rf'^{var}=(\S+)$', bs, re.M)
    assert vm, f"no {var}= in bootstrap.sh"
    literal = literal.replace("${%s}" % var, vm.group(1))
assert literal == expected_sshcmd("/home/admin"), (literal, expected_sshcmd("/home/admin"))
# ...and the README's hand-build clone must carry the same string verbatim, or
# a hand-built Pi gets core.sshCommand rewritten on its first update.
readme = (REPO / "README.md").read_text()
assert expected_sshcmd("/home/admin") in readme, "README.md clone -c core.sshCommand drifted"

# 17. legacy full-account PRIVATE key with no .pub alongside it: still reported
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    sshdir = home / ".ssh"; sshdir.mkdir(mode=0o700)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "legacy",
                    "-f", str(sshdir / "id_ed25519")], check=True)
    (sshdir / "id_ed25519.pub").unlink()
    r = run(edge, home)
    assert r.returncode == 0, r.stderr
    assert "legacy key still present" in r.stdout and "SHA256:" in r.stdout, r.stdout
    assert (sshdir / "id_ed25519").exists()

# 18. bad GIT_DEPLOY_KEY_B64 while a VALID key is already on disk: keep the
#     on-disk key, warn, still wire the repo. A typo in .env must not strand a
#     working Pi -- aborting here would leave origin on https:// forever.
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line="GIT_DEPLOY_KEY_B64=bm90LWEta2V5")  # "not-a-key"
    sshdir = home / ".ssh"; sshdir.mkdir(mode=0o700)
    key = sshdir / "id_d2edge_deploy"
    key.write_text(FAKE_KEY); os.chmod(key, 0o600)
    r = run(edge, home)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "keeping the existing valid" in r.stdout, (r.stdout, r.stderr)
    assert key.read_text() == FAKE_KEY, "existing valid key was clobbered"
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN

# 19. probe timeout: a dead WAN (fake ssh that just hangs) must not stall the
#     update for the SSH connect timeout -- `timeout 20` bounds the probe, then
#     the same WARNING fires. The wall-clock bound IS the assertion.
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    bindir = pathlib.Path(td, "bin"); bindir.mkdir()
    fake_ssh = bindir / "ssh"
    fake_ssh.write_text("#!/bin/sh\nsleep 60\n"); os.chmod(fake_ssh, 0o755)
    t0 = time.monotonic()
    r = run(edge, home, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"},
            remote_check=True, timeout=90)
    elapsed = time.monotonic() - t0
    assert elapsed < 40, f"probe was not bounded: {elapsed:.1f}s"
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "ls-remote origin' failed" in r.stdout, r.stdout

# 20. legacy port-22 SSH origin + key: rewritten to the 443 form, and the log
#     line names both ends so the rollout is auditable from update.sh output.
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, origin=LEGACY_SSH_ORIGIN,
                         env_line=f"GIT_DEPLOY_KEY_B64={FAKE_B64}")
    r = run(edge, home)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert git_cfg(edge, "remote.origin.url") == SSH_ORIGIN, git_cfg(edge, "remote.origin.url")
    assert f"origin: {LEGACY_SSH_ORIGIN} -> {SSH_ORIGIN}" in r.stdout, r.stdout

# 21. legacy port-22 SSH origin, NO key anywhere: exit 0 and NO warning. The
#     https:// warning is about a Pi that cannot authenticate at all; a port-22
#     Pi still pulls via the operator's legacy account key until it is revoked.
with tempfile.TemporaryDirectory() as td:
    edge, home = sandbox(td, origin=LEGACY_SSH_ORIGIN)
    r = run(edge, home)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "WARNING" not in r.stdout, r.stdout
    assert git_cfg(edge, "remote.origin.url") == LEGACY_SSH_ORIGIN

print("ok")
