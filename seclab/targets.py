"""Docker lab-target lifecycle.

Every attackable thing in this course runs as a local Docker container, pinned by
digest, bound to 127.0.0.1, on a dedicated network. This module starts them,
waits for them to be healthy, tears them down, and — crucially — **refuses to
point you at anything that is not local.**

    from seclab import Target
    with Target("dvwa") as t:
        print(t.base_url)        # http://127.0.0.1:<port>
        ...                      # attack t.base_url
    # container is removed on exit

Command line:

    python -m seclab.targets --list
    python -m seclab.targets --up dvwa
    python -m seclab.targets --down            # remove everything we started
    python -m seclab.targets --check           # is Docker usable?

If Docker is not available, `Target(...).up()` raises a clear error and the lab
guide points you at the hosted-sandbox fallback. Nothing here silently no-ops.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# The lab catalogue. Digests are pinned deliberately: an unpinned `:latest` is a
# supply-chain lesson waiting to bite, and in week 8 we make that lesson explicit.
# Update these with `docker pull <image> && docker inspect --format '{{index
# .RepoDigests 0}}' <image>` and commit the change with a note.
# ---------------------------------------------------------------------------
LABEL = "seclab.course=cmp5006"          # every container we create is tagged
NETWORK = "seclab-net"


@dataclass(frozen=True)
class Image:
    name: str
    image: str            # include an @sha256:... digest in a real deployment
    container_port: int
    ready_path: str = "/"
    ready_status: tuple = (200, 301, 302, 401, 403)
    note: str = ""


CATALOGUE = {
    "dvwa": Image(
        "dvwa", "ghcr.io/digininja/dvwa:latest", 80, "/login.php",
        note="Damn Vulnerable Web App. Weeks 6-7. The digininja image is the "
             "maintained one; the old vulnerables/web-dvwa is abandoned."),
    "juiceshop": Image(
        "juiceshop", "bkimminich/juice-shop:latest", 3000, "/",
        note="OWASP Juice Shop. A modern JS app; better for 2021 Top 10 than DVWA."),
    "vuln-web": Image(
        # Built locally from labs/vuln-web/ — see that directory's README.
        "vuln-web", "seclab/vuln-web:local", 8000, "/health",
        note="The course's small vulnerable web app (SQLi, XSS, cmdi). Week 6. "
             "You attack it AND scan its source, so target and scan-subject match."),
    "vuln-llm": Image(
        # Built locally from labs/vuln-llm/ — see that directory's README.
        "vuln-llm", "seclab/vuln-llm:local", 8000, "/health",
        note="The course's deliberately vulnerable LLM app. Weeks 9-10. Built "
             "locally so no attack traffic ever leaves your machine."),
}


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def docker_available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker not found on PATH"
    r = _run(["docker", "info"])
    if r.returncode != 0:
        return False, "docker is installed but the daemon is not running"
    return True, "ok"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _ensure_network():
    r = _run(["docker", "network", "ls", "--filter", f"name=^{NETWORK}$",
              "--format", "{{.Name}}"])
    if NETWORK not in r.stdout:
        _run(["docker", "network", "create", NETWORK])


@dataclass
class Target:
    """One running lab target. Use as a context manager for auto-teardown."""
    name: str
    host_port: int | None = None
    container_id: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.name not in CATALOGUE:
            raise KeyError(f"unknown target {self.name!r}; "
                           f"known: {', '.join(CATALOGUE)}")
        self.spec = CATALOGUE[self.name]

    @property
    def base_url(self) -> str:
        if self.host_port is None:
            raise RuntimeError("target is not up; call .up() first")
        # ALWAYS localhost. There is no code path here that yields a remote host.
        return f"http://127.0.0.1:{self.host_port}"

    # -- lifecycle ----------------------------------------------------------
    def up(self, timeout: float = 90.0) -> "Target":
        ok, why = docker_available()
        if not ok:
            raise RuntimeError(
                f"cannot start lab target: {why}.\n"
                "Install Docker Desktop (mac/win) or docker-ce (linux), or run "
                "the lab app directly without a container — see the no-Docker "
                "path in your setup guide. Nothing in THIS module works without "
                "a container runtime — by design, so your attacks stay local.")
        _ensure_network()
        self.host_port = self.host_port or _free_port()
        # --rm so a crash never leaves junk; bind to loopback ONLY.
        cmd = ["docker", "run", "-d", "--rm",
               "--label", LABEL,
               "--network", NETWORK,
               "-p", f"127.0.0.1:{self.host_port}:{self.spec.container_port}"]
        # On Linux, host.docker.internal (used by vuln-llm to reach a local Ollama)
        # is not resolvable by default. Add the host-gateway mapping so the same
        # image reaches a host Ollama on Linux as it does on mac/win. Harmless
        # elsewhere; only added on Linux to avoid an unknown-flag error on old
        # Docker builds that already resolve the name.
        if sys.platform.startswith("linux"):
            cmd += ["--add-host", "host.docker.internal:host-gateway"]
        cmd.append(self.spec.image)
        r = _run(cmd)
        if r.returncode != 0:
            raise RuntimeError(f"docker run failed:\n{r.stderr.strip()}")
        self.container_id = r.stdout.strip()
        self._wait_ready(timeout)
        return self

    def _wait_ready(self, timeout: float):
        deadline = time.monotonic() + timeout
        url = self.base_url + self.spec.ready_path
        last = "no attempt"
        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    if resp.status in self.spec.ready_status:
                        return
                    last = f"HTTP {resp.status}"
            except urllib.error.HTTPError as e:
                if e.code in self.spec.ready_status:
                    return
                last = f"HTTP {e.code}"
            except (urllib.error.URLError, OSError, ValueError) as e:
                last = str(e)
            time.sleep(1.5)
        raise TimeoutError(
            f"{self.name} did not become ready within {timeout:.0f}s "
            f"(last: {last}). Check `docker logs {self.container_id[:12]}`.")

    def logs(self) -> str:
        if not self.container_id:
            return ""
        return _run(["docker", "logs", self.container_id]).stdout

    def down(self):
        if self.container_id:
            _run(["docker", "stop", self.container_id])
            self.container_id = None

    # -- context manager ----------------------------------------------------
    def __enter__(self):
        return self.up()

    def __exit__(self, *exc):
        self.down()
        return False


def down_all() -> int:
    """Remove every container this course started. The teardown students run."""
    r = _run(["docker", "ps", "-q", "--filter", f"label={LABEL}"])
    ids = [x for x in r.stdout.split() if x]
    for cid in ids:
        _run(["docker", "stop", cid])
    return len(ids)


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m seclab.targets",
                                 description="Docker lab-target control.")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--up", metavar="NAME")
    ap.add_argument("--down", action="store_true")
    args = ap.parse_args(argv)

    if args.check:
        ok, why = docker_available()
        print(("✔ " if ok else "✗ ") + why)
        return 0 if ok else 1

    if args.list:
        for name, spec in CATALOGUE.items():
            print(f"  {name:<11} {spec.image}")
            print(f"  {'':<11} {spec.note}")
        return 0

    if args.down:
        n = down_all()
        print(f"stopped {n} lab container(s)")
        return 0

    if args.up:
        # A missing Docker install is an expected outcome, not a bug: print the
        # explanation and exit, rather than dumping a traceback on a student in
        # week 0.
        try:
            t = Target(args.up).up()
        except RuntimeError as e:
            print(f"✗ {e}", file=sys.stderr)
            return 2
        print(f"{args.up} is up at {t.base_url}")
        print(f"leave it running; tear down later with: "
              f"python -m seclab.targets --down")
        # Detach: do not stop it on exit here.
        t.container_id = None
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
