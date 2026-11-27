import json
import threading
import urllib.parse
import urllib.request

from seclab.targets import Target

_target: Target | None = None
_lock = threading.Lock()


def serve() -> str:
    global _target
    with _lock:
        if _target is None:
            _target = Target("vuln-web").up()
    return _target.base_url


def down() -> None:
    global _target
    with _lock:
        if _target is not None:
            _target.down()
            _target = None


def _get(path: str) -> str:
    with urllib.request.urlopen(serve() + path, timeout=10) as r:
        return r.read().decode()


def _post(path: str, obj: dict) -> str:
    req = urllib.request.Request(
        serve() + path,
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()


def login_send(user_payload: str) -> str:
    return _post("/login", {"user": user_payload, "pw": "x"})


def reflect_send(name_payload: str) -> str:
    return _get("/?name=" + urllib.parse.quote(name_payload))


def reflect_safe_send(name_payload: str) -> str:
    return _get("/safe?name=" + urllib.parse.quote(name_payload))


def ping_send(host_payload: str) -> str:
    return _post("/ping", {"host": host_payload})
