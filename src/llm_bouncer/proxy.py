"""The egress proxy: Claude Code's sandbox sends every connection a Bash command makes through here.

Set `sandbox.network.httpProxyPort` (and `socksProxyPort`) to the ports below; `llm-bouncer setup`
prints the settings. Each connection is decided by `effects.egress_decision` from the hostname the
client asks for: nothing is resolved, so a blocked `$(cat .env).evil.example` never reaches DNS.
HTTPS is not decrypted, so for HTTPS only the host is known; plain HTTP is also checked by URL.

    llm-bouncer proxy [--port N]       # HTTP proxy on N (default egress.proxy_port), SOCKS5 on N+1

Set LLM_BOUNCER_UPSTREAM_PROXY=http://host:port to send allowed traffic on through another proxy.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import socket
import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from . import effects, ledger, policy

MAX_HEAD = 64 * 1024


def _log(host: str, port: int, decision: policy.Decision, kind: str) -> None:
    try:
        ledger._ensure_dir()
        ledger._append_line(ledger.ledger_dir() / "egress.log", {
            "ts": time.time(), "host": host, "port": port, "via": kind, "action": decision.action, "reason": decision.reason,
        })
    except OSError:
        pass


_POLICY_TTL = 5.0
_policy_at = 0.0
_states: Dict[str, Tuple[float, int, dict]] = {}  # path -> (mtime, size, summary)


def _policy() -> dict:
    """The proxy is long-lived: pick up policy edits within a few seconds, as the hooks do."""
    global _policy_at
    if time.monotonic() - _policy_at > _POLICY_TTL:
        policy._load.cache_clear()
        _policy_at = time.monotonic()
    return policy.load_policy()


def _recent_states(minutes: float) -> Dict[str, dict]:
    """Recently active session summaries, re-parsed only when a file changed.

    Summaries can hold tens of thousands of hashes; parsing all of them on every connection made
    each connection cost more the longer the sessions ran.
    """
    d = ledger.ledger_dir()
    cutoff = time.time() - minutes * 60
    out: Dict[str, dict] = {}
    seen = set()
    for p in d.glob("*.state.json") if d.exists() else []:
        key = str(p)
        try:
            st = p.stat()
        except OSError:
            continue
        if st.st_mtime < cutoff:
            continue
        seen.add(key)
        cached = _states.get(key)
        if not cached or cached[0] != st.st_mtime or cached[1] != st.st_size:
            try:
                summary = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(summary, dict) or not isinstance(summary.get("sources"), dict):
                continue
            _states[key] = cached = (st.st_mtime, st.st_size, summary)
        out[p.name[: -len(".state.json")]] = cached[2]
    for key in set(_states) - seen:
        del _states[key]
    return out


def decide(host: str, port: int, url: Optional[str], kind: str) -> policy.Decision:
    try:
        pol = _policy()
        minutes = float((pol.get("egress") or {}).get("session_window_minutes", 240))
        d = effects.egress_decision(host, url, _recent_states(minutes), pol)
    except Exception as exc:  # fail closed: a broken policy or ledger blocks egress
        d = policy.Decision(policy.DENY, f"llm-bouncer: could not check this connection ({exc}).", ["egress", "error"])
    if d.action != policy.ALLOW or d.risk:
        _log(host, port, d, kind)
    return d


async def _authorize(host: str, port: int, url: Optional[str], kind: str) -> policy.Decision:
    d = decide(host, port, url, kind)
    if d.action == policy.ALLOW:
        reason = await _check_resolution(host, port)
        if reason:
            d = policy.Decision(policy.DENY, reason, ["egress", "local_address"])
            _log(host, port, d, kind)
    return d


def _local_refusal(host: str, addrs: List[str]) -> Optional[str]:
    """Refuse names that resolve to this machine or the cloud metadata range.

    Like Claude Code's built-in proxy: a hostname that resolves only to loopback or link-local
    addresses is a way to reach local services (DNS rebinding), and 169.254.169.254 serves cloud
    credentials. Names in egress.always_allow (localhost, 127.0.0.1 by default) are exempt.
    """
    import ipaddress

    ips = []
    for a in addrs:
        try:
            ips.append(ipaddress.ip_address(a.split("%")[0]))
        except ValueError:
            continue
    if any(ip.is_link_local for ip in ips):
        return f"llm-bouncer: {host} resolves to a link-local address (cloud metadata range)."
    if ips and all(ip.is_loopback or ip.is_unspecified for ip in ips):
        return f"llm-bouncer: {host} resolves to this machine; add it to egress.always_allow if that is intended."
    return None


async def _check_resolution(host: str, port: int) -> Optional[str]:
    pol = _policy()
    allow = (pol.get("egress") or {}).get("always_allow") or []
    if any(fnmatch.fnmatchcase(host.lower(), str(p).lower()) for p in allow) or os.environ.get("LLM_BOUNCER_UPSTREAM_PROXY"):
        return None  # exempt, or the upstream proxy resolves and applies its own rules
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None  # the connection attempt will fail on its own
    return _local_refusal(host, [i[4][0] for i in infos])


async def _open(host: str, port: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    up = os.environ.get("LLM_BOUNCER_UPSTREAM_PROXY")
    if not up:
        return await asyncio.wait_for(asyncio.open_connection(host, port), 30)
    u = urlparse(up)
    r, w = await asyncio.wait_for(asyncio.open_connection(u.hostname, u.port or 8080), 30)
    auth = ""
    if u.username:
        import base64
        from urllib.parse import unquote

        cred = base64.b64encode(f"{unquote(u.username)}:{unquote(u.password or '')}".encode()).decode()
        auth = f"Proxy-Authorization: Basic {cred}\r\n"
    w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{auth}\r\n".encode())
    await w.drain()
    head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 30)
    if b" 200" not in head.split(b"\r\n", 1)[0]:
        w.close()
        raise OSError(f"upstream proxy refused {host}:{port}")
    return r, w


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def _splice(cr, cw, sr, sw) -> None:
    await asyncio.gather(_pipe(cr, sw), _pipe(sr, cw))


def _refusal(d: policy.Decision) -> bytes:
    body = (d.reason or "blocked by llm-bouncer").encode("utf-8", "replace") + b"\n"
    return (
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nX-LLM-Bouncer: blocked\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    )


def _split_hostport(target: str, default: int) -> Tuple[str, int]:
    if target.startswith("["):  # [::1]:443
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default
    host, sep, port = target.rpartition(":")
    if sep and port.isdigit() and host:
        return host, int(port)
    return target, default


async def handle_http(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 30)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ConnectionError):
        cw.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, version = lines[0].split(" ", 2)
    except ValueError:
        cw.close()
        return
    if method.upper() == "CONNECT":
        host, port = _split_hostport(target, 443)
        d = await _authorize(host, port, None, "connect")
        if d.action != policy.ALLOW:
            cw.write(_refusal(d))
            await cw.drain()
            cw.close()
            return
        try:
            sr, sw = await _open(host, port)
        except (OSError, asyncio.TimeoutError) as exc:
            cw.write(f"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\nX-LLM-Bouncer-Error: {type(exc).__name__}\r\n\r\n".encode())
            cw.close()
            return
        cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await cw.drain()
        await _splice(cr, cw, sr, sw)
        return
    # Plain HTTP with an absolute URL: the full URL is visible, so it is checked too.
    u = urlparse(target)
    if u.scheme != "http" or not u.hostname:
        cw.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        cw.close()
        return
    host, port = u.hostname, u.port or 80
    d = await _authorize(host, port, target, "http")
    if d.action != policy.ALLOW:
        cw.write(_refusal(d))
        await cw.drain()
        cw.close()
        return
    try:
        sr, sw = await _open(host, port)
    except (OSError, asyncio.TimeoutError):
        cw.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        cw.close()
        return
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    # One request per connection: a kept-alive connection could carry a second, unchecked URL.
    headers = [h for h in lines[1:] if h and not h.lower().startswith(("proxy-", "connection:", "keep-alive:"))]
    out = f"{method} {path} {version}\r\n" + "\r\n".join(headers + ["Connection: close"]) + "\r\n\r\n"
    sw.write(out.encode("latin-1"))
    await sw.drain()
    await _splice(cr, cw, sr, sw)


async def handle_socks(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
    """SOCKS5, CONNECT only, no authentication."""
    try:
        ver, n = await cr.readexactly(2)
        await cr.readexactly(n)
        if ver != 5:
            cw.close()
            return
        cw.write(b"\x05\x00")
        await cw.drain()
        ver, cmd, _, atyp = await cr.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, await cr.readexactly(4))
        elif atyp == 3:
            ln = (await cr.readexactly(1))[0]
            host = (await cr.readexactly(ln)).decode("ascii", "replace")  # on the wire, names are ASCII (punycode)
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await cr.readexactly(16))
        else:
            cw.close()
            return
        port = int.from_bytes(await cr.readexactly(2), "big")
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        cw.close()
        return
    fail = b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"  # "connection not allowed by ruleset"
    if cmd != 1:
        cw.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        cw.close()
        return
    d = await _authorize(host, port, None, "socks")
    if d.action != policy.ALLOW:
        cw.write(fail)
        await cw.drain()
        cw.close()
        return
    try:
        sr, sw = await _open(host, port)
    except (OSError, asyncio.TimeoutError):
        cw.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        cw.close()
        return
    cw.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await cw.drain()
    await _splice(cr, cw, sr, sw)


async def serve(port: int, host: str = "127.0.0.1", ready: Optional[asyncio.Event] = None) -> None:
    http = await asyncio.start_server(handle_http, host, port, limit=MAX_HEAD)
    socks = await asyncio.start_server(handle_socks, host, port + 1)
    if ready is not None:
        ready.set()
    async with http, socks:
        await asyncio.gather(http.serve_forever(), socks.serve_forever())


def is_running(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def main(args: List[str]) -> int:
    port = int((policy.load_policy().get("egress") or {}).get("proxy_port", 18877))
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    print(f"llm-bouncer proxy: HTTP on 127.0.0.1:{port}, SOCKS5 on 127.0.0.1:{port + 1}", file=sys.stderr)
    try:
        asyncio.run(serve(port))
    except KeyboardInterrupt:
        pass
    return 0
