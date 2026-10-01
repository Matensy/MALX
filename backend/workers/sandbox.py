"""Best-effort hardening applied inside each analysis worker process.

The worker never executes samples; these measures limit the blast radius of a
*parser* bug triggered by a hostile file:

* RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE / RLIMIT_NOFILE / RLIMIT_CORE
* umask 077, scratch working directory, minimal environment
* PR_SET_NO_NEW_PRIVS (Linux)
* a private network namespace when permitted (root/CAP_SYS_ADMIN), otherwise a
  socket guard that refuses outbound connections from Python code in the worker

Containers or VMs add stronger isolation; see docs/security.md.
"""

from __future__ import annotations

import ctypes
import os
import socket
import sys
from typing import Any

CLONE_NEWNET = 0x40000000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE = 4


def _libc():
    try:
        return ctypes.CDLL(None, use_errno=True)
    except OSError:  # pragma: no cover
        return None


def apply_limits(memory_bytes: int, cpu_seconds: int, max_file_bytes: int) -> dict[str, Any]:
    status: dict[str, Any] = {}
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        status["rlimits"] = "unavailable"
        return status

    def setlim(name: str, value: int) -> None:
        lim = getattr(resource, name, None)
        if lim is None:
            return
        try:
            soft, hard = resource.getrlimit(lim)
            new_hard = value if hard == resource.RLIM_INFINITY else min(hard, value)
            resource.setrlimit(lim, (min(value, new_hard), new_hard))
            status[name] = value
        except (ValueError, OSError) as exc:
            status[name] = f"failed: {exc}"

    setlim("RLIMIT_AS", memory_bytes)
    setlim("RLIMIT_CPU", cpu_seconds)
    setlim("RLIMIT_FSIZE", max_file_bytes)
    setlim("RLIMIT_NOFILE", 512)
    setlim("RLIMIT_CORE", 0)
    return status


def drop_privileges_and_network() -> dict[str, Any]:
    status: dict[str, Any] = {}
    os.umask(0o077)
    libc = _libc() if sys.platform.startswith("linux") else None
    if libc is not None:
        try:
            status["no_new_privs"] = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except Exception:  # pragma: no cover
            status["no_new_privs"] = False
        try:
            status["network_namespace"] = libc.unshare(CLONE_NEWNET) == 0
        except Exception:  # pragma: no cover
            status["network_namespace"] = False
    if not status.get("network_namespace"):
        _install_socket_guard()
        status["socket_guard"] = True
    return status


class NetworkDisabled(OSError):
    pass


def _install_socket_guard() -> None:
    def _blocked(*_a, **_k):
        raise NetworkDisabled("network access is disabled inside MALX analysis workers")

    socket.socket.connect = _blocked  # type: ignore[assignment]
    socket.socket.connect_ex = _blocked  # type: ignore[assignment]
    socket.create_connection = _blocked  # type: ignore[assignment]
    socket.getaddrinfo = _blocked  # type: ignore[assignment]


def minimal_environment(tmp_dir: str) -> None:
    keep = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "PYTHONPATH", "MALX_CONFIG", "JAVA_HOME", "GHIDRA_HOME") if k in os.environ}
    os.environ.clear()
    os.environ.update(keep)
    os.environ["HOME"] = tmp_dir
    os.environ["TMPDIR"] = tmp_dir
    os.chdir(tmp_dir)
