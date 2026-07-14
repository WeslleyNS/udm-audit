"""
Command execution strategies for udm-audit — v1.0.2.

Implements the Strategy pattern via a ``CommandExecutor`` Protocol and three
concrete implementations:

* **LocalExecutor**  — runs commands on the local shell via ``subprocess.run``
  (for analysts already inside the UDM terminal).
* **SSHExecutor**    — runs commands over an SSH session (paramiko).
* **CachedExecutor** — decorator that keeps an in-memory dict of already-seen
  commands, avoiding redundant execution within the same audit session.
"""
from __future__ import annotations

import subprocess
from typing import Protocol, runtime_checkable

import paramiko


# ---------------------------------------------------------------------------
# Protocol (interface)
# ---------------------------------------------------------------------------

@runtime_checkable
class CommandExecutor(Protocol):
    """Contract for all command-execution strategies."""

    def execute(self, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
        """Execute *cmd* and return ``(stdout, stderr, exit_code)``."""
        ...


# ---------------------------------------------------------------------------
# Strategy: local execution (subprocess)
# ---------------------------------------------------------------------------

class LocalExecutor:
    """Execute commands locally via ``subprocess.run``.

    Designed for use when the analyst is already inside the UDM Pro
    terminal and no SSH hop is required.  Returns POSIX exit-code 124
    on timeout (consistent with coreutils ``timeout`` command).
    """

    def execute(self, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return (
                result.stdout.strip(),
                result.stderr.strip(),
                result.returncode,
            )
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", 124
        except Exception as exc:
            return "", str(exc), -1


# ---------------------------------------------------------------------------
# Strategy: remote execution (SSH / paramiko)
# ---------------------------------------------------------------------------

class SSHExecutor:
    """Execute commands over an SSH connection using *paramiko*.

    This is the same logic previously found in ``SSHClient.exec``, now
    extracted into a standalone strategy that satisfies the
    ``CommandExecutor`` protocol.
    """

    def __init__(self, client: paramiko.SSHClient) -> None:
        self._client = client

    def execute(self, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            code = stdout.channel.recv_exit_status()
            return out, err, code
        except Exception as exc:
            return "", str(exc), -1


# ---------------------------------------------------------------------------
# Decorator: in-memory cache
# ---------------------------------------------------------------------------

class CachedExecutor:
    """Decorator that caches command results in memory for the session.

    Many checks read the same files (e.g. ``/etc/ssh/sshd_config``,
    ``ss -tlnp``).  Wrapping the real executor in ``CachedExecutor``
    avoids duplicate round-trips — especially relevant over SSH.

    The cache key is the **exact command string**; the cache never
    expires within a single audit session.
    """

    def __init__(self, executor: CommandExecutor) -> None:
        self._executor = executor
        self._cache: dict[str, tuple[str, str, int]] = {}
        self._hits: int = 0
        self._misses: int = 0

    def execute(self, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
        if cmd in self._cache:
            self._hits += 1
            return self._cache[cmd]
        self._misses += 1
        result = self._executor.execute(cmd, timeout)
        self._cache[cmd] = result
        return result

    # -- introspection helpers (useful for debug / verbose mode) --

    @property
    def stats(self) -> dict[str, int]:
        """Return cache hit/miss counters."""
        return {
            "cached_commands": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
        }

    def clear(self) -> None:
        """Flush the cache (e.g. between hosts in a fleet run)."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
