"""
Backward-compatibility shim — v1.0.2.

All public names have been moved to ``udm_audit.core``.
This module re-exports them so that external consumers and legacy
scripts continue to work without changes.

.. deprecated:: 1.0.2
    Import directly from ``udm_audit.core`` instead.
"""
from udm_audit.core.models import Finding, Severity, Status
from udm_audit.core.base import CheckBase
from udm_audit.core.executor import CommandExecutor, SSHExecutor

import paramiko


class SSHClient(SSHExecutor):
    """Legacy wrapper kept for backward compatibility.

    New code should use ``SSHExecutor`` directly.  This subclass adds
    the old ``.exec()`` / ``.exec_multi()`` names that existing scripts
    may reference.
    """

    def __init__(self, client: paramiko.SSHClient) -> None:
        super().__init__(client)

    def exec(self, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
        """Old-style alias → delegates to ``execute``."""
        return self.execute(cmd, timeout)

    def exec_multi(self, cmds: list[str]) -> dict[str, tuple[str, str, int]]:
        return {cmd: self.execute(cmd) for cmd in cmds}


__all__ = [
    "Finding", "Severity", "Status", "CheckBase",
    "CommandExecutor", "SSHExecutor", "SSHClient",
]
