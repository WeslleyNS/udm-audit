"""
Base class for all security checks — v1.0.2.

``CheckBase`` now receives a ``CommandExecutor`` via dependency injection
instead of a concrete ``paramiko.SSHClient``, making every check agnostic
to whether commands run locally or over an SSH tunnel.
"""
from __future__ import annotations

from typing import Optional

from .models import Finding, Severity, Status
from .executor import CommandExecutor


class CheckBase:
    """Abstract base for all audit checks.

    Subclasses MUST define ``check_id``, ``name``, ``description`` as
    class attributes and implement the ``run()`` method.

    The injected ``executor`` is available as ``self.executor`` and
    exposes a single ``execute(cmd, timeout) -> (stdout, stderr, code)``
    interface regardless of the underlying transport.
    """

    check_id: str = ""
    name: str = ""
    description: str = ""

    def __init__(self, executor: CommandExecutor) -> None:
        self.executor = executor

    def run(self) -> list[Finding]:
        raise NotImplementedError

    # -- convenience: batch execution --

    def exec_multi(self, cmds: list[str]) -> dict[str, tuple[str, str, int]]:
        """Execute *cmds* sequentially, returning ``{cmd: (out, err, code)}``."""
        return {cmd: self.executor.execute(cmd) for cmd in cmds}

    # -- Finding factory helpers (unchanged from v1.0.0) --

    def _pass(self, title: str, detail: str, severity: Severity = Severity.INFO) -> Finding:
        return Finding(self.check_id, title, severity, Status.PASS, detail)

    def _fail(
        self,
        title: str,
        detail: str,
        severity: Severity,
        evidence: str = "",
        remediation: str = "",
        references: Optional[list[str]] = None,
    ) -> Finding:
        return Finding(
            self.check_id, title, severity, Status.FAIL,
            detail, evidence, remediation, references or [],
        )

    def _warn(
        self,
        title: str,
        detail: str,
        severity: Severity,
        evidence: str = "",
        remediation: str = "",
        references: Optional[list[str]] = None,
    ) -> Finding:
        return Finding(
            self.check_id, title, severity, Status.WARN,
            detail, evidence, remediation, references or [],
        )

    def _unknown(self, title: str, detail: str) -> Finding:
        return Finding(self.check_id, title, Severity.INFO, Status.UNKNOWN, detail)
