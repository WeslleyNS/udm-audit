from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import paramiko


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def order(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    def __lt__(self, other: "Severity") -> bool:
        return self.order < other.order


class Status(str, Enum):
    FAIL = "FAIL"
    WARN = "WARN"
    PASS = "PASS"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    status: Status
    detail: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


class SSHClient:
    """Thin wrapper over paramiko with exec helper."""

    def __init__(self, client: paramiko.SSHClient):
        self._client = client

    def exec(self, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
        """Execute command. Returns (stdout, stderr, exit_code)."""
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            code = stdout.channel.recv_exit_status()
            return out, err, code
        except Exception as exc:
            return "", str(exc), -1

    def exec_multi(self, cmds: list[str]) -> dict[str, tuple[str, str, int]]:
        return {cmd: self.exec(cmd) for cmd in cmds}


class CheckBase:
    check_id: str = ""
    name: str = ""
    description: str = ""

    def __init__(self, ssh: SSHClient):
        self.ssh = ssh

    def run(self) -> list[Finding]:
        raise NotImplementedError

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
