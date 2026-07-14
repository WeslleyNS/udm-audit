"""
Data models for udm-audit findings.

Moved from udm_audit.checks.base — v1.0.2.
The dataclasses Finding, Severity and Status are intentionally kept
unchanged to preserve backward compatibility with existing JSON reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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
