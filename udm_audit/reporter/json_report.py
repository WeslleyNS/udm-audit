"""
JSON reporter — gera relatório estruturado para integração com SIEM/ticketing.
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from ..checks.base import Finding, Severity, Status


def generate(
    host_name: str,
    host_addr: str,
    findings: list[Finding],
    output_path: str | None = None,
) -> dict:
    fail_warn = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]

    report = {
        "meta": {
            "tool": "udm-audit",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "host": host_name,
            "address": host_addr,
        },
        "summary": {
            "total_checks": len(findings),
            "critical": sum(1 for f in fail_warn if f.severity == Severity.CRITICAL),
            "high":     sum(1 for f in fail_warn if f.severity == Severity.HIGH),
            "medium":   sum(1 for f in fail_warn if f.severity == Severity.MEDIUM),
            "low":      sum(1 for f in fail_warn if f.severity == Severity.LOW),
            "pass":     sum(1 for f in findings if f.status == Status.PASS),
            "unknown":  sum(1 for f in findings if f.status == Status.UNKNOWN),
        },
        "findings": [f.to_dict() for f in findings],
        "failures": [f.to_dict() for f in fail_warn],
    }

    if output_path:
        Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False))

    return report


def generate_fleet(
    results: dict[str, tuple[str, list[Finding]]],
    output_path: str | None = None,
) -> dict:
    """
    results: {host_name: (host_addr, findings_list)}
    """
    fleet_report = {
        "meta": {
            "tool": "udm-audit",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hosts": len(results),
        },
        "fleet_summary": {},
        "hosts": {},
    }

    total_crit = 0
    for host_name, (host_addr, findings) in results.items():
        host_report = generate(host_name, host_addr, findings)
        fleet_report["hosts"][host_name] = host_report
        s = host_report["summary"]
        fleet_report["fleet_summary"][host_name] = s
        total_crit += s["critical"]

    fleet_report["meta"]["total_critical_findings"] = total_crit

    if output_path:
        Path(output_path).write_text(
            json.dumps(fleet_report, indent=2, ensure_ascii=False)
        )

    return fleet_report
