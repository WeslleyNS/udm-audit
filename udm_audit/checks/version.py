"""
CHK-001: Version check
Compares UniFiOS and UniFi Network Application versions against known vulnerable ranges.
"""
from __future__ import annotations
import re
from .base import CheckBase, Finding, Severity, Status

# Minimum safe versions per component.
# Key: component name. Value: (min_safe_version_tuple, CVEs_fixed, advisory_note)
KNOWN_VULNERABLE = {
    "unifios": {
        # Local privilege escalation via sudo misconfiguration
        "3.2.17": ("CVE-2024-42028-like", "Upgrade to UniFiOS >= 4.0.6"),
        "4.0.5":  ("CVE-2024-42028-like", "Upgrade to UniFiOS >= 4.0.6"),
    },
    "network_app": {
        # SSRF (CVE-2021-22908), XSS (CVE-2021-22910), privesc (CVE-2021-22909)
        "6.0.0": ("CVE-2021-22908,CVE-2021-22909,CVE-2021-22910", "Upgrade to >= 6.5.x"),
        # SQL Injection
        "7.4.161": ("CVE-2023-35807", "Upgrade to >= 7.4.162"),
    },
}

# Tuples (max_vulnerable, cves, note) — any version <= max_vulnerable is affected
VULN_RANGES = {
    "unifios": [
        ((4, 0, 5),  "Local privesc / container escape", "Upgrade to UniFiOS >= 4.0.6",
         ["CVE-2024-42028"]),
    ],
    "network_app": [
        ((6, 4, 99), "SSRF não autenticado + privilege escalation + XSS",
         "Upgrade para Network Application >= 6.5.x",
         ["CVE-2021-22908", "CVE-2021-22909", "CVE-2021-22910"]),
        ((7, 4, 161), "SQL Injection — usuário autenticado pode extrair dados",
         "Upgrade para Network Application >= 7.4.162",
         ["CVE-2023-35807"]),
    ],
}


def _parse_version(ver_str: str) -> tuple[int, ...] | None:
    """Extract numeric version tuple from string like '3.2.17' or 'v4.0.5-build123'."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
    if m:
        return tuple(int(x) for x in m.groups())
    return None


class VersionCheck(CheckBase):
    check_id = "CHK-001"
    name = "Version / CVE Check"
    description = "Detecta versões do UniFiOS e Network App com CVEs conhecidas"

    # Commands to try for UniFiOS version (in order)
    _OS_VERSION_CMDS = [
        "ubnt-device-info firmware 2>/dev/null",
        "cat /etc/unifi-os/version 2>/dev/null",
        "cat /etc/os-release 2>/dev/null | grep -i 'version=' | head -1",
    ]

    # Commands to try for Network App version
    _APP_VERSION_CMDS = [
        "cat /data/unifi/data/db/version 2>/dev/null",
        "find /usr/lib/unifi -name 'unifi.jar' 2>/dev/null | xargs -I{} unzip -p {} META-INF/MANIFEST.MF 2>/dev/null | grep -i 'Implementation-Version'",
        "grep -r 'unifi.version\\|app.version' /data/unifi/data/system.properties 2>/dev/null | head -3",
        # API local (acessível dentro do device)
        "curl -sk http://localhost:8080/api/self 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('data',[{}])[0].get('server_version',''))\" 2>/dev/null",
    ]

    def _get_os_version(self) -> tuple[str, str]:
        """Returns (raw_string, source_cmd)."""
        for cmd in self._OS_VERSION_CMDS:
            out, _, code = self.ssh.exec(cmd)
            if out and code == 0:
                return out, cmd
        return "", ""

    def _get_app_version(self) -> tuple[str, str]:
        for cmd in self._APP_VERSION_CMDS:
            out, _, code = self.ssh.exec(cmd)
            if out and code == 0:
                return out, cmd
        return "", ""

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # --- UniFiOS ---
        os_raw, os_src = self._get_os_version()
        if not os_raw:
            findings.append(self._unknown(
                "Versão UniFiOS não detectada",
                "Não foi possível determinar a versão do UniFiOS via comandos conhecidos. "
                "Verifique manualmente com: ubnt-device-info firmware"
            ))
        else:
            os_ver = _parse_version(os_raw)
            evidence = f"Fonte: {os_src}\nOutput: {os_raw}"

            if os_ver is None:
                findings.append(self._warn(
                    "Versão UniFiOS com formato inesperado",
                    f"Output obtido mas versão não parseável: {os_raw!r}",
                    Severity.LOW, evidence,
                ))
            else:
                ver_str = ".".join(str(x) for x in os_ver)
                vuln_hits = []
                for (max_vuln, desc, remediation, cves) in VULN_RANGES["unifios"]:
                    if os_ver <= max_vuln:
                        vuln_hits.append((desc, remediation, cves))

                if vuln_hits:
                    all_cves = [c for _, _, cves in vuln_hits for c in cves]
                    all_remediations = "; ".join(r for _, r, _ in vuln_hits)
                    findings.append(self._fail(
                        f"UniFiOS {ver_str} — versão vulnerável",
                        f"Versão {ver_str} está dentro do range de pelo menos "
                        f"{len(vuln_hits)} CVE(s) conhecida(s): "
                        + ", ".join(d for d, _, _ in vuln_hits),
                        Severity.HIGH,
                        evidence,
                        all_remediations,
                        all_cves,
                    ))
                else:
                    findings.append(self._pass(
                        f"UniFiOS {ver_str} — sem CVEs conhecidas nesta versão",
                        f"Versão {ver_str} não identificada em ranges vulneráveis conhecidos. "
                        "Confirme sempre no NVD e advisories Ubiquiti.",
                    ))

        # --- Network Application ---
        app_raw, app_src = self._get_app_version()
        if not app_raw:
            findings.append(self._unknown(
                "Versão Network Application não detectada",
                "Não foi possível determinar a versão do UniFi Network App. "
                "Verifique via painel web: Settings → System → Updates"
            ))
        else:
            app_ver = _parse_version(app_raw)
            evidence = f"Fonte: {app_src}\nOutput: {app_raw}"

            if app_ver is None:
                findings.append(self._warn(
                    "Versão Network App com formato inesperado",
                    f"Output obtido mas versão não parseável: {app_raw!r}",
                    Severity.LOW, evidence,
                ))
            else:
                ver_str = ".".join(str(x) for x in app_ver)
                vuln_hits = []
                for (max_vuln, desc, remediation, cves) in VULN_RANGES["network_app"]:
                    if app_ver <= max_vuln:
                        vuln_hits.append((desc, remediation, cves))

                if vuln_hits:
                    all_cves = [c for _, _, cves in vuln_hits for c in cves]
                    all_remediations = "; ".join(r for _, r, _ in vuln_hits)
                    # Highest severity if SSRF/RCE range
                    sev = Severity.CRITICAL if app_ver <= (6, 4, 99) else Severity.HIGH
                    findings.append(self._fail(
                        f"Network App {ver_str} — versão vulnerável",
                        f"Versão {ver_str} está dentro do range de {len(vuln_hits)} "
                        "CVE(s) conhecida(s): "
                        + ", ".join(d for d, _, _ in vuln_hits),
                        sev,
                        evidence,
                        all_remediations,
                        all_cves,
                    ))
                else:
                    findings.append(self._pass(
                        f"Network App {ver_str} — sem CVEs conhecidas nesta versão",
                        f"Versão {ver_str} não identificada em ranges vulneráveis conhecidos.",
                    ))

        return findings
