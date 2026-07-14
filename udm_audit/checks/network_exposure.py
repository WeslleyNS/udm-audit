"""
CHK-005: Network Exposure
Verifica serviços expostos, portas abertas e configuração de firewall local.
"""
from __future__ import annotations
import re
from .base import CheckBase, Finding, Severity, Status


class NetworkExposureCheck(CheckBase):
    check_id = "CHK-005"
    name = "Network Exposure"
    description = "Verifica portas abertas, serviços expostos e regras de firewall locais"

    # Portas que não deveriam estar acessíveis externamente
    RISKY_PORTS = {
        "8443": ("UniFi Network App (legacy HTTPS)", Severity.HIGH),
        "8080": ("UniFi Network App (HTTP)", Severity.HIGH),
        "27117": ("MongoDB interno", Severity.CRITICAL),
        "6789": ("UniFi throughput test", Severity.MEDIUM),
        "10001": ("UniFi device discovery (UDP)", Severity.HIGH),
        "22":   ("SSH", Severity.MEDIUM),  # MEDIUM porque depende de context
        "1900": ("SSDP/UPnP", Severity.MEDIUM),
    }

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Lista portas em escuta
        ss_out, _, _ = self.ssh.exec("ss -tlnp 2>/dev/null; ss -ulnp 2>/dev/null")
        if not ss_out:
            ss_out, _, _ = self.ssh.exec("netstat -tlunp 2>/dev/null")

        if not ss_out:
            findings.append(self._unknown(
                "Portas em escuta não detectáveis",
                "ss/netstat não disponível ou sem permissão."
            ))
            return findings

        # Portas abertas em 0.0.0.0 (todas interfaces)
        open_on_all = re.findall(
            r"(?:0\.0\.0\.0|::|\*):(\d+)\s", ss_out
        )

        risky_found = []
        for port in set(open_on_all):
            if port in self.RISKY_PORTS:
                desc, sev = self.RISKY_PORTS[port]
                risky_found.append((port, desc, sev))

        # MongoDB exposto é crítico — direto
        if "27117" in open_on_all:
            findings.append(self._fail(
                "MongoDB (27117) acessível em todas as interfaces",
                "MongoDB do UniFi exposto em 0.0.0.0:27117. Sem autenticação por padrão "
                "em versões antigas. Acesso direto ao banco = dump completo de configs, "
                "credenciais e informações de dispositivos.",
                Severity.CRITICAL,
                next((l for l in ss_out.splitlines() if "27117" in l), ""),
                "Bind MongoDB apenas em 127.0.0.1:\n"
                "  Editar /data/unifi/data/system.properties:\n"
                "  db.mongo.local=true\n"
                "  db.mongo.host=127.0.0.1"
            ))

        for port, desc, sev in risky_found:
            if port == "27117":
                continue  # já tratado acima
            evidence = next((l for l in ss_out.splitlines() if f":{port}" in l), "")
            findings.append(self._warn(
                f"Porta {port} ({desc}) acessível em todas as interfaces",
                f"Serviço '{desc}' escutando em 0.0.0.0:{port}. "
                "Dependendo da exposição de rede, pode ser acessível da WAN.",
                sev,
                evidence,
                f"Verificar se porta {port} está bloqueada no firewall upstream/WAN. "
                "Considerar bind em interface específica de gerenciamento."
            ))

        if not risky_found:
            findings.append(self._pass(
                "Nenhuma porta de alto risco exposta em 0.0.0.0",
                "Portas críticas não detectadas em escuta em todas as interfaces.",
            ))

        # Resumo geral de portas abertas
        findings.append(Finding(
            self.check_id,
            f"Portas em escuta: {len(set(open_on_all))} detectadas",
            Severity.INFO, Status.PASS,
            "Lista de todas as portas em escuta em 0.0.0.0/any.",
            ss_out[:600] + ("..." if len(ss_out) > 600 else ""),
        ))

        # Verifica iptables/nftables
        findings.extend(self._check_firewall())

        return findings

    def _check_firewall(self) -> list[Finding]:
        findings: list[Finding] = []

        ipt, _, _ = self.ssh.exec("iptables -L INPUT -n --line-numbers 2>/dev/null | head -30")
        nft, _, _ = self.ssh.exec("nft list ruleset 2>/dev/null | head -50")

        if not ipt and not nft:
            findings.append(self._warn(
                "Firewall local não acessível",
                "iptables e nft não retornaram output. Não foi possível verificar regras locais.",
                Severity.MEDIUM,
                "",
                "Verificar manualmente com: iptables -L -n ou nft list ruleset"
            ))
            return findings

        # Verifica se há ACCEPT all na chain INPUT sem restrição
        if ipt and re.search(r"ACCEPT\s+all\s+--\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0\s*$", ipt, re.MULTILINE):
            findings.append(self._warn(
                "iptables INPUT: regra ACCEPT all sem restrição",
                "Há uma regra aceitando todo tráfego na chain INPUT sem match específico. "
                "Verificar se é esperado ou se a política padrão deveria ser DROP.",
                Severity.MEDIUM,
                ipt,
                "Revisar política padrão: iptables -P INPUT DROP\n"
                "e adicionar regras explícitas para tráfego legítimo."
            ))

        return findings


# ======================================================================

"""
CHK-006: Update Status
Verifica se o dispositivo está atualizado e com auto-update configurado.
"""


class UpdateStatusCheck(CheckBase):
    check_id = "CHK-006"
    name = "Update Status"
    description = "Verifica status de atualizações e data do último update"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # Verifica se há atualização disponível
        upgrade_check, _, code = self.ssh.exec("ubnt-check-upgrade 2>/dev/null")
        if code == 0 and upgrade_check:
            if "upgrade" in upgrade_check.lower() or "available" in upgrade_check.lower():
                findings.append(self._fail(
                    "Atualização disponível para UniFiOS",
                    "O sistema identificou uma atualização disponível. "
                    "Manter UniFiOS atualizado é a mitigação mais efetiva para a maioria das CVEs.",
                    Severity.HIGH,
                    upgrade_check,
                    "Aplicar atualização via painel UniFi: Settings → System → Updates\n"
                    "Ou via CLI: ubnt-upgrade <firmware_url>"
                ))
            else:
                findings.append(self._pass(
                    "UniFiOS atualizado (sem upgrade disponível)",
                    upgrade_check or "Nenhuma atualização pendente detectada."
                ))

        # Verifica auto-updates do apt (Debian base)
        auto_upgrade, _, _ = self.ssh.exec(
            "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || "
            "cat /etc/apt/apt.conf.d/10periodic 2>/dev/null"
        )
        if auto_upgrade:
            if 'Unattended-Upgrade "1"' in auto_upgrade:
                findings.append(self._pass(
                    "Auto-upgrades do sistema (apt) habilitados",
                    "Unattended upgrades configurados para pacotes base Debian."
                ))
        else:
            findings.append(self._warn(
                "Auto-upgrade apt não verificável / não configurado",
                "Não foi possível confirmar configuração de auto-upgrades Debian. "
                "No UDM Pro, updates do firmware são gerenciados pelo UniFiOS, não pelo apt diretamente.",
                Severity.LOW,
                "",
                "Garantir que updates do UniFiOS são aplicados regularmente via painel ou automação."
            ))

        # Últimos logins — detecta atividade suspeita
        last_logins, _, _ = self.ssh.exec("last -n 15 2>/dev/null | head -15")
        if last_logins:
            findings.append(Finding(
                self.check_id,
                "Últimos 15 logins no sistema",
                Severity.INFO, Status.PASS,
                "Revisar por IPs ou usuários não reconhecidos.",
                last_logins,
            ))

        return findings


# ======================================================================

"""
CHK-007: Logging Configuration
Verifica se logs estão sendo enviados para destino remoto e configuração de retenção.
"""


class LoggingConfigCheck(CheckBase):
    check_id = "CHK-007"
    name = "Logging Configuration"
    description = "Verifica configuração de syslog remoto e retenção de logs"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # rsyslog
        rsyslog, _, _ = self.ssh.exec(
            "cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        )

        # syslog-ng
        syslog_ng, _, _ = self.ssh.exec("cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null")

        combined = "\n".join(filter(None, [rsyslog, syslog_ng]))

        if not combined:
            findings.append(self._warn(
                "Configuração de syslog não encontrada",
                "Nenhum rsyslog.conf ou syslog-ng.conf encontrado.",
                Severity.MEDIUM,
                "",
                "Configurar rsyslog para envio remoto via painel UniFi: "
                "Settings → System → Remote Logging"
            ))
            return findings

        # Verifica se há destino remoto configurado (@@host ou @host para UDP)
        remote_targets = re.findall(r"@@?[\w\d\.\-]+(?::\d+)?", combined)
        if remote_targets:
            findings.append(self._pass(
                f"Syslog remoto configurado ({len(remote_targets)} destino(s))",
                f"Logs sendo enviados para: {', '.join(remote_targets)}\n"
                "Logs remotos são críticos para forense em caso de compromisso do device."
            ))
        else:
            findings.append(self._fail(
                "Syslog remoto NÃO configurado",
                "Logs do sistema ficam apenas no device. Se o UDM Pro for comprometido, "
                "o atacante pode apagar logs locais — sem evidência forense.",
                Severity.HIGH,
                "Nenhum destino remoto encontrado no rsyslog.conf",
                "Configurar syslog remoto:\n"
                "1. Painel UniFi: Settings → System → Remote Logging\n"
                "2. Ou direto no rsyslog.conf:\n"
                "   *.* @@syslog-server:514  (TCP)\n"
                "   *.* @syslog-server:514   (UDP)"
            ))

        # Verifica se journald está persistindo logs
        journald, _, _ = self.ssh.exec("cat /etc/systemd/journald.conf 2>/dev/null | grep -i storage")
        if journald:
            if "volatile" in journald.lower():
                findings.append(self._warn(
                    "journald com storage volatile (logs perdidos no reboot)",
                    "Logs do systemd não persistem entre reboots.",
                    Severity.MEDIUM,
                    journald,
                    "Editar /etc/systemd/journald.conf:\n  Storage=persistent"
                ))

        return findings
