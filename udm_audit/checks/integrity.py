"""
CHK-008: System Integrity & Malware Persistence
Verifica a integridade de binários do sistema operativo e busca por scripts anômalos
em cronjobs ou init que possam indicar persistência de rootkits/botnets (como Mirai).
"""
from __future__ import annotations
import re
from udm_audit.core.base import CheckBase
from udm_audit.core.models import Finding, Severity, Status


class IntegrityCheck(CheckBase):
    check_id = "CHK-008"
    name = "System Integrity & Persistence"
    description = "Busca por persistência de malwares (cronjobs) e valida integridade de pacotes do sistema"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_dpkg_integrity())
        findings.extend(self._check_cron_persistence())
        findings.extend(self._check_recent_binaries())
        return findings

    def _check_dpkg_integrity(self) -> list[Finding]:
        findings: list[Finding] = []

        # Tenta rodar dpkg -V para pacotes core críticos. 
        # No UniFiOS 3+, o sistema é um Debian.
        dpkg_out, _, code = self.executor.execute(
            "dpkg -V openssh-server sudo bash systemd 2>/dev/null"
        )
        
        if not dpkg_out and code != 0:
            findings.append(self._unknown(
                "Verificação de integridade DPKG falhou",
                "Comando 'dpkg -V' não executou ou pacotes base não foram encontrados. "
                "Dispositivo pode estar usando Alpine (versão legada) ou ambiente containerizado."
            ))
            return findings

        # dpkg -V output lines indicating modification (e.g., '..5...... c /etc/ssh/sshd_config')
        # We care about binary changes (missing 'c' for config files, usually starts with '?5' or '..5')
        # Example format: 
        # ??5?????? c /etc/sudoers
        # ..5......   /bin/bash
        modified_binaries = []
        for line in dpkg_out.splitlines():
            if not line.strip():
                continue
            parts = line.split(maxsplit=2)
            if len(parts) >= 2:
                flags = parts[0]
                # Ignora arquivos de configuração marcados com 'c'
                if len(parts) == 3 and parts[1] == 'c':
                    continue
                
                file_path = parts[-1]
                # Ignora /usr/share/ que frequentemente tem docs, locales e manuais removidos no UniFiOS para poupar espaço
                if file_path.startswith("/usr/share/"):
                    continue
                
                # Se a flag de MD5 ('5') aparecer, o hash foi alterado
                if '5' in flags:
                    modified_binaries.append(line)

        if modified_binaries:
            findings.append(self._fail(
                "Binários críticos do sistema modificados",
                "A verificação do dpkg (hash MD5) indicou que binários base (SSH, bash, etc.) "
                "foram alterados no disco. Isso é um forte indicativo de comprometimento (Rootkit).",
                Severity.CRITICAL,
                "\n".join(modified_binaries),
                "Investigar imediatamente os binários alterados e considerar factory reset "
                "seguido de restore seguro de backup.",
            ))
        elif dpkg_out:
            findings.append(self._pass(
                "Integridade de pacotes base verificada",
                "Hashes dos binários críticos do sistema coincidem com o registro do dpkg."
            ))

        return findings

    def _check_cron_persistence(self) -> list[Finding]:
        findings: list[Finding] = []
        
        # Lê todas as entradas cron ativas (system e root)
        cron_out, _, _ = self.executor.execute(
            "cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/root 2>/dev/null | grep -v '^#' | grep -v '^$'"
        )

        if not cron_out:
            findings.append(self._pass(
                "Cronjobs limpos",
                "Nenhum cronjob ativo encontrado (fora dos comentados/padrões)."
            ))
            return findings

        suspicious_keywords = [
            "curl ", "wget ", "nc ", "netcat", "bash -i", "/dev/tcp/",
            "base64", "chmod +x", "ubnt-systool", "/tmp/"
        ]

        whitelist = [
            "alarms/cleanup",
            "mdns_services.json",
        ]

        suspicious_hits = []
        for line in cron_out.splitlines():
            line_lower = line.lower()
            if any(wl in line_lower for wl in whitelist):
                continue
            
            for kw in suspicious_keywords:
                if kw in line_lower:
                    suspicious_hits.append(line)
                    break

        if suspicious_hits:
            findings.append(self._fail(
                f"Possível persistência de malware no Cron ({len(suspicious_hits)} entrada(s))",
                "Cronjobs encontrados contendo padrões suspeitos (curl/wget, netcat, uso de /tmp). "
                "Malwares de roteadores usam cron para garantir reinfecção.",
                Severity.HIGH,
                "\n".join(suspicious_hits),
                "Revisar manualmente as entradas em /etc/cron.d/ ou /var/spool/cron/crontabs/root e "
                "remover scripts não reconhecidos."
            ))
        else:
            findings.append(self._warn(
                "Cronjobs não-padrões encontrados (Revisão manual recomendada)",
                "Existem entradas de cron ativas. Embora não tenham correspondido a assinaturas de malware, "
                "é recomendado revisar se são legítimas do UniFiOS.",
                Severity.LOW,
                cron_out[:800],
                "Manter apenas cronjobs padrão do sistema."
            ))

        return findings

    def _check_recent_binaries(self) -> list[Finding]:
        findings: list[Finding] = []
        
        # Encontra binários alterados nos últimos 7 dias
        recent_bins, _, _ = self.executor.execute(
            "find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 -exec ls -la {} \\; 2>/dev/null | head -20"
        )

        if recent_bins:
            findings.append(self._warn(
                "Arquivos em diretórios de binários modificados recentemente (<7 dias)",
                "Arquivos de sistema foram criados ou alterados na última semana. Pode ser resultado "
                "de uma atualização de firmware legítima, ou uma instalação silenciosa de backdoor.",
                Severity.LOW,
                recent_bins,
                "Verificar se ocorreu um 'Firmware Update' nos últimos 7 dias. Caso negativo, auditar "
                "os arquivos listados (uso de ubnt-check-upgrade ou logs do dpkg)."
            ))

        return findings
