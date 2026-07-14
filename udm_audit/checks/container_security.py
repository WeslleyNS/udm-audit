"""
CHK-004: Container Security
Verifica configuração de containers no UniFiOS (podman) e risco de escape.
"""
from __future__ import annotations
import json
import re
from .base import CheckBase, Finding, Severity, Status

# Capabilities que permitem escape de container
DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN": "Permite mount, modificação de namespaces, carregamento de módulos kernel",
    "CAP_NET_ADMIN": "Permite modificar interfaces, rotas, firewall rules do host",
    "CAP_SYS_PTRACE": "Permite rastrear processos do host fora do container",
    "CAP_DAC_OVERRIDE": "Bypass de permissões de arquivo — acesso a qualquer arquivo",
    "CAP_SYS_MODULE": "Permite carregar módulos kernel",
    "CAP_SYS_RAWIO": "Acesso direto a dispositivos de hardware",
}


class ContainerSecurityCheck(CheckBase):
    check_id = "CHK-004"
    name = "Container Security"
    description = "Verifica capabilities, volumes e sudo rules que permitem escape de container"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sudo())
        findings.extend(self._check_containers())
        return findings

    def _check_sudo(self) -> list[Finding]:
        findings: list[Finding] = []

        sudo_l, _, code = self.ssh.exec("sudo -l 2>/dev/null")
        sudoers, _, _ = self.ssh.exec("cat /etc/sudoers 2>/dev/null")
        sudoers_d, _, _ = self.ssh.exec("cat /etc/sudoers.d/* 2>/dev/null")

        all_sudo = "\n".join(filter(None, [sudo_l, sudoers, sudoers_d]))

        if not all_sudo:
            findings.append(self._unknown(
                "Regras sudo não acessíveis",
                "Não foi possível ler configurações sudo. Execute como root para verificar."
            ))
            return findings

        # NOPASSWD com comandos perigosos
        nopasswd_lines = re.findall(
            r"^[^#].*NOPASSWD.*$", all_sudo, re.MULTILINE | re.IGNORECASE
        )

        dangerous_nopasswd = []
        for line in nopasswd_lines:
            # Wildcard = execução arbitrária
            if re.search(r"ALL\s*=.*ALL|NOPASSWD\s*:\s*ALL", line, re.IGNORECASE):
                dangerous_nopasswd.append((line, "NOPASSWD: ALL — execução de qualquer comando sem senha"))
            elif re.search(r"\*|/bin/sh|/bin/bash|/usr/bin/python|/bin/cp\s+\*", line):
                dangerous_nopasswd.append((line, "Wildcard ou shell — permite execução arbitrária"))
            elif "vim" in line or "nano" in line or "less" in line or "man" in line:
                dangerous_nopasswd.append((line, "Editor de texto com sudo = shell root via :!bash"))

        if dangerous_nopasswd:
            evidence = "\n".join(f"[{note}]\n  {line}" for line, note in dangerous_nopasswd)
            findings.append(self._fail(
                f"Sudo: {len(dangerous_nopasswd)} regra(s) NOPASSWD perigosa(s)",
                "Regras sudo sem senha com comandos que permitem privilege escalation ou "
                "execução arbitrária. Vetor principal do container escape no UniFiOS.",
                Severity.CRITICAL,
                evidence,
                "Revisar /etc/sudoers e /etc/sudoers.d/. Remover entradas NOPASSWD desnecessárias. "
                "Nunca usar wildcards (*) em regras sudo.",
                ["CVE-2024-42028"],
            ))
        elif nopasswd_lines:
            findings.append(self._warn(
                f"Sudo: {len(nopasswd_lines)} regra(s) NOPASSWD (revisar manualmente)",
                "Regras NOPASSWD presentes mas não identificadas como imediatamente exploráveis. "
                "Revisar manualmente.",
                Severity.MEDIUM,
                "\n".join(nopasswd_lines),
                "Princípio de menor privilégio: cada regra NOPASSWD deve ser justificada."
            ))
        else:
            findings.append(self._pass(
                "Sudo: nenhuma regra NOPASSWD obviamente perigosa",
                "Regras sudo sem wildcards ou comandos de shell direto."
            ))

        return findings

    def _check_containers(self) -> list[Finding]:
        findings: list[Finding] = []

        containers, _, code = self.ssh.exec(
            "podman ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null || "
            "docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null"
        )

        if not containers or code != 0:
            findings.append(self._unknown(
                "Containers não listados",
                "podman/docker não acessível ou nenhum container rodando."
            ))
            return findings

        container_list = [l.split() for l in containers.splitlines() if l.strip()]
        findings.append(Finding(
            self.check_id,
            f"{len(container_list)} container(s) rodando",
            Severity.INFO, Status.PASS,
            "Containers ativos no UniFiOS.",
            containers,
        ))

        for parts in container_list:
            if len(parts) < 3:
                continue
            cid, image, name = parts[0], parts[1], parts[2]

            inspect_out, _, _ = self.ssh.exec(
                f"podman inspect {cid} 2>/dev/null || docker inspect {cid} 2>/dev/null"
            )
            if not inspect_out:
                continue

            try:
                data = json.loads(inspect_out)
                if not data:
                    continue
                cfg = data[0]
            except (json.JSONDecodeError, IndexError):
                continue

            host_cfg = cfg.get("HostConfig", {})

            # Privileged mode
            if host_cfg.get("Privileged"):
                findings.append(self._fail(
                    f"Container '{name}' rodando em modo privilegiado",
                    "Modo privilegiado = acesso completo ao host. Equivale a root no host sem container.",
                    Severity.CRITICAL,
                    f"Container: {name} ({image})\nPrivileged: true",
                    "Remover --privileged. Usar capabilities específicas necessárias.",
                ))

            # Capabilities perigosas
            cap_add = host_cfg.get("CapAdd") or []
            dangerous = [(c, DANGEROUS_CAPS[c]) for c in cap_add if c in DANGEROUS_CAPS]
            if dangerous:
                findings.append(self._fail(
                    f"Container '{name}': {len(dangerous)} capability(ies) perigosa(s)",
                    "Capabilities que permitem escape de container para o host.",
                    Severity.HIGH,
                    "\n".join(f"  {c}: {d}" for c, d in dangerous),
                    "Remover capabilities desnecessárias. "
                    "Revisar se o serviço realmente precisa de cada capability.",
                    ["CVE-2024-42028"],
                ))

            # Volumes com acesso ao host filesystem sensível
            mounts = cfg.get("Mounts") or []
            sensitive_mounts = []
            for mount in mounts:
                src = mount.get("Source", "")
                dst = mount.get("Destination", "")
                mode = mount.get("Mode", "rw")
                sensitive_paths = ["/etc", "/var", "/run", "/proc", "/sys", "/dev"]
                if any(src.startswith(p) for p in sensitive_paths) and "rw" in mode:
                    sensitive_mounts.append(f"{src} → {dst} ({mode})")

            if sensitive_mounts:
                findings.append(self._warn(
                    f"Container '{name}': mounts sensíveis com escrita",
                    "Volumes montando diretórios sensíveis do host com permissão de escrita.",
                    Severity.HIGH,
                    "\n".join(sensitive_mounts),
                    "Revisar necessidade de cada mount. Preferir read-only (:ro) quando possível."
                ))

        return findings
