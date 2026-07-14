"""
CHK-010: Controller API & Internal Configs
Verifica a segurança dos serviços subjacentes ao UniFi Network App (Controller),
como o MongoDB local, configurações de API e o Guest Portal.
"""
from __future__ import annotations
import re
from udm_audit.core.base import CheckBase
from udm_audit.core.models import Finding, Severity, Status


class APICheck(CheckBase):
    check_id = "CHK-010"
    name = "Controller API & Internal Configs"
    description = "Valida a exposição do MongoDB local, 2FA e configurações do Guest Portal"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_mongodb_bind())
        findings.extend(self._check_guest_portal())
        findings.extend(self._check_2fa_status())
        return findings

    def _check_mongodb_bind(self) -> list[Finding]:
        findings: list[Finding] = []

        # O UniFi Network usa o MongoDB (geralmente porta 27117).
        # Ele NÃO deve escutar em 0.0.0.0, apenas em 127.0.0.1.
        # Vamos verificar pelo netstat ou ss
        netstat_out, _, _ = self.executor.execute("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        
        if not netstat_out:
            findings.append(self._unknown(
                "MongoDB Bind Status",
                "Comando ss/netstat falhou ou não retornou dados. Não foi possível verificar portas locais."
            ))
            return findings

        mongo_lines = [line for line in netstat_out.splitlines() if "27117" in line or "mongod" in line]
        
        if not mongo_lines:
            findings.append(self._pass(
                "MongoDB não detectado",
                "Nenhum processo MongoDB escutando na porta 27117 (pode estar desligado ou usando socket unix)."
            ))
            return findings

        exposed = False
        for line in mongo_lines:
            # Procura por *:27117 ou 0.0.0.0:27117
            if re.search(r"(\*|0\.0\.0\.0):27117", line):
                exposed = True
                break

        if exposed:
            findings.append(self._fail(
                "MongoDB interno acessível em todas as interfaces",
                "O banco de dados principal do UniFi (MongoDB) está escutando na porta 27117 em 0.0.0.0. "
                "Isso permite acesso direto à base de dados do controlador a partir da rede local (ou WAN, se não bloqueado).",
                Severity.CRITICAL,
                "\n".join(mongo_lines),
                "No arquivo system.properties (/data/unifi/data/system.properties), defina: unifi.db.extraargs=--bind_ip 127.0.0.1"
            ))
        else:
            findings.append(self._pass(
                "MongoDB interno isolado (Bind seguro)",
                "O MongoDB está escutando apenas localmente (127.0.0.1)."
            ))

        return findings

    def _check_guest_portal(self) -> list[Finding]:
        findings: list[Finding] = []

        # Verifica se o Guest Portal está ativo (Porta 8843 HTTPS ou 8880 HTTP)
        netstat_out, _, _ = self.executor.execute("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        
        if netstat_out:
            portal_lines = [line for line in netstat_out.splitlines() if "8843" in line or "8880" in line]
            if portal_lines:
                findings.append(self._warn(
                    "Guest Portal Ativo",
                    "As portas do Guest Portal (8880 HTTP / 8843 HTTPS) estão abertas. Se estiver usando HTTPS (8843), "
                    "certifique-se de que um Certificado SSL válido (não autoassinado) foi configurado para evitar "
                    "que visitantes recebam avisos de segurança ao conectar na rede.",
                    Severity.LOW,
                    "\n".join(portal_lines),
                    "Se você não utiliza rede de Visitantes com Captive Portal, desative o 'Guest Portal' no painel do UniFi."
                ))
            else:
                findings.append(self._pass(
                    "Guest Portal Desativado",
                    "Portas do Captive Portal (8880/8843) não estão em escuta."
                ))
                
        return findings

    def _check_2fa_status(self) -> list[Finding]:
        findings: list[Finding] = []

        # Como ler a configuração 2FA sem credenciais de API é difícil/impossível apenas por shell no novo UniFiOS,
        # emitimos um Finding educativo (INFO) lembrando da política.
        findings.append(self._warn(
            "Verificação manual necessária: Multi-Factor Authentication (MFA/2FA)",
            "A API local não expõe nativamente o status de MFA de todos os administradores sem token. "
            "Contas locais sem MFA ativado (especialmente Owner/Super Admin) são o vetor primário de invasão em roteadores de borda.",
            Severity.MEDIUM,
            "Não foi possível extrair a lista de usuários com 2FA desativado localmente.",
            "Acesse o UniFi OS (System -> Admins) e garanta que *todas* as contas administrativas tenham 2FA (MFA) ativado, "
            "incluindo contas de Cloud Access (Ubiquiti SSO)."
        ))

        return findings
