"""
CHK-002: SSH Hardening
Verifica configurações do sshd que representam risco em UDM Pro.
"""
from __future__ import annotations
import re
from .base import CheckBase, Finding, Severity, Status


class SSHHardeningCheck(CheckBase):
    check_id = "CHK-002"
    name = "SSH Hardening"
    description = "Verifica configurações do sshd_config e exposição de credenciais SSH"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        # --- Lê sshd_config ---
        sshd_out, _, code = self.ssh.exec("cat /etc/ssh/sshd_config 2>/dev/null")

        if code != 0 or not sshd_out:
            findings.append(self._unknown(
                "sshd_config não acessível",
                "Não foi possível ler /etc/ssh/sshd_config. Verifique permissões."
            ))
        else:
            def get_param(name: str) -> str | None:
                """Extrai valor de diretiva do sshd_config (case-insensitive, ignora comentários)."""
                for line in sshd_out.splitlines():
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    m = re.match(rf"^{re.escape(name)}\s+(.+)$", line, re.IGNORECASE)
                    if m:
                        return m.group(1).strip().lower()
                return None

            # PermitRootLogin
            root_login = get_param("PermitRootLogin")
            if root_login in (None, "yes", "without-password", "prohibit-password"):
                val = root_login or "não definido (padrão: yes em algumas versões)"
                findings.append(self._fail(
                    "Root login SSH permitido",
                    f"PermitRootLogin = {val}. No UDM Pro, root SSH usa as mesmas credenciais "
                    "do painel admin — se a senha for fraca ou reutilizada, shell root é trivial.",
                    Severity.HIGH,
                    f"PermitRootLogin {val}",
                    "Desabilitar root SSH ou restringir com AllowUsers + chave pública apenas:\n"
                    "  PermitRootLogin prohibit-password\n"
                    "  PasswordAuthentication no",
                    [],
                ))
            else:
                findings.append(self._pass(
                    "PermitRootLogin restrito",
                    f"PermitRootLogin = {root_login}"
                ))

            # PasswordAuthentication
            pw_auth = get_param("PasswordAuthentication")
            if pw_auth in (None, "yes"):
                findings.append(self._fail(
                    "Autenticação SSH por senha habilitada",
                    "PasswordAuthentication = yes (ou padrão). Sujeito a brute force e "
                    "credential stuffing. Crítico se o painel estiver exposto na internet.",
                    Severity.HIGH,
                    f"PasswordAuthentication {pw_auth or 'não definido (padrão: yes)'}",
                    "Usar apenas chave pública:\n"
                    "  PasswordAuthentication no\n"
                    "  PubkeyAuthentication yes\n"
                    "Adicionar chave em /root/.ssh/authorized_keys antes de aplicar.",
                ))
            else:
                findings.append(self._pass(
                    "Autenticação SSH por senha desabilitada",
                    f"PasswordAuthentication = {pw_auth}"
                ))

            # Port padrão
            port = get_param("Port")
            if port is None or port == "22":
                findings.append(self._warn(
                    "SSH na porta padrão (22)",
                    "Porta 22 é scanneada continuamente por bots. Não é mitigação de segurança "
                    "real, mas reduz ruído de logs e tentativas automatizadas.",
                    Severity.LOW,
                    f"Port {port or '22 (padrão)'}",
                    "Considerar porta alternativa (ex: 2222) ou port knocking.\n"
                    "Prioridade baixa — AllowUsers e PasswordAuthentication no são mais impactantes."
                ))

            # MaxAuthTries
            max_tries = get_param("MaxAuthTries")
            if max_tries is None or int(max_tries or "6") > 3:
                findings.append(self._warn(
                    "MaxAuthTries alto ou não definido",
                    f"MaxAuthTries = {max_tries or 'não definido (padrão: 6)'}. "
                    "Facilita ataques de brute force com múltiplas tentativas por conexão.",
                    Severity.LOW,
                    f"MaxAuthTries {max_tries or 'default 6'}",
                    "Definir MaxAuthTries 3 no sshd_config."
                ))

            # AllowUsers / AllowGroups
            allow_users = get_param("AllowUsers")
            allow_groups = get_param("AllowGroups")
            if not allow_users and not allow_groups:
                findings.append(self._warn(
                    "Sem restrição de usuários SSH (AllowUsers/AllowGroups)",
                    "Qualquer usuário válido do sistema pode tentar autenticar via SSH. "
                    "Definir AllowUsers restringe a superfície de ataque.",
                    Severity.MEDIUM,
                    "AllowUsers não definido",
                    "Adicionar ao sshd_config:\n  AllowUsers root\n"
                    "(ou o usuário específico de gerenciamento)"
                ))

            # ClientAliveInterval (timeout de sessão)
            alive = get_param("ClientAliveInterval")
            if alive is None or int(alive or "0") == 0:
                findings.append(self._warn(
                    "Timeout de sessão SSH não configurado",
                    "Sessões SSH idle permanecem abertas indefinidamente. "
                    "Sessão abandonada em device comprometido = acesso persistente.",
                    Severity.LOW,
                    f"ClientAliveInterval {alive or 'não definido (0 = sem timeout)'}",
                    "Adicionar:\n  ClientAliveInterval 300\n  ClientAliveCountMax 2"
                ))

        # --- authorized_keys ---
        keys_out, _, _ = self.ssh.exec(
            "for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; "
            "do [ -f \"$f\" ] && echo \"=== $f ===\"; cat \"$f\" 2>/dev/null; done"
        )
        if keys_out:
            key_lines = [l for l in keys_out.splitlines() if not l.startswith("===")]
            num_keys = len([l for l in key_lines if l.strip() and not l.startswith("#")])
            findings.append(Finding(
                self.check_id,
                f"authorized_keys presentes ({num_keys} chave(s))",
                Severity.INFO,
                Status.PASS,
                "Chaves SSH autorizadas encontradas. Revisar regularmente — chaves antigas "
                "ou de ex-funcionários são vetores de acesso permanente.",
                keys_out[:500] + ("..." if len(keys_out) > 500 else ""),
                "Auditar authorized_keys regularmente. Remover chaves não utilizadas ou "
                "de pessoas que não precisam mais de acesso.",
            ))
        else:
            findings.append(Finding(
                self.check_id,
                "Nenhuma authorized_key encontrada",
                Severity.INFO,
                Status.PASS,
                "Nenhuma chave pública configurada. SSH só funciona com senha.",
            ))

        # --- Verifica se SSH está exposto em interface WAN ---
        wan_ssh, _, _ = self.ssh.exec(
            "ss -tlnp 2>/dev/null | grep ':22 \\|:22$'"
        )
        if wan_ssh:
            # Tenta detectar se está em 0.0.0.0 (todas as interfaces, potencialmente WAN)
            if "0.0.0.0" in wan_ssh or "*:22" in wan_ssh:
                findings.append(self._warn(
                    "SSH escutando em todas as interfaces (0.0.0.0)",
                    "SSH está acessível em todas as interfaces, incluindo potencialmente a WAN. "
                    "Verifique se há regra de firewall bloqueando acesso externo à porta SSH.",
                    Severity.HIGH,
                    wan_ssh,
                    "Restringir via ListenAddress no sshd_config para interface de gerenciamento:\n"
                    "  ListenAddress 192.168.1.1\n"
                    "Ou adicionar regra de firewall bloqueando porta 22 da interface WAN."
                ))

        return findings
