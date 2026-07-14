"""
CHK-003: VPN Security
Verifica exposição de credenciais VPN (WireGuard, IPsec, OpenVPN) no UDM Pro.
O UDM Pro frequentemente atua como concentrador VPN para redes cloud — compromisso
das chaves = acesso direto às redes cloud sem passar por controles de borda.
"""
from __future__ import annotations
import re
from .base import CheckBase, Finding, Severity, Status


class VPNSecurityCheck(CheckBase):
    check_id = "CHK-003"
    name = "VPN Credentials Security"
    description = "Verifica permissões e exposição de chaves VPN (WireGuard, IPsec, OpenVPN)"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_wireguard())
        findings.extend(self._check_ipsec())
        findings.extend(self._check_openvpn())
        return findings

    # ------------------------------------------------------------------
    # WireGuard
    # ------------------------------------------------------------------
    def _check_wireguard(self) -> list[Finding]:
        findings: list[Finding] = []

        wg_dir, _, _ = self.ssh.exec("ls -la /etc/wireguard/ 2>/dev/null")
        if not wg_dir:
            findings.append(self._pass(
                "WireGuard: nenhum diretório encontrado",
                "WireGuard não parece estar configurado neste device."
            ))
            return findings

        findings.append(Finding(
            self.check_id, "WireGuard configurado",
            Severity.INFO, Status.PASS,
            "Diretório /etc/wireguard/ encontrado. Verificando segurança das chaves.",
            wg_dir,
        ))

        # Permissões do diretório
        # ls -la retorna algo como: drwx------ 2 root root 4096 ...
        dir_perm_m = re.search(r"^(d\S+)\s+\d+\s+(\w+)\s+(\w+)", wg_dir, re.MULTILINE)
        if dir_perm_m:
            perms = dir_perm_m.group(1)
            owner = dir_perm_m.group(2)
            # Deve ser drwx------ (700) ou drwx--x--x no máximo
            if "r" in perms[4:] or "r" in perms[7:]:  # group ou other readable
                findings.append(self._fail(
                    "WireGuard: diretório /etc/wireguard/ com permissões excessivas",
                    f"Permissões {perms} — grupo ou outros têm leitura. "
                    "Chaves privadas WireGuard em texto plano neste diretório.",
                    Severity.CRITICAL,
                    wg_dir,
                    "chmod 700 /etc/wireguard/\nchmod 600 /etc/wireguard/*.conf",
                ))

        # Verifica arquivos .conf individualmente
        conf_files, _, _ = self.ssh.exec(
            "find /etc/wireguard -name '*.conf' -exec ls -la {} \\; 2>/dev/null"
        )
        if conf_files:
            for line in conf_files.splitlines():
                perm_m = re.match(r"^(-\S+)\s+\d+\s+(\w+)\s+(\w+)\s+\d+\s+\S+\s+\d+\s+\S+\s+(.+)$", line)
                if perm_m:
                    perms, owner, group, fname = perm_m.groups()
                    # Deve ser -rw------- (600)
                    if perms[4] != "-" or perms[7] != "-":  # group ou other readable
                        findings.append(self._fail(
                            f"WireGuard: {fname} com permissões inseguras",
                            f"Arquivo de config {fname} com perms {perms}. "
                            "Contém PrivateKey em texto plano — legível por outros processos/usuários.",
                            Severity.CRITICAL,
                            line,
                            f"chmod 600 {fname}",
                        ))

        # Lista peers ativos (informational + verifica peers não documentados)
        wg_show, _, code = self.ssh.exec("wg show 2>/dev/null")
        if wg_show and code == 0:
            peers = re.findall(r"peer:\s+(\S+)", wg_show)
            endpoints = re.findall(r"endpoint:\s+(\S+)", wg_show)
            allowed_ips = re.findall(r"allowed ips:\s+(.+)", wg_show)

            # Verifica se algum peer tem allowed-ips 0.0.0.0/0 (roteamento total)
            full_route_peers = []
            for i, ips in enumerate(allowed_ips):
                if "0.0.0.0/0" in ips or "::/0" in ips:
                    ep = endpoints[i] if i < len(endpoints) else "desconhecido"
                    full_route_peers.append(f"peer {peers[i][:16]}... endpoint={ep}")

            if full_route_peers:
                findings.append(self._warn(
                    f"WireGuard: {len(full_route_peers)} peer(s) com rota default (0.0.0.0/0)",
                    "Peers com allowed-ips 0.0.0.0/0 roteiam TODO o tráfego pelo túnel. "
                    "Se comprometido, atacante redireciona tráfego completo.",
                    Severity.MEDIUM,
                    "\n".join(full_route_peers),
                    "Revisar se o roteamento default é necessário. "
                    "Preferir split-tunnel com subnets específicas quando possível."
                ))

            findings.append(Finding(
                self.check_id,
                f"WireGuard: {len(peers)} peer(s) ativo(s)",
                Severity.INFO, Status.PASS,
                f"Peers: {', '.join(p[:16] + '...' for p in peers)}\n"
                f"Endpoints: {', '.join(endpoints)}",
                wg_show[:800],
            ))

        # Verifica se private key está no config (vs keyfile separado)
        wg_conf_content, _, _ = self.ssh.exec(
            "cat /etc/wireguard/wg0.conf 2>/dev/null || "
            "find /etc/wireguard -name '*.conf' | head -1 | xargs cat 2>/dev/null"
        )
        if wg_conf_content and "PrivateKey" in wg_conf_content:
            findings.append(self._warn(
                "WireGuard: PrivateKey embutida no arquivo .conf",
                "A chave privada está em texto plano dentro do arquivo de config. "
                "Exfiltração do arquivo = comprometimento imediato do túnel.",
                Severity.MEDIUM,
                "PrivateKey = <REDACTED>  (chave presente no arquivo)",
                "Considerar armazenar a private key separada com PostUp/PreUp carregando "
                "de local protegido, ou usar wg-quick com configuração de keyfile."
            ))

        return findings

    # ------------------------------------------------------------------
    # IPsec
    # ------------------------------------------------------------------
    def _check_ipsec(self) -> list[Finding]:
        findings: list[Finding] = []

        ipsec_conf, _, _ = self.ssh.exec("cat /etc/ipsec.conf 2>/dev/null")
        ipsec_secrets, _, _ = self.ssh.exec("cat /etc/ipsec.secrets 2>/dev/null")

        if not ipsec_conf and not ipsec_secrets:
            # Tenta strongswan
            swanctl, _, _ = self.ssh.exec("ls /etc/swanctl/ 2>/dev/null")
            if not swanctl:
                findings.append(self._pass(
                    "IPsec: não configurado",
                    "Nenhuma configuração IPsec/StrongSwan encontrada."
                ))
                return findings

        if ipsec_secrets:
            # Verifica PSK em texto plano
            psk_matches = re.findall(r'PSK\s+"?(.+?)"?\s*$', ipsec_secrets, re.MULTILINE)
            if psk_matches:
                findings.append(self._fail(
                    f"IPsec: {len(psk_matches)} PSK(s) em texto plano em ipsec.secrets",
                    "Pre-shared keys IPsec armazenadas em texto plano. "
                    "Comprometimento do arquivo = comprometimento de todos os túneis IPsec.",
                    Severity.HIGH,
                    f"PSK encontrado em /etc/ipsec.secrets ({len(psk_matches)} entrada(s))\n"
                    "(conteúdo não exibido por segurança)",
                    "Migrar para autenticação por certificado X.509 onde possível. "
                    "Garantir permissões 600 em /etc/ipsec.secrets:\n"
                    "  chmod 600 /etc/ipsec.secrets"
                ))

            # Permissões do arquivo secrets
            secrets_perm, _, _ = self.ssh.exec("ls -la /etc/ipsec.secrets 2>/dev/null")
            if secrets_perm:
                perm_m = re.match(r"(-\S+)", secrets_perm)
                if perm_m:
                    perms = perm_m.group(1)
                    if perms[4] != "-" or perms[7] != "-":
                        findings.append(self._fail(
                            "IPsec: /etc/ipsec.secrets com permissões excessivas",
                            f"Permissões {perms} — grupo ou outros têm leitura.",
                            Severity.HIGH,
                            secrets_perm,
                            "chmod 600 /etc/ipsec.secrets\nchown root:root /etc/ipsec.secrets"
                        ))

        return findings

    # ------------------------------------------------------------------
    # OpenVPN
    # ------------------------------------------------------------------
    def _check_openvpn(self) -> list[Finding]:
        findings: list[Finding] = []

        ovpn_dir, _, _ = self.ssh.exec("ls -la /etc/openvpn/ 2>/dev/null")
        if not ovpn_dir:
            findings.append(self._pass(
                "OpenVPN: não configurado",
                "Nenhuma configuração OpenVPN encontrada em /etc/openvpn/"
            ))
            return findings

        # Verifica arquivos de chave com permissões erradas
        key_files, _, _ = self.ssh.exec(
            "find /etc/openvpn -name '*.key' -o -name '*.pem' -o -name 'ta.key' "
            "2>/dev/null | xargs ls -la 2>/dev/null"
        )
        if key_files:
            for line in key_files.splitlines():
                perm_m = re.match(r"^(-\S+)\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\S+\s+(.+)$", line)
                if perm_m:
                    perms, fname = perm_m.groups()
                    if perms[4] != "-" or perms[7] != "-":
                        findings.append(self._fail(
                            f"OpenVPN: {fname.split('/')[-1]} com permissões inseguras",
                            f"Arquivo de chave com perms {perms}.",
                            Severity.HIGH,
                            line,
                            f"chmod 600 {fname}"
                        ))

        return findings
