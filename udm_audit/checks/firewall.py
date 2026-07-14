"""
CHK-009: Firewall & Network Policies
Verifica configurações ativas do Firewall do UDM (iptables/nftables),
validação de Isolamento Inter-VLAN (Layer 3), status do IPS/IDS (Suricata),
e políticas de segurança de rede da WAN.
"""
from __future__ import annotations
import re
from udm_audit.core.base import CheckBase
from udm_audit.core.models import Finding, Severity, Status


class FirewallCheck(CheckBase):
    check_id = "CHK-009"
    name = "Firewall & Network Policies"
    description = "Valida isolamento inter-VLAN, políticas WAN e status do IPS (Suricata)"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_ips_suricata())
        findings.extend(self._check_inter_vlan_isolation())
        findings.extend(self._check_wan_default_drop())
        findings.extend(self._check_dns_filtering())
        return findings

    def _check_ips_suricata(self) -> list[Finding]:
        findings: list[Finding] = []

        # Verifica se o processo suricata está ativo (usado para IDS/IPS no UniFi)
        ps_out, _, code = self.executor.execute("ps aux | grep '[s]uricata' 2>/dev/null")

        if not ps_out:
            findings.append(self._fail(
                "Threat Management (IPS/IDS) desativado",
                "O processo 'suricata' não foi encontrado rodando no sistema. "
                "Isso significa que a detecção e prevenção de intrusão do UDM estão desligadas.",
                Severity.HIGH,
                "Processo suricata ausente no ps aux.",
                "Habilitar o 'Suspicious Activity' (IPS) no painel do UniFi Network App (Security -> Suspicious Activity).",
            ))
        else:
            findings.append(self._pass(
                "Threat Management (IPS/IDS) ativo",
                "O Suricata está em execução protegendo a rede contra assinaturas conhecidas."
            ))

        return findings

    def _check_inter_vlan_isolation(self) -> list[Finding]:
        findings: list[Finding] = []

        # No UniFi, o tráfego corporativo inter-VLAN é liberado por padrão (UBIOS_LAN_IN).
        # Para bloquear, o admin tem que criar regras DROP manuais para RFC1918.
        # Vamos buscar no iptables-save se há regras que DROPpam tráfego entre subredes privadas.
        iptables_out, _, code = self.executor.execute("iptables-save 2>/dev/null")

        if not iptables_out or code != 0:
            findings.append(self._unknown(
                "Não foi possível ler as regras do iptables",
                "Comando iptables-save falhou. Permissões de root são necessárias."
            ))
            return findings

        # Busca por regras explícitas de DROP contendo os blocos RFC1918 ou 'return/drop' nas chains locais
        rfc1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        isolation_rules_found = False

        # Avalia se há regras de DROP para tráfego RFC1918 -> RFC1918
        # Procuramos por algo como: -A UBIOS_LAN_IN -d 192.168.0.0/16 -j DROP ou similar
        drop_rules = re.findall(r"-A\s+UBIOS_LAN_IN.*?(-j\s+DROP|-j\s+REJECT)", iptables_out)
        
        # Um teste simples: se não houver quase nenhuma regra DROP na LAN_IN, a rede está flat
        if len(drop_rules) < 2:
            findings.append(self._warn(
                "Possível falta de Isolamento Inter-VLAN (Rede Flat)",
                "Foram encontradas poucas ou nenhuma regra de DROP na chain UBIOS_LAN_IN do iptables. "
                "No UniFi, todas as redes Corporativas comunicam-se entre si por padrão, a menos que "
                "bloqueios explícitos sejam criados.",
                Severity.MEDIUM,
                f"Regras DROP em UBIOS_LAN_IN encontradas: {len(drop_rules)}",
                "Se houver redes separadas (ex: IoT, Câmeras, Visitantes não-Guest-Portal), "
                "crie regras LAN IN bloqueando tráfego inter-VLAN (RFC1918 to RFC1918)."
            ))
        else:
            findings.append(self._pass(
                "Regras de bloqueio na LAN (Isolamento VLAN) detectadas",
                f"Foram encontradas {len(drop_rules)} regras de DROP/REJECT em UBIOS_LAN_IN."
            ))

        return findings

    def _check_wan_default_drop(self) -> list[Finding]:
        findings: list[Finding] = []

        iptables_out, _, _ = self.executor.execute("iptables-save 2>/dev/null")
        if not iptables_out:
            return findings

        # Verifica se as chains WAN IN e WAN LOCAL têmACCEPT abertos incondicionais que não deveriam estar lá
        # Geralmente -A UBIOS_WAN_IN -j RETURN (que delega)
        # Procuramos por regras -A UBIOS_WAN_IN que dão ACCEPT em portas perigosas (ex: 22, 80, 443) sem limitadores
        dangerous_ports = ["22", "80", "443", "8080", "8443"]
        exposed_wan = []

        for line in iptables_out.splitlines():
            if "UBIOS_WAN_LOCAL" in line or "UBIOS_WAN_IN" in line:
                if "-j ACCEPT" in line or "-j RETURN" in line:
                    for port in dangerous_ports:
                        # Regex para checar --dport 22 ou porta múltipla
                        if re.search(r"--dport\s+" + port + r"\b", line):
                            exposed_wan.append(line)

        if exposed_wan:
            findings.append(self._warn(
                "Portas sensíveis explicitamente abertas na Interface WAN",
                "As regras de Firewall (iptables) contém ACCEPTs para portas de gerência/sensíveis "
                "na interface de internet (WAN).",
                Severity.HIGH,
                "\n".join(exposed_wan[:5]) + ("..." if len(exposed_wan) > 5 else ""),
                "Revisar 'Internet Local' ou 'Internet In' no painel de Firewall do UniFi. "
                "Remover liberações de acesso externo para portas de gerência."
            ))
        else:
            findings.append(self._pass(
                "Regras WAN Default limpas",
                "Nenhuma porta de gerência (22, 8080, etc) exposta explicitamente no iptables da WAN."
            ))

        return findings

    def _check_dns_filtering(self) -> list[Finding]:
        findings: list[Finding] = []

        # Verifica se o serviço dnsmasq ou unifi-core tem bloqueio ad/malware ativo
        # No UDM, o adblocking do dnsmasq fica em /run/dnsmasq.conf.d/adblock.conf
        adblock_conf, _, code = self.executor.execute("ls /run/dnsmasq.conf.d/adblock* 2>/dev/null || ls /config/dnsmasq.d/adblock* 2>/dev/null")

        if not adblock_conf and code != 0:
            findings.append(self._warn(
                "Filtro DNS / AdBlocking desativado",
                "Nenhuma configuração de bloqueio de anúncios ou malware via DNS (dnsmasq) encontrada. "
                "O bloqueio a nível de DNS previne que hosts internos resolvam domínios de malwares/C2.",
                Severity.LOW,
                "Arquivos de adblock do dnsmasq ausentes.",
                "Habilitar o 'Ad Blocking' ou usar DNS seguro (ex: Cloudflare 1.1.1.2) na WAN."
            ))
        else:
            findings.append(self._pass(
                "Filtro DNS (AdBlocking) ativo",
                "Configurações de adblock no dnsmasq foram detectadas."
            ))

        return findings
