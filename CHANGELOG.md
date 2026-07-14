# Changelog

Todos os lançamentos e mudanças notáveis no projeto `udm-audit` serão documentados neste arquivo.

O formato é baseado no [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/), e este projeto adere ao [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-07-14

### Adicionado
- **CHK-008: System Integrity & Persistence:**
  - Validação de integridade do sistema operacional nativo (Debian) via hashes MD5 do `dpkg -V`.
  - Detecção de modificação de binários críticos (`sshd`, `bash`, `sudo`, `systemd`).
  - Monitoramento de Cronjobs (`/etc/cron.*`, `/var/spool/cron/crontabs`) em busca de backdoors/malwares.
  - Varredura de binários criados/modificados nos últimos 7 dias nas pastas `/bin` e `/sbin`.
- **CHK-009: Firewall & Network Policies:**
  - Verificação de Isolamento Inter-VLAN (Layer 3) garantindo ausência de roteamento aberto entre redes RFC1918.
  - Validação de status ativo do mecanismo de Threat Management / IPS / IDS (Suricata).
  - Validação da postura de segurança na WAN (Detecção de Portas Abertas acidentalmente para a internet).
  - Verificação de AdBlocking / DNS Filtering a nível de firewall via `dnsmasq`.
- **CHK-010: Controller API & Internal Configs:**
  - Análise de Bind Seguro do banco de dados (MongoDB / porta 27117).
  - Verificação do status do Guest Portal (Portas 8880/8843) e boas práticas de HTTPS.
  - Alertas focados em validação manual para obrigatoriedade de 2FA em contas administrativas.

### Modificado
- (v1.0.2) Refatoração estrutural com Injeção de Dependências e padrão Strategy (`core/executor.py`).
- Implementação de um `CacheExecutor` local, minimizando gargalos de performance e excesso de subprocessos.
- Remoção do acoplamento forçado à biblioteca `paramiko` nos checks internos.

### Corrigido
- `CHK-003` (VPN): Correção de falsos positivos gerados pelo comportamento de retorno vazio no `xargs` no ambiente BusyBox.
- `CHK-004` (Sudo): Ajuste em REGEX do Sudoers para reconhecer comandos wildcard `ALL` reais, ao invés de alertar contas legítimas como `ALL=(ALL:ALL)`.
- Requisito de versão do script `run.sh` rebaixado de Python 3.10+ para Python 3.9+ (Garantindo suporte nativo ao UDM Pro Firmware 3.x+).
- `CHK-008` (Integridade): Exceção adicionada para a pasta `/usr/share/` visando abafar ruídos normais do OS da Ubiquiti (deleção de manpages/locales).

---

## [1.0.0] - Lançamento Inicial

### Adicionado
- Fundação inicial das ferramentas (CHK-001 a CHK-007).
- Varredura de Container Escape, VPN, Hardening SSH.
