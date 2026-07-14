# udm-audit

Security audit tool para **UniFi Dream Machine Pro** (UDM Pro / UniFiOS).

Conecta via SSH ou executa **localmente dentro do UDM** e roda verificações
automatizadas contra CVEs conhecidas, misconfigurations e exposições de
credenciais. Gera relatório com findings classificados por severidade e
remediações específicas.

---

## Quick Start — Execução direta no UDM

Rode direto no terminal SSH do UDM Pro com um único comando:

```bash
curl -sSL https://raw.githubusercontent.com/WeslleyNS/udm-audit/main/run.sh | bash
```

Ou se preferir executar checks específicos:

```bash
curl -sSL https://raw.githubusercontent.com/WeslleyNS/udm-audit/main/run.sh | bash -s -- --check CHK-002 --check CHK-003
```

> **Nota:** Requer Python 3.9+ instalado no UDM. O script faz download
> temporário do projeto, instala dependências e executa `python main.py audit --local`.

---

## Checks implementados

| ID       | Nome                    | O que verifica                                              |
|----------|-------------------------|-------------------------------------------------------------|
| CHK-001  | Version / CVE Check     | Versão UniFiOS e Network App vs CVEs conhecidas             |
| CHK-002  | SSH Hardening           | sshd_config, root login, auth por senha, exposição de porta |
| CHK-003  | VPN Credentials         | Permissões WireGuard/IPsec/OpenVPN, peers, private keys     |
| CHK-004  | Container Security      | sudo rules, capabilities, volume mounts perigosos           |
| CHK-005  | Network Exposure        | Portas em escuta, MongoDB exposto, iptables/nftables        |
| CHK-006  | Update Status           | Upgrades disponíveis, últimos logins                        |
| CHK-007  | Logging Config          | Syslog remoto, journald persistence                         |

CVEs cobertas (principais): CVE-2021-22908 (SSRF), CVE-2021-22909 (privesc),
CVE-2021-22910 (XSS), CVE-2023-35807 (SQLi), CVE-2024-42028 (container escape).

---

## Instalação

```bash
# Clonar / extrair o projeto
cd udm-audit

# Instalar dependências
pip install -r requirements.txt

# Verificar
python main.py list-checks
```

**Requisitos:** Python 3.9+, acesso SSH ao UDM Pro (root ou usuário com sudo).

---

## Uso

### Modo local (dentro do UDM)

```bash
# Executar todos os checks localmente
python main.py audit --local

# Apenas checks específicos
python main.py audit --local --check CHK-002 --check CHK-003

# Salvar relatório JSON
python main.py audit --local --output report.json

# Exibir apenas HIGH e CRITICAL
python main.py audit --local --severity HIGH
```

### Host único (remoto via SSH)

```bash
# Com chave SSH (recomendado)
python main.py audit --host 192.168.1.1 --key ~/.ssh/id_rsa

# Com senha (não recomendado para produção)
python main.py audit --host 192.168.1.1 --user root --password minhasenha

# Salvar relatório JSON
python main.py audit --host 192.168.1.1 --key ~/.ssh/id_rsa --output report.json

# Exibir apenas HIGH e CRITICAL
python main.py audit --host 192.168.1.1 --key ~/.ssh/id_rsa --severity HIGH

# Executar checks específicos
python main.py audit --host 192.168.1.1 --key ~/.ssh/id_rsa --check CHK-002 --check CHK-003
```

### Fleet (múltiplos hosts)

```bash
# Copiar e editar o arquivo de configuração
cp hosts.example.yaml hosts.yaml
vim hosts.yaml

# Auditar toda a fleet
python main.py audit --config hosts.yaml --output fleet-report.json

# Apenas checks críticos na fleet
python main.py audit --config hosts.yaml --severity HIGH --output fleet-report.json
```

### Arquivo hosts.yaml

```yaml
hosts:
  - name: "site-sp-01"
    host: "192.168.1.1"
    port: 22
    username: "root"
    key_file: "~/.ssh/id_rsa"

  - name: "site-rj-01"
    host: "10.10.0.1"
    port: 22
    username: "root"
    key_file: "~/.ssh/id_rsa"
```

---

## Output

### Terminal (Rich)

```
▶ CHK-002 SSH Hardening
  ✗ [HIGH]    Root login SSH permitido
    PermitRootLogin = yes. No UDM Pro, root SSH usa as mesmas credenciais...
    → Fix: Desabilitar root SSH ou restringir com AllowUsers + chave pública...

  ✗ [HIGH]    Autenticação SSH por senha habilitada
    PasswordAuthentication = yes (ou padrão). Sujeito a brute force...
    → Fix: PasswordAuthentication no

  ✓ [INFO]    authorized_keys presentes (1 chave(s))
```

### JSON Report

```json
{
  "meta": { "host": "site-sp-01", "version": "1.0.2", "timestamp": "2025-01-15T10:30:00Z" },
  "summary": { "critical": 1, "high": 3, "medium": 2, "low": 4, "pass": 8 },
  "failures": [
    {
      "check_id": "CHK-002",
      "title": "Root login SSH permitido",
      "severity": "HIGH",
      "status": "FAIL",
      "evidence": "PermitRootLogin yes",
      "remediation": "PermitRootLogin prohibit-password\nPasswordAuthentication no",
      "references": []
    }
  ]
}
```

---

## Arquitetura (v1.0.2)

```
udm_audit/
├── core/
│   ├── executor.py      # CommandExecutor Protocol + Local/SSH/Cached strategies
│   ├── models.py         # Finding, Severity, Status (dataclasses)
│   └── base.py           # CheckBase com Dependency Injection
├── checks/
│   ├── base.py           # Backward compat shim
│   ├── version.py        # CHK-001
│   ├── ssh_hardening.py  # CHK-002
│   ├── vpn_security.py   # CHK-003
│   ├── container_security.py # CHK-004
│   └── network_exposure.py   # CHK-005/006/007
├── reporter/
│   ├── console.py        # Rich terminal output
│   └── json_report.py    # JSON para SIEM/ticketing
└── main.py               # CLI (Click) com --local / --host / --config
```

### Padrão Strategy (Executors)

```
CommandExecutor (Protocol)
├── LocalExecutor    →  subprocess.run  (--local)
├── SSHExecutor      →  paramiko        (--host / --config)
└── CachedExecutor   →  dict in-memory  (decorator, evita comandos duplicados)
```

---

## Adicionando novos checks

```python
# udm_audit/checks/meu_check.py
from udm_audit.core.base import CheckBase
from udm_audit.core.models import Finding, Severity, Status

class MeuCheck(CheckBase):
    check_id = "CHK-008"
    name = "Meu Check"
    description = "Descrição do que verifica"

    def run(self) -> list[Finding]:
        findings = []
        out, err, code = self.executor.execute("comando aqui")

        if "problema" in out:
            findings.append(self._fail(
                title="Título do finding",
                detail="Explicação do problema",
                severity=Severity.HIGH,
                evidence=out,
                remediation="Como corrigir",
                references=["CVE-XXXX-XXXXX"],
            ))
        return findings
```

Registrar em `udm_audit/checks/__init__.py`:
```python
from .meu_check import MeuCheck
ALL_CHECKS = [..., MeuCheck]
```

---

## Changelog

### v1.0.2

- **Modo local** (`--local`): execução direta no terminal do UDM sem SSH
- **Strategy Pattern**: `CommandExecutor` Protocol com `LocalExecutor`, `SSHExecutor`, `CachedExecutor`
- **Dependency Injection**: `CheckBase` desacoplado de paramiko
- **Cache em memória**: evita reexecução de comandos POSIX repetidos na mesma sessão
- **One-liner curl**: `run.sh` para execução direta no UDM
- **Backward compat**: `checks/base.py` mantém `SSHClient` como alias

### v1.0.0

- Release inicial com 7 checks de segurança
- Suporte a host único e fleet via YAML
- Relatórios terminal (Rich) e JSON

---

## Notas

- **Ferramenta de audit, não de exploit.** Lê configurações via SSH/local, não executa payloads.
- CVE IDs são baseados em pesquisa pública até 2025. Verificar sempre no NVD e
  [advisories Ubiquiti](https://community.ubnt.com/t5/Security-Advisory-Board/bg-p/sec_advisories).
- Testar primeiro em ambiente não-produção.
- Requer Python 3.9+.
