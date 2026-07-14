# udm-audit

Security audit tool para **UniFi Dream Machine Pro** (UDM Pro / UniFiOS).

Conecta via SSH e executa verificações automatizadas contra CVEs conhecidas,
misconfigurations e exposições de credenciais. Gera relatório com findings
classificados por severidade e remediações específicas.

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

**Requisitos:** Python 3.10+, acesso SSH ao UDM Pro (root ou usuário com sudo).

---

## Uso

### Host único

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
  "meta": { "host": "site-sp-01", "timestamp": "2025-01-15T10:30:00Z" },
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

## Adicionando novos checks

```python
# udm_audit/checks/meu_check.py
from .base import CheckBase, Finding, Severity, Status

class MeuCheck(CheckBase):
    check_id = "CHK-008"
    name = "Meu Check"
    description = "Descrição do que verifica"

    def run(self) -> list[Finding]:
        findings = []
        out, err, code = self.ssh.exec("comando aqui")

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

## Notas

- **Ferramenta de audit, não de exploit.** Lê configurações via SSH, não executa payloads.
- CVE IDs são baseados em pesquisa pública até 2025. Verificar sempre no NVD e
  [advisories Ubiquiti](https://community.ubnt.com/t5/Security-Advisory-Board/bg-p/sec_advisories).
- Testar primeiro em ambiente não-produção.
- Requer Python 3.10+.
