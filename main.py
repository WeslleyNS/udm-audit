#!/usr/bin/env python3
"""
udm-audit — UDM Pro Security Audit Tool
Conecta via SSH e executa checks de segurança contra CVEs e misconfigs conhecidas.

Uso rápido:
    python main.py audit --host 192.168.1.1 --user root --key ~/.ssh/id_rsa
    python main.py audit --config hosts.yaml --output report.json
    python main.py audit --host 192.168.1.1 --check CHK-002 --check CHK-003
"""
from __future__ import annotations
import sys
import time
from pathlib import Path

import click
import paramiko
import yaml

from udm_audit.checks.base import SSHClient
from udm_audit.checks import ALL_CHECKS, CHECK_MAP
from udm_audit.reporter import (
    console as rpt,
    json_report,
)


# ---------------------------------------------------------------------------
# SSH connection helper
# ---------------------------------------------------------------------------

def connect_ssh(host: str, port: int, username: str,
                password: str | None, key_file: str | None,
                timeout: int = 15) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict = dict(
        hostname=host, port=port, username=username,
        timeout=timeout, banner_timeout=30,
    )

    if key_file:
        kpath = Path(key_file).expanduser()
        if not kpath.exists():
            raise FileNotFoundError(f"Key file not found: {kpath}")
        connect_kwargs["key_filename"] = str(kpath)
        if password:
            connect_kwargs["passphrase"] = password
    elif password:
        connect_kwargs["password"] = password
    else:
        # Tenta agent SSH
        connect_kwargs["allow_agent"] = True
        connect_kwargs["look_for_keys"] = True

    client.connect(**connect_kwargs)
    return client


# ---------------------------------------------------------------------------
# Audit runner
# ---------------------------------------------------------------------------

def run_audit(
    host_name: str,
    host_addr: str,
    ssh: SSHClient,
    selected_checks: list[str] | None,
    min_severity: str,
) -> list:
    from udm_audit.checks.base import Severity, Status

    checks_to_run = ALL_CHECKS
    if selected_checks:
        checks_to_run = [c for c in ALL_CHECKS if c.check_id in selected_checks]
        if not checks_to_run:
            rpt.console.print(f"[red]Nenhum check encontrado para: {selected_checks}[/red]")
            return []

    rpt.print_header(host_name, host_addr)

    all_findings = []
    for check_cls in checks_to_run:
        check = check_cls(ssh)
        rpt.print_check_header(check.check_id, check.name)
        try:
            findings = check.run()
        except Exception as exc:
            rpt.console.print(f"  [red]ERRO no check {check.check_id}: {exc}[/red]")
            findings = []

        # Filtra por severidade mínima para display
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        min_order = sev_order.get(min_severity.upper(), 4)
        display_findings = [
            f for f in findings
            if sev_order.get(f.severity.value, 4) <= min_order
            or f.status == Status.FAIL
        ]

        rpt.print_findings(display_findings)
        all_findings.extend(findings)

    rpt.print_summary(host_name, all_findings)
    return all_findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """UDM Pro Security Audit Tool — detecta CVEs, misconfigs e exposições."""
    pass


@cli.command()
@click.option("--host", "-H", help="IP ou hostname do UDM Pro")
@click.option("--port", "-p", default=22, show_default=True, help="Porta SSH")
@click.option("--user", "-u", default="root", show_default=True, help="Usuário SSH")
@click.option("--password", help="Senha SSH (preferir --key)")
@click.option("--key", "-k", help="Caminho para chave privada SSH")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Arquivo YAML com lista de hosts (para fleet)"
)
@click.option(
    "--check",
    multiple=True,
    help="Executar check específico (ex: --check CHK-002). Pode repetir."
)
@click.option(
    "--severity", "-s",
    default="LOW",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    show_default=True,
    help="Severidade mínima para exibir no terminal"
)
@click.option("--output", "-o", help="Salvar relatório JSON em arquivo")
@click.option("--timeout", default=15, show_default=True, help="Timeout SSH (segundos)")
def audit(host, port, user, password, key, config, check, severity, output, timeout):
    """Executa audit de segurança em um ou múltiplos UDM Pros."""

    # Resolve lista de hosts
    hosts: list[dict] = []

    if config:
        with open(config) as f:
            cfg = yaml.safe_load(f)
        hosts = cfg.get("hosts", [])
        if not hosts:
            click.echo("Nenhum host encontrado no arquivo de configuração.", err=True)
            sys.exit(1)
    elif host:
        hosts = [{
            "name": host,
            "host": host,
            "port": port,
            "username": user,
            "password": password,
            "key_file": key,
        }]
    else:
        click.echo("Especifique --host ou --config.", err=True)
        sys.exit(1)

    selected = list(check) if check else None
    fleet_results: dict[str, tuple[str, list]] = {}

    for h in hosts:
        h_name = h.get("name", h["host"])
        h_addr = h["host"]
        h_port = h.get("port", 22)
        h_user = h.get("username", "root")
        h_pass = h.get("password")
        h_key  = h.get("key_file")

        rpt.console.print(f"\n[bold cyan]Conectando em {h_name} ({h_addr}:{h_port})...[/bold cyan]")

        try:
            start = time.time()
            raw_ssh = connect_ssh(h_addr, h_port, h_user, h_pass, h_key, timeout)
            ssh = SSHClient(raw_ssh)
            elapsed = time.time() - start
            rpt.console.print(f"[green]✓ Conectado em {elapsed:.1f}s[/green]")
        except Exception as exc:
            rpt.console.print(f"[red]✗ Falha ao conectar em {h_name}: {exc}[/red]")
            continue

        try:
            findings = run_audit(h_name, h_addr, ssh, selected, severity)
            fleet_results[h_name] = (h_addr, findings)
        finally:
            raw_ssh.close()

    if not fleet_results:
        rpt.console.print("[red]Nenhum host auditado com sucesso.[/red]")
        sys.exit(1)

    # Fleet summary se múltiplos hosts
    if len(fleet_results) > 1:
        rpt.print_fleet_summary({k: v[1] for k, v in fleet_results.items()})

    # JSON output
    if output:
        if len(fleet_results) == 1:
            h_name, (h_addr, findings) = next(iter(fleet_results.items()))
            json_report.generate(h_name, h_addr, findings, output)
        else:
            json_report.generate_fleet(fleet_results, output)
        rpt.console.print(f"[green]Relatório salvo em: {output}[/green]")


@cli.command()
def list_checks():
    """Lista todos os checks disponíveis."""
    table_data = [(c.check_id, c.name, c.description) for c in ALL_CHECKS]
    rpt.console.print("\n[bold]Checks disponíveis:[/bold]\n")
    for cid, name, desc in table_data:
        rpt.console.print(f"  [cyan]{cid}[/cyan]  [white]{name}[/white]")
        rpt.console.print(f"         [dim]{desc}[/dim]")
    rpt.console.print()


if __name__ == "__main__":
    cli()
