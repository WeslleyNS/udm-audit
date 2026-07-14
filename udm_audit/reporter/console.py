"""
Console reporter — saída colorida no terminal usando Rich.
"""
from __future__ import annotations
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from ..checks.base import Finding, Severity, Status

console = Console()

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH:     "bold red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "yellow",
    Severity.INFO:     "dim",
}

STATUS_STYLE = {
    Status.FAIL:    "bold red",
    Status.WARN:    "bold yellow",
    Status.PASS:    "bold green",
    Status.UNKNOWN: "dim",
}

STATUS_ICON = {
    Status.FAIL:    "✗",
    Status.WARN:    "⚠",
    Status.PASS:    "✓",
    Status.UNKNOWN: "?",
}


def print_header(host_name: str, host_addr: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold]UDM Pro Security Audit[/bold]\n"
        f"Host: [cyan]{host_name}[/cyan] ([dim]{host_addr}[/dim])\n"
        f"Time: [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        style="bold blue",
        box=box.ROUNDED,
    ))
    console.print()


def print_check_header(check_id: str, check_name: str) -> None:
    console.print(f"[bold cyan]▶ {check_id}[/bold cyan] [white]{check_name}[/white]")


def print_findings(findings: list[Finding]) -> None:
    for f in findings:
        icon = STATUS_ICON[f.status]
        icon_style = STATUS_STYLE[f.status]
        sev_style = SEVERITY_STYLE[f.severity]

        line = Text()
        line.append(f"  {icon} ", style=icon_style)
        line.append(f"[{f.severity.value}] ", style=sev_style)
        line.append(f.title, style="white" if f.status == Status.FAIL else "")
        console.print(line)

        if f.status in (Status.FAIL, Status.WARN) and f.detail:
            console.print(f"    [dim]{f.detail}[/dim]")

        if f.evidence and f.status in (Status.FAIL, Status.WARN):
            evidence_preview = f.evidence[:200].replace("\n", " | ")
            if len(f.evidence) > 200:
                evidence_preview += "..."
            console.print(f"    [dim italic]Evidence: {evidence_preview}[/dim italic]")

        if f.remediation:
            console.print(f"    [green]→ Fix:[/green] [dim]{f.remediation[:120]}[/dim]")

        if f.references:
            console.print(f"    [dim]Refs: {', '.join(f.references)}[/dim]")

    console.print()


def print_summary(host_name: str, all_findings: list[Finding]) -> None:
    counts = {s: 0 for s in Severity}
    fail_warn = [f for f in all_findings if f.status in (Status.FAIL, Status.WARN)]

    for f in all_findings:
        counts[f.severity] += 1

    table = Table(title=f"Summary — {host_name}", box=box.SIMPLE_HEAD, show_footer=False)
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count", justify="right", width=8)
    table.add_column("Findings", width=50)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_findings = [f for f in fail_warn if f.severity == sev]
        if counts[sev] == 0:
            continue
        titles = ", ".join(f.title[:40] for f in sev_findings[:3])
        if len(sev_findings) > 3:
            titles += f" (+{len(sev_findings)-3} more)"
        style = SEVERITY_STYLE[sev]
        table.add_row(
            Text(sev.value, style=style),
            str(counts[sev]),
            titles or "—"
        )

    console.print(table)

    # Score rápido
    critical = counts[Severity.CRITICAL]
    high = counts[Severity.HIGH]
    medium = counts[Severity.MEDIUM]

    if critical > 0:
        risk = "[bold white on red] CRITICAL RISK [/bold white on red]"
    elif high > 0:
        risk = "[bold red] HIGH RISK [/bold red]"
    elif medium > 0:
        risk = "[bold yellow] MEDIUM RISK [/bold yellow]"
    else:
        risk = "[bold green] LOW RISK [/bold green]"

    console.print(f"\nOverall risk: {risk}")
    console.print(
        f"  {critical} critical  |  {high} high  |  {medium} medium  |  "
        f"{counts[Severity.LOW]} low  |  {counts[Severity.INFO]} info\n"
    )


def print_fleet_summary(results: dict[str, list[Finding]]) -> None:
    """Resumo de múltiplos hosts (fleet)."""
    if len(results) <= 1:
        return

    console.print(Panel("[bold]Fleet Summary[/bold]", style="blue"))
    table = Table(box=box.SIMPLE_HEAD)
    table.add_column("Host", width=20)
    table.add_column("Critical", justify="right", style="bold red")
    table.add_column("High", justify="right", style="red")
    table.add_column("Medium", justify="right", style="yellow")
    table.add_column("Low", justify="right")
    table.add_column("Pass", justify="right", style="green")

    for host, findings in results.items():
        fail_warn = [f for f in findings if f.status in (Status.FAIL, Status.WARN)]
        table.add_row(
            host,
            str(sum(1 for f in fail_warn if f.severity == Severity.CRITICAL)),
            str(sum(1 for f in fail_warn if f.severity == Severity.HIGH)),
            str(sum(1 for f in fail_warn if f.severity == Severity.MEDIUM)),
            str(sum(1 for f in fail_warn if f.severity == Severity.LOW)),
            str(sum(1 for f in findings if f.status == Status.PASS)),
        )

    console.print(table)
