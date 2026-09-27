"""Rich terminal display formatters, tables, and presentation helpers."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from apiguard.models.audit import AuditReport
from apiguard.models.enums import AuditStatus, Severity
from apiguard.models.jwt import JwtAnalysisResult, JwtStrengthResult

console = Console()

BANNER = r"""[bold cyan]
   █████╗ ██████╗ ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
  ██╔══██╗██╔══██╗██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ███████║██████╔╝██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔══██║██╔═══╝ ██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║  ██║██║     ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ [/bold cyan]
  [dim italic]Automated REST API Health & Security Compliance Linter v0.1.0[/dim italic]
"""


def print_banner() -> None:
    """Renders the stylized APIGUARD header banner."""
    console.print(BANNER)


def print_audit_report(report: AuditReport) -> None:
    """Renders an interactive, color-coded terminal report for an API audit."""
    print_banner()

    # Executive Summary Card
    grade_color = "bold green" if report.grade in ("A+", "A") else ("bold yellow" if report.grade in ("B", "C") else "bold red")
    score_text = Text()
    score_text.append(f"Target: {report.target_url}\n", style="bold white")
    score_text.append(f"Compliance Score: ", style="dim")
    score_text.append(f"{report.score}/100 ", style=f"bold {grade_color}")
    score_text.append(f"[{report.grade}]\n", style=f"{grade_color} reverse")
    score_text.append(f"Scan Duration: {report.duration_seconds}s  •  Findings: ", style="dim")
    score_text.append(f"CRIT:{report.critical_count} ", style="bold red" if report.critical_count > 0 else "dim")
    score_text.append(f"HIGH:{report.high_count} ", style="red" if report.high_count > 0 else "dim")
    score_text.append(f"MED:{report.medium_count} ", style="yellow" if report.medium_count > 0 else "dim")
    score_text.append(f"LOW:{report.low_count} ", style="cyan" if report.low_count > 0 else "dim")
    score_text.append(f"PASS:{len([f for f in report.header_findings if f.status == AuditStatus.PASSED])}", style="green")

    console.print(Panel(score_text, title="[bold]EXECUTIVE AUDIT SUMMARY[/bold]", border_style="cyan"))
    console.print()

    # 1. Security Headers Table
    header_table = Table(title="🛡️  HTTP Security Headers Compliance", title_style="bold magenta", expand=True)
    header_table.add_column("Header", style="bold white", width=26)
    header_table.add_column("Status", width=12)
    header_table.add_column("Severity", width=10)
    header_table.add_column("Configured Value", style="italic", max_width=32)
    header_table.add_column("Details & Guidance", style="dim")

    for h in report.header_findings:
        status_style = "bold green" if h.status == AuditStatus.PASSED else ("bold red" if h.status == AuditStatus.FAILED else "bold yellow")
        val_display = (h.value[:30] + "...") if h.value and len(h.value) > 30 else (h.value or "[dim]MISSING[/dim]")
        header_table.add_row(
            h.header_name,
            f"[{status_style}]{h.status.value}[/{status_style}]",
            f"[{h.severity.color}]{h.severity.value}[/{h.severity.color}]",
            val_display,
            f"{h.description}\n[cyan]Tip: {h.remediation}[/cyan]",
        )
    console.print(header_table)
    console.print()

    # 2. CORS Table
    cors_table = Table(title="🌐  Cross-Origin Resource Sharing (CORS) Audit", title_style="bold blue", expand=True)
    cors_table.add_column("Probe Origin", style="bold white", width=24)
    cors_table.add_column("ACAO Response", style="italic", width=24)
    cors_table.add_column("ACAC", width=8)
    cors_table.add_column("Severity", width=10)
    cors_table.add_column("Evaluation", style="dim")

    for c in report.cors_findings:
        cors_table.add_row(
            c.test_origin,
            c.allow_origin or "[dim]None[/dim]",
            c.allow_credentials or "[dim]-[/dim]",
            f"[{c.severity.color}]{c.severity.value}[/{c.severity.color}]",
            f"{c.description}\n[cyan]Fix: {c.remediation}[/cyan]",
        )
    console.print(cors_table)
    console.print()

    # 3. Sensitive Endpoints Table
    ep_table = Table(title="🔍  Exposed Metadata & Sensitive Endpoints", title_style="bold yellow", expand=True)
    ep_table.add_column("Path", style="bold white", width=22)
    ep_table.add_column("Status Code", width=12)
    ep_table.add_column("Exposed?", width=10)
    ep_table.add_column("Severity", width=10)
    ep_table.add_column("Risk & Remediation", style="dim")

    for e in report.endpoint_findings:
        is_exp_text = "[bold red]YES[/bold red]" if e.is_exposed else "[bold green]NO[/bold green]"
        code_str = str(e.status_code) if e.status_code else "[dim]ERR[/dim]"
        ep_table.add_row(
            e.path,
            code_str,
            is_exp_text,
            f"[{e.severity.color}]{e.severity.value}[/{e.severity.color}]",
            f"{e.risk_description}\n[cyan]Remediation: {e.remediation}[/cyan]",
        )
    console.print(ep_table)
    console.print()


def print_jwt_analysis(res: JwtAnalysisResult) -> None:
    """Renders structured inspection views for a JWT."""
    print_banner()

    # Header Card
    hdr_text = Text()
    hdr_text.append(f"Algorithm: ", style="dim")
    hdr_text.append(f"{res.algorithm.upper()} ", style="bold red" if res.is_none_algorithm else "bold green")
    hdr_text.append(f" | Type: {res.header.get('typ', 'JWT')} | Signature Length: {len(res.signature)} chars\n", style="dim")
    if res.header.get("kid"):
        hdr_text.append(f"Key ID (kid): {res.header.get('kid')}\n", style="cyan")

    console.print(Panel(hdr_text, title="[bold]JWT HEADER METADATA[/bold]", border_style="cyan"))

    # Claims Table
    claims_table = Table(title="📋  Decoded JWT Claims (Payload)", title_style="bold magenta", expand=True)
    claims_table.add_column("Claim Key", style="bold white", width=18)
    claims_table.add_column("Value", style="italic")
    claims_table.add_column("Standard Definition / Interpretation", style="dim")

    claim_meanings = {
        "iss": "Issuer: Principal issuing the token",
        "sub": "Subject: Unique identifier of token subject",
        "aud": "Audience: Intended recipient(s) of token",
        "exp": "Expiration Time: UTC epoch when token becomes invalid",
        "nbf": "Not Before: UTC epoch before which token is not accepted",
        "iat": "Issued At: UTC epoch when token was generated",
        "jti": "JWT ID: Unique token transaction identifier",
        "role": "Assigned user permission role",
        "roles": "Assigned user permission roles",
        "scope": "Granted authorization scopes",
        "admin": "Administrative privilege flag",
    }

    for k, v in res.payload.items():
        definition = claim_meanings.get(k.lower(), "Application-specific custom claim")
        val_str = str(v)
        if len(val_str) > 60:
            val_str = val_str[:57] + "..."
        claims_table.add_row(k, val_str, definition)

    console.print(claims_table)
    console.print()

    # Temporal Validity Panel
    temp_text = Text()
    if res.issued_at:
        temp_text.append(f"• Issued At (iat):   {res.issued_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="white")
    if res.not_before:
        temp_text.append(f"• Not Before (nbf):  {res.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="white")
    if res.expires_at:
        temp_text.append(f"• Expires At (exp):  {res.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", style="white")
        if res.is_expired:
            temp_text.append(f"• Status:            EXPIRED ({abs(int(res.time_to_expiration_seconds or 0))}s ago)\n", style="bold red")
        else:
            temp_text.append(f"• Status:            VALID ({int(res.time_to_expiration_seconds or 0)}s remaining)\n", style="bold green")
    else:
        temp_text.append("• Expiration:        NO EXPIRATION SET (Never expires!)\n", style="bold yellow")

    console.print(Panel(temp_text, title="[bold]TEMPORAL VALIDITY AUDIT[/bold]", border_style="blue"))
    console.print()

    # Security Findings
    if res.findings:
        f_table = Table(title="⚠️  Security & Cryptographic Observations", title_style="bold red", expand=True)
        f_table.add_column("Severity", width=12)
        f_table.add_column("Finding", style="bold white", width=28)
        f_table.add_column("Risk Description & Remediation", style="dim")

        for f in res.findings:
            f_table.add_row(
                f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}]",
                f.title,
                f"{f.description}\n[cyan]Action: {f.remediation}[/cyan]",
            )
        console.print(f_table)
        console.print()
    else:
        console.print("[bold green]✔ No immediate structural or claims vulnerabilities detected in token.[/bold green]\n")


def print_jwt_strength(res: JwtStrengthResult) -> None:
    """Renders dictionary test telemetry and resilience verdict."""
    print_banner()

    telemetry = Text()
    telemetry.append(f"Algorithm:           {res.algorithm}\n", style="bold white")
    telemetry.append(f"Candidates Tested:   {res.candidates_tested:,}\n", style="white")
    telemetry.append(f"Elapsed Time:        {res.duration_ms:.2f} ms\n", style="white")
    telemetry.append(f"Throughput:          {res.hashes_per_second:,.1f} hashes/sec\n", style="cyan")

    console.print(Panel(telemetry, title="[bold]HMAC RESILIENCE BENCHMARK[/bold]", border_style="cyan"))

    if res.is_weak:
        alert = Text()
        alert.append(f"CRITICAL: Token signed with weak dictionary secret: '{res.cracked_secret}'\n\n", style="bold red reverse")
        alert.append(f"{res.description}\n\n", style="white")
        alert.append(f"Remediation: {res.remediation}", style="bold yellow")
        console.print(Panel(alert, title="[bold red]VULNERABILITY CONFIRMED[/bold red]", border_style="red"))
    else:
        success = Text()
        success.append("PASS: No weak dictionary secret matches found.\n", style="bold green")
        success.append(f"{res.description}\n", style="dim")
        success.append(f"Best Practice: {res.remediation}", style="dim cyan")
        console.print(Panel(success, title="[bold green]INTEGRITY AUDIT PASSED[/bold green]", border_style="green"))
    console.print()
