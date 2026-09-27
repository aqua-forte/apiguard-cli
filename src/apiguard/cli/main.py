"""APIGuard CLI Entrypoint - Typer command-line interface."""

import asyncio
from pathlib import Path
from typing import Annotated, Optional
import typer
from rich.console import Console

from apiguard import __version__
from apiguard.cli.display import (
    console,
    print_audit_report,
    print_banner,
    print_jwt_analysis,
    print_jwt_strength,
)
from apiguard.core.engine import AuditEngine
from apiguard.core.jwt_analyzer import JwtAnalyzer
from apiguard.core.jwt_strength import JwtStrengthAuditor

app = typer.Typer(
    name="apiguard",
    help="APIGuard: Automated REST API Health & Security Compliance Linter",
    add_completion=False,
    no_args_is_help=True,
)

jwt_app = typer.Typer(
    name="jwt",
    help="Cryptographic inspection and resilience testing for JSON Web Tokens",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(jwt_app, name="jwt")

err_console = Console(stderr=True)


def version_callback(value: bool):
    if value:
        console.print(f"[bold cyan]apiguard[/bold cyan] version [bold white]{__version__}[/bold white]")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", help="Display APIGuard version and exit.", callback=version_callback, is_eager=True),
    ] = None,
):
    """APIGuard CLI - Compliance auditor for modern REST APIs."""
    pass


@app.command(name="audit")
def audit_command(
    url: Annotated[str, typer.Argument(help="Target base URL of the REST API (e.g. https://api.example.com)")],
    timeout: Annotated[float, typer.Option("--timeout", "-t", help="HTTP request timeout in seconds.")] = 10.0,
    verify_ssl: Annotated[bool, typer.Option("--verify-ssl/--no-verify-ssl", help="Enable or disable SSL certificate verification.")] = True,
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: 'table' or 'json'.")] = "table",
    concurrency: Annotated[int, typer.Option("--concurrency", "-c", help="Concurrent probe request limit.")] = 5,
    custom_path: Annotated[Optional[list[str]], typer.Option("--path", "-p", help="Custom path(s) to probe for exposure.")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="File path to save JSON audit report.")] = None,
):
    """Run an automated compliance audit (Security Headers, CORS policies, Exposed Endpoints)."""
    with console.status(f"[bold cyan]Auditing {url}...[/bold cyan]", spinner="dots"):
        try:
            engine = AuditEngine(
                timeout=timeout,
                verify_ssl=verify_ssl,
                concurrency=concurrency,
            )
            report = asyncio.run(engine.run_audit(url, custom_endpoints=custom_path))
        except Exception as exc:
            err_console.print(f"[bold red]Audit failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    if format.lower() == "json":
        print(report.model_dump_json(indent=2))
    else:
        print_audit_report(report)

    if output:
        try:
            output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[green]✔ Report saved successfully to {output}[/green]")
        except Exception as exc:
            err_console.print(f"[yellow]Warning: Could not save report to {output}: {exc}[/yellow]")


@jwt_app.command(name="inspect")
def jwt_inspect_command(
    token: Annotated[str, typer.Argument(help="Raw JWT token string (eyJ...)")],
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: 'table' or 'json'.")] = "table",
):
    """Inspect and decode JWT Header and Payload without verification, auditing claims and algorithms."""
    try:
        result = JwtAnalyzer.analyze(token)
    except Exception as exc:
        err_console.print(f"[bold red]JWT analysis error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if format.lower() == "json":
        print(result.model_dump_json(indent=2))
    else:
        print_jwt_analysis(result)


@jwt_app.command(name="verify-strength")
def jwt_verify_strength_command(
    token: Annotated[str, typer.Argument(help="Raw JWT token string (eyJ...) to audit for weak secrets.")],
    wordlist: Annotated[Optional[Path], typer.Option("--wordlist", "-w", help="Path to custom dictionary file.")] = None,
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: 'table' or 'json'.")] = "table",
):
    """Cryptographically audit HMAC-SHA256 signature against common weak default secrets."""
    custom_candidates = None
    if wordlist:
        if not wordlist.exists():
            err_console.print(f"[bold red]Wordlist file not found:[/bold red] {wordlist}")
            raise typer.Exit(code=1)
        custom_candidates = wordlist.read_text(encoding="utf-8", errors="ignore").splitlines()

    with console.status("[bold cyan]Benchmarking HMAC signature resilience...[/bold cyan]", spinner="dots"):
        try:
            result = JwtStrengthAuditor.test_strength(token, custom_wordlist=custom_candidates)
        except Exception as exc:
            err_console.print(f"[bold red]Strength audit error:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    if format.lower() == "json":
        print(result.model_dump_json(indent=2))
    else:
        print_jwt_strength(result)


if __name__ == "__main__":
    app()
