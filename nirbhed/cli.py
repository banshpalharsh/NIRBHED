"""Nirbhed CLI.

  nirbhed mcp                      start the MCP server (plug into Claude Desktop; no API key)
  nirbhed run <target>            autonomous agent pentest (needs an API key)
  nirbhed exec <tool> <target>    run a single tool directly — no LLM, zero tokens
  nirbhed tools                   list available tools (+ what's missing)
  nirbhed doctor                  show config, providers and installed binaries
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from nirbhed.config import Config
from nirbhed.version import __version__

app = typer.Typer(add_completion=False, help="Nirbhed — token-frugal offensive-security AI agent + MCP server.")
console = Console()


def _load_dotenv() -> None:
    """Minimal .env loader (no extra dependency)."""
    env = Path.cwd() / ".env"
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def _config(scope: str | None, approval: str | None) -> Config:
    _load_dotenv()
    if scope:
        os.environ["NIRBHED_SCOPE"] = scope
    if approval:
        os.environ["NIRBHED_APPROVAL"] = approval
    return Config.from_env()


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"nirbhed {__version__}")


@app.command()
def mcp(
    scope: str = typer.Option(None, help="comma-separated allowed host globs"),
    approval: str = typer.Option(None, help="quiet|balanced|aggressive"),
) -> None:
    """Start the MCP server over stdio (for Claude Desktop / any MCP client, no API key)."""
    cfg = _config(scope, approval)
    from nirbhed.mcp.server import serve
    serve(cfg)


@app.command()
def run(
    target: str = typer.Argument(..., help="URL / host / domain to test"),
    objective: str = typer.Option(
        "Find and prove high-impact vulnerabilities (OWASP Top 10, authz, injection, exposure).",
        help="what the agent should accomplish",
    ),
    scope: str = typer.Option(None, help="comma-separated allowed host globs (defaults to target host)"),
    approval: str = typer.Option("balanced", help="quiet|balanced|aggressive"),
    yes: bool = typer.Option(False, "--yes", "-y", help="auto-authorize gated (exploit) tools"),
    out: str = typer.Option("runs", help="report output directory"),
) -> None:
    """Run the autonomous agent (standalone mode — requires an API key)."""
    from urllib.parse import urlparse

    if not scope:
        host = urlparse(target).hostname if "://" in target else target.split("/")[0]
        scope = f"{host},*.{host}" if host else ""
    cfg = _config(scope, approval)

    from nirbhed.agent.loop import Agent
    from nirbhed.core.report import write_reports

    agent = Agent(cfg, console=console, allow_gated=yes)
    result = agent.run(target, objective)

    console.print(f"\n[bold]done[/] — {result['stop_reason']}")
    console.print(f"findings: {result['findings'].count()}  |  budget: {result['budget'].summary()}")

    paths = write_reports(
        Path(out), target, result["findings"], result["evidence"],
        result["budget"].summary(), result["cache_stats"],
    )
    for k, v in paths.items():
        console.print(f"[green]report[/] {k}: {v}")


@app.command()
def exec(
    tool: str = typer.Argument(..., help="tool name (see `nirbhed tools`)"),
    target: str = typer.Argument("", help="target host/url"),
    extra: str = typer.Option("", help="extra raw flags passed to the tool"),
    scope: str = typer.Option(None, help="comma-separated allowed host globs"),
    yes: bool = typer.Option(False, "--yes", "-y", help="authorize gated tool"),
) -> None:
    """Run ONE tool directly, with distillation + caching, no LLM involved (zero tokens)."""
    cfg = _config(scope, "aggressive" if yes else "balanced")
    from nirbhed.tools.registry import Registry

    reg = Registry(cfg)
    params = {"target": target} if target else {}
    if extra:
        params["extra"] = extra
    res = reg.run(tool, params, allow_gated=yes)
    if res.ok:
        console.print(res.output)
    else:
        console.print(f"[red]error[/]: {res.error}")
        if res.output:
            console.print(res.output)
        raise typer.Exit(1)


@app.command()
def tools(
    all_: bool = typer.Option(False, "--all", help="include tools whose binary isn't installed"),
) -> None:
    """List tools in the catalog."""
    cfg = Config.from_env()
    from nirbhed.tools.registry import Registry

    reg = Registry(cfg)
    specs = list(reg.specs.values()) if all_ else reg.available()
    table = Table(title=f"Nirbhed tools ({len(specs)} shown)")
    table.add_column("tool", style="cyan")
    table.add_column("cat")
    table.add_column("tier")
    table.add_column("installed")
    table.add_column("description")
    for s in sorted(specs, key=lambda x: (x.category, x.name)):
        installed = "—" if s.binary == "" else ("✓" if s.available() else "✗")
        table.add_row(s.name, s.category, s.tier, installed, s.desc[:60])
    console.print(table)
    if all_:
        miss = reg.missing_binaries()
        if miss:
            console.print(f"\n[yellow]not installed[/]: {', '.join(miss)}")


@app.command()
def doctor() -> None:
    """Show configuration, provider status and tool availability."""
    _load_dotenv()
    cfg = Config.from_env()
    from nirbhed.tools.registry import Registry

    reg = Registry(cfg)
    avail = reg.available()
    console.print("[bold]Nirbhed doctor[/]")
    console.print(f"version       : {__version__}")
    console.print(f"primary LLM   : {cfg.primary.model or '-'} @ {cfg.primary.base_url or '-'} "
                  f"({'key set' if cfg.primary.api_key else 'NO KEY'})")
    console.print(f"fallback LLM  : {cfg.fallback.model or '-'} "
                  f"({'usable' if cfg.fallback.usable else 'not set'})")
    console.print(f"budgets       : tokens={cfg.max_tokens} turns={cfg.max_turns} secs={cfg.max_seconds}")
    console.print(f"distill cap   : {cfg.distill_max_chars} chars   cache={'on' if cfg.cache else 'off'}")
    console.print(f"scope         : {cfg.scope or '(unrestricted)'}")
    console.print(f"approval      : {cfg.approval}")
    console.print(f"tools         : {len(avail)} available / {len(reg.specs)} in catalog")
    miss = reg.missing_binaries()
    if miss:
        console.print(f"[yellow]missing bins[/] : {', '.join(miss)}")


if __name__ == "__main__":
    app()
