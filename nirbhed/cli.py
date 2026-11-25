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
    """Minimal .env loader (no extra dependency). Searches, in priority order:
    ./.env, ~/.config/nirbhed/.env, ~/.nirbhed.env. Values already in the real
    environment win; among files, the current directory wins. This is what lets
    a globally pipx-installed `nirbhed` still find your API key."""
    candidates = [
        Path.cwd() / ".env",
        Path.home() / ".config" / "nirbhed" / ".env",
        Path.home() / ".nirbhed.env",
    ]
    for env in candidates:
        if not env.exists():
            continue
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


def _apply_auth(cfg, header, cookie, bearer, basic, auth_file) -> None:
    """Merge CLI auth flags into cfg.auth (in place, so the registry sees them)."""
    import json as _json

    if auth_file:
        data = _json.loads(Path(auth_file).read_text())
        cfg.auth.headers.update(data.get("headers", {}) or {})
        cfg.auth.cookie = data.get("cookie", cfg.auth.cookie) or cfg.auth.cookie
        cfg.auth.bearer = data.get("bearer", cfg.auth.bearer) or cfg.auth.bearer
        cfg.auth.basic = data.get("basic", cfg.auth.basic) or cfg.auth.basic
    for h in header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            cfg.auth.headers[k.strip()] = v.strip()
    if cookie:
        cfg.auth.cookie = cookie
    if bearer:
        cfg.auth.bearer = bearer
    if basic:
        cfg.auth.basic = basic


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
    view: bool = typer.Option(True, "--view/--no-view", help="start the live web dashboard"),
    port: int = typer.Option(8787, help="viewer port (tries next free if taken)"),
    header: list[str] = typer.Option(None, "--header", "-H", help="auth header 'K: V' (repeatable)"),
    cookie: str = typer.Option(None, help="Cookie header value for authenticated testing"),
    bearer: str = typer.Option(None, help="Bearer token (no 'Bearer ' prefix)"),
    basic: str = typer.Option(None, help="HTTP basic creds as user:pass"),
    auth_file: str = typer.Option(None, "--auth-file", help="JSON: {cookie,bearer,basic,headers}"),
) -> None:
    """Run the autonomous agent (standalone mode — requires an API key).

    Opens a live dashboard at http://127.0.0.1:<port> where you can watch
    findings, chat to steer the agent, pause/stop, and inject credentials.
    """
    import time
    from urllib.parse import urlparse

    if not scope:
        host = urlparse(target).hostname if "://" in target else target.split("/")[0]
        scope = f"{host},*.{host}" if host else ""
    cfg = _config(scope, approval)
    _apply_auth(cfg, header, cookie, bearer, basic, auth_file)

    from nirbhed.agent.loop import Agent
    from nirbhed.core.report import write_reports
    from nirbhed.core.session import Inbox, RunState

    run_id = time.strftime("%Y%m%d-%H%M%S")
    inbox = Inbox()
    state = RunState(run_id, target, objective, auth_masked=cfg.auth.masked())
    state.bind_persist(cfg.state_dir / "runs" / run_id / "state.json")

    def _on_auth(body: dict) -> str:
        if body.get("cookie"):
            cfg.auth.cookie = body["cookie"]
        if body.get("bearer"):
            cfg.auth.bearer = body["bearer"]
        if body.get("header") and ":" in body["header"]:
            k, v = body["header"].split(":", 1)
            cfg.auth.headers[k.strip()] = v.strip()
        state.update(auth_masked=cfg.auth.masked())
        inbox.push("operator updated credentials; re-test authenticated surface")
        return "auth applied"

    url = None
    if view:
        from nirbhed.viewer.server import start_viewer
        try:
            _srv, actual = start_viewer(state.snapshot, inbox=inbox, on_auth=_on_auth, port=port)
            url = f"http://127.0.0.1:{actual}"
            console.print(f"[bold green]live dashboard:[/] {url}  [dim](chat / pause / stop / creds)[/]")
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]viewer unavailable:[/] {e}")

    agent = Agent(cfg, console=console, allow_gated=yes, state=state, inbox=inbox)
    result = agent.run(target, objective)

    console.print(f"\n[bold]done[/] — {result['stop_reason']}")
    console.print(f"findings: {result['findings'].count()}  |  budget: {result['budget'].summary()}")
    paths = write_reports(
        Path(out), target, result["findings"], result["evidence"],
        result["budget"].summary(), result["cache_stats"],
    )
    for k, v in paths.items():
        console.print(f"[green]report[/] {k}: {v}")

    if view and url:
        console.print(f"\n[dim]dashboard still live at {url} — press Ctrl-C to exit[/]")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("bye")


@app.command()
def view(
    port: int = typer.Option(8787, help="viewer port"),
) -> None:
    """Serve the dashboard for the most recent run (read-only). Ctrl-C to exit."""
    import json as _json
    import time

    cfg = Config.from_env()
    runs_dir = cfg.state_dir / "runs"

    def latest_state() -> dict:
        files = sorted(runs_dir.glob("*/state.json"), key=lambda p: p.stat().st_mtime)
        if not files:
            return {"status": "done", "target": "(no runs yet)", "log": [],
                    "findings": [], "budget": {}, "objective": "run `nirbhed run <target>` first"}
        try:
            return _json.loads(files[-1].read_text())
        except (OSError, _json.JSONDecodeError):
            return {"status": "done", "target": "(unreadable)", "log": [], "findings": []}

    from nirbhed.viewer.server import start_viewer
    _srv, actual = start_viewer(latest_state, inbox=None, on_auth=None, port=port)
    console.print(f"[bold green]dashboard:[/] http://127.0.0.1:{actual}  [dim](Ctrl-C to exit)[/]")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("bye")


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
    on_termux = "com.termux" in os.environ.get("PREFIX", "") or bool(os.environ.get("TERMUX_VERSION"))
    console.print("[bold]Nirbhed doctor[/]")
    console.print(f"version       : {__version__}")
    console.print(f"platform      : {'Android/Termux' if on_termux else 'standard'}")
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
    if on_termux:
        console.print("[dim]Android: MCP mode is unavailable here; use `nirbhed run` "
                      "(agent mode). Guide: docs/android-termux.md[/]")


if __name__ == "__main__":
    app()
