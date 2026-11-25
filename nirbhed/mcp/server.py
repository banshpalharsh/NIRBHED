"""MCP server — the NO-API-KEY path.

Claude Desktop (or any MCP client) is the reasoning brain; Nirbhed exposes its
whole toolbelt + the finding/evidence/report machinery over MCP stdio. Scope
gating and output distillation still apply, so even here the client receives
token-cheap, on-target results.

Every installed catalog tool is published as its own MCP tool. Plus meta tools:
  nirbhed_catalog         list all tools (incl. gated / not-installed)
  nirbhed_record_finding  store a vulnerability with evidence refs
  nirbhed_report          write markdown+json reports and return paths
"""

from __future__ import annotations

from pathlib import Path

from nirbhed.config import Config
from nirbhed.core.findings import Finding, FindingStore, RetestStatus
from nirbhed.core.report import write_reports
from nirbhed.tools.registry import Registry


def _schema_for(spec) -> dict:
    props: dict = {}
    required: list[str] = []
    for pname, pspec in spec.params.items():
        props[pname] = {"type": "string", "description": pspec.help or pname}
        if pspec.required:
            required.append(pname)
    # 'approve' lets the client consent to a gated (exploit/destructive) run.
    props["approve"] = {
        "type": "boolean",
        "description": "set true to authorize this run if the tool is gated (exploit/destructive tier)",
    }
    return {"type": "object", "properties": props, "required": required}


def build_server(config: Config):
    try:
        from mcp import types
        from mcp.server import Server
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "MCP mode needs the MCP SDK. Install with: pip install 'nirbhed[mcp]'"
        ) from e

    registry = Registry(config)
    findings = FindingStore()
    server = Server("nirbhed")

    @server.list_tools()
    async def list_tools() -> list:
        tools = []
        for spec in registry.available():
            tools.append(types.Tool(
                name=spec.name,
                description=f"[{spec.category}/{spec.tier}] {spec.desc}",
                inputSchema=_schema_for(spec),
            ))
        tools += [
            types.Tool(
                name="nirbhed_catalog",
                description="List every Nirbhed tool, including gated ones and ones not installed on this host.",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="nirbhed_record_finding",
                description="Record a validated vulnerability finding (with evidence ids from prior tool runs).",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "target": {"type": "string"},
                        "description": {"type": "string"},
                        "owasp": {"type": "string"},
                        "cwe": {"type": "string"},
                        "cvss": {"type": "number"},
                        "repro": {"type": "string"},
                        "remediation": {"type": "string"},
                        "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["title", "severity", "target"],
                },
            ),
            types.Tool(
                name="nirbhed_report",
                description="Write markdown + json pentest reports for all recorded findings; returns file paths.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "out_dir": {"type": "string", "description": "output directory (default ./runs)"},
                    },
                    "required": ["target"],
                },
            ),
        ]
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        arguments = arguments or {}

        if name == "nirbhed_catalog":
            txt = registry.catalog_signature(only_available=False)
            missing = registry.missing_binaries()
            if missing:
                txt += "\n\n[not installed on this host]: " + ", ".join(missing)
            return [types.TextContent(type="text", text=txt)]

        if name == "nirbhed_record_finding":
            f = Finding(
                title=arguments.get("title", "untitled"),
                severity=arguments.get("severity", "info"),
                target=arguments.get("target", ""),
                description=arguments.get("description", ""),
                owasp=arguments.get("owasp", ""),
                cwe=arguments.get("cwe", ""),
                cvss=float(arguments.get("cvss", 0) or 0),
                evidence_ids=arguments.get("evidence_ids", []) or [],
                repro=arguments.get("repro", ""),
                remediation=arguments.get("remediation", ""),
                status=RetestStatus.REPRODUCIBLE if arguments.get("evidence_ids")
                else RetestStatus.UNVERIFIED,
            )
            is_new = findings.add(f)
            return [types.TextContent(
                type="text",
                text=f"{'recorded' if is_new else 'merged duplicate'}: [{f.severity}] {f.title} "
                     f"(total findings: {findings.count()})",
            )]

        if name == "nirbhed_report":
            out_dir = Path(arguments.get("out_dir") or (config.workdir / "runs"))
            paths = write_reports(
                out_dir, arguments.get("target", "target"), findings,
                registry.evidence, "n/a (MCP mode)", registry.cache.stats,
            )
            return [types.TextContent(
                type="text",
                text="reports written:\n" + "\n".join(f"- {k}: {v}" for k, v in paths.items()),
            )]

        # otherwise: a catalog tool
        approve = bool(arguments.pop("approve", False))
        res = registry.run(name, arguments, allow_gated=approve)
        if res.ok:
            return [types.TextContent(type="text", text=res.output)]
        return [types.TextContent(type="text", text=f"[error] {res.error}\n{res.output}".strip())]

    return server


def serve(config: Config) -> None:
    import anyio  # mcp ships anyio
    from mcp.server.stdio import stdio_server

    server = build_server(config)

    async def _main():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_main)
