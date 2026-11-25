# MCP setup (Claude Desktop — no API key)

In MCP mode, **Claude Desktop is the reasoning brain**. Nirbhed is a tool server:
it exposes the toolbelt + finding/evidence/report machinery over MCP stdio. You
pay nothing beyond your existing Claude plan.

> Requires the MCP 1.x SDK (what Claude Desktop uses): `pip install "nirbhed[mcp]"`
> installs a compatible version.

## 1. Install
```bash
pipx install "nirbhed[mcp]"      # or: pip install "nirbhed[mcp]"
nirbhed doctor                    # confirm it runs and see which tools are installed
```

## 2. Configure Claude Desktop
Open **Settings → Developer → Edit Config** and merge:

```json
{
  "mcpServers": {
    "nirbhed": {
      "command": "nirbhed",
      "args": ["mcp"],
      "env": {
        "NIRBHED_SCOPE": "example.com,*.example.com",
        "NIRBHED_APPROVAL": "balanced"
      }
    }
  }
}
```

Restart Claude Desktop.

## 3. Use it
Ask Claude things like:
- *"Use nirbhed to recon example.com: subfinder, httpx, then nuclei on the live hosts."*
- *"Call nirbhed_catalog so you know every tool available."*
- *"When you confirm a bug, call nirbhed_record_finding with the evidence id, then nirbhed_report."*

### Tools exposed
- every **installed** catalog tool (e.g. `nmap_quick`, `nuclei`, `httpx`, `ffuf`, `sqlmap`, `http_request`, `python_exploit`, …)
- `nirbhed_catalog` — list everything, including gated tools and ones not installed
- `nirbhed_record_finding` — store a validated finding with evidence ids
- `nirbhed_report` — write markdown + json reports, returns the paths

### Gating in MCP
Scope is always enforced (out-of-scope hosts are refused). Exploit/destructive
tools are gated: pass `"approve": true` on that tool call to authorize it, or set
`NIRBHED_APPROVAL=aggressive` to auto-authorize the exploit tier.

## Non-Claude MCP clients
Any MCP client that speaks stdio works the same way — run `nirbhed mcp` as the
server command.
