# Getting Started with Nirbhed (zero assumed knowledge)

This walks you from a fresh machine to a finished pentest report, with the exact
commands. It assumes Kali/Debian Linux (adapt `apt` for other distros). If a step
errors, jump to [Troubleshooting](#troubleshooting) — it lists the root cause and
fix for every common failure, including the "No matching distribution" one.

- [1. Prerequisites](#1-prerequisites)
- [2. Install Nirbhed](#2-install-nirbhed)
- [3. Install the security tools it drives](#3-install-the-security-tools-it-drives)
- [4. Mode A — standalone with a cheap API key (best on Kali)](#4-mode-a--standalone-with-a-cheap-api-key-best-on-kali)
- [5. Mode B — MCP with Claude Desktop (no API key)](#5-mode-b--mcp-with-claude-desktop-no-api-key)
- [6. Run a single tool (no LLM, zero tokens)](#6-run-a-single-tool-no-llm-zero-tokens)
- [7. Reading the report](#7-reading-the-report)
- [8. Updating Nirbhed](#8-updating-nirbhed)
- [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites

You need Python 3.10+ and `pipx`. On Kali:

```bash
sudo apt update
sudo apt install -y python3 python3-pip pipx git
pipx ensurepath      # adds ~/.local/bin to PATH so the `nirbhed` command is found
exec $SHELL          # reload your shell so PATH changes take effect
python3 --version    # must be 3.10 or higher
```

> **Why pipx?** Kali's system Python is "externally managed" (PEP 668) — a plain
> `pip install` is blocked. `pipx` installs each app in its own isolated
> environment and puts its command on your PATH. It's the clean way.

---

## 2. Install Nirbhed

Nirbhed is **not on PyPI yet**, so install it straight from GitHub (this is why
`pipx install "nirbhed"` fails with *"No matching distribution found"* — PyPI has
no such package).

```bash
# installs BOTH modes (agent + MCP) — recommended
pipx install "nirbhed[all] @ git+https://github.com/banshpalharsh/NIRBHED.git"
```

Only want one mode:

```bash
pipx install "nirbhed[agent] @ git+https://github.com/banshpalharsh/NIRBHED.git"  # API-key mode
pipx install "nirbhed[mcp]   @ git+https://github.com/banshpalharsh/NIRBHED.git"  # MCP mode
```

Prefer a local clone (e.g. to hack on it):

```bash
git clone https://github.com/banshpalharsh/NIRBHED.git
cd NIRBHED
pip install -e ".[all]" --break-system-packages
```

Confirm it works:

```bash
nirbhed doctor
```

You'll see your version, LLM config (no key yet — that's fine), and which security
tools are installed vs missing.

---

## 3. Install the security tools it drives

Nirbhed *orchestrates* real binaries — it doesn't bundle them. Install the ones
you want; `nirbhed tools --all` shows what's present (`✓`) and missing (`✗`).

On Kali, most are one line:

```bash
sudo apt install -y nmap nikto hydra john hashcat sqlmap whatweb wafw00f \
                    whois dnsutils exiftool steghide binwalk radare2 masscan
```

ProjectDiscovery tools (httpx, nuclei, katana, subfinder, dnsx) — install with Go,
or via apt on recent Kali:

```bash
sudo apt install -y httpx-toolkit nuclei katana subfinder dnsx   # if packaged
# or with Go:
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# (repeat for httpx, katana, subfinder, dnsx; ensure ~/go/bin is on PATH)
nuclei -update-templates
```

You don't need all of them. Even with only a handful installed, Nirbhed works —
it uses what's available and skips the rest.

---

## 4. Mode A — standalone with a cheap API key (best on Kali)

This is the mode to use on Kali: Nirbhed runs the whole loop itself using a cheap
LLM API. (Claude Desktop has no Linux build, so MCP mode is for Windows/macOS —
see Mode B.)

### 4.1 Get an API key

Any OpenAI-compatible provider works. Cheapest common choice is **DeepSeek**:
sign up at platform.deepseek.com → API keys → create one (starts with `sk-`).

### 4.2 Put the key where Nirbhed looks

Nirbhed reads, in priority order: `./.env` (current folder),
`~/.config/nirbhed/.env`, then `~/.nirbhed.env`. For a global install, the config
folder is the clean choice:

```bash
mkdir -p ~/.config/nirbhed
nano ~/.config/nirbhed/.env
```

Paste this and edit the key:

```env
NIRBHED_API_KEY=sk-your-deepseek-key
NIRBHED_BASE_URL=https://api.deepseek.com
NIRBHED_MODEL=deepseek-chat
```

Prefer not to use a file? Just export it for the session:

```bash
export NIRBHED_API_KEY=sk-your-deepseek-key
export NIRBHED_BASE_URL=https://api.deepseek.com
export NIRBHED_MODEL=deepseek-chat
```

Check it's picked up:

```bash
nirbhed doctor      # should show "key set" next to primary LLM
```

**Other providers** — same three variables, different values:

| Provider | `NIRBHED_BASE_URL` | `NIRBHED_MODEL` |
|----------|--------------------|-----------------|
| DeepSeek | `https://api.deepseek.com` | `deepseek-chat` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| Anthropic (Claude) | `https://api.anthropic.com/v1/` | `claude-haiku-4-5` |
| OpenRouter | `https://openrouter.ai/api/v1` | `deepseek/deepseek-chat` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-2.0-flash` |
| Ollama (local, free) | `http://localhost:11434/v1` | `llama3.1` (set `NIRBHED_API_KEY=ollama`) |

You can also set a **fallback** provider that's used automatically if the primary
errors or hits its rate limit:

```env
NIRBHED_FALLBACK_API_KEY=sk-ant-...
NIRBHED_FALLBACK_BASE_URL=https://api.anthropic.com/v1/
NIRBHED_FALLBACK_MODEL=claude-haiku-4-5
```

### 4.3 Run it

**Only test systems you are authorized to test.** Point it at an authorized lab or
your own asset:

```bash
nirbhed run http://testphp.vulnweb.com
```

What happens: Nirbhed derives the scope from the target host automatically, runs
recon → probing → (proof), records evidence-bound findings, and writes a report to
`./runs/`. Live progress prints to your terminal.

Useful flags:

```bash
nirbhed run https://target.tld \
  --objective "Find IDOR and SQLi in the API under /api/v2" \
  --scope "target.tld,*.target.tld" \
  --approval balanced \     # quiet | balanced | aggressive
  --yes \                   # auto-authorize exploit-tier tools (bruteforce, sqlmap...)
  --out runs
```

### 4.4 What scope and approval mean (plain version)

- **Scope** = which hosts Nirbhed may touch. By default it's the target host and
  its subdomains. Anything off-scope is refused, hard.
- **Approval tiers**: tools are `recon` (passive), `active` (non-destructive
  probing), `exploit` (bruteforce/fuzzing/sqlmap), or `destructive`.
  - `quiet` → only recon auto-runs.
  - `balanced` (default) → recon + active auto-run; exploit needs `--yes`.
  - `aggressive` → recon + active + exploit auto-run.
  - destructive always needs explicit approval.

### 4.5 Watch and steer it — the live dashboard

When you run `nirbhed run`, it prints a line like:

```
live dashboard: http://127.0.0.1:8787  (chat / pause / stop / creds)
```

Open that URL in a browser. You get, updating live:
- status, phase, elapsed time, and token/turn budget;
- the **asset graph** (subdomains/services/endpoints) and coverage;
- the **findings** table (severity, CWE, verified/suspected);
- a scrolling **log** of what the agent is doing.

And you can act on it, mid-engagement — this is the human-in-the-loop part:
- **Chat box** → type instructions the agent obeys on its next step, e.g.
  *"focus on the /api/v2 endpoints"*, *"skip bruteforce"*, *"try IDOR on the
  order ids"*, *"wrap up and report"*.
- **Pause / Resume / Stop** buttons → stop the test instantly, or hold it while
  you check something.
- **Inject credentials** panel → paste a cookie/token/header and hit Apply; the
  agent immediately re-tests authenticated surface with it.

Reopen the last run's dashboard any time (read-only):

```bash
nirbhed view
```

Turn the dashboard off with `nirbhed run ... --no-view`, or change the port with
`--port 9000`.

### 4.6 Authenticated testing (cookies / tokens / creds)

Most real bugs (IDOR/BOLA, broken access control, privilege escalation) are behind
a login. Give Nirbhed the session so it can test as a logged-in user. Four ways —
use whichever fits:

```bash
# one-off flags
nirbhed run https://app.target.tld \
  --cookie "session=eyJ...; csrftoken=abc" \
  --bearer "eyJhbGciOi..." \
  -H "X-API-Key: 123" -H "X-Tenant: acme"

# basic auth
nirbhed run https://app.target.tld --basic "alice:s3cret"

# a reusable file
nirbhed run https://app.target.tld --auth-file auth.json
```

`auth.json`:
```json
{ "cookie": "session=eyJ...", "bearer": "eyJ...", "basic": "", "headers": { "X-API-Key": "123" } }
```

Or set them in your `.env` (`NIRBHED_COOKIE`, `NIRBHED_BEARER`, `NIRBHED_BASIC`,
`NIRBHED_HEADERS`), or paste them into the dashboard while a run is going.

How it's used: the creds are attached automatically to the built-in `http_request`
tool and exposed to `python_exploit` PoCs as env vars (`NIRBHED_COOKIE`,
`NIRBHED_BEARER`, `NIRBHED_HDR_X_API_KEY`, …). **They are never shown to the LLM** —
the agent is only told "auth is configured" — so your session token can't leak into
a model prompt.

> Grab a cookie/token from your browser DevTools → Network tab → a request to the
> app → Request Headers → copy the `Cookie:` / `Authorization:` value.

---

## 5. Mode B — MCP with Claude Desktop (no API key)

Here **Claude Desktop is the brain** — you pay nothing beyond your Claude plan.
Claude Desktop runs on **Windows and macOS** (no Linux build). So either run this
on your Windows 11 host, or on Linux use another MCP-capable client.

1. Install Nirbhed on the same OS as Claude Desktop (step 2 above; on Windows,
   `pipx install "nirbhed[mcp] @ git+https://github.com/banshpalharsh/NIRBHED.git"`).
2. Edit Claude Desktop's config (**Settings → Developer → Edit Config**), or the file directly:
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "nirbhed": {
      "command": "nirbhed",
      "args": ["mcp"],
      "env": { "NIRBHED_SCOPE": "example.com,*.example.com", "NIRBHED_APPROVAL": "balanced" }
    }
  }
}
```

3. Fully restart Claude Desktop. Then ask, e.g.:
   *"Use nirbhed to recon example.com — subfinder then httpx then nuclei — record findings and write a report."*

Every installed tool appears as a callable tool, plus `nirbhed_catalog`,
`nirbhed_record_finding`, and `nirbhed_report`. Gated (exploit) tools need
`"approve": true` on the call, or set `NIRBHED_APPROVAL=aggressive`.

> Running Claude Desktop on Windows but want the tools from your Kali VM/WSL? Set
> `"command": "wsl"`, `"args": ["nirbhed", "mcp"]`. More detail in
> [docs/mcp-setup.md](mcp-setup.md).

---

## 6. Run a single tool (no LLM, zero tokens)

You don't need an API key or Claude to use the toolbelt. This runs one tool with
distillation + caching + scope gating, and nothing else:

```bash
nirbhed exec nmap_quick scanme.nmap.org
nirbhed exec httpx https://example.com
nirbhed exec subfinder example.com
nirbhed exec sqlmap "http://test/vuln.php?id=1" --extra "--dbs" --yes
```

List everything callable: `nirbhed tools --all`.

---

## 7. Reading the report

After `nirbhed run`, open `runs/<target>.md` (human-readable) or `runs/<target>.json`
(machine-readable). Each finding shows severity, CVSS/OWASP/CWE, reproduction, and
the **evidence** — the exact command and its captured output — so you can verify or
hand it to a client. Findings without evidence are marked *unverified/suspected*;
high/critical findings are only recorded once proven.

---

## 8. Updating Nirbhed

New version pushed to GitHub? Pull it in one line.

**If you installed with pipx:**
```bash
pipx reinstall nirbhed
# (pipx remembers the GitHub source. If it ever forgets, reinstall it:)
pipx install --force "nirbhed[all] @ git+https://github.com/banshpalharsh/NIRBHED.git"
nirbhed version      # confirm the new version
```

**If you cloned the repo:**
```bash
cd NIRBHED
git pull
pip install -e ".[all]" --break-system-packages
nirbhed version
```

Your API key and config are untouched by an update — they live in
`~/.config/nirbhed/.env`, not inside the package. Pin a specific version by adding
`@v0.3.0` (a git tag/branch) to the install URL.

---

## Troubleshooting

Each item is **root cause → fix**.

**`ERROR: No matching distribution found for nirbhed`**
Root cause: it's not on PyPI. Fix: install from GitHub (step 2), not `pipx install "nirbhed"`.

**`error: externally-managed-environment` (on `pip install`)**
Root cause: Kali/Debian PEP 668 protection. Fix: use `pipx` (step 2), or add
`--break-system-packages` to `pip install`, or work inside a `python3 -m venv`.

**`nirbhed: command not found` after install**
Root cause: `~/.local/bin` isn't on PATH. Fix: `pipx ensurepath` then open a new
terminal (or `exec $SHELL`).

**`doctor` shows `primary LLM ... (NO KEY)` / run says no usable provider**
Root cause: the key isn't in any location Nirbhed reads. Fix: put it in
`~/.config/nirbhed/.env` (step 4.2) or `export NIRBHED_API_KEY=...`, then re-run
`nirbhed doctor` to confirm "key set".

**A tool call returns `'<binary>' not installed on host`**
Root cause: that security tool isn't installed. Fix: install it (step 3), or let
Nirbhed use a different tool — `nirbhed tools` shows what's available.

**`out of scope: <host>`**
Root cause: the target isn't in scope. Fix: pass `--scope "host,*.host"`, or run
against the intended host. This guard is intentional — it keeps you legal.

**`approval required (exploit tier)`**
Root cause: an intrusive tool is gated. Fix: add `--yes`, or set
`--approval aggressive`. In MCP, pass `"approve": true` on the call.

**LLM replies are rejected as "not valid JSON" repeatedly, run stalls**
Root cause: the model is too weak to follow the JSON protocol. Fix: use a stronger
model (`deepseek-chat`, `gpt-4o-mini`, or a Claude model). The stall detector stops
the run instead of burning budget.

**TLS/`proxy` errors inside a locked-down network**
Root cause: egress filtering. Fix: run from a host that can reach your targets and
package registries; Nirbhed doesn't bypass network controls.
