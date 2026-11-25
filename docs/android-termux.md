# Running Nirbhed on Android (Termux)

Yes — Nirbhed's **agent mode** runs on a phone. It's the same Python package, run
inside **Termux** (a real terminal + package manager for Android). The web
dashboard works too: Termux serves it on localhost and you open it in your phone's
browser.

**What works on Android**
- `nirbhed run` (autonomous agent) with any cheap LLM API key (DeepSeek, etc.)
- the live dashboard, operator chat, pause/stop, credential injection
- the built-in `http_request` and `python_exploit` tools — always
- `nirbhed exec` single-tool runs
- whichever external security tools you install from Termux (nmap, sqlmap, Go-based ProjectDiscovery tools, …)

**What does NOT work on Android**
- MCP mode (`nirbhed mcp`) — there's no Claude Desktop on Android to be the brain.
- Tools that need raw sockets / root (e.g. `masscan`, nmap SYN `-sS`). On a
  non-rooted phone, use connect scans (nmap falls back automatically) or skip them.
- Some Kali-only binaries simply aren't packaged for Termux/ARM — that's fine,
  Nirbhed uses what's present and skips the rest.

> This is not an APK and shouldn't be. Nirbhed orchestrates command-line tools and
> an LLM API; a sandboxed Android app couldn't run those binaries. Termux is the
> correct, standard way to do security tooling on Android.

---

## A → Z

### A. Install Termux (do NOT use the Play Store version)
The Play Store build is outdated and broken. Install from **F-Droid** or GitHub:
- F-Droid: https://f-droid.org/packages/com.termux/
- or GitHub releases: https://github.com/termux/termux-app/releases

Open Termux once so it finishes first-run setup.

### B. One-command setup (easiest)
Paste this into Termux:

```bash
curl -fsSL https://raw.githubusercontent.com/banshpalharsh/NIRBHED/main/scripts/termux-setup.sh | bash
```

It installs Python, git, Nirbhed (agent mode), and the security tools available in
Termux, then prints the next steps. If you ran this, skip to **E**.

### C. Manual setup (if you prefer to see each step)
```bash
pkg update -y && pkg upgrade -y
pkg install -y python git
pip install --upgrade "nirbhed[agent] @ git+https://github.com/banshpalharsh/NIRBHED.git"
nirbhed version
```

> Termux's `pip` is not "externally managed", so no `--break-system-packages` here
> (unlike Kali).

### D. Install security tools (optional, install what you want)
```bash
pkg install -y nmap sqlmap dnsutils whois curl        # commonly available
pkg install -y tur-repo                                # unlocks more community packages
# ProjectDiscovery tools via Go:
pkg install -y golang
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
nuclei -update-templates
```

Check what Nirbhed sees:
```bash
nirbhed tools --all
```

### E. Add your API key
Any OpenAI-compatible provider. DeepSeek is cheap and the default:
```bash
mkdir -p ~/.config/nirbhed
nano ~/.config/nirbhed/.env
```
Put in:
```env
NIRBHED_API_KEY=sk-your-deepseek-key
NIRBHED_BASE_URL=https://api.deepseek.com
NIRBHED_MODEL=deepseek-chat
```
(Other providers: see the main [Getting Started guide](getting-started.md#42-put-the-key-where-nirbhed-looks).)

Verify:
```bash
nirbhed doctor      # platform should read "Android/Termux", LLM should say "key set"
```

### F. Keep it alive while scanning (recommended)
Android kills background work when the screen sleeps. Hold a wake-lock:
```bash
pkg install -y termux-api
termux-wake-lock          # run before a long engagement; termux-wake-unlock after
```

### G. Run it
Only test what you're authorized to test.
```bash
nirbhed run http://testphp.vulnweb.com
```
It prints a dashboard URL. **Open it in your phone's browser** (Chrome/Firefox):
```
http://127.0.0.1:8787
```
There you watch findings live, **chat to steer the agent**, pause/stop, and inject
cookies/tokens. Split-screen Termux + browser works well on a phone.

Authenticated test (grab the cookie from your mobile browser's DevTools, or a proxy):
```bash
nirbhed run https://app.target.tld --cookie "session=..." --bearer <jwt>
```

Reopen the last run's dashboard any time:
```bash
nirbhed view
```

### H. Update later
```bash
pip install --upgrade "nirbhed[agent] @ git+https://github.com/banshpalharsh/NIRBHED.git"
```

---

## Troubleshooting (root cause → fix)

**`curl: command not found` on the one-liner** → `pkg install -y curl`, then re-run.

**`No matching distribution found for nirbhed`** → you used a PyPI name. Install
from GitHub exactly as in step C (with the `@ git+https://…` URL).

**`nirbhed: command not found` after install** → `pip`'s bin dir isn't on PATH.
Run `export PATH=$PATH:$HOME/.local/bin` (add it to `~/.bashrc`), or reopen Termux.

**Dashboard URL won't open** → use `http://127.0.0.1:8787` (or `http://localhost:8787`)
in the browser on the *same phone*. If the port's taken, Nirbhed picks the next one —
use the URL it actually prints.

**A tool says `not installed on host`** → it's not packaged in your Termux. Install
it (`pkg search <name>`, try `tur-repo`), or let Nirbhed use another tool. The
built-in `http_request`/`python_exploit` always work.

**nmap SYN scan / masscan fails** → those need root. On a non-rooted phone use
connect scans (nmap does this automatically as a normal user) or skip them.

**Run dies when the screen turns off** → `termux-wake-lock` (step F).

**`pip` build errors on a package needing a C compiler** → `pkg install -y clang`
then retry. Nirbhed's own deps are pure-Python, so this is rare.
