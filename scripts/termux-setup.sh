#!/data/data/com.termux/files/usr/bin/bash
# NIRBHED — one-command Android/Termux setup.
# Installs Python + git, the agent build of Nirbhed, and the security tools that
# are packaged for Termux. Safe to re-run. It never fails the whole setup because
# one optional tool is missing — Nirbhed uses whatever ends up installed.
#
#   curl -fsSL https://raw.githubusercontent.com/banshpalharsh/NIRBHED/main/scripts/termux-setup.sh | bash
#
set -u

say() { printf '\n\033[35m==>\033[0m %s\n' "$*"; }
opt() { say "installing (optional): $*"; pkg install -y "$@" || echo "  (skipped: $* not available on this Termux)"; }

if [ -z "${PREFIX:-}" ] || [ "${PREFIX#*com.termux}" = "$PREFIX" ]; then
  echo "This script is for Termux on Android. On a PC use: pip install nirbhed from GitHub."
  exit 1
fi

say "updating Termux packages"
pkg update -y && pkg upgrade -y

say "core: python + git"
pkg install -y python git || { echo "failed to install python/git"; exit 1; }

say "installing Nirbhed (agent mode) from GitHub"
pip install --upgrade "nirbhed[agent] @ git+https://github.com/banshpalharsh/NIRBHED.git"

# Security tools that are commonly available in Termux repos. Missing ones are
# skipped — the built-in http_request and python_exploit always work regardless.
opt nmap sqlmap dnsutils whois curl openssl-tool
opt tur-repo            # extra community packages (adds more tools to pkg)

say "optional: ProjectDiscovery tools (nuclei/httpx/subfinder) need Go"
echo "  to add them later:  pkg install golang && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
echo "  (then add ~/go/bin to PATH)"

say "optional: keep scans alive when the screen is off"
echo "  pkg install termux-api  &&  termux-wake-lock"

say "done. next steps:"
cat <<'EOF'

  1) add your API key (DeepSeek shown; any OpenAI-compatible key works):
       mkdir -p ~/.config/nirbhed
       printf 'NIRBHED_API_KEY=sk-your-key\nNIRBHED_BASE_URL=https://api.deepseek.com\nNIRBHED_MODEL=deepseek-chat\n' > ~/.config/nirbhed/.env

  2) verify:
       nirbhed doctor

  3) run against a target you are AUTHORIZED to test, then open the dashboard
     in your phone browser at the URL it prints (http://127.0.0.1:8787):
       nirbhed run http://testphp.vulnweb.com

Full guide: https://github.com/banshpalharsh/NIRBHED/blob/main/docs/android-termux.md
EOF
