"""Built-in tools that aren't external binaries: an HTTP client (for manual
request crafting + replay) and a Python exploit runtime (Strix-style PoC runner).
These are always available regardless of what's installed on the host.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from noctyx.tools.base import ParamSpec, ToolSpec

# Declared as ToolSpecs with binary="" so autodetect treats them as always-on.
HTTP_TOOL = ToolSpec(
    name="http_request",
    category="web",
    tier="active",
    binary="",  # handled in-process
    desc="Send a single HTTP request (method/url/headers/body) and return status, headers, body. Use for manual IDOR/authz/replay testing.",
    cmd=[],
    salience=[r"HTTP/\d", r"^\S+:\s", r"\b[2345]\d\d\b"],
    timeout=30,
    params={
        "target": ParamSpec(required=True, help="full URL"),
        "method": ParamSpec(default="GET", help="HTTP method"),
        "headers": ParamSpec(default="", help="newline-separated 'Key: Value' pairs"),
        "body": ParamSpec(default="", help="request body"),
    },
)

PY_TOOL = ToolSpec(
    name="python_exploit",
    category="exploit",
    tier="exploit",
    binary="",  # handled in-process
    desc="Run a short Python PoC/exploit script (stdlib + requests if present). Isolated interpreter. Use to prove a vuln with a working script.",
    cmd=[],
    salience=[r"\b(PWNED|SUCCESS|VULNERABLE|FAIL|Traceback|Error)\b", r"\b[2345]\d\d\b"],
    timeout=60,
    params={
        "code": ParamSpec(required=True, help="python source to execute"),
    },
)

BUILTIN_SPECS = [HTTP_TOOL, PY_TOOL]


def run_http(params: dict) -> tuple[str, int]:
    try:
        import httpx
    except ImportError:
        return "[httpx not installed]", -2
    url = params.get("target", "")
    method = (params.get("method") or "GET").upper()
    headers: dict[str, str] = {}
    for line in (params.get("headers") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    body = params.get("body") or None
    try:
        with httpx.Client(follow_redirects=False, timeout=20, verify=True) as c:
            r = c.request(method, url, headers=headers or None, content=body)
        hdrs = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        out = (
            f"HTTP {r.status_code} {r.reason_phrase}\n"
            f"--- response headers ---\n{hdrs}\n"
            f"--- body ({len(r.text)} bytes) ---\n{r.text}"
        )
        return out, 0
    except Exception as e:  # noqa: BLE001 — surface any client error to the agent
        return f"[http error: {e}]", -2


def run_python(params: dict) -> tuple[str, int]:
    code = params.get("code", "")
    if not code.strip():
        return "[empty code]", -2
    d = tempfile.mkdtemp(prefix="noctyx_poc_")
    path = os.path.join(d, "poc.py")
    with open(path, "w") as f:
        f.write(code)
    try:
        # -I: isolated mode (ignore env + cwd imports), safer PoC execution.
        proc = subprocess.run(
            ["python3", "-I", path],
            capture_output=True, text=True, timeout=params.get("_timeout", 60), check=False,
        )
        return (proc.stdout or "") + (proc.stderr or ""), proc.returncode
    except subprocess.TimeoutExpired:
        return "[poc timed out]", -1
    finally:
        try:
            os.remove(path)
            os.rmdir(d)
        except OSError:
            pass


BUILTIN_RUNNERS = {
    "http_request": run_http,
    "python_exploit": run_python,
}
