"""Local web viewer — a localhost dashboard for a running (or finished) engagement.

Shows status/phase/budget, the asset graph, findings (evidence-bound), and a live
log — and gives the operator a chat box + Pause/Resume/Stop and a panel to inject
credentials mid-engagement. Pure stdlib (http.server); binds to 127.0.0.1 only.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nirbhed.core.session import Inbox

_PAGE = """<!doctype html><html><head><meta charset=utf-8>
<title>Nirbhed — live</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0b0e14;--pan:#141a24;--ln:#1f2733;--fg:#e6edf3;--mut:#8b98a9;--acc:#8A2BE2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
header{padding:12px 16px;border-bottom:1px solid var(--ln);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
h1{font-size:15px;margin:0;color:var(--acc);letter-spacing:1px}
.pill{padding:2px 8px;border:1px solid var(--ln);border-radius:12px;color:var(--mut);font-size:12px}
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px}
.panel{background:var(--pan);border:1px solid var(--ln);border-radius:8px;padding:12px;min-height:80px}
.panel h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin:0 0 8px}
pre{white-space:pre-wrap;word-break:break-word;margin:0;max-height:300px;overflow:auto}
#log{max-height:340px;overflow:auto;font-size:12.5px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--ln);vertical-align:top;font-size:12.5px}
.sev{font-weight:bold;padding:1px 6px;border-radius:4px}
.critical{background:#7f1d1d;color:#fff}.high{background:#9a3412;color:#fff}.medium{background:#854d0e;color:#fff}.low{background:#1e3a8a;color:#fff}.info{background:#334155;color:#fff}
input,textarea,button{font:inherit;background:#0b0e14;color:var(--fg);border:1px solid var(--ln);border-radius:6px;padding:6px 8px}
button{background:var(--acc);border:0;color:#fff;cursor:pointer}button.sec{background:#243040}
.row{display:flex;gap:6px;margin-top:6px}.row input,.row textarea{flex:1}
.full{grid-column:1 / -1}
.dot{height:8px;width:8px;border-radius:50%;display:inline-block;margin-right:6px}
.running{background:#22c55e}.paused{background:#eab308}.done{background:#3b82f6}.stopped{background:#ef4444}
</style></head><body>
<header>
  <h1>🗡️ NIRBHED</h1>
  <span class=pill id=target>—</span>
  <span class=pill><span class="dot running" id=dot></span><span id=status>—</span></span>
  <span class=pill id=phase>—</span>
  <span class=pill id=elapsed>0s</span>
  <span class=pill id=budget>—</span>
</header>
<div class=wrap>
  <div class=panel><h2>Objective</h2><pre id=objective>—</pre></div>
  <div class=panel><h2>Auth configured</h2><pre id=auth>none</pre></div>
  <div class=panel full><h2>Findings (<span id=fcount>0</span>)</h2>
    <table><thead><tr><th>sev</th><th>title</th><th>target</th><th>cwe</th><th>status</th></tr></thead>
    <tbody id=findings></tbody></table></div>
  <div class=panel><h2>Asset graph / coverage</h2><pre id=graph>—</pre></div>
  <div class=panel><h2>Live log</h2><pre id=log></pre></div>
  <div class=panel full><h2>Operator — talk to the agent</h2>
    <div class=row>
      <textarea id=msg rows=2 placeholder="e.g. focus on /api/v2 IDOR, skip bruteforce, stop after this"></textarea>
      <button onclick=send()>Send</button>
    </div>
    <div class=row>
      <button class=sec onclick="ctl('pause')">Pause</button>
      <button class=sec onclick="ctl('resume')">Resume</button>
      <button class=sec onclick="ctl('stop')" style="background:#7f1d1d">Stop</button>
    </div>
  </div>
  <div class=panel full><h2>Inject credentials (mid-engagement)</h2>
    <div class=row><input id=cookie placeholder="Cookie: session=...; other=..."></div>
    <div class=row><input id=bearer placeholder="Bearer token (no 'Bearer ' prefix)"></div>
    <div class=row><input id=hdr placeholder="Custom header  e.g.  X-API-Key: abc123"></div>
    <div class=row><button onclick=setauth()>Apply auth</button><span class=pill id=authmsg></span></div>
  </div>
</div>
<script>
async function poll(){try{let s=await(await fetch('/api/state')).json();render(s)}catch(e){}}
function esc(t){return (t||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function render(s){
  target.textContent=s.target||'—';status.textContent=s.status;phase.textContent='phase: '+(s.phase||'—');
  elapsed.textContent=(s.elapsed||0)+'s';objective.textContent=s.objective||'—';
  dot.className='dot '+(s.status||'running');
  let b=s.budget||{};budget.textContent=`tok ${b.tokens_used||0}/${b.max_tokens||0} · turns ${b.turns_used||0}/${b.max_turns||0}`;
  graph.textContent=s.graph_text||'—';
  let a=s.auth||{};auth.textContent=Object.keys(a).length?Object.entries(a).map(([k,v])=>k+': '+v).join('\\n'):'none';
  log.textContent=(s.log||[]).join('\\n');log.scrollTop=log.scrollHeight;
  let f=s.findings||[];fcount.textContent=f.length;
  findings.innerHTML=f.map(x=>`<tr><td><span class="sev ${x.severity}">${x.severity}</span></td><td>${esc(x.title)}</td><td>${esc(x.target)}</td><td>${esc(x.cwe||'')}</td><td>${esc(x.status||'')}</td></tr>`).join('');
}
async function send(){let m=msg.value.trim();if(!m)return;msg.value='';await fetch('/api/chat',{method:'POST',body:JSON.stringify({message:m})});poll()}
async function ctl(a){await fetch('/api/control',{method:'POST',body:JSON.stringify({action:a})});poll()}
async function setauth(){let r=await fetch('/api/auth',{method:'POST',body:JSON.stringify({cookie:cookie.value,bearer:bearer.value,header:hdr.value})});authmsg.textContent=(await r.json()).message||'applied';cookie.value=bearer.value=hdr.value='';poll()}
setInterval(poll,1500);poll();
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence default stderr logging
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except (json.JSONDecodeError, ValueError):
            return {}

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, _PAGE.encode(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self._json(self.server.get_state())  # type: ignore[attr-defined]
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        srv = self.server
        body = self._read_json()
        if self.path == "/api/chat" and srv.inbox:  # type: ignore[attr-defined]
            srv.inbox.push(body.get("message", ""))  # type: ignore[attr-defined]
            self._json({"ok": True})
        elif self.path == "/api/control" and srv.inbox:  # type: ignore[attr-defined]
            act = body.get("action")
            ib = srv.inbox  # type: ignore[attr-defined]
            if act == "pause":
                ib.set_pause(True)
            elif act == "resume":
                ib.set_pause(False)
            elif act == "stop":
                ib.request_stop()
            self._json({"ok": True, "action": act})
        elif self.path == "/api/auth" and srv.on_auth:  # type: ignore[attr-defined]
            msg = srv.on_auth(body)  # type: ignore[attr-defined]
            self._json({"ok": True, "message": msg})
        else:
            self._json({"ok": False, "message": "unsupported"}, code=400)


def start_viewer(get_state: Callable[[], dict], inbox: Inbox | None = None,
                 on_auth: Callable[[dict], str] | None = None,
                 host: str = "127.0.0.1", port: int = 8787):
    """Start the viewer in a daemon thread. Returns (server, actual_port)."""
    last_err = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer((host, p), _Handler)
            break
        except OSError as e:
            last_err = e
            srv = None
    if srv is None:
        raise RuntimeError(f"could not bind a viewer port: {last_err}")
    srv.get_state = get_state          # type: ignore[attr-defined]
    srv.inbox = inbox                  # type: ignore[attr-defined]
    srv.on_auth = on_auth              # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]
