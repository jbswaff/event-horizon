#!/usr/bin/env python3
import json
import os
import secrets
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ----------------------------
# Config loading
# ----------------------------

CONF_PATH = os.environ.get("EH_CONF", "/etc/event-horizon/event-horizon.conf")

def load_conf(path: str) -> dict:
    cfg = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        return {}
    return cfg


CFG = load_conf(CONF_PATH)


def cfg_int(key: str, default: int) -> int:
    # Check environment variable first, then config file
    val = os.environ.get(key, CFG.get(key, str(default)))
    try:
        return int(str(val).strip())
    except Exception:
        return default


def cfg_bool(key: str, default: bool) -> bool:
    # Check environment variable first, then config file
    val = os.environ.get(key, CFG.get(key, str(default)))
    v = str(val).strip().lower()
    if v in ("true", "1", "yes", "y"):
        return True
    if v in ("false", "0", "no", "n"):
        return False
    return default


def cfg_str(key: str, default: str = "") -> str:
    # Check environment variable first, then config file
    return os.environ.get(key, CFG.get(key, default)).strip()


PORT = cfg_int("PORT", 8080)
DISABLE_MINUTES = cfg_int("DISABLE_MINUTES", 10)
DISABLE_SECONDS = max(60, DISABLE_MINUTES * 60)
SHOW_LOG_LINK = cfg_bool("SHOW_LOG_LINK", True)
PIHOLE_COUNT = cfg_int("PIHOLE_COUNT", 1)

# Determine log location - configurable for Docker volumes, fallback for non-Docker
LOG_DIR = cfg_str("LOG_DIR", "/var/log/event-horizon")
REQUESTS_LOG = os.path.join(LOG_DIR, "requests.log")


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def now_iso():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def log_request(client_ip: str, action: str, details: str = ""):
    ensure_log_dir()
    line = f"{now_iso()} client_ip={client_ip} action={action}"
    if details:
        line += f" {details}"
    line += "\n"
    try:
        with open(REQUESTS_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        # Avoid crashing the server due to logging issues
        pass


def get_piholes():
    piholes = []
    for i in range(1, PIHOLE_COUNT + 1):
        name = cfg_str(f"PIHOLE_{i}_NAME", f"pihole{i}") or f"pihole{i}"
        base = cfg_str(f"PIHOLE_{i}_URL", "")
        pw = cfg_str(f"PIHOLE_{i}_APP_PASSWORD", "")
        if base and pw:
            piholes.append({"idx": i, "name": name, "base": base.rstrip("/"), "pw": pw})
    return piholes


PIHOLES = get_piholes()

# ----------------------------
# Pi-hole v6 API helpers
# ----------------------------


class ApiError(Exception):
    pass


def http_json(
    method: str,
    url: str,
    headers: dict | None = None,
    payload: dict | None = None,
    timeout: int = 6,
):
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ct = resp.headers.get("Content-Type", "")
            if "application/json" not in ct and not body.strip().startswith("{"):
                raise ApiError(f"Non-JSON response from {url}: {ct}")
            return resp.status, body, json.loads(body)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise ApiError(f"HTTP {e.code} for {url}: {body[:200]}")
    except urllib.error.URLError as e:
        raise ApiError(f"URL error for {url}: {e}")
    except json.JSONDecodeError:
        raise ApiError(f"JSON decode error for {url}")


def api_auth(pihole: dict):
    # POST /api/auth -> session.sid + session.csrf
    url = f"{pihole['base']}/api/auth"
    _, _, js = http_json("POST", url, payload={"password": pihole["pw"]})
    sess = js.get("session", {})
    sid = sess.get("sid", "")
    csrf = sess.get("csrf", "")
    if not sid or not csrf:
        raise ApiError(f"Auth missing sid/csrf for {pihole['name']}")
    return sid, csrf


def api_headers(sid: str, csrf: str) -> dict:
    return {"X-FTL-SID": sid, "X-FTL-CSRF": csrf}


def api_get_blocking(pihole: dict, sid: str, csrf: str):
    url = f"{pihole['base']}/api/dns/blocking"
    _, _, js = http_json("GET", url, headers=api_headers(sid, csrf))
    blocking = js.get("blocking", "")
    timer = js.get("timer", None)  # may be null
    # v6 returns "enabled"/"disabled"
    if isinstance(blocking, str):
        # normalize to enabled/disabled if API uses that wording
        if blocking.lower() in ("enabled", "disabled"):
            return blocking.lower(), timer
        return blocking, timer
    if blocking is True:
        return "enabled", timer
    if blocking is False:
        return "disabled", timer
    return "", timer


def api_disable_for(pihole: dict, seconds: int):
    sid, csrf = api_auth(pihole)

    # Disable call: set blocking disabled with a timer.
    url = f"{pihole['base']}/api/dns/blocking"
    http_json("POST", url, headers=api_headers(sid, csrf), payload={"blocking": False, "timer": seconds})

    # Verify via GET
    blocking, timer = api_get_blocking(pihole, sid, csrf)
    ok = (blocking == "disabled")
    return ok, blocking, timer


# ----------------------------
# HTML templates
# NOTE: These are formatted with .format(), so ALL literal { } braces inside CSS/JS
# must be doubled as {{ and }} to avoid KeyError like "KeyError: ' margin'".
# ----------------------------

WARNING_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protection Control</title>
  <style>
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: #ffffff; color: #111; }}
    .wrap {{ max-width: 560px; margin: 0 auto; padding: 24px 18px; }}
    h1 {{ margin: 0 0 16px; font-size: 28px; font-weight: 700; }}
    .warning {{
      border: 2px solid #b00000;
      background: #fff5f5;
      color: #b00000;
      padding: 14px 14px;
      border-radius: 10px;
      font-size: 16px;
      line-height: 1.35;
    }}
    .btn {{
      width: 100%;
      margin-top: 18px;
      padding: 18px 14px;
      font-size: 20px;
      font-weight: 800;
      border: none;
      border-radius: 12px;
      background: #d00000;
      color: #ffffff;
      cursor: pointer;
    }}
    .btn:disabled {{ opacity: 0.6; cursor: not-allowed; }}
    .subnote {{
      margin-top: 12px;
      color: #b00000;
      font-weight: 700;
      text-align: center;
    }}
    .footer {{ margin-top: 22px; font-size: 13px; color: #666; text-align: center; }}
    .links {{ margin-top: 18px; font-size: 14px; text-align: center; }}
    a {{ color: #1565c0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Adblocker Control</h1>

    <div class="warning">
      <strong>Warning:</strong> Disabling protection makes you significantly more vulnerable to scams,
      malicious ads, fake download buttons, and dangerous websites.
      If you proceed, assume <strong>anything you see could be a trap.</strong> Proceed at your own risk.
    </div>

    <form method="POST" action="/disable">
      <button class="btn" type="submit" id="btn">Disable Protection for {minutes} Minutes</button>
    </form>

    <div class="subnote">Only use this if something will not work.</div>
    <div class="footer">Protection will be disabled for {minutes} minutes and should return automatically.</div>

    {logs_link}
  </div>

  <script>
    const form = document.querySelector('form');
    const btn = document.getElementById('btn');
    form.addEventListener('submit', () => {{ btn.disabled = true; btn.textContent = 'Working...'; }});
  </script>
</body>
</html>
"""

SUCCESS_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Protection Disabled</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; padding: 0; background: #ffffff; }}
    .wrap {{ max-width: 720px; margin: 0 auto; padding: 24px; text-align: center; }}
    .timer {{ font-size: 48px; font-weight: 800; color: #111; margin-top: 18px; }}
    .msg {{ margin-top: 18px; font-size: 16px; color: #b00020; line-height: 1.35; }}
    .status {{ margin-top: 18px; font-size: 14px; color: #333; text-align: left; }}
    .ok {{ color: #2e7d32; font-weight: 700; }}
    .bad {{ color: #b00020; font-weight: 700; }}
    ul {{ margin: 8px 0 0 18px; padding: 0; }}
    a {{ color: #1565c0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="timer" id="t">{mm}:{ss}</div>
    <div class="msg">
      Ads enabled. Try your desired action again. Use extreme caution while protection is disabled.
    </div>

    <div class="status">
      <div><strong>Result:</strong> {result_line}</div>
      {details_block}
      <div style="margin-top: 12px;"><a href="/">Return</a></div>
    </div>
  </div>

<script>
(function() {{
  var remaining = {seconds};
  function fmt(n) {{ return (n < 10 ? "0" : "") + n; }}
  function tick() {{
    var m = Math.floor(remaining / 60);
    var s = remaining % 60;
    document.getElementById("t").textContent = fmt(m) + ":" + fmt(s);
    if (remaining <= 0) {{
      window.location.href = "/";
      return;
    }}
    remaining -= 1;
    setTimeout(tick, 1000);
  }}
  tick();
}})();
</script>
</body>
</html>
"""

ERROR_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Action Failed</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; padding: 0; background: #ffffff; }}
    .wrap {{ max-width: 720px; margin: 0 auto; padding: 24px; }}
    .title {{ color: #b00020; font-size: 22px; font-weight: 800; margin-bottom: 10px; }}
    .msg {{ color: #333; font-size: 15px; line-height: 1.4; }}
    ul {{ margin-top: 10px; }}
    a {{ color: #1565c0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="title">Protection could not be disabled</div>
    <div class="msg">
      One or more Pi-hole instances failed to disable protection.
      If this keeps happening, contact the administrator.
      <ul>
        {items}
      </ul>
      <p><a href="/">Return</a></p>
    </div>
  </div>
</body>
</html>
"""

LOGS_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Event Horizon Logs</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; padding: 0; background: #ffffff; }}
    .wrap {{ max-width: 900px; margin: 0 auto; padding: 24px; }}
    h1 {{ font-size: 20px; margin: 0 0 12px 0; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size: 12px; }}
    .row {{ padding: 10px 12px; border: 1px solid #eee; border-radius: 10px; margin-bottom: 10px; }}
    .muted {{ color: #666; }}
    a {{ color: #1565c0; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Event Horizon Logs (last {n})</h1>
    <div class="muted"><a href="/">Return</a></div>
    <div style="margin-top: 14px;">
      {rows}
    </div>
  </div>
</body>
</html>
"""

# ----------------------------
# Runtime state (cooldown)
# ----------------------------

LAST_PRESS_EPOCH = 0.0
COOLDOWN_SECONDS = 3

# ----------------------------
# Results cache (for /results)
# ----------------------------

# token -> {"expires": float, "html": str}
RESULTS_CACHE: dict[str, dict] = {}
RESULTS_TTL_SECONDS = 15 * 60  # keep results around briefly (15 min)


def cache_put(html: str) -> str:
    token = secrets.token_urlsafe(16)
    RESULTS_CACHE[token] = {"expires": time.time() + RESULTS_TTL_SECONDS, "html": html}
    return token


def cache_get(token: str) -> str | None:
    rec = RESULTS_CACHE.get(token)
    if not rec:
        return None
    if time.time() > rec["expires"]:
        RESULTS_CACHE.pop(token, None)
        return None
    return rec["html"]


# ----------------------------
# HTTP Handler
# ----------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "event-horizon/1.0"

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _send_html(self, html: str, code: int = 200):
        data = html.encode("utf-8", errors="replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            logs_link = ""
            if SHOW_LOG_LINK:
                logs_link = '<div class="links"><a href="/logs">View logs</a></div>'
            html = WARNING_HTML.format(minutes=DISABLE_MINUTES, logs_link=logs_link)
            self._send_html(html, 200)
            return

        if path == "/results":
            qs = parse_qs(parsed.query)
            token = (qs.get("t", [""])[0] or "").strip()
            html = cache_get(token)
            if not html:
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._send_html(html, 200)
            return

        if path == "/logs":
            # The logs page does not require authentication
            try:
                ensure_log_dir()
                lines = []
                if os.path.exists(REQUESTS_LOG):
                    with open(REQUESTS_LOG, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                last = lines[-10:] if len(lines) > 10 else lines
                rows = ""
                for line in reversed(last):
                    rows += f'<div class="row mono">{line.strip()}</div>\n'
                html = LOGS_HTML.format(
                    n=min(10, len(lines)),
                    rows=rows or '<div class="row mono">(no entries)</div>',
                )
                self._send_html(html, 200)
                return
            except Exception:
                self._send_html("Logs unavailable", 500)
                return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/disable":
            self.send_response(404)
            self.end_headers()
            return

        global LAST_PRESS_EPOCH
        client_ip = self._client_ip()
        now = time.time()

        if (now - LAST_PRESS_EPOCH) < COOLDOWN_SECONDS:
            log_request(client_ip, "cooldown=active")
            mm = DISABLE_SECONDS // 60
            ss = DISABLE_SECONDS % 60
            html = SUCCESS_HTML.format(
                seconds=DISABLE_SECONDS,
                mm=f"{mm:02d}",
                ss=f"{ss:02d}",
                result_line="Already in progress",
                details_block="",
            )
            token = cache_put(html)
            self.send_response(303)
            self.send_header("Location", f"/results?t={token}")
            self.end_headers()
            return

        LAST_PRESS_EPOCH = now

        results = []
        ok_all = True
        failures = []

        # Execute disable for each Pi-hole
        for p in PIHOLES:
            try:
                ok, blocking, timer = api_disable_for(p, DISABLE_SECONDS)
                results.append((p["name"], ok, blocking, timer))
                if not ok:
                    ok_all = False
                    failures.append(f"{p['name']} (verification: blocking={blocking})")
            except Exception as e:
                ok_all = False
                failures.append(f"{p['name']} ({str(e)[:120]})")
                results.append((p["name"], False, "error", None))

        # Log outcome with friendly names
        detail_parts = []
        for name, ok, blocking, timer in results:
            detail_parts.append(f"{name}:ok={1 if ok else 0},blocking={blocking},timer={timer}")
        log_request(client_ip, f"disable_{DISABLE_MINUTES}m", "; ".join(detail_parts))

        # If total failure: show error page
        if not results or (not ok_all and all(r[1] is False for r in results)):
            items = "\n".join(f"<li>{x}</li>" for x in failures) or "<li>Unknown error</li>"
            html = ERROR_HTML.format(items=items)
            token = cache_put(html)
            self.send_response(303)
            self.send_header("Location", f"/results?t={token}")
            self.end_headers()
            return

        # Otherwise, show success page with accurate status breakdown
        display_seconds = DISABLE_SECONDS
        timers = []
        for _, ok, _, timer in results:
            if ok and isinstance(timer, int) and timer > 0:
                timers.append(timer)
        if timers:
            display_seconds = min(timers)

        mm = display_seconds // 60
        ss = display_seconds % 60

        if ok_all:
            result_line = '<span class="ok">Protection disabled successfully</span>'
            details_block = ""
        else:
            result_line = '<span class="bad">Partial success</span>'
            bad_items = "".join(f"<li>{x}</li>" for x in failures)
            details_block = f"<div style='margin-top:8px;'><strong>Issues:</strong><ul>{bad_items}</ul></div>"

        html = SUCCESS_HTML.format(
            seconds=display_seconds,
            mm=f"{mm:02d}",
            ss=f"{ss:02d}",
            result_line=result_line,
            details_block=details_block,
        )
        token = cache_put(html)
        self.send_response(303)
        self.send_header("Location", f"/results?t={token}")
        self.end_headers()
        return


# ----------------------------
# Main
# ----------------------------

def main():
    if not PIHOLES:
        raise SystemExit(f"No Pi-holes configured. Check {CONF_PATH}")

    httpd = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Listening on http://0.0.0.0:{PORT}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
