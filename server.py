#!/usr/bin/env python3
import json
import os
import re
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

CONF_PATH = os.environ.get("EH_CONF", "/etc/event-horizon/event-horizon.conf")

LOG_DIR = "/var/log/event-horizon"
REQUESTS_LOG = os.path.join(LOG_DIR, "requests.log")

# In-memory state for last disable request
LAST_DISABLE_EPOCH = 0.0
LAST_DISABLE_SECONDS = 0
LAST_RESULTS = []  # list of dicts per pihole result


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def read_conf(path: str) -> dict:
    conf = {}
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            conf[k.strip()] = v.strip()
    return conf


def get_int(conf: dict, key: str, default: int) -> int:
    try:
        return int(conf.get(key, str(default)))
    except Exception:
        return default


def get_bool(conf: dict, key: str, default: bool) -> bool:
    v = conf.get(key, "true" if default else "false").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(REQUESTS_LOG):
        with open(REQUESTS_LOG, "a", encoding="utf-8"):
            pass


def log_request(client_ip: str, action: str, details: str):
    ensure_log_dir()
    line = f"{now_utc_iso()} client_ip={client_ip} action={action} {details}\n"
    with open(REQUESTS_LOG, "a", encoding="utf-8") as f:
        f.write(line)


def http_json(method: str, url: str, headers: dict, payload: dict | None, timeout: float = 4.0) -> tuple[int, dict]:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = Request(url=url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if payload is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            code = getattr(resp, "status", 200)
            try:
                return code, json.loads(body) if body else {}
            except Exception:
                return code, {}
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, json.loads(body) if body else {}
        except Exception:
            return e.code, {}
    except URLError:
        return 0, {}
    except Exception:
        return 0, {}


def pihole_login(base_url: str, app_password: str) -> tuple[bool, str, str]:
    # POST /api/auth  { "password": "..." } -> session.sid
    code, j = http_json(
        "POST",
        f"{base_url}/api/auth",
        headers={},
        payload={"password": app_password},
    )
    sid = ""
    if code == 200:
        sid = (j.get("session") or {}).get("sid") or ""
    if sid:
        return True, sid, ""
    return False, "", f"auth_failed_http_{code}" if code else "connect_failed"


def pihole_get_blocking(base_url: str, sid: str) -> tuple[bool, bool | None]:
    # GET /api/dns/blocking -> {"blocking": true/false}
    code, j = http_json(
        "GET",
        f"{base_url}/api/dns/blocking",
        headers={"X-FTL-SID": sid},
        payload=None,
    )
    if code == 200 and "blocking" in j:
        b = j.get("blocking")
        if isinstance(b, bool):
            return True, b
    return False, None


def pihole_set_blocking(base_url: str, sid: str, blocking: bool, timer_seconds: int) -> tuple[bool, str]:
    # POST /api/dns/blocking  {"blocking": false, "timer": <seconds>}
    payload = {"blocking": blocking, "timer": int(timer_seconds)}
    code, j = http_json(
        "POST",
        f"{base_url}/api/dns/blocking",
        headers={"X-FTL-SID": sid},
        payload=payload,
    )
    if code in (200, 201, 204):
        return True, ""
    # Try to surface a useful message if present
    msg = ""
    if isinstance(j, dict):
        err = j.get("error") or {}
        if isinstance(err, dict):
            msg = err.get("message") or ""
            hint = err.get("hint")
            if hint:
                msg = f"{msg} hint={hint}"
    return False, msg or (f"http_{code}" if code else "connect_failed")


WARNING_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Internet Protection</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: #ffffff;
      color: #b00020;
      margin: 0;
      padding: 0;
    }}
    .wrap {{
      max-width: 640px;
      margin: 0 auto;
      padding: 22px 16px;
    }}
    .card {{
      border: 1px solid #ffd6dc;
      border-radius: 14px;
      padding: 18px;
      background: #fff7f8;
    }}
    h1 {{
      font-size: 22px;
      margin: 0 0 10px 0;
      color: #b00020;
    }}
    p {{
      margin: 10px 0;
      line-height: 1.35;
      font-size: 16px;
    }}
    .btn {{
      display: block;
      width: 100%;
      border: 0;
      border-radius: 14px;
      padding: 16px 14px;
      font-size: 18px;
      font-weight: 700;
      background: #d0002a;
      color: white;
      cursor: pointer;
      margin-top: 16px;
    }}
    .btn:active {{
      opacity: 0.9;
    }}
    .small {{
      margin-top: 14px;
      font-size: 14px;
      color: #8a0018;
    }}
    a {{
      color: #8a0018;
      text-decoration: underline;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Warning</h1>
      <p>
        Disabling protection makes you more vulnerable to scams, malicious ads, and fake websites.
        If you proceed, use extreme caution and do not trust unexpected popups, warnings, or download prompts.
      </p>
      <form method="POST" action="/disable">
        <button class="btn" type="submit">Disable Protection for __MINUTES__ Minutes</button>
      </form>
      __LOG_LINK__
      <div class="small">
        This page is intentionally simple. If something fails, contact the administrator.
      </div>
    </div>
  </div>
</body>
</html>
"""

SUCCESS_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protection Disabled</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: #ffffff;
      color: #222;
      margin: 0;
      padding: 0;
      text-align: center;
    }}
    .wrap {{
      max-width: 520px;
      margin: 0 auto;
      padding: 26px 16px;
    }}
    .timer {{
      font-size: 54px;
      font-weight: 800;
      letter-spacing: 0.5px;
      margin: 14px 0 6px 0;
    }}
    .msg {{
      font-size: 16px;
      line-height: 1.35;
      margin-top: 12px;
      color: #b00020;
    }}
    .status {{
      margin-top: 16px;
      font-size: 15px;
      color: #444;
      line-height: 1.3;
    }}
    .hint {{
      margin-top: 20px;
      font-size: 14px;
      color: #666;
    }}
    .errbox {{
      margin-top: 16px;
      border: 1px solid #ffd6dc;
      background: #fff7f8;
      border-radius: 12px;
      padding: 12px;
      text-align: left;
      color: #b00020;
      font-size: 14px;
    }}
    .errbox ul {{
      margin: 8px 0 0 18px;
      padding: 0;
    }}
    .errbox li {{
      margin: 6px 0;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="timer" id="timer">--:--</div>
    <div class="msg">
      Ads enabled. Try your desired action again. Use extreme caution while protection is disabled.
    </div>
    <div class="status" id="status">Checking status...</div>
    <div class="errbox" id="errbox" style="display:none;">
      <div><strong>Some Pi-hole instances did not disable:</strong></div>
      <ul id="errlist"></ul>
    </div>
    <div class="hint">When the timer ends, this page will return automatically.</div>
  </div>

<script>
(function() {{
  const homeUrl = "/";
  let remaining = __SECONDS__;

  function fmt(sec) {{
    sec = Math.max(0, sec);
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    const mm = String(m).padStart(2, "0");
    const ss = String(s).padStart(2, "0");
    return mm + ":" + ss;
  }}

  function setText(id, text) {{
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }}

  function tick() {{
    setText("timer", fmt(remaining));
    if (remaining <= 0) {{
      window.location.replace(homeUrl);
      return;
    }}
    remaining -= 1;
    setTimeout(tick, 1000);
  }}

  function showFailures(fails) {{
    const box = document.getElementById("errbox");
    const list = document.getElementById("errlist");
    if (!box || !list) return;
    list.innerHTML = "";
    for (const f of fails) {{
      const li = document.createElement("li");
      li.textContent = f.name + ": " + (f.error || "unknown_error");
      list.appendChild(li);
    }}
    box.style.display = "block";
  }}

  async function pollStatus() {{
    try {{
      const resp = await fetch("/status.json", {{cache: "no-store"}});
      if (!resp.ok) throw new Error("http " + resp.status);
      const j = await resp.json();

      if (j && typeof j.remaining_seconds === "number") {{
        remaining = Math.max(0, Math.floor(j.remaining_seconds));
      }}

      if (j && Array.isArray(j.failures) && j.failures.length > 0) {{
        showFailures(j.failures);
      }}

      if (j && j.all_disabled === true) {{
        setText("status", "Protection is currently disabled.");
      }} else if (j && j.all_disabled === false) {{
        setText("status", "Protection is active again.");
        if (remaining <= 0) {{
          window.location.replace(homeUrl);
          return;
        }}
      }} else {{
        setText("status", "Status unavailable.");
      }}
    }} catch (e) {{
      setText("status", "Status unavailable.");
    }}
    setTimeout(pollStatus, 3000);
  }}

  tick();
  pollStatus();
}})();
</script>
</body>
</html>
"""

ERROR_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Request Failed</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: #ffffff;
      color: #222;
      margin: 0;
      padding: 0;
    }}
    .wrap {{
      max-width: 640px;
      margin: 0 auto;
      padding: 22px 16px;
    }}
    .card {{
      border: 1px solid #ffd6dc;
      border-radius: 14px;
      padding: 18px;
      background: #fff7f8;
    }}
    h1 {{
      font-size: 20px;
      margin: 0 0 10px 0;
      color: #b00020;
    }}
    ul {{
      margin: 10px 0 0 18px;
      padding: 0;
    }}
    li {{
      margin: 6px 0;
      color: #b00020;
    }}
    a {{
      display: inline-block;
      margin-top: 14px;
      color: #8a0018;
      text-decoration: underline;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Could not disable protection</h1>
      <div>The following Pi-hole instance(s) failed:</div>
      <ul>
        __FAIL_LIST__
      </ul>
      <a href="/">Return</a>
    </div>
  </div>
</body>
</html>
"""

LOGS_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Event Horizon Logs</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: #ffffff;
      color: #222;
      margin: 0;
      padding: 0;
    }}
    .wrap {{
      max-width: 900px;
      margin: 0 auto;
      padding: 18px 12px;
    }}
    h1 {{
      font-size: 18px;
      margin: 0 0 12px 0;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      border-bottom: 1px solid #eee;
      padding: 10px 8px;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{
      color: #444;
      font-weight: 700;
      background: #fafafa;
      position: sticky;
      top: 0;
    }}
    .muted {{
      color: #666;
      font-size: 13px;
      margin-top: 10px;
    }}
    a {{
      color: #333;
      text-decoration: underline;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Event Horizon Logs (last __N__ entries)</h1>
    <table>
      <thead>
        <tr><th>Timestamp (UTC)</th><th>Client IP</th><th>Action</th><th>Details</th></tr>
      </thead>
      <tbody>
        __ROWS__
      </tbody>
    </table>
    <div class="muted"><a href="/">Return</a></div>
  </div>
</body>
</html>
"""


def escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#039;")
    )


def load_piholes(conf: dict) -> list[dict]:
    count = get_int(conf, "PIHOLE_COUNT", 1)
    piholes = []
    for i in range(1, count + 1):
        name = conf.get(f"PIHOLE_{i}_NAME", f"pihole{i}")
        url = conf.get(f"PIHOLE_{i}_URL", "").rstrip("/")
        app_password = conf.get(f"PIHOLE_{i}_APP_PASSWORD", "")
        piholes.append({"name": name, "url": url, "app_password": app_password})
    return piholes


class Handler(BaseHTTPRequestHandler):
    server_version = "EventHorizon/1.0"

    def client_ip(self) -> str:
        return self.client_address[0]

    def send_html(self, html: str, code: int = 200):
        b = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def send_json(self, obj: dict, code: int = 200):
        s = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(s)))
        self.end_headers()
        self.wfile.write(s)

    def do_GET(self):
        conf = self.server.conf  # type: ignore

        if self.path == "/" or self.path.startswith("/?"):
            minutes = get_int(conf, "DISABLE_MINUTES", 10)
            show_logs = get_bool(conf, "SHOW_LOG_LINK", True)
            log_link = ""
            if show_logs:
                log_link = '<div class="small"><a href="/logs">View logs</a></div>'
            html = WARNING_HTML.replace("__MINUTES__", str(minutes)).replace("__LOG_LINK__", log_link)
            self.send_html(html)
            return

        if self.path == "/status":
            self.send_html(self.build_success_page(conf))
            return

        if self.path == "/status.json":
            self.send_json(self.compute_status_json(conf))
            return

        if self.path == "/logs":
            self.send_html(self.build_logs_page(10))
            return

        if self.path == "/favicon.ico":
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/disable":
            self.send_response(404)
            self.end_headers()
            return

        conf = self.server.conf  # type: ignore
        minutes = get_int(conf, "DISABLE_MINUTES", 10)
        seconds = max(60, int(minutes) * 60)

        client_ip = self.client_ip()

        ok_all, results, failures = self.disable_all(conf, seconds)

        global LAST_DISABLE_EPOCH, LAST_DISABLE_SECONDS, LAST_RESULTS
        LAST_DISABLE_EPOCH = time.time()
        LAST_DISABLE_SECONDS = seconds
        LAST_RESULTS = results

        # Log press with per-instance outcome
        details = "; ".join([f"{r['name']}:{'ok' if r['ok'] else 'fail'}" for r in results])
        log_request(client_ip, "disable_minutes", f"minutes={minutes} {details}")

        if not ok_all:
            fail_items = []
            for f in failures:
                msg = f.get("error") or "unknown_error"
                fail_items.append(f"<li>{escape_html(f['name'])} ({escape_html(msg)})</li>")
            html = ERROR_HTML.replace("__FAIL_LIST__", "\n".join(fail_items))
            self.send_html(html, code=200)
            return

        # Success: redirect to success page
        self.send_response(303)
        self.send_header("Location", "/status")
        self.end_headers()

    def build_success_page(self, conf: dict) -> str:
        remaining = self.compute_remaining_seconds()
        # If no remaining time, send them back to main page
        if remaining <= 0:
            minutes = get_int(conf, "DISABLE_MINUTES", 10)
            show_logs = get_bool(conf, "SHOW_LOG_LINK", True)
            log_link = '<div class="small"><a href="/logs">View logs</a></div>' if show_logs else ""
            return WARNING_HTML.replace("__MINUTES__", str(minutes)).replace("__LOG_LINK__", log_link)

        return SUCCESS_HTML.replace("__SECONDS__", str(int(remaining)))

    def compute_remaining_seconds(self) -> int:
        global LAST_DISABLE_EPOCH, LAST_DISABLE_SECONDS
        if LAST_DISABLE_EPOCH <= 0 or LAST_DISABLE_SECONDS <= 0:
            return 0
        end = LAST_DISABLE_EPOCH + LAST_DISABLE_SECONDS
        return max(0, int(end - time.time()))

    def compute_status_json(self, conf: dict) -> dict:
        status = self.query_all_status(conf)
        remaining = self.compute_remaining_seconds()
        failures = [r for r in (LAST_RESULTS or []) if not r.get("ok", False)]
        return {
            "remaining_seconds": remaining,
            "all_disabled": status["all_disabled"],
            "instances": status["instances"],
            "failures": [{"name": f.get("name", "unknown"), "error": f.get("error", "unknown")} for f in failures],
        }

    def query_all_status(self, conf: dict) -> dict:
        piholes = load_piholes(conf)
        instances = []
        all_disabled = True
        any_known = False

        for ph in piholes:
            ok, sid, _ = pihole_login(ph["url"], ph["app_password"])
            if not ok:
                instances.append({"name": ph["name"], "reachable": False, "disabled": None})
                all_disabled = False
                continue

            s_ok, blocking = pihole_get_blocking(ph["url"], sid)
            if not s_ok or blocking is None:
                instances.append({"name": ph["name"], "reachable": True, "disabled": None})
                all_disabled = False
                continue

            disabled = (blocking is False)  # blocking=false means protection is disabled
            any_known = True
            instances.append({"name": ph["name"], "reachable": True, "disabled": disabled})
            if not disabled:
                all_disabled = False

        if not any_known:
            return {"all_disabled": None, "instances": instances}

        return {"all_disabled": all_disabled, "instances": instances}

    def disable_all(self, conf: dict, seconds: int) -> tuple[bool, list[dict], list[dict]]:
        piholes = load_piholes(conf)
        results = []
        failures = []

        for ph in piholes:
            ok, sid, err = pihole_login(ph["url"], ph["app_password"])
            if not ok:
                results.append({"name": ph["name"], "ok": False, "error": err})
                failures.append({"name": ph["name"], "error": err})
                continue

            ok2, msg = pihole_set_blocking(ph["url"], sid, blocking=False, timer_seconds=seconds)
            if not ok2:
                results.append({"name": ph["name"], "ok": False, "error": msg})
                failures.append({"name": ph["name"], "error": msg})
                continue

            ok3, blocking = pihole_get_blocking(ph["url"], sid)
            if ok3 and blocking is False:
                results.append({"name": ph["name"], "ok": True, "error": ""})
            else:
                results.append({"name": ph["name"], "ok": False, "error": "verify_failed"})
                failures.append({"name": ph["name"], "error": "verify_failed"})

        return (len(failures) == 0), results, failures

    def build_logs_page(self, n: int) -> str:
        ensure_log_dir()
        rows = []
        try:
            with open(REQUESTS_LOG, "r", encoding="utf-8") as f:
                lines = f.readlines()[-n:]
        except Exception:
            lines = []

        for line in reversed(lines):
            ts = ""
            client_ip = ""
            action = ""
            details = line.strip()

            m = re.match(
                r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+client_ip=([^\s]+)\s+action=([^\s]+)\s+(.*)$",
                line.strip(),
            )
            if m:
                ts = m.group(1)
                client_ip = m.group(2)
                action = m.group(3)
                details = m.group(4)

            rows.append(
                "<tr>"
                f"<td>{escape_html(ts)}</td>"
                f"<td>{escape_html(client_ip)}</td>"
                f"<td>{escape_html(action)}</td>"
                f"<td>{escape_html(details)}</td>"
                "</tr>"
            )

        body = "\n".join(rows) if rows else "<tr><td colspan='4'>No log entries yet.</td></tr>"
        html = LOGS_HTML.replace("__N__", str(n)).replace("__ROWS__", body)
        return html


def main():
    conf = read_conf(CONF_PATH)
    port = get_int(conf, "PORT", 80)

    ensure_log_dir()

    httpd = HTTPServer(("0.0.0.0", port), Handler)
    httpd.conf = conf  # type: ignore

    print(f"Listening on http://0.0.0.0:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
