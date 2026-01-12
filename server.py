#!/usr/bin/env python3
# Event Horizon
# GitHub: github.com/jbswaff
# Revision: 0.3.2-beta.1
# Baseline revision: 0.3.1-beta.1

import html
import json
import os
import sys
import ipaddress
import signal
import threading
import secrets
import ssl
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ----------------------------
# Version
# ----------------------------

VERSION = "0.3.2-beta.1"

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


def cfg_get(key: str, default=None):
    """Read config value from environment (EH_<KEY>) first, then from config file."""
    env_key = f"EH_{key}"
    v = os.environ.get(env_key)
    if v is not None and v.strip() != "":
        return v
    return CFG.get(key, default)


def cfg_str(key: str, default: str) -> str:
    v = cfg_get(key, default)
    return str(v).strip() if v is not None else default


def cfg_int(key: str, default: int) -> int:
    try:
        v = cfg_get(key, str(default))
        return int(str(v).strip())
    except Exception:
        return default


def cfg_bool(key: str, default: bool) -> bool:
    v = str(cfg_get(key, str(default))).strip().lower()
    if v in ("true", "1", "yes", "y", "on"):
        return True
    if v in ("false", "0", "no", "n", "off"):
        return False
    return default


# ----------------------------
# Globals
# ----------------------------

PORT = cfg_int("PORT", 8080)
DISABLE_MINUTES = cfg_int("DISABLE_MINUTES", 10)
DISABLE_SECONDS = DISABLE_MINUTES * 60
SHOW_LOG_LINK = cfg_bool("SHOW_LOG_LINK", True)

PIHOLE_COUNT = cfg_int("PIHOLE_COUNT", 1)
BYPASS_GROUP_NAME = cfg_str("BYPASS_GROUP_NAME", "Event-Horizon-Bypass")
TRUST_PROXY = cfg_bool("TRUST_PROXY", False)
TRUSTED_PROXY_NETS_RAW = cfg_str("TRUSTED_PROXY_NETS", "")
HEALTH_CACHE_SECONDS = cfg_int("HEALTH_CACHE_SECONDS", 5)
COOLDOWN_SECONDS = cfg_int("COOLDOWN_SECONDS", 3)

# API request settings
VERIFY_SSL = cfg_bool("VERIFY_SSL", True)
API_TIMEOUT = cfg_int("API_TIMEOUT", 15)
API_MAX_RETRIES = cfg_int("API_MAX_RETRIES", 3)
API_RETRY_DELAY = cfg_int("API_RETRY_DELAY", 1)

# Logging settings
LOG_DIR = cfg_str("LOG_DIR", "/var/log/event-horizon")
REQUESTS_LOG = os.path.join(LOG_DIR, "requests.log")
API_LOG = os.path.join(LOG_DIR, "api.log")
LOG_MAX_SIZE_MB = cfg_int("LOG_MAX_SIZE_MB", 10)
LOG_MAX_AGE_DAYS = cfg_int("LOG_MAX_AGE_DAYS", 7)
API_LOG_ENABLED = cfg_bool("API_LOG_ENABLED", True)

# Session cache settings
SESSION_CACHE_TTL = cfg_int("SESSION_CACHE_TTL", 300)  # 5 minutes default

# Rate limiting settings
RATE_LIMIT_REQUESTS = cfg_int("RATE_LIMIT_REQUESTS", 10)  # Max requests per window
RATE_LIMIT_WINDOW = cfg_int("RATE_LIMIT_WINDOW", 3600)  # Window in seconds (1 hour)


def parse_proxy_nets(raw: str) -> list:
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except Exception:
            continue
    return nets


TRUSTED_PROXY_NETS = parse_proxy_nets(TRUSTED_PROXY_NETS_RAW)


# ----------------------------
# Logging with rotation
# ----------------------------

LOG_LOCK = threading.Lock()


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def _rotate_log_if_needed(log_path: str):
    """Rotate log file if it exceeds size limit or is too old."""
    try:
        if not os.path.exists(log_path):
            return

        stat = os.stat(log_path)
        size_mb = stat.st_size / (1024 * 1024)
        age_days = (time.time() - stat.st_mtime) / (24 * 3600)

        if size_mb > LOG_MAX_SIZE_MB or age_days > LOG_MAX_AGE_DAYS:
            # Rotate: rename current to .old (overwriting previous .old)
            old_path = log_path + ".old"
            if os.path.exists(old_path):
                os.remove(old_path)
            os.rename(log_path, old_path)
    except Exception:
        pass


def log_request(client_ip: str, action: str, details: str = ""):
    with LOG_LOCK:
        ensure_log_dir()
        _rotate_log_if_needed(REQUESTS_LOG)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        line = f"{ts} | {client_ip} | {action}"
        if details:
            line += f" | {details}"
        try:
            with open(REQUESTS_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


def log_api(method: str, url: str, status: int, body: str, error: str = None):
    """Log API request/response for debugging."""
    if not API_LOG_ENABLED:
        return
    with LOG_LOCK:
        ensure_log_dir()
        _rotate_log_if_needed(API_LOG)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        # Truncate body if too long
        if len(body) > 1000:
            body = body[:1000] + "...[truncated]"
        # Mask sensitive data in URL (passwords in auth requests are in body, not URL)
        line = f"{ts} | {method} {url} | status={status}"
        if error:
            line += f" | error={error}"
        else:
            line += f" | body={body}"
        try:
            with open(API_LOG, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


# ----------------------------
# IP normalization
# ----------------------------

def normalize_ip(ip: str) -> str:
    """Normalize IP address for consistent comparison (handles IPv6 variants)."""
    ip = (ip or "").strip()
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
        # Return compressed format for IPv6, standard format for IPv4
        return str(addr)
    except ValueError:
        # Not a valid IP, return as-is (might be hostname)
        return ip


# ----------------------------
# Pi-hole configuration
# ----------------------------

def get_piholes():
    piholes = []
    for i in range(1, PIHOLE_COUNT + 1):
        name = cfg_str(f"PIHOLE_{i}_NAME", f"pihole{i}").strip() or f"pihole{i}"
        base = cfg_str(f"PIHOLE_{i}_URL", "").strip()
        pw = cfg_str(f"PIHOLE_{i}_APP_PASSWORD", "").strip()
        if base and pw:
            piholes.append({"idx": i, "name": name, "base": base.rstrip("/"), "pw": pw})
    return piholes


PIHOLES = get_piholes()

# ----------------------------
# Session cache
# ----------------------------

SESSION_CACHE_LOCK = threading.Lock()
# key: pihole_idx -> {"sid": str, "csrf": str, "expires": float}
SESSION_CACHE = {}


def get_cached_session(pihole: dict) -> tuple[str, str] | None:
    """Get cached session if still valid."""
    idx = pihole["idx"]
    with SESSION_CACHE_LOCK:
        cached = SESSION_CACHE.get(idx)
        if cached and time.time() < cached.get("expires", 0):
            return cached["sid"], cached["csrf"]
    return None


def cache_session(pihole: dict, sid: str, csrf: str):
    """Cache session tokens."""
    idx = pihole["idx"]
    with SESSION_CACHE_LOCK:
        SESSION_CACHE[idx] = {
            "sid": sid,
            "csrf": csrf,
            "expires": time.time() + SESSION_CACHE_TTL
        }


def invalidate_session(pihole: dict):
    """Remove cached session (on auth failure)."""
    idx = pihole["idx"]
    with SESSION_CACHE_LOCK:
        SESSION_CACHE.pop(idx, None)


# ----------------------------
# Pi-hole API helpers
# ----------------------------


class ApiError(Exception):
    pass


DEFAULT_TIMEOUT = API_TIMEOUT


def _create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for HTTPS requests."""
    if VERIFY_SSL:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_json(method: str, url: str, headers: dict | None = None, payload: dict | None = None, timeout: int = DEFAULT_TIMEOUT):
    """Make HTTP request with JSON payload/response, retry logic, and proper SSL handling."""
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", f"Event-Horizon/{VERSION} (Pi-hole Control)")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ssl_ctx = _create_ssl_context()
    last_error = None

    for attempt in range(max(1, API_MAX_RETRIES)):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                try:
                    j = json.loads(body) if body else None
                except json.JSONDecodeError:
                    j = None
                log_api(method, url, resp.status, body)
                return resp.status, body, j
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            try:
                j = json.loads(body) if body else None
            except json.JSONDecodeError:
                j = None
            log_api(method, url, e.code, body, error=str(e.reason))
            raise ApiError(f"HTTP {e.code} {e.reason}: {body}") from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ConnectionError) as e:
            last_error = e
            log_api(method, url, 0, "", error=str(e))
            if attempt < API_MAX_RETRIES - 1:
                delay = API_RETRY_DELAY * (2 ** attempt)
                time.sleep(delay)
                continue
        except Exception as e:
            log_api(method, url, 0, "", error=str(e))
            raise ApiError(str(e)) from None

    if last_error:
        raise ApiError(f"Request failed after {API_MAX_RETRIES} attempts: {last_error}") from None
    raise ApiError("Request failed with no error details")


def api_get_version(pihole: dict, sid: str = None, csrf: str = None) -> dict:
    """Get Pi-hole version information."""
    try:
        url = f"{pihole['base']}/api/info/version"
        headers = api_headers(sid, csrf) if sid and csrf else None
        _, _, j = http_json("GET", url, headers=headers)
        if isinstance(j, dict):
            ver = j.get("version", {}) if isinstance(j.get("version"), dict) else {}
            core = ver.get("core", {}) if isinstance(ver.get("core"), dict) else {}
            core_local = core.get("local", {}) if isinstance(core.get("local"), dict) else {}
            ftl = ver.get("ftl", {}) if isinstance(ver.get("ftl"), dict) else {}
            ftl_local = ftl.get("local", {}) if isinstance(ftl.get("local"), dict) else {}
            return {
                "version": core_local.get("version"),
                "api_version": None,
                "ftl_version": ftl_local.get("version"),
            }
    except Exception:
        pass
    raise ApiError("Unable to determine Pi-hole version - ensure Pi-hole v6 is installed")


def api_validate_version(pihole: dict, sid: str = None, csrf: str = None):
    """Validate that Pi-hole is running a compatible version (v6+)."""
    try:
        version_info = api_get_version(pihole, sid, csrf)
        version = version_info.get("version", "")

        if not version:
            raise ApiError(f"Could not determine Pi-hole version on {pihole['name']}")

        try:
            # Handle "v6.3" or "6.3" format
            ver_str = version.lstrip("v")
            major_version = int(ver_str.split(".")[0])
            if major_version < 6:
                raise ApiError(f"Pi-hole {pihole['name']} is running v{version} - Event Horizon requires Pi-hole v6 or later")
        except (ValueError, IndexError):
            pass

        return version_info
    except ApiError:
        raise
    except Exception as e:
        raise ApiError(f"Version check failed for {pihole['name']}: {e}")


def api_auth(pihole: dict, use_cache: bool = True) -> tuple[str, str]:
    """Authenticate with Pi-hole and return session tokens."""
    # Try cached session first
    if use_cache:
        cached = get_cached_session(pihole)
        if cached:
            return cached

    url = f"{pihole['base']}/api/auth"
    _, _, j = http_json("POST", url, payload={"password": pihole["pw"]})
    if not isinstance(j, dict):
        raise ApiError("Invalid auth response")

    session = j.get("session", {})
    if isinstance(session, dict):
        sid = session.get("sid")
        csrf = session.get("csrf")
        if sid and csrf:
            cache_session(pihole, sid, csrf)
            return sid, csrf

    # Check for specific error messages
    error = j.get("error", {})
    if isinstance(error, dict):
        msg = error.get("message", "")
        if "seats" in msg.lower():
            raise ApiError(f"API session limit reached on {pihole['name']} - try again later")

    raise ApiError("Auth failed or missing session tokens")


def api_headers(sid: str, csrf: str) -> dict:
    return {"X-FTL-SID": sid, "X-FTL-CSRF": csrf}


def api_get_blocking(pihole: dict, sid: str, csrf: str) -> bool:
    url = f"{pihole['base']}/api/dns/blocking"
    _, _, j = http_json("GET", url, headers=api_headers(sid, csrf))
    if isinstance(j, dict) and "blocking" in j:
        return bool(j.get("blocking"))
    raise ApiError("Invalid blocking response")


# ----------------------------
# Per-client bypass via group membership (Pi-hole v6)
# ----------------------------


def _as_list(obj):
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for k in ("groups", "clients", "data", "items"):
            if k in obj and isinstance(obj[k], list):
                return obj[k]
    return []


def api_get_groups(pihole: dict, sid: str, csrf: str) -> list:
    url = f"{pihole['base']}/api/groups"
    _, _, j = http_json("GET", url, headers=api_headers(sid, csrf))
    return _as_list(j)


def api_get_clients(pihole: dict, sid: str, csrf: str) -> list:
    url = f"{pihole['base']}/api/clients"
    _, _, j = http_json("GET", url, headers=api_headers(sid, csrf))
    return _as_list(j)


def api_find_group_id(groups, name: str):
    for g in groups:
        if str(g.get("name", "")).strip().lower() == name.strip().lower():
            gid = g.get("id")
            if isinstance(gid, int):
                return gid
            try:
                return int(str(gid))
            except Exception:
                return None
    return None


def api_get_default_group_id(pihole: dict, sid: str, csrf: str) -> int:
    groups = api_get_groups(pihole, sid, csrf)
    gid = api_find_group_id(groups, "Default")
    if gid is None:
        return 0
    return gid


def api_ensure_group(pihole: dict, sid: str, csrf: str, name: str) -> int:
    groups = api_get_groups(pihole, sid, csrf)
    gid = api_find_group_id(groups, name)
    if gid is not None:
        return gid

    url = f"{pihole['base']}/api/groups"
    payload = {"name": name, "comment": "Event Horizon: temporary per-client bypass group", "enabled": True}
    http_json("POST", url, headers=api_headers(sid, csrf), payload=payload)

    groups = api_get_groups(pihole, sid, csrf)
    gid = api_find_group_id(groups, name)
    if gid is None:
        raise ApiError(f"Failed to create or find group '{name}' on {pihole['name']}")
    return gid


def api_find_client_by_ip(clients, ip: str):
    """Find a client record by IP address."""
    ip = normalize_ip(ip)
    if not ip:
        return None

    for c in clients:
        # Check the 'client' field (primary identifier in Pi-hole)
        client_val = str(c.get("client", "")).strip()
        if normalize_ip(client_val) == ip:
            return c
        # Also check if stored as plain value
        if client_val == ip:
            return c

        # Check other possible fields
        for k in ("ip", "address", "client_ip"):
            val = str(c.get(k, "")).strip()
            if val and normalize_ip(val) == ip:
                return c

        # Check name field
        if str(c.get("name", "")).strip() == ip:
            return c

    return None


def api_put_client(
    pihole: dict,
    sid: str,
    csrf: str,
    client_id: str,
    groups,
    comment,
    enabled: bool = True,
):
    url = f"{pihole['base']}/api/clients/{client_id}"
    payload = {
        "client": client_id,
        "groups": groups,
        "comment": comment,
        "enabled": bool(enabled),
    }
    http_json("PUT", url, headers=api_headers(sid, csrf), payload=payload)


BYPASS_LOCK = threading.Lock()
# key: (pihole_idx, client_ip) -> {"timer": Timer, "client_id": str, "orig_groups": list, "orig_comment": str, "orig_enabled": bool, "start_time": float}
BYPASS_STATE = {}

HEALTH_LOCK = threading.Lock()
HEALTH_CACHE = {"ts": 0.0, "rows": "", "data": []}

COOLDOWN_LOCK = threading.Lock()
LAST_PRESS_BY_IP = {}
COOLDOWN_CLEANUP_INTERVAL = 300  # Clean up every 5 minutes
LAST_COOLDOWN_CLEANUP = 0

# Rate limiting: track request counts per IP
RATE_LIMIT_LOCK = threading.Lock()
# key: client_ip -> {"count": int, "window_start": float}
RATE_LIMIT_DATA = {}


def check_rate_limit(client_ip: str) -> tuple[bool, int]:
    """Check if client is rate limited. Returns (is_allowed, requests_remaining)."""
    if RATE_LIMIT_REQUESTS <= 0:
        return True, 999  # Rate limiting disabled

    now = time.time()
    client_ip = normalize_ip(client_ip)

    with RATE_LIMIT_LOCK:
        data = RATE_LIMIT_DATA.get(client_ip)

        if data is None or (now - data["window_start"]) > RATE_LIMIT_WINDOW:
            # New window
            RATE_LIMIT_DATA[client_ip] = {"count": 1, "window_start": now}
            return True, RATE_LIMIT_REQUESTS - 1

        if data["count"] >= RATE_LIMIT_REQUESTS:
            # Rate limited
            return False, 0

        # Increment count
        data["count"] += 1
        return True, RATE_LIMIT_REQUESTS - data["count"]


def cleanup_rate_limit_cache():
    """Remove expired rate limit entries."""
    now = time.time()
    with RATE_LIMIT_LOCK:
        expired = [ip for ip, data in RATE_LIMIT_DATA.items()
                   if (now - data["window_start"]) > RATE_LIMIT_WINDOW]
        for ip in expired:
            RATE_LIMIT_DATA.pop(ip, None)


def cleanup_cooldown_cache():
    """Remove old entries from cooldown and rate limit caches to prevent memory leak."""
    global LAST_COOLDOWN_CLEANUP
    now = time.time()

    if (now - LAST_COOLDOWN_CLEANUP) < COOLDOWN_CLEANUP_INTERVAL:
        return

    LAST_COOLDOWN_CLEANUP = now
    cutoff = now - max(COOLDOWN_SECONDS * 2, 60)  # Keep entries for at least 60 seconds

    with COOLDOWN_LOCK:
        expired = [ip for ip, ts in LAST_PRESS_BY_IP.items() if ts < cutoff]
        for ip in expired:
            LAST_PRESS_BY_IP.pop(ip, None)

    # Also clean up rate limit cache
    cleanup_rate_limit_cache()


def get_bypass_remaining(client_ip: str) -> int | None:
    """Get remaining bypass time in seconds for a client, or None if not active."""
    client_ip = normalize_ip(client_ip)
    now = time.time()

    with BYPASS_LOCK:
        for (idx, ip), state in BYPASS_STATE.items():
            if normalize_ip(ip) == client_ip:
                start_time = state.get("start_time", 0)
                if start_time:
                    elapsed = now - start_time
                    remaining = DISABLE_SECONDS - elapsed
                    if remaining > 0:
                        return int(remaining)
    return None


def cancel_bypass_for_client(client_ip: str) -> tuple[bool, list]:
    """Cancel active bypass for a client. Returns (success, failures)."""
    client_ip = normalize_ip(client_ip)
    failures = []
    cancelled_any = False

    keys_to_restore = []
    with BYPASS_LOCK:
        for key in list(BYPASS_STATE.keys()):
            idx, ip = key
            if normalize_ip(ip) == client_ip:
                keys_to_restore.append(key)

    for key in keys_to_restore:
        idx, ip = key
        pihole = None
        for p in PIHOLES:
            if p["idx"] == idx:
                pihole = p
                break

        if not pihole:
            continue

        try:
            with BYPASS_LOCK:
                state = BYPASS_STATE.get(key)
                if state and state.get("timer"):
                    try:
                        state["timer"].cancel()
                    except Exception:
                        pass

            # Restore original groups
            sid, csrf = api_auth(pihole)
            with BYPASS_LOCK:
                state = BYPASS_STATE.get(key)

            if state:
                api_put_client(
                    pihole,
                    sid,
                    csrf,
                    state["client_id"],
                    state["orig_groups"],
                    state.get("orig_comment"),
                    enabled=state.get("orig_enabled", True),
                )
                cancelled_any = True

            with BYPASS_LOCK:
                BYPASS_STATE.pop(key, None)

        except Exception as e:
            failures.append(f"{pihole['name']}: {e}")

    return cancelled_any and not failures, failures


def apply_bypass_for_client(client_ip: str, seconds: int):
    failures = []
    ok_any = False
    client_ip = normalize_ip(client_ip)
    start_time = time.time()

    for p in PIHOLES:
        try:
            sid, csrf = api_auth(p)
            bypass_gid = api_ensure_group(p, sid, csrf, BYPASS_GROUP_NAME)

            clients = api_get_clients(p, sid, csrf)
            rec = api_find_client_by_ip(clients, client_ip)

            if rec is not None:
                client_id = str(rec.get("client") or rec.get("id") or "").strip()
                if not client_id:
                    client_id = client_ip

                orig_groups = rec.get("groups")
                if isinstance(orig_groups, list):
                    og = []
                    for x in orig_groups:
                        try:
                            og.append(int(x))
                        except Exception:
                            pass
                    orig_groups = og
                else:
                    orig_groups = None

                if orig_groups is None:
                    orig_groups = [api_get_default_group_id(p, sid, csrf)]
                orig_comment = rec.get("comment")
                orig_enabled = bool(rec.get("enabled", True))
            else:
                client_id = client_ip
                orig_groups = [api_get_default_group_id(p, sid, csrf)]
                orig_comment = "Event Horizon client"
                orig_enabled = True

            key = (int(p["idx"]), client_ip)

            with BYPASS_LOCK:
                existing = BYPASS_STATE.get(key)
                if existing is None:
                    BYPASS_STATE[key] = {
                        "timer": None,
                        "client_id": client_id,
                        "orig_groups": orig_groups,
                        "orig_comment": orig_comment,
                        "orig_enabled": orig_enabled,
                        "start_time": start_time,
                    }
                else:
                    # Update start time for existing bypass
                    existing["start_time"] = start_time
                    client_id = existing.get("client_id", client_id)
                    orig_groups = existing.get("orig_groups", orig_groups)
                    orig_comment = existing.get("orig_comment", orig_comment)
                    orig_enabled = existing.get("orig_enabled", orig_enabled)

            api_put_client(p, sid, csrf, client_id, [bypass_gid], orig_comment, enabled=orig_enabled)
            ok_any = True

            def _restore(p=p, key=key):
                try:
                    sid2, csrf2 = api_auth(p)
                    with BYPASS_LOCK:
                        st = BYPASS_STATE.get(key)
                    if not st:
                        return
                    api_put_client(
                        p,
                        sid2,
                        csrf2,
                        st["client_id"],
                        st["orig_groups"],
                        st.get("orig_comment"),
                        enabled=st.get("orig_enabled", True),
                    )
                    log_request(key[1], "bypass_restored", f"pihole={p['name']}")
                except Exception as e:
                    log_request(key[1], "bypass_restore_failed", f"pihole={p['name']} error={e}")
                finally:
                    with BYPASS_LOCK:
                        BYPASS_STATE.pop(key, None)

            t = threading.Timer(seconds, _restore)
            t.daemon = True
            with BYPASS_LOCK:
                st = BYPASS_STATE.get(key)
                if st and st.get("timer") is not None:
                    try:
                        st["timer"].cancel()
                    except Exception:
                        pass
                if st is not None:
                    st["timer"] = t
            t.start()

        except Exception as e:
            failures.append(f"{p.get('name','pihole')}: {e}")

    return ok_any and not failures, failures


def get_pihole_health_rows() -> str:
    now = time.time()
    with HEALTH_LOCK:
        ts = float(HEALTH_CACHE.get("ts", 0.0) or 0.0)
        if (now - ts) <= max(1, HEALTH_CACHE_SECONDS):
            return str(HEALTH_CACHE.get("rows", ""))

    rows = []
    health_data = []

    for p in PIHOLES:
        status = "api failure"
        version_str = ""
        healthy = False

        try:
            sid, csrf = api_auth(p)
            version_info = api_validate_version(p, sid, csrf)
            version = version_info.get("version", "unknown")
            if version.startswith("v"):
                version = version[1:]
            version_str = f" (v{version})"
            api_get_blocking(p, sid, csrf)
            status = "healthy"
            healthy = True
        except ApiError as e:
            status = str(e)
            if "v6 or later" in status:
                status = "incompatible version"
            # Invalidate session on auth errors
            if "auth" in status.lower() or "unauthorized" in status.lower():
                invalidate_session(p)
        except Exception:
            status = "api failure"

        health_data.append({"name": p["name"], "healthy": healthy, "status": status, "version": version_str})
        cls = "ok" if status == "healthy" else "bad"
        rows.append(f"<div class='ph-row'><span class='ph-name'>{html.escape(p['name'])}{html.escape(version_str)}</span><span class='{cls}'>{html.escape(status)}</span></div>")

    html_out = "<div class='ph-status'><div class='ph-title'>Pi-hole status</div>" + "".join(rows) + "</div>"

    with HEALTH_LOCK:
        HEALTH_CACHE["ts"] = now
        HEALTH_CACHE["rows"] = html_out
        HEALTH_CACHE["data"] = health_data
    return html_out


def get_health_json() -> dict:
    """Get health status as JSON for API endpoint."""
    # Trigger refresh if needed
    get_pihole_health_rows()

    with HEALTH_LOCK:
        data = HEALTH_CACHE.get("data", [])

    all_healthy = all(p.get("healthy", False) for p in data) if data else False

    return {
        "status": "healthy" if all_healthy else "degraded",
        "version": VERSION,
        "piholes": data,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


# ----------------------------
# Results cache (for friendly redirects)
# ----------------------------

CACHE = {}
CACHE_LOCK = threading.Lock()
CACHE_TTL = 120


def cache_put(html_content: str) -> str:
    token = secrets.token_urlsafe(16)
    with CACHE_LOCK:
        CACHE[token] = {"ts": time.time(), "html": html_content}
    return token


def cache_get(token: str) -> str | None:
    now = time.time()
    with CACHE_LOCK:
        dead = [k for k, v in CACHE.items() if (now - v.get("ts", 0)) > CACHE_TTL]
        for k in dead:
            CACHE.pop(k, None)
        v = CACHE.get(token)
        if not v:
            return None
        return v.get("html")


# ----------------------------
# HTML templates
# ----------------------------

DARK_MODE_CSS = """
    @media (prefers-color-scheme: dark) {
      body { background: #1a1a1a; color: #e0e0e0; }
      .container { background: #2d2d2d; box-shadow: 0 2px 8px rgba(0,0,0,0.4); }
      .warning { background: #3d3020; border-color: #5a4a30; }
      button { background: #c0392b; }
      button:hover { background: #e74c3c; }
      a { color: #5dade2; }
      .ph-status { border-top-color: #444; color: #ccc; }
      pre { background: #000; }
      .details { background: #222; border-color: #444; }
      .subnote { color: #999; }
      .footer { color: #888; }
    }
"""

WARNING_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ad Blocking Control</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 640px;
      margin: 40px auto;
      padding: 20px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
      text-align: center;
    }}
    h1 {{
      margin-top: 0;
    }}
    .warning {{
      margin: 18px 0;
      padding: 14px;
      background: #fff4e5;
      border: 1px solid #ffd8a8;
      border-radius: 8px;
      text-align: left;
      font-size: 14px;
      line-height: 1.45;
    }}
    .active-bypass {{
      margin: 18px 0;
      padding: 14px;
      background: #e8f5e9;
      border: 1px solid #a5d6a7;
      border-radius: 8px;
      text-align: center;
    }}
    .active-bypass .countdown {{
      font-size: 28px;
      font-weight: bold;
      margin: 8px 0;
    }}
    .subnote {{
      color: #666;
      font-size: 13px;
      margin-bottom: 18px;
    }}
    button {{
      font-size: 18px;
      padding: 14px 20px;
      border: none;
      border-radius: 10px;
      cursor: pointer;
      background: #c0392b;
      color: #fff;
      width: 100%;
      margin-bottom: 10px;
    }}
    button:hover {{
      background: #a93226;
    }}
    button.secondary {{
      background: #7f8c8d;
      font-size: 14px;
      padding: 10px 16px;
    }}
    button.secondary:hover {{
      background: #95a5a6;
    }}
    .footer {{
      margin-top: 14px;
      font-size: 12px;
      color: #777;
    }}
    a {{
      color: #2b6cb0;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    .ph-status {{
      margin-top: 18px;
      padding-top: 12px;
      border-top: 1px solid #e7e7e7;
      font-size: 14px;
      color: #333;
    }}
    .ph-title {{ font-weight: 800; margin-bottom: 6px; }}
    .ph-row {{ display: flex; justify-content: space-between; padding: 4px 0; }}
    .ph-name {{ font-weight: 700; }}
    .ok {{ color: #0a7a0a; font-weight: 800; }}
    .bad {{ color: #b00000; font-weight: 800; }}
    .version {{ font-size: 11px; color: #999; margin-top: 12px; }}
    {dark_mode}
  </style>
</head>
<body>
  <div class="container">
    <h1>Adblocker Control</h1>
    {bypass_status}
    <div class="warning">
      <strong>Note:</strong> Pausing ad blocking may show more ads and reduce protection against some known harmful domains.
      Use this briefly if a site is not loading correctly. Filtering will resume automatically.
    </div>
    <div class="subnote">Use this if a site is not loading correctly.</div>
    <form method="POST" action="/disable">
      <button type="submit">Pause Ad Blocking for {minutes} Minutes</button>
    </form>
    {cancel_button}
    <div class="footer">
      Ad blocking will be paused for {minutes} minutes and will resume automatically.
    </div>
    {logs_link}
    {pihole_status}
    <div class="version">Event Horizon v{version}</div>
  </div>
  {bypass_script}
</body>
</html>
"""

BYPASS_ACTIVE_HTML = """
<div class="active-bypass">
  <div>Ad blocking is currently <strong>paused</strong> for your device</div>
  <div class="countdown" id="main-cd">{mm}:{ss}</div>
  <div style="font-size: 13px; color: #666;">Filtering will resume automatically</div>
</div>
"""

BYPASS_SCRIPT = """
<script>
(function() {{
  var remain = {seconds};
  var el = document.getElementById("main-cd");
  if (!el) return;
  function pad(n) {{ return (n < 10) ? ("0" + n) : ("" + n); }}
  function tick() {{
    if (remain <= 0) {{
      location.reload();
      return;
    }}
    remain -= 1;
    var mm = Math.floor(remain / 60);
    var ss = remain % 60;
    el.textContent = pad(mm) + ":" + pad(ss);
    setTimeout(tick, 1000);
  }}
  setTimeout(tick, 1000);
}})();
</script>
"""

CANCEL_BUTTON_HTML = """
<form method="POST" action="/cancel" style="margin-top: 10px;">
  <button type="submit" class="secondary">Resume Blocking Now</button>
</form>
"""

SUCCESS_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ad Blocking Paused</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 640px;
      margin: 40px auto;
      padding: 20px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
      text-align: center;
    }}
    .ok {{ color: #0a7a0a; font-weight: bold; }}
    .bad {{ color: #b00000; font-weight: bold; }}
    .title {{
      font-size: 22px;
      margin: 0 0 10px 0;
      font-weight: bold;
    }}
    .subtitle {{
      color: #555;
      font-size: 14px;
      margin-bottom: 18px;
    }}
    .countdown {{
      font-size: 44px;
      font-weight: bold;
      letter-spacing: 1px;
      margin: 10px 0 14px 0;
    }}
    .details {{
      text-align: left;
      font-size: 13px;
      margin-top: 10px;
      padding: 12px;
      background: #f8f8f8;
      border-radius: 8px;
      border: 1px solid #eee;
    }}
    a {{
      color: #2b6cb0;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    {dark_mode}
  </style>
</head>
<body>
  <div class="container">
    <div class="title">{result_line}</div>
    <div class="subtitle">
      Ad blocking is paused for this device. Try your action again. Filtering will resume automatically.
    </div>
    <div class="countdown" id="cd">{mm}:{ss}</div>
    {details_block}
    <div style="margin-top:16px;">
      <a href="/">Back</a>
    </div>
  </div>
<script>
  (function() {{
    var remain = {seconds};
    function pad(n) {{ return (n < 10) ? ("0" + n) : ("" + n); }}
    function tick() {{
      if (remain <= 0) {{
        document.getElementById("cd").textContent = "00:00";
        return;
      }}
      remain -= 1;
      var mm = Math.floor(remain / 60);
      var ss = remain % 60;
      document.getElementById("cd").textContent = pad(mm) + ":" + pad(ss);
      setTimeout(tick, 1000);
    }}
    setTimeout(tick, 1000);
  }})();
</script>
</body>
</html>
"""

CANCELLED_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ad Blocking Resumed</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 640px;
      margin: 40px auto;
      padding: 20px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
      text-align: center;
    }}
    .ok {{ color: #0a7a0a; font-weight: bold; }}
    .title {{
      font-size: 22px;
      margin: 0 0 10px 0;
      font-weight: bold;
    }}
    .subtitle {{
      color: #555;
      font-size: 14px;
      margin-bottom: 18px;
    }}
    a {{
      color: #2b6cb0;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    {dark_mode}
  </style>
</head>
<body>
  <div class="container">
    <div class="title">{result_line}</div>
    <div class="subtitle">{message}</div>
    <div style="margin-top:16px;">
      <a href="/">Back</a>
    </div>
  </div>
</body>
</html>
"""

LOGS_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Event Horizon Logs</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 860px;
      margin: 20px auto;
      padding: 20px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
    }}
    pre {{
      white-space: pre-wrap;
      word-wrap: break-word;
      background: #111;
      color: #eee;
      padding: 14px;
      border-radius: 10px;
      overflow-x: auto;
    }}
    a {{
      color: #2b6cb0;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    .tabs {{
      display: flex;
      gap: 10px;
      margin-bottom: 15px;
    }}
    .tab {{
      padding: 8px 16px;
      background: #e0e0e0;
      border-radius: 6px;
      cursor: pointer;
      text-decoration: none;
      color: #333;
    }}
    .tab.active {{
      background: #2b6cb0;
      color: #fff;
    }}
    {dark_mode}
  </style>
</head>
<body>
  <div class="container">
    <h1>{title}</h1>
    <p><a href="/">Back</a></p>
    <div class="tabs">
      <a href="/logs" class="tab {requests_active}">Requests</a>
      <a href="/logs?type=api" class="tab {api_active}">API</a>
    </div>
    <pre>{logs}</pre>
  </div>
</body>
</html>
"""

RATE_LIMITED_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rate Limited</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 640px;
      margin: 40px auto;
      padding: 20px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
      text-align: center;
    }}
    h1 {{ margin-top: 0; color: #c0392b; }}
    a {{
      color: #2b6cb0;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    {dark_mode}
  </style>
</head>
<body>
  <div class="container">
    <h1>Too Many Requests</h1>
    <p>You have made too many bypass requests. Please wait before trying again.</p>
    <p>Limit: {limit} requests per {window} minutes</p>
    <p style="margin-top:14px;"><a href="/">Back</a></p>
  </div>
</body>
</html>
"""

ERROR_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Error</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #f4f4f4;
      margin: 0;
      padding: 0;
    }}
    .container {{
      max-width: 640px;
      margin: 40px auto;
      padding: 20px;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
    }}
    h1 {{ margin-top: 0; }}
    ul {{ margin: 0; padding-left: 18px; }}
    a {{
      color: #2b6cb0;
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    {dark_mode}
  </style>
</head>
<body>
  <div class="container">
    <h1>Could not pause ad blocking</h1>
    <p>One or more Pi-hole instances returned an error:</p>
    <ul>
      {items}
    </ul>
    <p style="margin-top:14px;"><a href="/">Back</a></p>
  </div>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    # Suppress default logging
    def log_message(self, format, *args):
        pass

    def _client_ip(self) -> str:
        remote = self.client_address[0]
        if TRUST_PROXY:
            try:
                rip = ipaddress.ip_address(remote)
                trusted = (not TRUSTED_PROXY_NETS) or any(rip in net for net in TRUSTED_PROXY_NETS)
                if trusted:
                    xff = self.headers.get("X-Forwarded-For", "") or self.headers.get("X-Real-IP", "")
                    if xff:
                        cand = xff.split(",")[0].strip()
                        try:
                            ipaddress.ip_address(cand)
                            return normalize_ip(cand)
                        except Exception:
                            pass
            except Exception:
                pass
        return normalize_ip(remote)

    def _send_html(self, html_content: str, code: int = 200):
        body = html_content.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Event-Horizon-Version", VERSION)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: dict, code: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Event-Horizon-Version", VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Cleanup old cooldown entries periodically
        cleanup_cooldown_cache()

        if path == "/":
            client_ip = self._client_ip()
            remaining = get_bypass_remaining(client_ip)

            bypass_status = ""
            bypass_script = ""
            cancel_button = ""

            if remaining:
                mm = remaining // 60
                ss = remaining % 60
                bypass_status = BYPASS_ACTIVE_HTML.format(mm=f"{mm:02d}", ss=f"{ss:02d}")
                bypass_script = BYPASS_SCRIPT.format(seconds=remaining)
                cancel_button = CANCEL_BUTTON_HTML

            logs_link = ""
            if SHOW_LOG_LINK:
                logs_link = '<div style="margin-top:14px;"><a href="/logs">View logs</a></div>'

            page_html = WARNING_HTML.format(
                minutes=DISABLE_MINUTES,
                logs_link=logs_link,
                pihole_status=get_pihole_health_rows(),
                bypass_status=bypass_status,
                bypass_script=bypass_script,
                cancel_button=cancel_button,
                version=VERSION,
                dark_mode=DARK_MODE_CSS,
            )
            self._send_html(page_html)
            return

        if path == "/logs":
            qs = parse_qs(parsed.query)
            log_type = (qs.get("type", ["requests"])[0] or "requests").strip()

            ensure_log_dir()

            if log_type == "api":
                log_file = API_LOG
                title = "API Logs"
                requests_active = ""
                api_active = "active"
            else:
                log_file = REQUESTS_LOG
                title = "Request Logs"
                requests_active = "active"
                api_active = ""

            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                last = lines[-200:]
                logs = html.escape("".join(last).strip())
            except FileNotFoundError:
                logs = "(no logs yet)"

            self._send_html(LOGS_HTML.format(
                logs=logs,
                title=title,
                requests_active=requests_active,
                api_active=api_active,
                dark_mode=DARK_MODE_CSS,
            ))
            return

        if path == "/results":
            qs = parse_qs(parsed.query)
            token = (qs.get("t", [""])[0] or "").strip()
            cached_html = cache_get(token)
            if not cached_html:
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self._send_html(cached_html)
            return

        if path == "/health":
            self._send_json(get_health_json())
            return

        if path == "/favicon.ico":
            # Return 204 No Content for favicon
            self.send_response(204)
            self.end_headers()
            return

        self.send_response(404)
        self.send_header("X-Event-Horizon-Version", VERSION)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/disable":
            self._handle_disable()
            return

        if path == "/cancel":
            self._handle_cancel()
            return

        self.send_response(404)
        self.send_header("X-Event-Horizon-Version", VERSION)
        self.end_headers()

    def _handle_disable(self):
        client_ip = self._client_ip()
        now = time.time()

        # Check rate limit first
        allowed, remaining = check_rate_limit(client_ip)
        if not allowed:
            log_request(client_ip, "rate_limited")
            page_html = RATE_LIMITED_HTML.format(
                limit=RATE_LIMIT_REQUESTS,
                window=RATE_LIMIT_WINDOW // 60,
                dark_mode=DARK_MODE_CSS,
            )
            token = cache_put(page_html)
            self.send_response(303)
            self.send_header("Location", f"/results?t={token}")
            self.end_headers()
            return

        with COOLDOWN_LOCK:
            last = float(LAST_PRESS_BY_IP.get(client_ip, 0.0) or 0.0)
            if (now - last) < max(1, COOLDOWN_SECONDS):
                log_request(client_ip, "cooldown=active")
                mm = DISABLE_SECONDS // 60
                ss = DISABLE_SECONDS % 60
                page_html = SUCCESS_HTML.format(
                    seconds=DISABLE_SECONDS,
                    mm=f"{mm:02d}",
                    ss=f"{ss:02d}",
                    result_line="Request already in progress",
                    details_block="",
                    dark_mode=DARK_MODE_CSS,
                )
                token = cache_put(page_html)
                self.send_response(303)
                self.send_header("Location", f"/results?t={token}")
                self.end_headers()
                return
            LAST_PRESS_BY_IP[client_ip] = now

        results = []
        ok_all, failures = apply_bypass_for_client(client_ip, DISABLE_SECONDS)

        fail_names = set()
        for f in failures:
            name = f.split(":", 1)[0].strip()
            if name:
                fail_names.add(name)

        for p in PIHOLES:
            if p["name"] in fail_names:
                results.append((p["name"], False, "api failure", None))
            else:
                results.append((p["name"], True, "paused", DISABLE_SECONDS))

        detail_parts = []
        for name, ok, state, _ in results:
            detail_parts.append(f"{name}:ok={1 if ok else 0},state={state}")
        log_request(client_ip, f"pause_{DISABLE_MINUTES}m", "; ".join(detail_parts))

        if not results or (not ok_all and all(r[1] is False for r in results)):
            items = "\n".join(f"<li>{html.escape(x)}</li>" for x in failures) or "<li>Unknown error</li>"
            page_html = ERROR_HTML.format(items=items, dark_mode=DARK_MODE_CSS)
            token = cache_put(page_html)
            self.send_response(303)
            self.send_header("Location", f"/results?t={token}")
            self.end_headers()
            return

        display_seconds = DISABLE_SECONDS
        mm = display_seconds // 60
        ss = display_seconds % 60

        if ok_all:
            result_line = '<span class="ok">Ad blocking paused for this device</span>'
        else:
            result_line = '<span class="bad">Partial success</span>'

        ok_items = []
        bad_items = []
        for name, ok, state, _ in results:
            if ok:
                ok_items.append(f"<li><span class='ok'>{html.escape(name)}</span>: {html.escape(state)}</li>")
            else:
                bad_items.append(f"<li><span class='bad'>{html.escape(name)}</span>: {html.escape(state)}</li>")

        details_html = ""
        if ok_items or bad_items:
            details_html = "<div class='details'>"
            if ok_items:
                details_html += "<div><strong>Updated:</strong><ul>" + "".join(ok_items) + "</ul></div>"
            if bad_items:
                details_html += "<div style='margin-top:10px;'><strong>Failed:</strong><ul>" + "".join(bad_items) + "</ul></div>"
            details_html += "</div>"

        page_html = SUCCESS_HTML.format(
            seconds=display_seconds,
            mm=f"{mm:02d}",
            ss=f"{ss:02d}",
            result_line=result_line,
            details_block=details_html,
            dark_mode=DARK_MODE_CSS,
        )
        token = cache_put(page_html)
        self.send_response(303)
        self.send_header("Location", f"/results?t={token}")
        self.end_headers()

    def _handle_cancel(self):
        client_ip = self._client_ip()

        remaining = get_bypass_remaining(client_ip)
        if not remaining:
            page_html = CANCELLED_HTML.format(
                result_line='<span class="ok">No active bypass</span>',
                message="Ad blocking was not paused for your device.",
                dark_mode=DARK_MODE_CSS,
            )
            token = cache_put(page_html)
            self.send_response(303)
            self.send_header("Location", f"/results?t={token}")
            self.end_headers()
            return

        ok, failures = cancel_bypass_for_client(client_ip)
        log_request(client_ip, "cancel_bypass", f"ok={1 if ok else 0} failures={len(failures)}")

        if ok:
            page_html = CANCELLED_HTML.format(
                result_line='<span class="ok">Ad blocking resumed</span>',
                message="Filtering has been restored for your device.",
                dark_mode=DARK_MODE_CSS,
            )
        else:
            page_html = CANCELLED_HTML.format(
                result_line='<span class="bad">Partial success</span>',
                message=f"Some Pi-holes could not be updated: {', '.join(failures)}",
                dark_mode=DARK_MODE_CSS,
            )

        token = cache_put(page_html)
        self.send_response(303)
        self.send_header("Location", f"/results?t={token}")
        self.end_headers()


def print_startup_banner():
    """Print configuration summary at startup."""
    print(f"Event Horizon v{VERSION}")
    print(f"=" * 50)
    print(f"Port: {PORT}")
    print(f"Disable duration: {DISABLE_MINUTES} minutes")
    print(f"Pi-holes configured: {len(PIHOLES)}")
    for p in PIHOLES:
        print(f"  - {p['name']}: {p['base']}")
    print(f"Trust proxy: {TRUST_PROXY}")
    if TRUST_PROXY and TRUSTED_PROXY_NETS:
        print(f"  Trusted networks: {TRUSTED_PROXY_NETS_RAW}")
    print(f"SSL verification: {VERIFY_SSL}")
    print(f"API timeout: {API_TIMEOUT}s")
    print(f"Session cache TTL: {SESSION_CACHE_TTL}s")
    print(f"Log directory: {LOG_DIR}")
    print(f"API logging: {API_LOG_ENABLED}")
    print(f"Log max size: {LOG_MAX_SIZE_MB}MB")
    print(f"Log max age: {LOG_MAX_AGE_DAYS} days")
    print(f"Rate limit: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW // 60} minutes")
    print(f"=" * 50)
    sys.stdout.flush()

    if not PIHOLES:
        print("WARNING: No Pi-holes configured!")

    print(f"Listening on http://0.0.0.0:{PORT}")


def main():
    ensure_log_dir()
    print_startup_banner()

    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)

    def _stop(*_):
        print("\nShutting down...")
        try:
            httpd.shutdown()
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
