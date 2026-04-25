#!/usr/bin/env python3

import sys

if sys.version_info < (3, 8):
    raise SystemExit(
        f"Python 3.8+ necessário — versão detectada: {sys.version_info.major}.{sys.version_info.minor}"
    )

import argparse
import concurrent.futures
import functools
import glob
import http.server
import json
import multiprocessing
import os
import platform
import queue
import random
import re
import shutil
import signal
import socketserver
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


import asyncio as _asyncio

try:
    import httpx as _httpx
    _HTTPX_OK = True
except ImportError:
    _HTTPX_OK = False

try:
    import h2 as _h2  # noqa: F401
    _HTTP2_AVAILABLE = True
except ImportError:
    _HTTP2_AVAILABLE = False


_HTTP_MAX_CONN    = int(os.environ.get("RECON_HTTP_MAX_CONN",    "150"))
_HTTP_TIMEOUT_SEC = float(os.environ.get("RECON_HTTP_TIMEOUT",  "15"))
_HTTP_RETRIES     = int(os.environ.get("RECON_HTTP_RETRIES",    "3"))


_http_semaphore: Optional[_asyncio.Semaphore] = None


class AsyncScannerClient:


    def __init__(self) -> None:
        limits = _httpx.Limits(
            max_keepalive_connections=_HTTP_MAX_CONN,
            max_connections=_HTTP_MAX_CONN,
            keepalive_expiry=30,
        )
        self._client = _httpx.AsyncClient(
            http2=_HTTP2_AVAILABLE,
            verify=False,
            limits=limits,
            timeout=_httpx.Timeout(
                connect=5.0,
                read=_HTTP_TIMEOUT_SEC,
                write=5.0,
                pool=3.0,
            ),
            follow_redirects=True,
            headers={"User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
            )},
        )

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        head_only: bool = False,
    ) -> Tuple[int, str, float]:


        global _http_semaphore
        if _http_semaphore is None:
            _http_semaphore = _asyncio.Semaphore(_HTTP_MAX_CONN)

        if head_only:
            method = "HEAD"


        merged_headers: Dict[str, str] = {"User-Agent": random_ua()}
        if headers:
            merged_headers.update(headers)

        wait = 1.0
        for attempt in range(_HTTP_RETRIES):
            try:
                async with _http_semaphore:
                    resp = await self._client.request(
                        method=method,
                        url=url,
                        headers=merged_headers,
                        content=data.encode(errors="replace") if data else None,
                    )
                elapsed = resp.elapsed.total_seconds() if resp.elapsed else 0.0
                return resp.status_code, resp.text, elapsed
            except _httpx.TimeoutException:
                pass
            except _httpx.TooManyRedirects:
                return -1, "", 0.0
            except _httpx.RequestError:
                pass
            except Exception:
                return -1, "", 0.0

            if attempt < _HTTP_RETRIES - 1:
                await _asyncio.sleep(wait)
                wait *= 2.0

        return -1, "", 0.0

    async def aclose(self) -> None:
        await self._client.aclose()


_http_client: Optional[AsyncScannerClient] = None
_http_loop:   Optional[_asyncio.AbstractEventLoop] = None
_http_thread: Optional[threading.Thread] = None


def http_client_start() -> None:

    global _http_client, _http_loop, _http_thread
    if not _HTTPX_OK:
        return

    _http_loop = _asyncio.new_event_loop()

    def _run(loop: _asyncio.AbstractEventLoop) -> None:
        _asyncio.set_event_loop(loop)
        loop.run_forever()

    _http_thread = threading.Thread(
        target=_run, args=(_http_loop,), daemon=True, name="http-client-loop"
    )
    _http_thread.start()


    future = _asyncio.run_coroutine_threadsafe(_async_init_client(), _http_loop)
    try:
        future.result(timeout=10)
    except Exception as exc:
        print(f"[HTTP-CLIENT] Falha ao inicializar: {exc}", file=sys.stderr)


async def _async_init_client() -> None:
    global _http_client, _http_semaphore
    _http_client   = AsyncScannerClient()
    _http_semaphore = _asyncio.Semaphore(_HTTP_MAX_CONN)


def http_client_stop() -> None:

    global _http_loop, _http_client
    if _http_loop is None or not _http_loop.is_running():
        return
    if _http_client is not None:
        try:
            future = _asyncio.run_coroutine_threadsafe(
                _http_client.aclose(), _http_loop
            )
            future.result(timeout=5)
        except Exception:
            pass
    try:
        _http_loop.call_soon_threadsafe(_http_loop.stop)
    except Exception:
        pass


def http_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
    head_only: bool = False,
) -> Tuple[int, str]:
    if cfg.dry_run:
        return 200, f"[DRY-RUN] {url}"

    if not _HTTPX_OK or _http_loop is None or _http_client is None:
        return retry_curl(url, head_only=head_only, extra_headers=headers,
                          method=method, data=data)

    if _shutdown_event.is_set():
        return -1, ""

    host_throttle(url)

    timeout_total = _HTTP_TIMEOUT_SEC * _HTTP_RETRIES + 10

    async def _fetch_or_shutdown():
        async def _shutdown_waiter():
            loop = _asyncio.get_running_loop()
            await loop.run_in_executor(None, _shutdown_event.wait)

        try:
            fetch_task    = _asyncio.ensure_future(
                _asyncio.wait_for(
                    _http_client.fetch(url, method=method, headers=headers,
                                       data=data, head_only=head_only),
                    timeout=timeout_total,
                )
            )
            shutdown_task = _asyncio.ensure_future(_shutdown_waiter())

            done, pending = await _asyncio.wait(
                [fetch_task, shutdown_task],
                return_when=_asyncio.FIRST_COMPLETED,
            )

            for t in pending:
                t.cancel()
                try:
                    await t
                except (_asyncio.CancelledError, Exception):
                    pass

            if fetch_task in done and not fetch_task.cancelled():
                return await fetch_task
            return -1, "", 0.0
        except _asyncio.TimeoutError:
            return -1, "", 0.0
        except Exception:
            return -1, "", 0.0

    try:
        future = _asyncio.run_coroutine_threadsafe(_fetch_or_shutdown(), _http_loop)
        status, body, _elapsed = future.result(timeout=timeout_total + 5)
        if status != -1:
            feedback_hook("http", "", status, url=url)
            _host_health.record(url, status)
        return status, body
    except concurrent.futures.TimeoutError:
        log_err(f"http_fetch bridge timeout: {url}")
        return -1, ""
    except concurrent.futures.CancelledError:
        return -1, ""
    except Exception as exc:
        log_err(f"http_fetch error {url}: {exc}")
        return -1, ""


def http_fetch_timed(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
) -> Tuple[int, str, float]:


    if cfg.dry_run:
        return 200, f"[DRY-RUN] {url}", 0.0

    if not _HTTPX_OK or _http_loop is None or _http_client is None:
        t0 = time.monotonic()
        status, body = retry_curl(url, extra_headers=headers, method=method, data=data)
        return status, body, time.monotonic() - t0

    if _shutdown_event.is_set():
        return -1, "", 0.0

    host_throttle(url)
    try:
        future = _asyncio.run_coroutine_threadsafe(
            _http_client.fetch(url, method=method, headers=headers, data=data),
            _http_loop,
        )
        timeout_total = _HTTP_TIMEOUT_SEC * _HTTP_RETRIES + 10
        deadline = time.monotonic() + timeout_total

        while True:
            if _shutdown_event.is_set():
                future.cancel()
                return -1, "", 0.0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                future.cancel()
                log_err(f"http_fetch_timed bridge timeout: {url}")
                return -1, "", 0.0
            try:
                status, body, elapsed = future.result(timeout=min(0.5, remaining))
                break
            except concurrent.futures.TimeoutError:
                continue

        if status != -1:
            feedback_hook("http", "", status, url=url)
            _host_health.record(url, status)
        return status, body, elapsed
    except Exception as exc:
        log_err(f"http_fetch_timed error {url}: {exc}")
        return -1, "", 0.0


from collections import deque as _deque

_HOST_WINDOW    = int(os.environ.get("RECON_HOST_WINDOW",    "100"))
_HOST_THRESHOLD = float(os.environ.get("RECON_HOST_THRESHOLD", "0.15"))
_HOST_PAUSE_SEC = int(os.environ.get("RECON_HOST_PAUSE",    "120"))


class HostHealthMonitor:


    def __init__(self, window: int = _HOST_WINDOW,
                 threshold: float = _HOST_THRESHOLD,
                 pause_sec: int = _HOST_PAUSE_SEC) -> None:
        self._window    = window
        self._threshold = threshold
        self._pause_sec = pause_sec
        self._history:  Dict[str, _deque] = {}
        self._paused:   Dict[str, float]  = {}
        self._lock = threading.Lock()

    def _host_of(self, url: str) -> str:
        try:
            return urllib.parse.urlparse(url).netloc or url
        except Exception:
            return url

    def record(self, url: str, status: int) -> None:


        host = self._host_of(url)
        should_warn = False
        warn_data: Dict = {}
        with self._lock:
            if host not in self._history:
                self._history[host] = _deque(maxlen=self._window)
            self._history[host].append(status)

            window = self._history[host]
            if len(window) < self._window:
                return

            blocked = sum(1 for s in window if s in (403, 429, 503))
            rate    = blocked / len(window)
            if rate >= self._threshold and host not in self._paused:
                self._paused[host] = time.time() + self._pause_sec
                should_warn = True
                warn_data = {
                    "host": host, "rate": rate, "blocked": blocked,
                    "window_len": len(window),
                    "pause_until": self._paused[host],
                }

        if should_warn:
            warn(
                f"[HostHealth] {warn_data['host']}: {warn_data['rate']:.0%} de bloqueio "
                f"({warn_data['blocked']}/{warn_data['window_len']}) → pausando {self._pause_sec}s"
            )
            jsonl_log("host_circuit_open", {
                "host": warn_data["host"],
                "block_rate": round(warn_data["rate"], 4),
                "blocked": warn_data["blocked"],
                "window": warn_data["window_len"],
                "pause_until": warn_data["pause_until"],
            })

    def wait_if_paused(self, url: str) -> None:


        host = self._host_of(url)
        with self._lock:
            until = self._paused.get(host, 0.0)
            now   = time.time()
            if until <= now:
                self._paused.pop(host, None)
                return
            remaining = until - now


        jitter_offset = random.uniform(0, min(remaining * 0.10, 5.0))
        deadline = time.time() + remaining + jitter_offset


        while time.time() < deadline:
            if _shutdown_event.is_set():
                return
            remaining_now = deadline - time.time()
            time.sleep(min(0.5, max(0.0, remaining_now)))

        with self._lock:
            current_until = self._paused.get(host, 0.0)
            if current_until <= time.time():
                self._paused.pop(host, None)
                self._history.pop(host, None)

    def is_paused(self, url: str) -> bool:
        host = self._host_of(url)
        with self._lock:
            until = self._paused.get(host, 0.0)
            if until > time.time():
                return True
            self._paused.pop(host, None)
            return False


_host_health = HostHealthMonitor()


_jsonl_fh:   Optional[object] = None
_jsonl_lock  = threading.Lock()


def _open_jsonl_file(path: str) -> None:
    global _jsonl_fh
    with _jsonl_lock:
        try:
            _jsonl_fh = open(path, "a", buffering=1)
        except OSError as exc:
            print(f"[JSONL] Falha ao abrir {path}: {exc}", file=sys.stderr)


def _close_jsonl_file() -> None:
    global _jsonl_fh
    with _jsonl_lock:
        if _jsonl_fh:
            try:
                _jsonl_fh.flush()
                _jsonl_fh.close()
            except Exception:
                pass
            _jsonl_fh = None


def jsonl_log(event_type: str, data: Dict) -> None:


    with _jsonl_lock:
        if _jsonl_fh is None:
            return
        try:
            record = {
                "ts":       datetime.now(timezone.utc).isoformat(),
                "type":     event_type,
                "scan_id":  getattr(cfg, "scan_dir", "unknown"),
                **data,
            }
            _jsonl_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

try:
    from tqdm import tqdm as _tqdm
except ImportError:

    class _tqdm:
        def __init__(self, *a, **kw): pass
        def update(self, n=1): pass
        def set_postfix(self, **kw): pass
        def set_description(self, s): pass
        def write(self, s): print(s)
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass


RED      = '\033[0;31m'
LRED     = '\033[1;31m'
GREEN    = '\033[0;32m'
LGREEN   = '\033[1;32m'
YELLOW   = '\033[1;33m'
BLUE     = '\033[0;34m'
LBLUE    = '\033[1;34m'
MAGENTA  = '\033[0;35m'
LMAGENTA = '\033[1;35m'
CYAN     = '\033[0;36m'
LCYAN    = '\033[1;36m'
WHITE    = '\033[1;37m'
GRAY     = '\033[0;37m'
BOLD     = '\033[1m'
DIM      = '\033[2m'
NC       = '\033[0m'


ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\x1b\(B|\x1b=')

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub('', s)


class ToolRunner:


    def run(self, name: str, cmd: List[str], timeout: int = 300,
            input_data: Optional[str] = None,
            write_to: Optional[str] = None) -> Tuple[int, str, str]:


        if cfg.dry_run:
            log_err(f"[DRY-RUN] ToolRunner.run({name}): {' '.join(cmd[:4])}...")
            return 0, f"[DRY-RUN] {name}", ""

        try:
            if write_to:


                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE if input_data else None,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                except FileNotFoundError:
                    log_err(f"{name}: binário não encontrado — '{cmd[0]}'")
                    return -2, '', 'not found'
                except OSError as e:
                    log_err(f"{name}: OSError ao iniciar processo — {e}")
                    return -3, '', str(e)
                with _child_lock:
                    _child_pids.add(proc.pid)
                    _child_pgids.add(proc.pid)
                try:
                    out_bytes, _ = proc.communicate(
                        input=input_data.encode(errors='replace') if input_data else None,
                        timeout=timeout
                    )

                    try:
                        with open(write_to, 'wb') as fout:
                            fout.write(out_bytes or b'')
                    except OSError as e:
                        log_err(f"{name}: falha ao gravar em {write_to}: {e}")


                    return _SubprocessResult(proc.returncode, '', '')
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.communicate(timeout=2)
                    except Exception:
                        try: proc.wait(timeout=2)
                        except Exception: pass
                    log_err(f"{name}: timeout {timeout}s")
                    return _SubprocessResult(-1, '', 'timeout')
                finally:
                    with _child_lock:
                        _child_pids.discard(proc.pid)
                        _child_pgids.discard(proc.pid)
            else:


                rc, out, err = _tracked_run(cmd, timeout=timeout, input=input_data)
                return rc, strip_ansi(out), strip_ansi(err)

        except FileNotFoundError:
            log_err(f"{name}: binário não encontrado — '{cmd[0]}'")
            return -2, '', 'not found'
        except subprocess.TimeoutExpired:
            log_err(f"{name}: timeout após {timeout}s")
            return -1, '', 'timeout'
        except OSError as e:
            log_err(f"{name}: OSError — {e}")
            return -3, '', str(e)
        except subprocess.SubprocessError as e:
            log_err(f"{name}: SubprocessError — {e}")
            return -4, '', str(e)
        except ValueError as e:
            log_err(f"{name}: ValueError — {e}")
            return -5, '', str(e)


tool_runner = ToolRunner()


class CircuitBreaker:


    _HALF_OPEN_COOLDOWN = 300

    def __init__(self, max_failures: int = 3):
        self.max_failures = max_failures
        self._failures: Dict[str, int] = {}
        self._timeouts: Dict[str, int] = {}
        self._open: Set[str] = set()
        self._half_open_time: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _try_half_open_locked(self, module: str) -> bool:

        if time.time() >= self._half_open_time.get(module, float('inf')):
            self._open.discard(module)
            self._failures.pop(module, None)
            self._timeouts.pop(module, None)
            warn(f"Circuit breaker: '{module}' em HALF-OPEN — tentando reabilitar")
            return True
        return False

    def record_failure(self, module: str, rc: int = -1) -> None:
        with self._lock:
            if rc == -1:
                self._timeouts[module] = self._timeouts.get(module, 0) + 1
                count = self._timeouts[module]
                limit = self.max_failures * 2
            else:
                self._failures[module] = self._failures.get(module, 0) + 1
                count = self._failures[module]
                limit = self.max_failures
            if count >= limit and module not in self._open:
                self._open.add(module)
                self._half_open_time[module] = time.time() + self._HALF_OPEN_COOLDOWN
                error(f"⚡ CIRCUIT BREAKER ABERTO: módulo '{module}' desabilitado "
                      f"após {count} falhas (rc={rc}). Retry automático em {self._HALF_OPEN_COOLDOWN}s.")

    def record_success(self, module: str) -> None:
        with self._lock:
            self._failures.pop(module, None)
            self._timeouts.pop(module, None)
            self._open.discard(module)
            self._half_open_time.pop(module, None)

    def is_open(self, module: str) -> bool:
        with self._lock:
            if module not in self._open:
                return False
            return not self._try_half_open_locked(module)

    def allow(self, module: str) -> bool:
        with self._lock:
            if module not in self._open:
                return True
            if self._try_half_open_locked(module):
                return True
            remaining = max(0, int(self._half_open_time.get(module, 0) - time.time()))
        warn(f"Circuit breaker: módulo '{module}' desabilitado — retry em {remaining}s")
        return False


circuit_breaker = CircuitBreaker(max_failures=3)


@dataclass
class Config:

    domain: str = ""
    threads: int = 100
    deep_mode: bool = False
    skip_scans: bool = False
    skip_screenshots: bool = False
    verbose: bool = False
    timeout: int = 10
    rate_limit: int = 50
    max_sqli: int = 30
    gau_threads: int = 10
    katana_depth: int = 3
    scan_start: float = 0.0
    anthropic_api_key: str = ""

    max_retries: int = 3
    retry_delay: float = 1.0
    jitter_mode: bool = False
    waf_evasion: bool = True
    install_mode: bool = False


    limit_cors: int = 50
    limit_headers: int = 30
    limit_sensitive: int = 20
    limit_lfi: int = 30
    limit_redirect: int = 30
    limit_js_endpoints: int = 100
    limit_js_secrets: int = 50
    limit_arjun: int = 20
    limit_idor: int = 30
    limit_crlf: int = 30
    limit_xss_manual: int = 50
    limit_waf: int = 20
    curl_delay: float = 0.0

    limit_403bypass: int = 30
    limit_metadata: int = 20
    xss_url_deadline: int = 45

    shodan_api_key: str = ""
    adaptive_mode: bool = True
    scan_profile: str = "normal"
    endpoint_scoring: bool = True
    passive_intel: bool = True
    noise_reduction: bool = True
    burst_pause: float = 0.0

    ai_plan_mode: bool = False
    watcher_mode: bool = False
    watch_interval: int = 3600
    sqlite_db: str = ""
    delta_mode: bool = False
    validate_secrets: bool = True

    rate_feedback: bool = True
    _rate_429_count: int = 0
    _rate_backoff: float = 0.0

    _host_429: Dict[str, int] = field(default_factory=dict)
    _host_backoff: Dict[str, float] = field(default_factory=dict)
    _host_lock: threading.Lock = field(default_factory=threading.Lock)

    whitelist: List[str] = field(default_factory=list)
    dry_run: bool = False
    encrypt_output: bool = False
    encrypt_password: str = ""

    hibp_api_key: str = ""

    webhook_url: str = ""
    agent_mode: bool = False
    playwright_mode: bool = False
    wordlist_path: str = ""

    has_arjun: bool = False
    has_assetfinder: bool = False
    has_amass: bool = False
    has_findomain: bool = False
    has_wafw00f: bool = False
    has_gpg: bool = False

    has_sqlmap: bool = False
    has_subfinder: bool = False
    has_httpx: bool = False
    has_waybackurls: bool = False
    has_gau: bool = False
    has_katana: bool = False
    has_curl: bool = False
    waf_detected: bool = False

    # ── Novas ferramentas ────────────────────────────────────────────────────
    has_ffuf: bool = False
    has_feroxbuster: bool = False
    has_gospider: bool = False
    has_hakrawler: bool = False
    has_xnlinkfinder: bool = False
    _xnlinkfinder_bin: str = "xnLinkFinder"   # nome real detectado em check_deps
    has_paramspider: bool = False
    has_x8: bool = False
    _x8_bin: str = "x8"                        # caminho absoluto detectado em check_deps
    has_github_endpoints: bool = False

    # limites e configuração dos novos módulos
    limit_ffuf: int = 50          # máx de hosts para ffuf/feroxbuster
    limit_gospider: int = 20      # máx de hosts para gospider/hakrawler
    limit_js_mining: int = 100    # máx de JS a minerar com xnLinkFinder
    ffuf_wordlist: str = ""       # wordlist explícita; auto-detectada se vazio
    ffuf_threads: int = 40        # threads do ffuf (ajustado para stealth)
    ffuf_rate: int = 0            # req/s do ffuf (0 = sem limite)
    ffuf_timeout: int = 10        # timeout por request do ffuf (segundos)
    no_ffuf: bool = False         # --no-ffuf desabilita fuzzing ativo
    no_github_endpoints: bool = False  # --no-github-endpoints desabilita busca no GitHub

    tech_php: bool = False
    tech_nodejs: bool = False
    tech_java: bool = False
    tech_dotnet: bool = False
    tech_python: bool = False
    tech_ruby: bool = False
    tech_apache: bool = False
    tech_nginx: bool = False
    tech_iis: bool = False
    tech_wordpress: bool = False
    tech_graphql: bool = False
    tech_aws: bool = False

    scan_dir: str = ""
    dir_root: str = ""
    dir_disc: str = ""
    dir_urls: str = ""
    dir_params: str = ""
    dir_vulns: str = ""
    dir_scans: str = ""
    dir_shots: str = ""
    dir_js: str = ""
    dir_extra: str = ""
    dir_report: str = ""
    log_file: str = ""
    error_log: str = ""


cfg = Config()

_trap_event = threading.Event()


_shutdown_event = threading.Event()
_log_lock = threading.Lock()


class _BoundedFileLocks:


    _MAX = 2048

    def __init__(self):
        from collections import OrderedDict
        self._cache: "OrderedDict[str, threading.Lock]" = __import__('collections').OrderedDict()
        self._meta  = threading.Lock()

    def __getitem__(self, path: str) -> threading.Lock:
        with self._meta:
            if path in self._cache:
                self._cache.move_to_end(path)
                return self._cache[path]
            lock = threading.Lock()
            self._cache[path] = lock
            if len(self._cache) > self._MAX:
                self._cache.popitem(last=False)
            return lock

_file_locks = _BoundedFileLocks()
_child_pids:  Set[int] = set()
_child_pgids: Set[int] = set()


_child_lock = threading.Lock()


_db_worker_stop   = threading.Event()
_db_queue:         queue.Queue = queue.Queue(maxsize=50_000)
_db_worker_thread: Optional[threading.Thread] = None
_counters_lock     = threading.Lock()


class TokenBucket:


    def __init__(self, rate: float = 10.0, capacity: int = 20):
        self._rate     = rate
        self._capacity = capacity
        self._tokens   = float(capacity)
        self._last     = time.time()
        self._tlock    = threading.Lock()

    def set_rate(self, rate: float):
        with self._tlock:
            self._rate = max(0.1, rate)

    def acquire(self, cost: float = 1.0) -> float:

        with self._tlock:
            now = time.time()
            elapsed = now - self._last
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last = now
            if self._tokens >= cost:
                self._tokens -= cost
                return 0.0


            wait = (cost - self._tokens) / self._rate
            self._tokens -= cost
            self._last = now + wait
        if wait > 0:
            time.sleep(wait)
        return wait

_token_bucket = TokenBucket(rate=10.0, capacity=20)


_STEP_TIMEOUT = int(os.environ.get('RECON_STEP_TIMEOUT', '1800'))

def _safe_step_worker(fn, args, kwargs, step_name):
    try:
        _append_fds.clear()
    except Exception:
        pass
    try:
        fn(*args, **kwargs)
    except SystemExit as se:
        sys.exit(se.code)
    except Exception as exc:
        builtins_print(f"[_safe_step] {step_name}: {exc}", file=sys.stderr)
    finally:
        try:
            flush_append_buffer()
        except Exception:
            pass


def _safe_step(fn, *args, timeout: int = _STEP_TIMEOUT, **kwargs):
    step_name = getattr(fn, '__name__', str(fn))
    ctx  = multiprocessing.get_context('fork')
    proc = ctx.Process(
        target=_safe_step_worker,
        args=(fn, args, kwargs, step_name),
        name=f"step-{step_name}",
        daemon=False,
    )
    proc.start()
    proc.join(timeout=timeout)

    if proc.is_alive():
        log_err(f"_safe_step: '{step_name}' travou após {timeout}s — terminando processo")
        warn(f"⚠ Step '{step_name}' excedeu {timeout}s — pulando e continuando pipeline")
        proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=2)
        try:
            flush_append_buffer()
        except Exception:
            pass
        return None

    if proc.exitcode not in (0, None):
        log_err(f"_safe_step: '{step_name}' encerrou com código {proc.exitcode}")
        warn(f"⚠ Step '{step_name}' falhou — continuando pipeline")

    return None

def _db_worker_loop():


    db_path = None
    con = None
    batch_count = 0
    last_commit = time.time()
    _BATCH_SIZE = 50
    _COMMIT_INTERVAL = 2.0

    def _ensure_conn():
        nonlocal con, db_path
        path = cfg.sqlite_db or os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
        if con is not None and db_path == path:
            return
        if con:
            try: con.close()
            except Exception: pass
            con = None
        db_path = path
        new_con = None
        try:
            new_con = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
            new_con.execute("PRAGMA journal_mode=WAL")
            new_con.execute("PRAGMA busy_timeout=10000")
            new_con.execute("PRAGMA synchronous=NORMAL")
            con = new_con
            new_con = None
        except Exception as exc:
            db_path = None
            raise exc
        finally:

            if new_con is not None:
                try: new_con.close()
                except Exception: pass

    while not _db_worker_stop.is_set() or not _db_queue.empty():
        try:
            task = _db_queue.get(timeout=1.0)
            if task is None:
                _db_queue.task_done()
                break
            sql, params = task
            try:
                _ensure_conn()
                if con is None:
                    log_err("db_worker: conexão indisponível — descartando INSERT")
                    _db_queue.task_done()
                    continue
                now = time.time()
                if batch_count >= _BATCH_SIZE or (now - last_commit) >= _COMMIT_INTERVAL:

                    try:
                        con.commit()
                    except Exception as commit_exc:
                        log_err(f"db_worker COMMIT falhou: {commit_exc} — descartando batch")
                        try: con.rollback()
                        except Exception: pass
                    finally:
                        batch_count = 0
                        last_commit = time.time()
                con.execute(sql, params)
                batch_count += 1
            except Exception as exc:
                log_err(f"db_worker INSERT falhou: {exc}")
                if con is not None:
                    try: con.rollback()
                    except Exception: pass
            finally:
                _db_queue.task_done()
        except queue.Empty:
            if batch_count > 0 and con:
                try:
                    con.commit()
                    batch_count = 0
                    last_commit = time.time()
                except Exception:
                    pass
            continue


    if con:
        try:
            con.commit()
            con.close()
        except Exception:
            pass


def _start_db_worker():
    global _db_worker_thread
    _db_worker_stop.clear()
    _db_worker_thread = threading.Thread(target=_db_worker_loop, daemon=True, name="db-worker")
    _db_worker_thread.start()


def _stop_db_worker():


    global _db_worker_thread
    _db_worker_stop.set()
    time.sleep(0.2)
    _db_queue.put(None)
    if _db_worker_thread:
        _db_worker_thread.join(timeout=10)
        _db_worker_thread = None


def _load_dotenv():


    def _parse_value(raw: str) -> str:

        raw = raw.strip()


        if len(raw) >= 2 and ((raw.startswith('"') and raw.endswith('"')) or \
           (raw.startswith("'") and raw.endswith("'"))):
            return raw[1:-1]

        result = []
        in_sq = in_dq = False
        for ch in raw:
            if ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
            elif ch == '#' and not in_sq and not in_dq:
                break
            else:
                result.append(ch)


        if in_sq or in_dq:
            print(f"[.env WARN] Aspas não fechadas em valor: {raw!r} — '#' inline pode ter sido incluído incorretamente",
                  file=sys.stderr)
        return ''.join(result).strip()

    for dotenv_path in ['.env', os.path.expanduser('~/.recon.env')]:
        if os.path.exists(dotenv_path):
            try:
                with open(dotenv_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, _, v = line.partition('=')
                            os.environ.setdefault(k.strip(), _parse_value(v))
            except OSError:
                pass


def _kill_pids_gracefully(pgids: Set[int], grace_sec: float = 3.0) -> None:


    if not pgids:
        return

    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        except Exception:
            try:
                os.kill(pgid, signal.SIGTERM)
            except Exception:
                pass

    time.sleep(grace_sec)

    for pgid in pgids:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        except Exception:
            try:
                os.kill(pgid, signal.SIGKILL)
            except Exception:
                pass


def cleanup_trap(signum=None, frame=None):

    if _trap_event.is_set():
        return
    _trap_event.set()


    _shutdown_event.set()
    print(f"\n{YELLOW}[{_ts()}] ⚠ Sinal recebido — encerrando e matando processos filhos...{NC}")


    with _child_lock:
        pgids_snapshot: Set[int] = set(_child_pgids)


    _kill_pids_gracefully(pgids_snapshot, grace_sec=3.0)


    try:
        if _db_worker_thread and _db_worker_thread.is_alive():
            _stop_db_worker()
    except Exception:
        pass


    try:
        flush_append_buffer()
    except Exception:
        pass

    _close_log_file()
    _close_err_file()
    _close_jsonl_file()
    try:
        _close_all_append_fds()
    except Exception:
        pass
    try:
        http_client_stop()
    except Exception:
        pass
    if cfg.scan_dir and os.path.isdir(cfg.scan_dir):
        print(f"{YELLOW}[{_ts()}] ⚠ Outputs parciais preservados em: {cfg.scan_dir}{NC}")
    sys.exit(130)

signal.signal(signal.SIGINT, cleanup_trap)
signal.signal(signal.SIGTERM, cleanup_trap)


def _ts() -> str:
    return datetime.now().strftime('%H:%M:%S')


_log_fh: Optional[object] = None
_log_fh_lock = threading.Lock()


_err_fh: Optional[object] = None
_err_fh_lock = threading.Lock()

def _open_log_file(path: str):
    global _log_fh
    with _log_fh_lock:
        try:
            _log_fh = open(path, 'a', buffering=1)
        except OSError as e:
            print(f"[LOG-ERROR] Falha ao abrir log {path}: {e}", file=sys.stderr)

def _open_err_file(path: str):
    global _err_fh
    with _err_fh_lock:
        try:
            _err_fh = open(path, 'a', buffering=1)
        except OSError as e:
            print(f"[ERR-LOG-ERROR] Falha ao abrir error log {path}: {e}", file=sys.stderr)

def _close_log_file():
    global _log_fh
    with _log_fh_lock:
        if _log_fh:
            try: _log_fh.flush(); _log_fh.close()
            except Exception: pass
            _log_fh = None

def _close_err_file():
    global _err_fh
    with _err_fh_lock:
        if _err_fh:
            try: _err_fh.flush(); _err_fh.close()
            except Exception: pass
            _err_fh = None

def _write_log(raw: str):
    if not cfg.log_file:
        return
    with _log_fh_lock:
        if _log_fh:
            try:
                _log_fh.write(raw + '\n')
            except OSError as e:
                print(f"[LOG-ERROR] Falha ao escrever em {cfg.log_file}: {e}", file=sys.stderr)
        else:

            try:
                with open(cfg.log_file, 'a') as f:
                    f.write(raw + '\n')
            except OSError as e:
                print(f"[LOG-ERROR] Falha ao escrever em {cfg.log_file}: {e}", file=sys.stderr)


def log(msg: str):
    line = f"{CYAN}[{_ts()}]{NC} {WHITE}{msg}{NC}"
    with _log_lock:
        print(line)
        _write_log(f"[{_ts()}] {msg}")

def success(msg: str):
    line = f"{LGREEN}[{_ts()}] ✔{NC} {GREEN}{msg}{NC}"
    with _log_lock:
        print(line)
        _write_log(f"[{_ts()}] OK: {msg}")

def warn(msg: str):
    line = f"{YELLOW}[{_ts()}] ⚠{NC} {YELLOW}{msg}{NC}"
    with _log_lock:
        print(line)
        _write_log(f"[{_ts()}] WARN: {msg}")

def error(msg: str):
    line = f"{LRED}[{_ts()}] ✘{NC} {RED}{msg}{NC}"
    with _log_lock:
        print(line)
        _write_log(f"[{_ts()}] ERR: {msg}")

def info(msg: str):
    line = f"{LBLUE}[{_ts()}] ℹ{NC} {BLUE}{msg}{NC}"
    with _log_lock:
        print(line)
        _write_log(f"[{_ts()}] INFO: {msg}")

def log_err(msg: str):


    if not cfg.error_log:
        return
    with _err_fh_lock:
        if _err_fh:
            try:
                _err_fh.write(f"[{_ts()}] {msg}\n")
                return
            except OSError as e:
                print(f"[ERR-LOG-ERROR] Falha ao escrever em {cfg.error_log}: {e}",
                      file=sys.stderr)

    try:
        with open(cfg.error_log, 'a') as f:
            f.write(f"[{_ts()}] {msg}\n")
    except Exception:
        pass

def section(title: str):
    sep = f"{LMAGENTA}[{_ts()}] ══════════════════════════════════════{NC}"
    print("")
    print(sep)
    print(f"{LMAGENTA}[{_ts()}]  {title}{NC}")
    print(sep)
    _write_log(f"\n=== {title} ===")


def count_lines(path: str) -> int:
    flush_append_buffer(path)
    try:
        with open(path) as f:
            return sum(1 for l in f if l.strip())
    except Exception:
        return 0

def is_empty(path: str) -> bool:
    return count_lines(path) == 0

def safe_read(path: str) -> List[str]:
    flush_append_buffer(path)
    try:
        with open(path) as f:
            return [l.rstrip('\n') for l in f if l.strip()]
    except Exception:
        return []

def touch(path: str):
    Path(path).touch()


_append_buf: Dict[str, List[str]] = {}
_append_buf_lock = threading.Lock()
_append_buf_last_flush: float = 0.0
_APPEND_BUF_MAX = 25
_APPEND_BUF_FLUSH_INTERVAL = 1.0


_append_fds: Dict[str, object] = {}
_append_fds_lock = threading.Lock()


def _get_append_fd(path: str):
    with _append_fds_lock:
        if path not in _append_fds:
            try:
                _append_fds[path] = open(path, 'a', buffering=1)
            except OSError as e:
                print(f"[APPEND-BUF] erro ao abrir FD {path}: {e}", file=sys.stderr)
                return None
        return _append_fds[path]


def _close_all_append_fds() -> None:
    with _append_fds_lock:
        for fh in _append_fds.values():
            try:
                fh.flush()
                fh.close()
            except Exception:
                pass
        _append_fds.clear()


def _flush_append_buf_locked(path: Optional[str] = None) -> Dict[str, List[str]]:
    global _append_buf_last_flush
    targets = [path] if path and path in _append_buf else list(_append_buf.keys())
    snapshot: Dict[str, List[str]] = {}
    for p in targets:
        if _append_buf.get(p):
            snapshot[p] = list(_append_buf[p])
    _append_buf_last_flush = time.time()
    return snapshot


def _write_append_buf(snapshot: Dict[str, List[str]]) -> None:
    written: Set[str] = set()
    for p, lines in snapshot.items():
        try:
            with _file_locks[p]:
                fh = _get_append_fd(p)
                if fh is not None:
                    fh.write('\n'.join(lines) + '\n')
                    written.add(p)
        except OSError as e:
            print(f"[APPEND-BUF] erro ao gravar {p}: {e}", file=sys.stderr)
    with _append_buf_lock:
        for p in written:
            written_count = len(snapshot[p])
            current = _append_buf.get(p, [])
            if len(current) <= written_count:
                _append_buf.pop(p, None)
            else:
                _append_buf[p] = current[written_count:]


def flush_append_buffer(path: Optional[str] = None) -> None:
    with _append_buf_lock:
        snapshot = _flush_append_buf_locked(path)
    _write_append_buf(snapshot)


def append_line(path: str, line: str) -> None:


    global _append_buf_last_flush
    to_write: Optional[Dict[str, List[str]]] = None
    with _append_buf_lock:
        _append_buf.setdefault(path, []).append(line)
        now = time.time()
        path_count = len(_append_buf[path])
        time_elapsed = (now - _append_buf_last_flush) >= _APPEND_BUF_FLUSH_INTERVAL

        if path_count >= _APPEND_BUF_MAX:

            lines = _append_buf.pop(path, [])
            to_write = {path: lines} if lines else None
            _append_buf_last_flush = now
        elif time_elapsed:

            to_write = _flush_append_buf_locked()
    if to_write:
        _write_append_buf(to_write)

def read_head(path: str, n: int) -> List[str]:
    return safe_read(path)[:n]


_sort_unique_sem = threading.Semaphore(4)

def sort_unique_file(path: str):


    flush_append_buffer(path)
    with _sort_unique_sem:
        seen: Set[str] = set()
        try:
            with open(path, errors='replace') as f:
                for raw in f:
                    line = raw.rstrip('\n')
                    if line:
                        seen.add(line)
        except FileNotFoundError:
            return
        except OSError as e:
            log_err(f"sort_unique_file read {path}: {e}")
            return

        sorted_lines = sorted(seen)
        content = '\n'.join(sorted_lines) + ('\n' if sorted_lines else '')


        tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)) or '.')
        try:
            with os.fdopen(tmp_fd, 'w') as tf:
                tf.write(content)
            os.replace(tmp_path, path)
        except OSError as e:
            log_err(f"sort_unique_file write {path}: {e}")
            try: os.unlink(tmp_path)
            except Exception: pass


@contextmanager
def _db_conn():

    db_path = cfg.sqlite_db or os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
    con = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=10000")
    con.execute("PRAGMA synchronous=NORMAL")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def db_init():

    db_path = cfg.sqlite_db or os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
    cfg.sqlite_db = db_path
    with _db_conn() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS subdomains
                (domain TEXT, subdomain TEXT, first_seen TEXT, last_seen TEXT,
                 PRIMARY KEY(domain, subdomain));
            CREATE TABLE IF NOT EXISTS vulns
                (domain TEXT, type TEXT, url TEXT, payload TEXT, severity TEXT,
                 first_seen TEXT, last_seen TEXT,
                 PRIMARY KEY(domain, type, url));
            CREATE TABLE IF NOT EXISTS blocked_ips
                (ip TEXT, target TEXT, blocked_at TEXT,
                 PRIMARY KEY(ip, target));
            CREATE TABLE IF NOT EXISTS scan_history
                (domain TEXT, scan_dir TEXT, started_at TEXT, finished_at TEXT,
                 total_findings INTEGER);
        """)
    info(f"SQLite DB (WAL): {db_path}")

def db_save_subdomain(sub: str):


    if _db_worker_stop.is_set():
        return
    try:
        now = datetime.now().isoformat()
        _db_queue.put((
            "INSERT INTO subdomains(domain,subdomain,first_seen,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(domain,subdomain) DO UPDATE SET last_seen=?",
            (cfg.domain, sub, now, now, now)
        ), timeout=5)
    except queue.Full:
        log_err(f"db_save_subdomain: fila cheia (worker morto?) — descartando {sub}")
    except Exception as exc:
        log_err(f"db_save_subdomain enqueue: {exc}")

def db_get_known_subdomains() -> Set[str]:
    try:
        with _db_conn() as con:
            rows = con.execute("SELECT subdomain FROM subdomains WHERE domain=?", (cfg.domain,)).fetchall()
        return {r[0] for r in rows}
    except Exception:
        return set()

def db_get_new_subdomains(current: List[str]) -> List[str]:

    known = db_get_known_subdomains()
    return [s for s in current if s not in known]


_blocked_payloads: Dict[str, int] = {}
_blocked_lock = threading.Lock()

def record_blocked(attack_type: str, payload: str) -> None:

    key = f"{attack_type}:{payload[:80]}"
    with _blocked_lock:
        _blocked_payloads[key] = _blocked_payloads.get(key, 0) + 1

def get_blocked_payloads() -> Dict[str, int]:
    with _blocked_lock:
        return dict(_blocked_payloads)
def feedback_hook(attack_type: str, payload: str, status: int, url: str = ""):

    if status == 403:
        record_blocked(attack_type, payload)

    if status == 429 and cfg.rate_feedback:
        with _counters_lock:
            cfg._rate_429_count += 1
            cfg._rate_backoff = min(cfg._rate_backoff + 1.0, 10.0)
            count_snap = cfg._rate_429_count
        if count_snap % 5 == 0:
            warn(f"Rate limit (429) detectado {count_snap}x — backoff global={cfg._rate_backoff:.1f}s")
    elif status in (200, 201, 301, 302) and cfg._rate_backoff > 0:
        with _counters_lock:
            cfg._rate_backoff = max(cfg._rate_backoff - 0.1, 0.0)


    if url:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc
            if host:
                with cfg._host_lock:
                    if status == 429:
                        cfg._host_429[host] = cfg._host_429.get(host, 0) + 1
                        cfg._host_backoff[host] = min(
                            cfg._host_backoff.get(host, 0.0) + 1.5, 15.0
                        )
                        if cfg._host_429[host] % 3 == 0:
                            warn(f"Rate limit por host ({host}): "
                                 f"{cfg._host_429[host]}x → backoff={cfg._host_backoff[host]:.1f}s")
                    elif status in (200, 201, 301, 302):
                        if cfg._host_backoff.get(host, 0) > 0:
                            cfg._host_backoff[host] = max(
                                cfg._host_backoff[host] - 0.2, 0.0
                            )
        except Exception:
            pass


def host_throttle(url: str):


    if _shutdown_event.is_set():
        return
    try:
        host = urllib.parse.urlparse(url).netloc
        if host:
            _host_health.wait_if_paused(url)
            if _shutdown_event.is_set():
                return
            with cfg._host_lock:
                backoff = cfg._host_backoff.get(host, 0.0)
            if backoff > 0:

                deadline = time.time() + min(backoff, 15.0)
                while time.time() < deadline:
                    if _shutdown_event.is_set():
                        return
                    time.sleep(min(0.25, deadline - time.time()))
    except Exception:
        pass


_UA_ROTATE = os.environ.get("RECON_UA_ROTATE", "1") != "0"

_UA_POOL: List[str] = [
    # Chrome 135 / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    # Chrome 135 / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    # Chrome 135 / Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    # Firefox 137 / Windows + macOS + Linux
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
    # Safari 17.x / macOS + iOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Edge 135
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.3124.72",
    # Chrome Mobile / Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
    # Googlebot / bingbot (úteis para bypass de alguns WAFs)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    # Ferramentas (para mimetizar tráfego legítimo de CI/CD)
    "curl/8.7.1",
    "python-requests/2.32.3",
    "Go-http-client/2.0",
]

def random_ua() -> str:

    if not _UA_ROTATE:
        return _UA_POOL[0]
    return random.choice(_UA_POOL)

def jitter():


    if _shutdown_event.is_set():
        return
    total_cost = 0.0
    if cfg.jitter_mode or cfg.waf_detected:
        if random.random() < 0.70:
            raw_ms = max(100, int(random.gauss(800, 300)))
        else:
            raw_ms = max(800, int(random.gauss(4000, 1500)))
        raw_ms = min(raw_ms, 15000)
        jitter_cost = raw_ms / 1000.0 * 10.0
        total_cost += max(0.1, jitter_cost)
    with _counters_lock:
        backoff_snap = cfg._rate_backoff
    if backoff_snap > 0:
        _token_bucket.set_rate(max(0.5, 10.0 - backoff_snap))
        total_cost += 1.0
    if total_cost > 0:
        _token_bucket.acquire(cost=total_cost)


def burst_sleep():
    if cfg.burst_pause > 0:
        time.sleep(cfg.burst_pause)

def curl_throttle():
    if cfg.curl_delay > 0:
        time.sleep(cfg.curl_delay)

class _SubprocessResult:


    __slots__ = ('returncode', 'stdout', 'stderr')

    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout     = stdout
        self.stderr     = stderr

    def __iter__(self):
        return iter((self.returncode, self.stdout, self.stderr))


def _tracked_run(cmd: List[str], **kwargs):


    _popen_blacklist = {'capture_output', 'check', 'input', 'timeout', 'stdout', 'stderr'}


    _has_input = kwargs.get('input') is not None
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if _has_input else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        **{k: v for k, v in kwargs.items() if k not in _popen_blacklist}
    )
    with _child_lock:
        _child_pids.add(proc.pid)
        _child_pgids.add(proc.pid)
    try:
        timeout = kwargs.get('timeout')


        raw_input = kwargs.get('input')
        if raw_input is None:
            stdin_data = None
        elif isinstance(raw_input, str):
            stdin_data = raw_input.encode(errors='replace')
        else:
            stdin_data = raw_input
        out, err = proc.communicate(input=stdin_data, timeout=timeout)
        ret = proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()


        _reap_needed = False
        try:
            proc.communicate(timeout=2)
        except (subprocess.TimeoutExpired, Exception):
            try:
                proc.wait(timeout=2)
            except Exception:
                _reap_needed = True
        if _reap_needed:
            _pid_to_reap = proc.pid
            def _bg_reap():
                try:
                    proc.wait(timeout=30)
                except Exception:
                    try:
                        os.kill(_pid_to_reap, signal.SIGKILL)
                        proc.wait(timeout=5)
                    except Exception:
                        pass
            threading.Thread(
                target=_bg_reap, daemon=True, name=f"reaper-{proc.pid}"
            ).start()
        raise
    finally:
        with _child_lock:
            _child_pids.discard(proc.pid)
            _child_pgids.discard(proc.pid)

    return _SubprocessResult(
        returncode=ret,
        stdout=out.decode(errors='replace') if isinstance(out, bytes) else (out or ''),
        stderr=err.decode(errors='replace') if isinstance(err, bytes) else (err or ''),
    )

def _build_curl_cmd(url: str, head_only=False, extra_headers=None,
                    method='GET', data=None, follow=False) -> List[str]:

    cmd = ['curl', '-sk', '--max-time', str(cfg.timeout),
           '--connect-timeout', '5', '-A', random_ua()]
    if head_only:
        cmd.append('-I')
    if follow:
        cmd.append('-L')
    if method.upper() == 'POST':
        cmd.extend(['-X', 'POST'])
    if data:
        cmd.extend(['-d', data])
    for k, v in (extra_headers or {}).items():
        cmd.extend(['-H', f'{k}: {v}'])
    cmd.extend(['-w', '\n__S__%{http_code}__', url])
    return cmd

def retry_curl(url: str, head_only=False, extra_headers=None,
               method='GET', data=None, follow=False) -> Tuple[int, str]:
    if not cfg.has_curl:
        log_err("retry_curl: curl não encontrado no PATH — retornando falha")
        return -1, ""

    if cfg.dry_run:
        return 200, f"[DRY-RUN] {url}"
    wait = cfg.retry_delay
    for attempt in range(cfg.max_retries):


        host_throttle(url)
        cmd = _build_curl_cmd(url, head_only=head_only, extra_headers=extra_headers,
                               method=method, data=data, follow=follow)
        try:

            r = _tracked_run(cmd, timeout=cfg.timeout + 5)
            out = r.stdout
            if '__S__' in out:
                body, _, rest = out.rpartition('\n__S__')
                status_str = rest.replace('__', '').strip()
                if status_str.isdigit():
                    code = int(status_str)
                    feedback_hook('http', '', code, url=url)
                    return code, body
        except subprocess.TimeoutExpired:
            log_err(f"retry_curl timeout attempt {attempt+1} — {url}")
        except subprocess.SubprocessError as e:
            log_err(f"retry_curl subprocess error attempt {attempt+1} — {url}: {e}")
        except OSError as e:
            log_err(f"retry_curl OS error attempt {attempt+1} — {url}: {e}")
        except ValueError as e:
            log_err(f"retry_curl value error attempt {attempt+1} — {url}: {e}")
        if attempt < cfg.max_retries - 1:
            time.sleep(wait)
            wait *= 2
            jitter()
    log_err(f"retry_curl FINAL FAILURE after {cfg.max_retries} tries for {url}")

    return -1, ""

def cfetch(url: str) -> Tuple[int, str]:


    return http_fetch(url)

def cfetch_headers(url: str) -> Tuple[int, str]:

    return http_fetch(url, head_only=True)


_URL_SIG_CACHE: Dict[str, str] = {}
_URL_SIG_LOCK  = threading.Lock()
_URL_SIG_MAX   = 20_000


def url_signature(url: str) -> str:
    with _URL_SIG_LOCK:
        cached = _URL_SIG_CACHE.get(url)
        if cached is not None:
            return cached

    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname or p.netloc
        param_names = sorted(urllib.parse.parse_qs(p.query, keep_blank_values=True).keys())
        sig = f"{p.scheme}://{host}{p.path}?{'&'.join(name + '=X' for name in param_names)}"
    except Exception:
        sig = url

    with _URL_SIG_LOCK:
        if url in _URL_SIG_CACHE:
            return _URL_SIG_CACHE[url]
        if len(_URL_SIG_CACHE) >= _URL_SIG_MAX:
            evict_count = max(1, _URL_SIG_MAX // 10)
            for k in list(_URL_SIG_CACHE.keys())[:evict_count]:
                del _URL_SIG_CACHE[k]
        _URL_SIG_CACHE[url] = sig
    return sig


def deduplicate_by_signature(urls: List[str]) -> List[str]:


    seen: Dict[str, str] = {}
    for url in urls:
        sig = url_signature(url)
        if sig not in seen:
            seen[sig] = url
    result = list(seen.values())
    if len(result) < len(urls):
        info(f"Deduplicação: {len(urls)} → {len(result)} URLs únicas por assinatura "
             f"(−{len(urls) - len(result)} redundantes)")
    return result


def step_filter_active_assets():


    section("00b / FILTRO DE ATIVOS VIVOS (200 OK)")
    alive_file = f"{cfg.dir_disc}/alive.txt"
    hosts = safe_read(alive_file)
    if not hosts:
        warn("[filter_active_assets] alive.txt vazio — pulando"); return

    out_file = f"{cfg.dir_disc}/live_targets_200.txt"
    Path(out_file).touch()

    log(f"Verificando status real de {len(hosts)} host(s) (seguindo redirects)...")

    confirmed_200: List[str] = []
    _lock = threading.Lock()

    def _probe(url: str):
        if _shutdown_event.is_set():
            return
        target = url if url.startswith("http") else f"https://{url}"
        try:
            r = _tracked_run(
                ["curl", "-sk", "--max-time", str(cfg.timeout),
                 "-L", "--max-redirs", "2",
                 "-o", "/dev/null", "-w", "%{http_code}", target],
                timeout=cfg.timeout + 5,
            )
            final_status = r.stdout.strip()
            if final_status == "200":
                with _lock:
                    confirmed_200.append(target)
                    append_line(out_file, target)
        except Exception as exc:
            log_err(f"filter_active_assets probe error {target}: {exc}")

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=30)
    try:
        futs = {ex.submit(_probe, h): h for h in hosts}
        done, not_done = concurrent.futures.wait(futs, timeout=600)
        if not_done:

            _, still_running = concurrent.futures.wait(not_done, timeout=10)
            for f in still_running:
                f.cancel()
                log_err(f"filter_active_assets: worker não terminou: {futs[f]}")

        ex.shutdown(wait=True)
        for f in done:
            try: f.result()
            except Exception as e: log_err(f"filter_active_assets result error: {e}")
    except Exception:
        ex.shutdown(wait=False, cancel_futures=True)


    with _lock:
        snapshot = list(confirmed_200)

    total = len(snapshot)
    if total:
        success(f"Ativos com 200 OK real: {total}/{len(hosts)} → {out_file}")
    else:
        warn("Nenhum host confirmado como 200 OK — verifique conectividade")

    if total > 0:
        with open(alive_file, "w") as f:
            f.write("\n".join(snapshot) + "\n")
        info(f"alive.txt atualizado com {total} alvos 200 OK (era {len(hosts)})")


def banner():
    os.system('clear')
    print(f"{LCYAN}")
    print("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗")
    print("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║")
    print("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║")
    print("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║")
    print("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║")
    print("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝")
    print(f"{NC}")
    print(f"  {DIM}Full Automated Reconnaissance Framework{NC}")
    print(f"  {LRED}⚠  USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA ⚠{NC}")
    print(f"  {DIM}─────────────────────────────────────────────────────────{NC}")
    print()

def setup_dirs():
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    safe_domain = re.sub(r'[^a-zA-Z0-9._-]', '_', cfg.domain)
    cfg.scan_dir    = f"{safe_domain}_{ts}"
    cfg.dir_root    = cfg.scan_dir
    cfg.dir_disc    = f"{cfg.scan_dir}/01_discovery"
    cfg.dir_urls    = f"{cfg.scan_dir}/02_urls"
    cfg.dir_params  = f"{cfg.scan_dir}/03_params"
    cfg.dir_extra   = f"{cfg.scan_dir}/04_extra"
    cfg.dir_js      = f"{cfg.scan_dir}/05_js"
    cfg.dir_report  = f"{cfg.scan_dir}/06_report"
    cfg.dir_vulns   = f"{cfg.scan_dir}/07_vulns"
    cfg.dir_scans   = f"{cfg.scan_dir}/08_scans"
    cfg.dir_shots   = f"{cfg.scan_dir}/09_screenshots"
    cfg.log_file    = f"{cfg.dir_root}/recon.log"
    cfg.error_log   = f"{cfg.dir_root}/errors.log"

    # Pastas sempre necessárias
    always = [cfg.dir_disc, cfg.dir_urls, cfg.dir_params,
               cfg.dir_extra, cfg.dir_js, cfg.dir_report,
               cfg.dir_vulns, cfg.dir_scans]
    for d in always:
        Path(d).mkdir(parents=True, exist_ok=True)

    # dir_shots: criada só se screenshots estiver habilitado
    if not cfg.skip_screenshots:
        Path(cfg.dir_shots).mkdir(parents=True, exist_ok=True)
    for f in [cfg.log_file, cfg.error_log]:


        try:
            Path(f).touch()
        except FileNotFoundError:
            Path(f).parent.mkdir(parents=True, exist_ok=True)
            Path(f).touch()
        except OSError as _te:
            print(f"[SETUP] Aviso: não foi possível criar {f}: {_te}", file=sys.stderr)
    _open_log_file(cfg.log_file)
    _open_err_file(cfg.error_log)
    _open_jsonl_file(f"{cfg.dir_root}/findings.jsonl")
    http_client_start()


def auto_install():
    ilog = f"recon_install_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    print(f"{LCYAN}")
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║       RECON — AUTO-INSTALL DE FERRAMENTAS                    ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print(f"{NC}")

    with open(ilog, 'w') as f:
        f.write(f"# RECON Auto-Install — {datetime.now()}\n")

    def _ilog(m):
        with open(ilog, 'a') as _f:
            _f.write(m + '\n')

    def iok(m):  print(f"  {LGREEN}✔{NC} {m}"); _ilog(f"[OK ] {m}")
    def ierr(m): print(f"  {LRED}✘{NC} {m}");   _ilog(f"[ERR] {m}")
    def iinf(m): print(f"  {LBLUE}ℹ{NC} {m}");   _ilog(f"[INF] {m}")
    def irun(m): print(f"  {YELLOW}▶{NC} {m}");   _ilog(f"[RUN] {m}")

    def run(cmd, timeout=300, env=None):
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, env=(env or os.environ),
            )
            with open(ilog, 'a') as _f:
                _f.write((r.stdout or '')[-300:] + (r.stderr or '')[-200:])
            return r.returncode == 0
        except Exception as e:
            with open(ilog, 'a') as _f:
                _f.write(f"ERROR: {e}\n")
            return False

    # ── Setup de PATH para esta sessão ─────────────────────────────────────
    # Inclui todos os dirs de binários desde o início para que shutil.which()
    # os encontre IMEDIATAMENTE após qualquer instalação.
    _home       = os.path.expanduser('~')
    _local_bin  = os.path.join(_home, '.local', 'bin')
    _cargo_bin  = os.path.join(_home, '.cargo', 'bin')
    _gopath_bin = os.path.join(os.environ.get('GOPATH', os.path.join(_home, 'go')), 'bin')
    _go_sys_bin = '/usr/local/go/bin'
    for _d in [_local_bin, _cargo_bin, _gopath_bin, _go_sys_bin]:
        if _d not in os.environ.get('PATH', '').split(':'):
            os.environ['PATH'] = os.environ['PATH'] + f':{_d}'
    Path(_local_bin).mkdir(parents=True, exist_ok=True)
    Path(_gopath_bin).mkdir(parents=True, exist_ok=True)

    # ── Detectar gerenciador de pacotes ────────────────────────────────────
    pkg = None
    for mgr, chk in [('apt','apt-get'),('yum','yum'),('pacman','pacman'),('brew','brew')]:
        if shutil.which(chk):
            pkg = mgr; break
    iinf(f"Gerenciador de pacotes: {pkg or 'desconhecido'}")
    iinf(f"PATH → ...{os.environ['PATH'][-100:]}")

    # ── Dependências base ──────────────────────────────────────────────────
    irun("Instalando dependências base...")
    if pkg == 'apt':
        run(['sudo','apt-get','update','-qq'])
        if run(['sudo','apt-get','install','-y','-qq',
                'curl','git','make','gcc','wget','unzip',
                'python3','python3-pip','pipx','cargo','rustc','jq']):
            iok("Deps base (apt)")
        if run(['sudo','apt-get','install','-y','-qq','sqlmap']):  iok("sqlmap (apt)")
        # amass ainda disponível no apt de algumas distros — tenta, mas go install é fallback
        if run(['sudo','apt-get','install','-y','-qq','amass']):   iok("amass (apt)")
        if run(['sudo','apt-get','install','-y','-qq','wafw00f']): iok("wafw00f (apt)")
    elif pkg == 'brew':
        # wafw00f NÃO está no Homebrew oficial → vai via pipx abaixo
        # amass pode estar disponível via brew
        run(['brew', 'install', 'curl', 'git', 'wget', 'unzip', 'python3', 'pipx', 'rust'])
        if run(['brew','install','sqlmap']): iok("sqlmap (brew)")
        if run(['brew','install','amass']):  iok("amass (brew)")
    elif pkg == 'yum':
        run(['sudo','yum','install','-y','curl','git','wget','unzip',
             'python3','python3-pip','cargo','rustc'])
        run([sys.executable,'-m','pip','install','pipx','-q'])
        # amass não está no yum → go install abaixo
    elif pkg == 'pacman':
        # amass foi REMOVIDO do AUR oficial → vai via go install
        run(['sudo','pacman','-S','--noconfirm',
             'curl','git','wget','unzip','python','python-pip','python-pipx',
             'rust','cargo'])
        if run(['sudo','pacman','-S','--noconfirm','sqlmap']): iok("sqlmap (pacman)")
        if run(['sudo','pacman','-S','--noconfirm','feroxbuster']): iok("feroxbuster (pacman)")
        # wafw00f não está nos repos oficiais do Arch → pipx abaixo
    else:
        iinf("Gerenciador desconhecido — instale curl,git,wget,python3,pipx e rust manualmente")

    # ── Go: versão estável atual ───────────────────────────────────────────
    print(); irun("Verificando Go...")
    gopath = os.environ.get('GOPATH', os.path.join(_home, 'go'))
    gobin  = os.path.join(gopath, 'bin')
    if not shutil.which('go'):
        go_ver = "1.23.4"   # fallback seguro (versão LTS atual)
        try:
            raw = urllib.request.urlopen(
                "https://go.dev/VERSION?m=text", timeout=10
            ).read().decode().strip().splitlines()[0]           # ex: "go1.23.4"
            go_ver = raw.lstrip("go")
            iinf(f"Versão estável detectada: go{go_ver}")
        except Exception:
            iinf(f"go.dev indisponível — usando fallback go{go_ver}")

        go_os   = "darwin" if platform.system() == "Darwin" else "linux"
        go_arch = "arm64"  if platform.machine() in ('arm64','aarch64') else "amd64"
        go_tar  = f"go{go_ver}.{go_os}-{go_arch}.tar.gz"
        # dl.google.com é o CDN mais confiável para o binário oficial
        go_url  = f"https://dl.google.com/go/{go_tar}"
        irun(f"Baixando Go {go_ver} ({go_arch})...")
        iinf(f"URL: {go_url}")
        if run(['wget','-q', go_url, '-O', f'/tmp/{go_tar}'], timeout=600):
            run(['sudo','rm','-rf','/usr/local/go'])
            if run(['sudo','tar','-C','/usr/local','-xzf',f'/tmp/{go_tar}']):
                if _go_sys_bin not in os.environ['PATH']:
                    os.environ['PATH'] = os.environ['PATH'] + f':{_go_sys_bin}'
                iok(f"Go {go_ver} instalado em /usr/local/go")
            else:
                ierr("Falha ao extrair Go")
        else:
            ierr(f"Download Go falhou — instale manualmente: https://go.dev/dl/")
    else:
        v = subprocess.run(['go','version'], capture_output=True,
                           text=True, timeout=10).stdout.strip()
        iok(f"Go já instalado → {v}")

    os.environ.update({'GOPATH': gopath, 'GOBIN': gobin})
    if gobin not in os.environ['PATH']:
        os.environ['PATH'] = os.environ['PATH'] + f':{gobin}'
    Path(gobin).mkdir(parents=True, exist_ok=True)

    def install_go(name, pkg_path, check_name=None):
        """Instala via `go install`. check_name: nome do binário se diferente do pacote."""
        bin_name = check_name or name
        if shutil.which(bin_name):
            iok(f"{name} já instalado → {shutil.which(bin_name)}"); return
        irun(f"go install {pkg_path}...")
        env_go = dict(os.environ, GOPATH=gopath, GOBIN=gobin)
        if run(['go','install', pkg_path], timeout=360, env=env_go):
            found = shutil.which(bin_name) or os.path.join(gobin, bin_name)
            iok(f"{name} OK → {found}")
        else:
            ierr(f"{name}: go install FALHOU — {pkg_path}")

    # ── Ferramentas Go ─────────────────────────────────────────────────────
    print(); iinf("══════ Ferramentas Go ══════")
    install_go("subfinder",   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    install_go("httpx",       "github.com/projectdiscovery/httpx/cmd/httpx@latest")
    install_go("waybackurls", "github.com/tomnomnom/waybackurls@latest")
    install_go("gau",         "github.com/lc/gau/v2/cmd/gau@latest")
    install_go("katana",      "github.com/projectdiscovery/katana/cmd/katana@latest")
    install_go("qsreplace",   "github.com/tomnomnom/qsreplace@latest")
    install_go("assetfinder", "github.com/tomnomnom/assetfinder@latest")
    install_go("dnsx",        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
    install_go("ffuf",        "github.com/ffuf/ffuf/v2@latest")
    install_go("gospider",    "github.com/jaeles-project/gospider@latest")
    install_go("hakrawler",   "github.com/hakluke/hakrawler@latest")
    install_go("github-endpoints", "github.com/gwen001/github-endpoints@latest")

    # amass v3 — v4 tem build quebrado com Go>=1.22 no @latest
    # pacman/AUR removeu amass; yum nunca teve — go install é o único caminho confiável
    if not shutil.which('amass'):
        install_go("amass", "github.com/owasp-amass/amass/v3/...@master")

    # ── findomain: binário Rust pré-compilado ──────────────────────────────
    print(); iinf("══════ findomain ══════")
    if not shutil.which("findomain"):
        _fd_sys  = platform.system()
        _fd_arch = platform.machine()
        # Assets reais em github.com/findomain/findomain/releases
        if _fd_sys == "Darwin":
            _fd_asset = "findomain-osx-arm" if _fd_arch in ('arm64','aarch64') else "findomain-osx"
        elif _fd_arch in ('aarch64','arm64'):
            _fd_asset = "findomain-aarch64"
        else:
            _fd_asset = "findomain-linux"
        _fd_url  = ("https://github.com/findomain/findomain/releases/latest/download/"
                    + _fd_asset)
        _fd_dest = os.path.join(gobin, "findomain")
        irun(f"Baixando findomain ({_fd_asset})...")
        iinf(f"URL: {_fd_url}")
        try:
            urllib.request.urlretrieve(_fd_url, _fd_dest)
            os.chmod(_fd_dest, 0o755)
            iok(f"findomain instalado → {_fd_dest}")
        except Exception as _fe:
            ierr(f"findomain: {_fe}")
            ierr("  → https://github.com/findomain/findomain/releases")
    else:
        iok(f"findomain já instalado → {shutil.which('findomain')}")

    # ── feroxbuster: scanner de diretórios Rust ────────────────────────────
    print(); iinf("══════ feroxbuster ══════")
    if not shutil.which('feroxbuster'):
        _fb_sys  = platform.system()
        _fb_arch = platform.machine()
        # Assets em github.com/epi052/feroxbuster/releases
        if _fb_sys == "Darwin":
            _fb_asset = ("feroxbuster-mac-arm64.zip"
                         if _fb_arch in ('arm64','aarch64')
                         else "feroxbuster-mac-amd64.zip")
        elif _fb_arch in ('aarch64','arm64'):
            _fb_asset = "feroxbuster-linux-aarch64.zip"
        else:
            _fb_asset = "feroxbuster-linux-amd64.zip"
        _fb_url = ("https://github.com/epi052/feroxbuster/releases/latest/download/"
                   + _fb_asset)
        _fb_zip  = f"/tmp/{_fb_asset}"
        _fb_dest = os.path.join(gobin, "feroxbuster")
        irun(f"Baixando feroxbuster ({_fb_asset})...")
        iinf(f"URL: {_fb_url}")
        ok_dl = run(['wget','-q', _fb_url, '-O', _fb_zip], timeout=180)
        if ok_dl and run(['unzip','-o','-j', _fb_zip, 'feroxbuster','-d', gobin]):
            if os.path.exists(_fb_dest):
                os.chmod(_fb_dest, 0o755)
                iok(f"feroxbuster instalado → {_fb_dest}")
            else:
                ierr("feroxbuster: binário não encontrado após unzip")
        elif shutil.which('cargo'):
            irun("Download falhou — tentando cargo install feroxbuster...")
            if run(['cargo','install','feroxbuster','--locked'], timeout=600):
                if _cargo_bin not in os.environ['PATH']:
                    os.environ['PATH'] += f':{_cargo_bin}'
                iok(f"feroxbuster (cargo) → {shutil.which('feroxbuster') or _cargo_bin+'/feroxbuster'}")
            else:
                ierr("feroxbuster: cargo também falhou")
        else:
            ierr("feroxbuster: sem wget nem cargo — veja https://github.com/epi052/feroxbuster/releases")
    else:
        iok(f"feroxbuster já instalado → {shutil.which('feroxbuster')}")

    # ── pipx: garantir disponibilidade ────────────────────────────────────
    print(); iinf("══════ Ferramentas Python (pipx) ══════")
    if not shutil.which('pipx'):
        irun("pipx não encontrado — instalando via pip (--user)...")
        run([sys.executable,'-m','pip','install','--user','pipx','-q'])
        if _local_bin not in os.environ['PATH']:
            os.environ['PATH'] = os.environ['PATH'] + f':{_local_bin}'
    try:
        subprocess.run([sys.executable,'-m','pipx','ensurepath','--force'],
                       capture_output=True, timeout=15)
    except Exception:
        pass

    def install_pipx(name, pkg_name=None, bin_aliases=None):
        """
        Instala via pipx.
        bin_aliases: lista de nomes alternativos gerados pelo pipx
        (ex: xnLinkFinder → xnlinkfinder em sistemas case-sensitive).
        """
        pkg_name  = pkg_name or name
        all_names = [name] + (bin_aliases or [])
        found     = next((n for n in all_names if shutil.which(n)), None)
        if found:
            iok(f"{name} já instalado → {shutil.which(found)}"); return
        irun(f"pipx install {pkg_name}...")
        if run(['pipx','install', pkg_name, '-q']):
            found2 = next((n for n in all_names if shutil.which(n)), None)
            if found2:
                iok(f"{name} OK → {shutil.which(found2)}")
            else:
                iok(f"{name} OK (binário em {_local_bin})")
        else:
            ierr(f"{name}: pipx install FALHOU")

    install_pipx("uro")
    install_pipx("arjun")
    # wafw00f: sem fórmula Homebrew oficial → pipx funciona em todos os SOs
    install_pipx("wafw00f")
    if not shutil.which('sqlmap'):
        install_pipx("sqlmap")

    # ── Ferramentas Python extras ──────────────────────────────────────────
    print(); iinf("══════ Ferramentas extras (pipx) ══════")
    # xnLinkFinder: PyPI name=xnLinkFinder mas pipx pode gerar 'xnlinkfinder' (lowercase)
    install_pipx("xnLinkFinder", "xnLinkFinder", bin_aliases=["xnlinkfinder"])
    install_pipx("paramspider", "paramspider")

    # ── x8: param finder Rust ─────────────────────────────────────────────
    print(); iinf("══════ x8 (Rust — param finder) ══════")
    _x8_paths = [
        shutil.which('x8'),
        os.path.join(_cargo_bin, 'x8'),
        os.path.join(gobin, 'x8'),
    ]
    _x8_found = next((p for p in _x8_paths if p and os.path.isfile(p)), None)
    if _x8_found:
        iok(f"x8 já instalado → {_x8_found}")
        if _cargo_bin not in os.environ['PATH']:
            os.environ['PATH'] += f':{_cargo_bin}'
    else:
        _x8_sys  = platform.system()
        _x8_arch = platform.machine()
        # Binários em github.com/sh1yo/x8/releases (arquivos sem extensão, bare binary)
        if _x8_sys == "Darwin":
            _x8_asset = ("x8-aarch64-apple-darwin"
                         if _x8_arch in ('arm64','aarch64')
                         else "x8-x86_64-apple-darwin")
        elif _x8_arch in ('aarch64','arm64'):
            _x8_asset = "x8-aarch64-unknown-linux-musl"
        else:
            _x8_asset = "x8-x86_64-unknown-linux-musl"
        _x8_url  = ("https://github.com/sh1yo/x8/releases/latest/download/" + _x8_asset)
        _x8_dest = os.path.join(gobin, "x8")
        irun(f"Baixando x8 ({_x8_asset})...")
        iinf(f"URL: {_x8_url}")
        try:
            urllib.request.urlretrieve(_x8_url, _x8_dest)
            os.chmod(_x8_dest, 0o755)
            iok(f"x8 instalado (GitHub binário) → {_x8_dest}")
        except Exception as _x8e:
            ierr(f"x8: download falhou ({_x8e})")
            if shutil.which('cargo'):
                irun("Tentando cargo install x8 --locked (pode demorar ~5min)...")
                if run(['cargo','install','x8','--locked'], timeout=600):
                    if _cargo_bin not in os.environ['PATH']:
                        os.environ['PATH'] += f':{_cargo_bin}'
                    _x8b = shutil.which('x8') or os.path.join(_cargo_bin,'x8')
                    if os.path.isfile(_x8b):
                        iok(f"x8 instalado via cargo → {_x8b}")
                    else:
                        ierr(f"x8: cargo concluiu mas binário não encontrado — verifique {_cargo_bin}/x8")
                else:
                    ierr("x8: cargo install também falhou")
                    ierr("  → https://github.com/sh1yo/x8/releases")
            else:
                ierr("x8: cargo não disponível")
                ierr("  → instale rustup: https://rustup.rs  ou baixe em: https://github.com/sh1yo/x8/releases")

    # ── WordLists (SecLists) ───────────────────────────────────────────────
    print(); iinf("══════ WordLists (SecLists) ══════")
    _sl_system = '/usr/share/seclists'
    _sl_user   = os.path.join(_home, 'SecLists')
    if os.path.isdir(_sl_system) or os.path.isdir(_sl_user):
        _sl_where = _sl_system if os.path.isdir(_sl_system) else _sl_user
        iok(f"SecLists já presente → {_sl_where}")
    else:
        if pkg == 'apt':
            if run(['sudo','apt-get','install','-y','-qq','seclists']):
                iok("SecLists (apt)")
            else:
                irun(f"Clonando SecLists em /usr/share/seclists (sudo)...")
                if not run(['sudo','git','clone','-q','--depth','1',
                            'https://github.com/danielmiessler/SecLists',
                            _sl_system], timeout=600):
                    irun(f"Falha com sudo — clonando em {_sl_user} (sem root)...")
                    run(['git','clone','-q','--depth','1',
                         'https://github.com/danielmiessler/SecLists',
                         _sl_user], timeout=600)
        else:
            irun(f"Clonando SecLists em {_sl_user}...")
            run(['git','clone','-q','--depth','1',
                 'https://github.com/danielmiessler/SecLists',
                 _sl_user], timeout=600)
        if os.path.isdir(_sl_system) or os.path.isdir(_sl_user):
            iok("SecLists clonado com sucesso")
        else:
            ierr("SecLists: clone falhou — defina --ffuf-wordlist manualmente")

    # ── Sumário final ──────────────────────────────────────────────────────
    print()
    def _resolve_bin(name, *extra_paths):
        """Verifica PATH + caminhos extras para encontrar binário."""
        return (shutil.which(name)
                or next((p for p in extra_paths if p and os.path.isfile(p)), None))

    all_tools = [
        ('subfinder',        _resolve_bin('subfinder')),
        ('httpx',            _resolve_bin('httpx')),
        ('waybackurls',      _resolve_bin('waybackurls')),
        ('gau',              _resolve_bin('gau')),
        ('katana',           _resolve_bin('katana')),
        ('qsreplace',        _resolve_bin('qsreplace')),
        ('assetfinder',      _resolve_bin('assetfinder')),
        ('dnsx',             _resolve_bin('dnsx')),
        ('findomain',        _resolve_bin('findomain')),
        ('amass',            _resolve_bin('amass')),
        ('sqlmap',           _resolve_bin('sqlmap')),
        ('wafw00f',          _resolve_bin('wafw00f')),
        ('uro',              _resolve_bin('uro')),
        ('arjun',            _resolve_bin('arjun')),
        ('ffuf',             _resolve_bin('ffuf')),
        ('feroxbuster',      _resolve_bin('feroxbuster', os.path.join(gobin,'feroxbuster'))),
        ('gospider',         _resolve_bin('gospider')),
        ('hakrawler',        _resolve_bin('hakrawler')),
        ('github-endpoints', _resolve_bin('github-endpoints')),
        ('xnLinkFinder',     _resolve_bin('xnLinkFinder') or _resolve_bin('xnlinkfinder')),
        ('paramspider',      _resolve_bin('paramspider')),
        ('x8',               _resolve_bin('x8', os.path.join(_cargo_bin,'x8'),
                                          os.path.join(gobin,'x8'))),
    ]
    ok_n = sum(1 for _, p in all_tools if p)
    for name, path in all_tools:
        sym = f"{LGREEN}✔{NC}" if path else f"{LRED}✘{NC}"
        print(f"  {sym} {name:<22} → {path or 'não encontrado'}")
    print(f"\n  {BOLD}Instalados:{NC} {LGREEN}{ok_n}{NC}/{len(all_tools)}")
    print(f"  {BOLD}Log:{NC} {CYAN}{ilog}{NC}")

    # ── Health check pós-install ───────────────────────────────────────────
    print(f"\n  {BOLD}{LBLUE}══ Health Check pós-install ══{NC}")

    def _hc_resolve(name):
        """Resolve binário verificando PATH e diretórios extras (cargo, gobin)."""
        return (shutil.which(name)
                or (os.path.join(_cargo_bin, name)
                    if os.path.isfile(os.path.join(_cargo_bin, name)) else None)
                or (os.path.join(gobin, name)
                    if os.path.isfile(os.path.join(gobin, name)) else None))

    # (ferramenta, flags, accept_codes, é_opcional?)
    health_cmds = [
        ('subfinder',   ['-version'],   (0,1,2), False),
        ('httpx',       ['-version'],   (0,1,2), False),
        ('katana',      ['-version'],   (0,1,2), False),
        ('waybackurls', ['-h'],         (0,1,2), False),
        ('gau',         ['--version'],  (0,1,2), False),
        ('ffuf',        ['-V'],         (0,1,2), False),
        ('feroxbuster', ['--version'],  (0,1,2), True),
        ('gospider',    ['--version'],  (0,1,2), True),
        ('hakrawler',   ['-h'],         (0,1,2), True),
        ('sqlmap',      ['--version'],  (0,1,2), True),
        ('wafw00f',     ['--version'],  (0,1,2), True),
        ('qsreplace',   ['-h'],         (0,1,2), False),
        ('x8',          ['-h'],         (0,1,2), True),
    ]
    critical_fail = []
    for tool, flags, good_codes, optional in health_cmds:
        bin_path = _hc_resolve(tool)
        if not bin_path:
            if optional:
                warn(f"Health: {tool} — não instalado (opcional)")
            else:
                ierr(f"Health: {tool} — binário ausente"); critical_fail.append(tool)
            continue
        try:
            r = subprocess.run([bin_path] + flags, capture_output=True, text=True,
                               timeout=15, env=os.environ)
            if r.returncode in good_codes:
                iok(f"Health: {tool} OK ({bin_path})")
            else:
                ierr(f"Health: {tool} — exit={r.returncode}"); critical_fail.append(tool)
        except Exception as e:
            ierr(f"Health: {tool} — {e}"); critical_fail.append(tool)

    print()
    if critical_fail:
        print(f"  {LRED}⚠ Falhas críticas: {', '.join(critical_fail)}{NC}")
        print(f"  {YELLOW}  → Corrija manualmente antes de rodar um scan.{NC}")
    else:
        print(f"  {LGREEN}✔ Health check OK — todas as ferramentas respondem.{NC}")
    sys.exit(0)


def step_initial_health_check():


    section("00 / HEALTH CHECK INICIAL")
    critical_ok = True


    system_tools = {'curl': True, 'git': False, 'python3': True}
    for tool, is_critical in system_tools.items():
        if shutil.which(tool):
            success(f"  {tool}: OK → {shutil.which(tool)}")
        elif is_critical:
            error(f"  {tool}: NÃO ENCONTRADO — CRÍTICO")
            critical_ok = False
        else:
            warn(f"  {tool}: não encontrado (opcional)")


    try:
        test_file = os.path.join(os.getcwd(), '.recon_write_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        success("  Escrita na pasta atual: OK")
    except OSError as e:
        error(f"  Escrita na pasta atual: FALHOU — {e}")
        critical_ok = False


    _sqlite_test_path = cfg.sqlite_db or (
        os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
        if (cfg.delta_mode or cfg.watcher_mode)
        else ""
    )
    if _sqlite_test_path:
        _tmp_db_fd, _tmp_db_path = tempfile.mkstemp(
            prefix='.recon_sqlite_test_',
            dir=os.path.dirname(os.path.abspath(_sqlite_test_path)) or '.'
        )
        os.close(_tmp_db_fd)
        try:
            con = sqlite3.connect(_tmp_db_path, timeout=5)
            con.execute("CREATE TABLE IF NOT EXISTS _test (x INTEGER)")
            con.commit()
            con.close()
            success(f"  SQLite: escrita OK → {_sqlite_test_path}")
        except (sqlite3.OperationalError, OSError) as e:
            error(f"  SQLite: sem permissão de escrita — {e}")
            critical_ok = False
        finally:
            try:
                os.unlink(_tmp_db_path)
            except OSError:
                pass


    try:
        import resource as _resource
        soft, hard = _resource.getrlimit(_resource.RLIMIT_NOFILE)
        required = _HTTP_MAX_CONN + cfg.threads * 3 + 256
        if soft < required:
            try:
                new_soft = min(required, hard if hard > 0 else required)
                _resource.setrlimit(_resource.RLIMIT_NOFILE, (new_soft, hard))
                success(f"  ulimit -n elevado: {soft} → {new_soft} (mínimo recomendado: {required})")
            except (ValueError, _resource.error):
                warn(f"  ulimit -n={soft} abaixo do mínimo recomendado ({required}). "
                     f"Execute 'ulimit -n {required}' antes de rodar para evitar EMFILE.")
        else:
            success(f"  ulimit -n={soft}: OK (mínimo={required})")
    except ImportError:
        pass
    except Exception as e:
        warn(f"  Não foi possível verificar ulimit: {e}")


    if cfg.anthropic_api_key:
        try:
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/models",
                headers={"x-api-key": cfg.anthropic_api_key,
                         "anthropic-version": "2023-06-01",
                         "User-Agent": random_ua()}
            )
            urllib.request.urlopen(req, timeout=10)
            success("  Anthropic API: acessível e chave válida")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                error("  Anthropic API: chave inválida (401) — funções de IA desabilitadas")
                cfg.anthropic_api_key = ""
            elif e.code in (429, 529):
                warn(f"  Anthropic API: quota/sobrecarga ({e.code}) — IA pode ser lenta")
            else:
                warn(f"  Anthropic API: HTTP {e.code} — verifique manualmente")
        except urllib.error.URLError as e:
            warn(f"  Anthropic API: sem acesso de rede — {e.reason}")
        except OSError as e:
            warn(f"  Anthropic API: erro de OS — {e}")


    if cfg.wordlist_path:
        if os.path.exists(cfg.wordlist_path):
            size_kb = os.path.getsize(cfg.wordlist_path) // 1024
            success(f"  Wordlist: OK → {cfg.wordlist_path} ({size_kb} KB)")
        else:
            warn(f"  Wordlist RECON_WORDLIST não encontrada: {cfg.wordlist_path}")
            cfg.wordlist_path = ""


    if cfg.webhook_url:
        try:
            ping = json.dumps({"text": f"[RECON] Health check iniciado para {cfg.domain}"}).encode()
            req2 = urllib.request.Request(cfg.webhook_url, data=ping,
                                          headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req2, timeout=5)
            success("  Webhook: OK")
        except Exception:
            warn("  Webhook: não acessível ou URL inválida — alertas desabilitados")
            cfg.webhook_url = ""

    print()
    if not critical_ok:
        error("Health check inicial falhou em itens CRÍTICOS — corrija antes de prosseguir.")
        sys.exit(3)
    else:
        success("Health check inicial: todos os itens críticos OK ✔")


def check_deps():
    section("VERIFICANDO DEPENDÊNCIAS")

    # ── Garante PATH completo para esta sessão ─────────────────────────────
    _home = os.path.expanduser('~')
    for _p in [
        os.path.join(_home, '.local', 'bin'),       # pipx
        os.path.join(_home, '.cargo', 'bin'),        # cargo (x8, feroxbuster)
        os.path.join(os.environ.get('GOPATH',
                     os.path.join(_home,'go')), 'bin'),   # go install
        '/usr/local/go/bin',                          # go sistema
    ]:
        if _p not in os.environ.get('PATH','').split(':'):
            os.environ['PATH'] = os.environ['PATH'] + f':{_p}'

    required = ['subfinder','httpx','waybackurls','gau','katana']
    optional = [
        'arjun','assetfinder','amass','findomain','wafw00f','dnsx',
        'ffuf','feroxbuster','gospider','hakrawler',
        'github-endpoints','xnLinkFinder','paramspider','x8',
    ]
    missing = []
    for t in required:
        if shutil.which(t): success(f"{t} → {shutil.which(t)}")
        else: error(f"{t} → NÃO ENCONTRADO"); missing.append(t)
    print()
    for t in optional:
        p = shutil.which(t)
        if p: info(f"{t} (opcional) → {p}")
        else: warn(f"{t} (opcional) → não encontrado")
    if missing:
        error(f"Obrigatórias ausentes: {' '.join(missing)}")
        warn("  → Use 'python3 recon.py --install' para instalar tudo")
        sys.exit(1)

    cfg.has_arjun       = bool(shutil.which('arjun'))
    cfg.has_assetfinder = bool(shutil.which('assetfinder'))
    cfg.has_amass       = bool(shutil.which('amass'))
    cfg.has_findomain   = bool(shutil.which('findomain'))
    cfg.has_wafw00f     = bool(shutil.which('wafw00f'))
    cfg.has_gpg         = bool(shutil.which('gpg'))
    cfg.has_subfinder   = bool(shutil.which('subfinder'))
    cfg.has_httpx       = bool(shutil.which('httpx'))
    cfg.has_waybackurls = bool(shutil.which('waybackurls'))
    cfg.has_gau         = bool(shutil.which('gau'))
    cfg.has_katana      = bool(shutil.which('katana'))
    cfg.has_sqlmap      = bool(shutil.which('sqlmap'))
    cfg.has_curl        = bool(shutil.which('curl'))

    cfg.has_ffuf             = bool(shutil.which('ffuf'))
    cfg.has_feroxbuster      = bool(shutil.which('feroxbuster'))
    cfg.has_gospider         = bool(shutil.which('gospider'))
    cfg.has_hakrawler        = bool(shutil.which('hakrawler'))
    cfg.has_paramspider      = bool(shutil.which('paramspider'))
    cfg.has_github_endpoints = bool(shutil.which('github-endpoints'))

    # x8: pode estar em ~/.cargo/bin mesmo fora do PATH do shell
    _cargo_bin_path = os.path.join(_home, '.cargo', 'bin', 'x8')
    _gobin_x8_path  = os.path.join(os.environ.get('GOPATH',
                       os.path.join(_home,'go')), 'bin', 'x8')
    _x8_path = (shutil.which('x8')
                or (_cargo_bin_path if os.path.isfile(_cargo_bin_path) else None)
                or (_gobin_x8_path  if os.path.isfile(_gobin_x8_path)  else None))
    cfg.has_x8  = bool(_x8_path)
    cfg._x8_bin = _x8_path or 'x8'

    # xnLinkFinder: pipx pode gerar 'xnlinkfinder' (lowercase) em sistemas case-sensitive
    _xnlf = (shutil.which('xnLinkFinder')
              or shutil.which('xnlinkfinder')
              or shutil.which('xnLinkFinder'.lower()))
    cfg.has_xnlinkfinder  = bool(_xnlf)
    cfg._xnlinkfinder_bin = _xnlf or 'xnLinkFinder'

    for tool, flag, path in [
        ('ffuf',             cfg.has_ffuf,             shutil.which('ffuf')),
        ('feroxbuster',      cfg.has_feroxbuster,      shutil.which('feroxbuster')),
        ('gospider',         cfg.has_gospider,         shutil.which('gospider')),
        ('hakrawler',        cfg.has_hakrawler,        shutil.which('hakrawler')),
        ('xnLinkFinder',     cfg.has_xnlinkfinder,     cfg._xnlinkfinder_bin),
        ('paramspider',      cfg.has_paramspider,      shutil.which('paramspider')),
        ('x8',               cfg.has_x8,               cfg._x8_bin),
        ('github-endpoints', cfg.has_github_endpoints, shutil.which('github-endpoints')),
    ]:
        if flag:
            info(f"{tool} → {path}")
        else:
            warn(f"{tool} (opcional) → não encontrado")

    def _check_min_version(tool: str, cmd: List[str], min_str: str, version_re: str):
        def _parse(s: str):
            parts = re.findall(r'\d+', s)
            return tuple(int(x) for x in parts) if parts else (0,)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=10, errors='replace', env=os.environ)
            output = (r.stdout + r.stderr).lower()
            m = re.search(version_re, output)
            if m:
                ver = m.group(1)
                if _parse(ver) < _parse(min_str):
                    warn(f"  {tool}: versão '{ver}' < mínimo '{min_str}' — flags incompatíveis possíveis")
                else:
                    info(f"  {tool}: versão {ver} OK")
            else:
                warn(f"  {tool}: versão não detectada — verifique manualmente")
        except Exception:
            pass

    _check_min_version('subfinder', ['subfinder','-version'], '2', r'v?(\d+)\.')
    _check_min_version('httpx',     ['httpx','-version'],     '1', r'v?(\d+)\.')

    success("Todas as dependências obrigatórias OK")


def adapt_to_waf():
    if not cfg.adaptive_mode or not cfg.waf_detected:
        return
    waf_path = f"{cfg.dir_extra}/waf_detected.txt"
    waf_type = ""
    if os.path.exists(waf_path):

        try:
            with open(waf_path) as _wf:
                content = strip_ansi(_wf.read()).lower()
        except OSError as e:
            log_err(f"adapt_to_waf: não foi possível ler {waf_path} — {e}")
            content = ""
        for wt in ['cloudflare','akamai','imperva','modsecurity','fortinet','f5',
                   'sucuri','barracuda','awsalb','fastly','incapsula']:
            if wt in content:
                waf_type = wt; break
    warn(f"🧠 Inteligência Adaptativa ativada — WAF: {waf_type or 'unknown'}")
    cfg.jitter_mode = True
    if waf_type in ('cloudflare','akamai','imperva','incapsula'):
        cfg.curl_delay = 2; cfg.burst_pause = 5
        cfg.scan_profile = "stealth"; cfg.xss_url_deadline = 30
    elif waf_type in ('modsecurity','fortinet','f5','barracuda'):
        cfg.curl_delay = 1; cfg.burst_pause = 3
        cfg.scan_profile = "stealth"; cfg.xss_url_deadline = 40
    else:
        cfg.curl_delay = 1; cfg.burst_pause = 2
        cfg.scan_profile = "stealth"; cfg.xss_url_deadline = 45
    for attr, limit in [('limit_cors',20),('limit_headers',15),('limit_sensitive',10),
                         ('limit_lfi',15),('limit_redirect',15),('limit_idor',15),
                         ('limit_crlf',15),('max_sqli',15),('limit_xss_manual',25)]:
        if getattr(cfg, attr) > limit:
            setattr(cfg, attr, limit)
    cfg.waf_evasion = True
    info(f"Perfil adaptado → stealth: delay={cfg.curl_delay}s burst={cfg.burst_pause}s xss_deadline={cfg.xss_url_deadline}s")


    try:
        with open(waf_path) as _wf_existing:
            existing = _wf_existing.read()
    except OSError:
        existing = ''
    marker = f"[ADAPTIVE v6] WAF={waf_type} profile=stealth"
    if marker not in existing:
        try:
            with open(waf_path, 'a') as f:
                f.write(f"\n{marker}\n")
        except OSError as e:
            log_err(f"adapt_to_waf: não foi possível escrever marcador — {e}")


_PARAMS_STATUS_RE = re.compile(r'\s\[(\d{3})\]\s*$')


_CAT_RE: Dict[str, "re.Pattern"] = {
    'php':   re.compile(r'\.php(\?|$)', re.I),
    'aspx':  re.compile(r'\.(asp|aspx)(\?|$)', re.I),
    'api':   re.compile(r'/(api|v[0-9]+|rest|graphql)', re.I),
    'admin': re.compile(r'/(admin|dashboard|panel|manager|backend|wp-admin|cpanel|portal|internal|console|staff)', re.I),
    'js':    re.compile(r'\.js(\?|$)', re.I),
}
_CAT_FILES: Dict[str, str] = {
    'php':   'urls_php.txt',
    'aspx':  'urls_asp.txt',
    'api':   'urls_api.txt',
    'admin': 'urls_admin.txt',
    'js':    'urls_js.txt',
}

_SCORE_RE_PARAMS   = re.compile(r'[?&](id|user_id|uid|account|admin|token|key|secret|pass|auth|session|debug|cmd|exec|file|path|redirect|url|next|to|src|dest|data|load|include|require|page|template)=', re.I)
_SCORE_RE_ADMIN    = re.compile(r'/(admin|dashboard|panel|manager|backend|cms|phpmyadmin|wp-admin|cpanel|portal|internal|staff|console)', re.I)
_SCORE_RE_API      = re.compile(r'/(api|v[0-9]+|rest|rpc|soap|service)', re.I)
_SCORE_RE_EXT      = re.compile(r'\.(php|asp|aspx|jsp|cfm|cgi|pl)(\?|$)', re.I)
_SCORE_RE_UPLOAD   = re.compile(r'(upload|file|attach|document|image|pdf|import|export)', re.I)
_SCORE_RE_KEYWORDS = re.compile(r'(login|auth|signup|register|password|reset|pay|billing|checkout|invoice|order|user|account|profile|settings|config|upload|download|export|import|report|search|query)', re.I)
_SCORE_RE_PARAMS_COUNT = re.compile(r'[?&][^=&]+=')

_SCORE_RE_GRAPHQL  = re.compile(r'/(graphql|gql|graph)(\?|/|$)', re.I)
_SCORE_RE_INTERNAL = re.compile(r'/(actuator|metrics|health|swagger|openapi|\.well-known|debug|trace|env|status|info|heapdump|threaddump|logfile)', re.I)
_SCORE_RE_FILEEXT  = re.compile(r'\.(bak|old|backup|sql|dump|tar\.gz|tar|zip|7z|rar|log|conf|config|yaml|yml|env|key|pem|crt|pfx|p12)(\?|$)', re.I)
_SCORE_RE_AUTHZ    = re.compile(r'/(oauth|sso|saml|oidc|token|authorize|callback|logout|signin|signout|connect)', re.I)

def score_endpoint(url: str) -> int:
    score = 0
    if _SCORE_RE_PARAMS.search(url):   score += 30
    if _SCORE_RE_ADMIN.search(url):    score += 25
    if _SCORE_RE_GRAPHQL.search(url):  score += 40
    if _SCORE_RE_INTERNAL.search(url): score += 35
    if _SCORE_RE_FILEEXT.search(url):  score += 50
    if _SCORE_RE_AUTHZ.search(url):    score += 30
    if _SCORE_RE_API.search(url):      score += 20
    if _SCORE_RE_EXT.search(url):      score += 15
    score += len(_SCORE_RE_PARAMS_COUNT.findall(url)) * 5
    if _SCORE_RE_KEYWORDS.search(url): score += 10
    if _SCORE_RE_UPLOAD.search(url):   score += 15
    return score

def prioritize_targets(infile: str, outfile: str):
    if not os.path.exists(infile):
        Path(outfile).touch(); return
    if not cfg.endpoint_scoring:
        shutil.copy(infile, outfile); return
    urls = safe_read(infile)
    scored = sorted(urls, key=lambda u: score_endpoint(u), reverse=True)
    if cfg.noise_reduction and len(scored) > 1:


        max_pos = len(scored) - 1
        weights = [1.0 - 0.9 * (i / max_pos) for i in range(len(scored))]

        seen: Dict[str, bool] = {}
        result = []
        for url in random.choices(scored, weights=weights, k=len(scored)):
            if url not in seen:
                seen[url] = True
                result.append(url)

        for url in scored:
            if url not in seen:
                result.append(url)
        scored = result
    with open(outfile, 'w') as f:
        f.write('\n'.join(scored) + '\n')
    info(f"Scoring: {len(scored)} endpoints priorizados por risco")


def step_subdomains():
    section("01 / ENUMERAÇÃO DE SUBDOMÍNIOS")

    def run_sub(name, cmd, outfile):
        if not circuit_breaker.allow(name):
            Path(outfile).touch(); return
        log(f"Rodando {name}...")
        rc, stdout, stderr = tool_runner.run(name, cmd, timeout=300)
        if rc < 0:
            circuit_breaker.record_failure(name)
            Path(outfile).touch()
            return
        circuit_breaker.record_success(name)
        lines = sorted(set(l.strip() for l in stdout.splitlines() if l.strip()))
        try:
            with open(outfile, 'w') as f:
                f.write('\n'.join(lines) + '\n')
        except OSError as e:
            log_err(f"{name}: não foi possível salvar resultado — {e}")
        success(f"{name}: {len(lines)} subdomínios")

    if cfg.has_subfinder:
        sf_args = ['subfinder', '-d', cfg.domain, '-silent']
        if cfg.deep_mode:
            sf_args.append('-all')
        run_sub("subfinder", sf_args, f"{cfg.dir_disc}/subs_subfinder.txt")
    else:
        warn("subfinder não encontrado — enumeração primária pulada")
        Path(f"{cfg.dir_disc}/subs_subfinder.txt").touch()

    if cfg.has_assetfinder:
        run_sub("assetfinder", ['assetfinder','--subs-only',cfg.domain], f"{cfg.dir_disc}/subs_assetfinder.txt")
    else:
        Path(f"{cfg.dir_disc}/subs_assetfinder.txt").touch()

    if cfg.has_findomain:
        run_sub("findomain", ['findomain','-t',cfg.domain,'-q'], f"{cfg.dir_disc}/subs_findomain.txt")
    else:
        Path(f"{cfg.dir_disc}/subs_findomain.txt").touch()

    if cfg.has_amass:
        amass_args = ['amass','enum']
        amass_args += ['-passive','-d',cfg.domain,'-silent'] if not cfg.deep_mode else ['-d',cfg.domain,'-silent']
        run_sub("amass", amass_args, f"{cfg.dir_disc}/subs_amass.txt")
    else:
        Path(f"{cfg.dir_disc}/subs_amass.txt").touch()

    all_subs = set()
    for f in ['subs_subfinder.txt','subs_assetfinder.txt','subs_findomain.txt','subs_amass.txt']:
        all_subs.update(safe_read(f"{cfg.dir_disc}/{f}"))
    valid = sorted(s for s in all_subs if re.match(r'^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$', s))
    try:
        with open(f"{cfg.dir_disc}/subs_all.txt", 'w') as f:
            f.write('\n'.join(valid) + '\n')
    except OSError as e:
        log_err(f"step_subdomains: falha ao salvar subs_all.txt — {e}")
    success(f"Total subdomínios únicos: {len(valid)}")


    subs_all_path = f"{cfg.dir_disc}/subs_all.txt"
    if shutil.which('dnsx') and not is_empty(subs_all_path):
        log("dnsx: filtrando subdomínios por resolução DNS real...")
        subs_resolved = f"{cfg.dir_disc}/subs_resolved.txt"
        rc_dnsx, _, _ = tool_runner.run(
            "dnsx",
            ['dnsx', '-l', subs_all_path, '-silent',
             '-wd', cfg.domain,
             '-r', '8.8.8.8,1.1.1.1,8.8.4.4',
             '-t', '50',
             '-o', subs_resolved],
            timeout=300
        )
        if rc_dnsx == 0 and not is_empty(subs_resolved):
            n_before = count_lines(subs_all_path)
            shutil.copy(subs_resolved, subs_all_path)
            n_after = count_lines(subs_all_path)
            success(f"dnsx: {n_before} → {n_after} subdomínios reais (-{n_before - n_after} NXDOMAIN/wildcard)")
        else:
            info("dnsx: sem output ou falhou — mantendo lista original")
    elif not shutil.which('dnsx'):
        info("dnsx não encontrado — pulando filtro DNS (opcional: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest)")
    if cfg.delta_mode and cfg.sqlite_db:
        new_subs = db_get_new_subdomains(valid)
        if new_subs:
            warn(f"DELTA: {len(new_subs)} subdomínios NOVOS desde o último scan!")
            try:
                with open(f"{cfg.dir_disc}/subs_new.txt", 'w') as f:
                    f.write('\n'.join(new_subs) + '\n')
            except OSError as e:
                log_err(f"step_subdomains: falha ao salvar subs_new.txt — {e}")
        else:
            info("DELTA: nenhum subdomínio novo")

    if cfg.sqlite_db:
        for s in valid:
            db_save_subdomain(s)


def step_alive():
    section("02 / VERIFICAÇÃO DE HOSTS ATIVOS")
    subs_all  = f"{cfg.dir_disc}/subs_all.txt"
    alive_det = f"{cfg.dir_disc}/alive_detailed.txt"
    alive     = f"{cfg.dir_disc}/alive.txt"
    if not cfg.has_httpx:
        warn("httpx não encontrado — step_alive abortado")
        Path(alive_det).touch(); Path(alive).touch(); return
    log("Rodando httpx...")
    if not circuit_breaker.allow("httpx"):
        Path(alive_det).touch(); Path(alive).touch(); return
    rc, _, err = tool_runner.run(
        "httpx",
        ['httpx', '-l', subs_all, '-silent', '-threads', str(cfg.threads),
         '-status-code', '-title', '-tech-detect', '-content-length',
         '-follow-redirects', '-o', alive_det],
        timeout=600
    )
    if rc < 0:
        circuit_breaker.record_failure("httpx")
        warn("httpx falhou — resultado de hosts ativos pode estar vazio")
    else:
        circuit_breaker.record_success("httpx")

    lines = safe_read(alive_det)
    urls = []
    for l in lines:
        if l.startswith('http'):
            parts = l.split()
            if parts and parts[0].startswith('http'):
                urls.append(parts[0])
    try:
        with open(alive, 'w') as f:
            f.write('\n'.join(sorted(set(urls))) + '\n')
    except OSError as e:
        log_err(f"step_alive: não foi possível salvar alive.txt — {e}")
    success(f"Hosts ativos: {count_lines(alive)}")


    status_counts: Counter = Counter()
    for l in lines:
        m = re.search(r'\[(\d{3})\]', l)
        if m:
            status_counts[m.group(1)] += 1
    for code, cnt in sorted(status_counts.items()):
        info(f"  HTTP {code}: {cnt}")


    tech_from_httpx = f"{cfg.dir_extra}/technologies_httpx.txt"
    try:
        with open(tech_from_httpx, 'w') as f:
            for l in lines:
                if '[' in l and ']' in l:
                    f.write(l + '\n')
    except OSError as e:
        log_err(f"step_alive: falha ao salvar technologies_httpx.txt — {e}")


def step_urls():
    section("06 / COLETA DE URLs")
    alive = f"{cfg.dir_disc}/alive.txt"
    urls_dir = cfg.dir_urls

    def run_url(name, cmd, outfile, input_data=None):
        log(f"{name}...")
        if not circuit_breaker.allow(name):
            Path(outfile).touch(); return
        rc, stdout, _ = tool_runner.run(name, cmd, timeout=600, input_data=input_data)
        if rc < 0:
            circuit_breaker.record_failure(name)
            Path(outfile).touch()
            return
        circuit_breaker.record_success(name)
        lines = sorted(set(l.strip() for l in stdout.splitlines()
                           if l.strip().startswith('http')))
        try:
            with open(outfile, 'w') as f:
                f.write('\n'.join(lines) + '\n')
        except OSError as e:
            log_err(f"{name}: não foi possível salvar — {e}")
        success(f"{name}: {len(lines)} URLs")


    alive_lines = safe_read(alive)
    domains_for_wayback = []
    for line in alive_lines:
        try:
            parsed = urllib.parse.urlparse(line)
            host = parsed.hostname or ''
            if host:
                domains_for_wayback.append(host)
        except Exception:
            pass
    domains_for_wayback = sorted(set(domains_for_wayback))
    if cfg.has_waybackurls:
        run_url("waybackurls", ['waybackurls'], f"{urls_dir}/wayback.txt",
                input_data='\n'.join(domains_for_wayback))
    else:
        Path(f"{urls_dir}/wayback.txt").touch()
    if cfg.has_gau:
        run_url("gau", ['gau', '--threads', str(cfg.gau_threads), '--subs', cfg.domain],
                f"{urls_dir}/gau.txt")
    else:
        Path(f"{urls_dir}/gau.txt").touch()

    if cfg.has_katana:
        katana_args = ['katana', '-list', alive, '-silent', '-jc', '-d', str(cfg.katana_depth),
                       '-c', str(cfg.threads), '-nc']
        if cfg.deep_mode:
            katana_args += ['-aff', '-xhr']
        run_url("katana", katana_args, f"{urls_dir}/katana.txt")
    else:
        Path(f"{urls_dir}/katana.txt").touch()


    urls_all_path = f"{urls_dir}/urls_all.txt"
    seen: Set[str] = set()
    total_merged = 0
    try:
        with open(urls_all_path, 'w') as fout:
            for fname in ['wayback.txt', 'gau.txt', 'katana.txt']:
                fpath = f"{urls_dir}/{fname}"
                if not os.path.exists(fpath):
                    continue
                with open(fpath, errors='replace') as fin:
                    for line in fin:
                        u = line.rstrip('\n')
                        if u.startswith('http') and u not in seen:
                            seen.add(u)
                            fout.write(u + '\n')
                            total_merged += 1
    except OSError as e:
        log_err(f"step_urls merge: {e}")
    success(f"Total URLs únicas: {total_merged}")


def step_filter_urls():
    section("07 / FILTRAGEM E CATEGORIZAÇÃO DE URLs")
    all_file = f"{cfg.dir_urls}/urls_all.txt"
    if is_empty(all_file):
        warn("Sem URLs para filtrar"); return


    _uro_tmp_in  = None
    _uro_tmp_out = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as _uro_ti:
            _uro_tmp_in = _uro_ti.name
        with open(all_file, errors='replace') as _af, open(_uro_tmp_in, 'w') as _uro_ti_w:
            shutil.copyfileobj(_af, _uro_ti_w)


        _uro_tmp_out_fd, _uro_tmp_out = tempfile.mkstemp(suffix='_uro_out.txt')
        os.close(_uro_tmp_out_fd)


        _rc_uro = -1
        _MEDIA_RE = re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|zip|pdf)(\?|$)', re.I)
        try:
            with open(_uro_tmp_in, 'rb') as _uro_fin_rb:
                _uro_proc = subprocess.Popen(
                    ['uro'], stdin=_uro_fin_rb,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                with _child_lock:
                    _child_pids.add(_uro_proc.pid)
                    _child_pgids.add(_uro_proc.pid)
                try:
                    with open(_uro_tmp_out, 'w') as _uro_fout:
                        for _raw in _uro_proc.stdout:
                            _line = _raw.decode(errors='replace').strip()
                            if _line:
                                _uro_fout.write(_line + '\n')
                    _uro_proc.wait(timeout=120)
                    _rc_uro = _uro_proc.returncode
                except subprocess.TimeoutExpired:
                    _uro_proc.kill()
                    try: _uro_proc.communicate(timeout=2)
                    except Exception: pass
                finally:
                    with _child_lock:
                        _child_pids.discard(_uro_proc.pid)
                        _child_pgids.discard(_uro_proc.pid)
        except FileNotFoundError:
            pass
        except Exception as _uro_exc:
            log_err(f"uro exec error: {_uro_exc}")
        if _rc_uro != 0:
            with open(_uro_tmp_out, 'w') as _uro_fout:
                with open(_uro_tmp_in, errors='replace') as _uro_fallback:
                    shutil.copyfileobj(_uro_fallback, _uro_fout)
        clean_set: Set[str] = set()
        with open(_uro_tmp_out, errors='replace') as _uro_r:
            for _uline in _uro_r:
                _u = _uline.strip()
                if _u and _u.startswith('http') and not _MEDIA_RE.search(_u):
                    clean_set.add(_u)
        clean = sorted(clean_set)
    except Exception as _filter_exc:
        log_err(f"step_filter_urls: falha no pipeline uro/filtro ({_filter_exc}) — usando fallback streaming")
        warn("⚠ Filtragem de URLs falhou — usando lista bruta como fallback")
        _MEDIA_FB_RE = re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|zip|pdf)(\?|$)', re.I)
        clean = []
        try:
            with open(all_file, errors='replace') as _fb:
                for _fline in _fb:
                    _u = _fline.strip()
                    if _u.startswith('http') and not _MEDIA_FB_RE.search(_u):
                        clean.append(_u)
        except OSError as _ose:
            log_err(f"step_filter_urls fallback streaming também falhou: {_ose}")
            clean = []
    finally:
        for _up in [_uro_tmp_in, _uro_tmp_out]:
            if _up:
                try: os.unlink(_up)
                except OSError: pass
    with open(f"{cfg.dir_urls}/urls_clean.txt",'w') as f:
        f.write('\n'.join(clean)+'\n')
    success(f"URLs limpas: {len(clean)}")


    cats = {
        'php':   (r'\.php(\?|$)', f"{cfg.dir_urls}/urls_php.txt"),
        'aspx':  (r'\.(asp|aspx)(\?|$)', f"{cfg.dir_urls}/urls_asp.txt"),
        'api':   (r'/(api|v[0-9]+|rest|graphql)', f"{cfg.dir_urls}/urls_api.txt"),
        'admin': (r'/(admin|dashboard|panel|manager|backend|wp-admin|cpanel|portal|internal|console|staff)', f"{cfg.dir_urls}/urls_admin.txt"),
        'js':    (r'\.js(\?|$)', f"{cfg.dir_urls}/urls_js.txt"),
    }
    for name, (pattern, outfile) in cats.items():
        matched = sorted(set(u for u in clean if re.search(pattern, u, re.I)))
        with open(outfile,'w') as f:
            f.write('\n'.join(matched)+'\n')
        info(f"  {name.upper():<10}: {len(matched)}")


    try:
        with open(f"{cfg.dir_urls}/urls_js.txt") as _js_src:
            with open(f"{cfg.dir_js}/js_files.txt", 'w') as f:
                f.write(_js_src.read())
    except OSError as e:
        log_err(f"step_js: falha ao copiar urls_js.txt → js_files.txt — {e}")


def step_waf_detect():
    section("07b / WAF DETECTION")
    waf_file = f"{cfg.dir_extra}/waf_detected.txt"


    Path(waf_file).parent.mkdir(parents=True, exist_ok=True)
    Path(waf_file).touch()
    targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_waf)
    if not targets:
        warn("Sem hosts para WAF detect"); return


    if cfg.has_wafw00f:
        log(f"Rodando wafw00f nos primeiros {len(targets)} hosts...")

        def run_wafw00f(url):
            try:

                rc, stdout, _ = _tracked_run(
                    ['wafw00f', url, '-a'], timeout=30
                )
                clean_out = strip_ansi(stdout)
                for line in clean_out.splitlines():
                    m = re.search(r'is behind\s+(.+)', line, re.I)
                    if m:
                        waf_name = m.group(1).strip()
                        return f"{url} | WAF={waf_name}"
                    if re.search(r'No WAF|no firewall', line, re.I):
                        return None
                return None
            except Exception:
                return None


        ex_waf = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        try:
            futures = {ex_waf.submit(run_wafw00f, t): t for t in targets}
            done, not_done = concurrent.futures.wait(futures, timeout=120)
            for f in not_done:
                f.cancel()
                log_err(f"wafw00f timeout: {futures[f]}")
            ex_waf.shutdown(wait=False, cancel_futures=True)
            results = []
            for f in done:
                try:
                    results.append(f.result())
                except Exception as e:
                    log_err(f"wafw00f resultado com erro: {e}")
        except Exception:
            ex_waf.shutdown(wait=False, cancel_futures=True)
            results = []
        for r in results:
            if r:
                append_line(waf_file, r)
                warn(f"WAF detectado: {r}")


    if cfg.has_sqlmap and targets:
        log("SQLMap --identify-waf (spot-check em 3 hosts)...")
        for url in targets[:3]:
            try:


                rc, stdout, stderr = _tracked_run(
                    ['sqlmap', '-u', url, '--batch', '--identify-waf',
                     '--random-agent', f'--timeout={cfg.timeout}', '--retries=1', '-q'],
                    timeout=45
                )
                combined = strip_ansi(stdout + stderr)
                m = re.search(r'WAF/IPS identified as (.+)', combined, re.I)
                if m:
                    waf_name = m.group(1).strip()
                    result_line = f"{url} | WAF={waf_name} [sqlmap]"
                    append_line(waf_file, result_line)
                    warn(f"SQLMap WAF ID: {result_line}")
            except subprocess.TimeoutExpired:
                log_err(f"sqlmap --identify-waf: timeout para {url}")
            except (OSError, subprocess.SubprocessError) as e:
                log_err(f"sqlmap --identify-waf: {e}")
            curl_throttle()


    waf_sigs = {
        'cloudflare':   ['cf-ray:', 'cloudflare', 'cf-cache-status'],
        'akamai':       ['akamai-ghost-ip', 'x-check-cacheable', 'x-akamai'],
        'imperva':      ['x-iinfo:', 'incap_ses', 'visid_incap'],
        'modsecurity':  ['mod_security', 'modsec', 'x-modsec', 'ModSecurity'],
        'awswaf':       ['x-amzn-requestid', 'awswaf', 'x-amz-cf'],
        'f5':           ['bigip', 'x-wa-info:', 'x-cnection', 'BigIP'],
        'sucuri':       ['x-sucuri-id:', 'sucuri', 'x-sucuri-cache'],
        'barracuda':    ['barra_counter_session', 'BNI__BARRACUDA', 'barracuda'],
        'fastly':       ['x-fastly-request-id', 'fastly', 'X-Served-By'],
        'stackpath':    ['x-sp-url', 'stackpath', 'x-hw'],
        'ddosguard':    ['__ddg1_', '__ddg2_', 'ddos-guard'],
        'fortinet':     ['FORTIWAFSID', 'FortiWeb', 'x-forwarded-for-fortiwaf'],
        'incapsula':    ['incap_ses', 'visid_incap', 'X-Iinfo'],
    }
    log(f"Fingerprint manual WAF em {len(targets)} hosts...")
    for url in targets:
        try:

            rc_base, stdout_base, _ = _tracked_run(
                ['curl','-sk','--max-time',str(cfg.timeout),'-I',
                 '-H','X-Test: 1 OR 1=1-- -',
                 '-H', "User-Agent: Mozilla/5.0 ' OR '1'='1", url],
                timeout=cfg.timeout+5
            )
            resp_lower = strip_ansi(stdout_base).lower()
            for waf_name, patterns in waf_sigs.items():
                if any(p.lower() in resp_lower for p in patterns):
                    line = f"{url} | WAF={waf_name} [header-fingerprint]"
                    append_line(waf_file, line)
                    break
        except Exception:
            pass
        curl_throttle()


    log("Verificando respostas anômalas com payloads de injeção...")
    for url in targets[:10]:
        try:

            rc_base2, stdout_base2, _ = _tracked_run(
                ['curl','-sk','--max-time',str(cfg.timeout),'-o','/dev/null','-w','%{http_code}',url],
                timeout=cfg.timeout+3
            )
            base_code = stdout_base2.strip()

            rc_inj, stdout_inj, _ = _tracked_run(
                ['curl','-sk','--max-time',str(cfg.timeout),'-o','/dev/null','-w','%{http_code}',
                 f"{url}?test=' OR 1=1-- -&x=<script>alert(1)</script>"],
                timeout=cfg.timeout+3
            )
            inj_code = stdout_inj.strip()
            if base_code == '200' and inj_code in ('403','429','503','406'):
                line = f"{url} | WAF=unknown [anomaly-response: {base_code}→{inj_code}]"
                append_line(waf_file, line)
                warn(f"WAF por resposta anômala: {url} ({base_code}→{inj_code})")
        except Exception:
            pass
        curl_throttle()

    n_waf = count_lines(waf_file)
    if n_waf > 0:
        warn(f"WAF detectado em {n_waf} hosts")
        cfg.waf_detected = True
    else:
        info("Nenhum WAF identificado")
        cfg.waf_detected = False


def step_params():
    section("09 / EXTRAÇÃO DE PARÂMETROS")
    urls = safe_read(f"{cfg.dir_urls}/urls_clean.txt")
    params_raw = sorted(set(u for u in urls if '?' in u and '=' in u))
    with open(f"{cfg.dir_params}/params_raw.txt", 'w') as f:
        f.write('\n'.join(params_raw) + '\n')
    success(f"URLs com parâmetros (raw): {len(params_raw)}")

    if not params_raw:
        warn("Nenhuma URL com parâmetros")
        for fn in ['params.txt', 'params_fuzz.txt', 'params_alive.txt', 'params_200_ok.txt']:
            Path(f"{cfg.dir_params}/{fn}").touch()
        return


    tmp_in_path  = None
    tmp_out_path = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as tmp_in:
            tmp_in.write('\n'.join(params_raw) + '\n')
            tmp_in_path = tmp_in.name
        tmp_out_fd, tmp_out_path = tempfile.mkstemp(suffix='_params_out.txt')
        os.close(tmp_out_fd)
        _uro_rc = -1
        try:
            with open(tmp_in_path, 'rb') as _param_fin_rb:
                _param_proc = subprocess.Popen(
                    ['uro'], stdin=_param_fin_rb,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                with _child_lock:
                    _child_pids.add(_param_proc.pid)
                    _child_pgids.add(_param_proc.pid)
                try:
                    with open(tmp_out_path, 'w') as _pout:
                        for _raw in _param_proc.stdout:
                            _line = _raw.decode(errors='replace').strip()
                            if _line:
                                _pout.write(_line + '\n')
                    _param_proc.wait(timeout=120)
                    _uro_rc = _param_proc.returncode
                except subprocess.TimeoutExpired:
                    _param_proc.kill()
                    try: _param_proc.communicate(timeout=2)
                    except Exception: pass
                finally:
                    with _child_lock:
                        _child_pids.discard(_param_proc.pid)
                        _child_pgids.discard(_param_proc.pid)
        except FileNotFoundError:
            pass
        except Exception as _pe:
            log_err(f"uro params error: {_pe}")
        if _uro_rc != 0:
            with open(tmp_out_path, 'w') as fout:
                with open(tmp_in_path, errors='replace') as _param_fallback:
                    shutil.copyfileobj(_param_fallback, fout)
        _params_set: Set[str] = set()
        with open(tmp_out_path, errors='replace') as _pr:
            for _pl in _pr:
                _s = _pl.strip()
                if _s:
                    _params_set.add(_s)
        params = sorted(_params_set) if _params_set else params_raw
    except Exception as _e:
        log_err(f"uro falhou ({_e}) — usando params_raw")
        params = params_raw
    finally:
        for _p in [tmp_in_path, tmp_out_path]:
            if _p:
                try: os.unlink(_p)
                except OSError: pass

    with open(f"{cfg.dir_params}/params.txt", 'w') as f:
        f.write('\n'.join(params) + '\n')
    success(f"Parâmetros únicos (após uro): {len(params)}")


    _tq_path = None
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as _tq:
            _tq.write('\n'.join(params) + '\n')
            _tq_path = _tq.name
        with open(_tq_path) as _fin:
            _qs_in = _fin.read()
        _qs_rc, _qs_out, _ = _tracked_run(['qsreplace', 'FUZZ'], input=_qs_in, timeout=60)
        fuzz = sorted(set(l.strip() for l in _qs_out.splitlines() if l.strip()))
        with open(f"{cfg.dir_params}/params_fuzz.txt", 'w') as f:
            f.write('\n'.join(fuzz) + '\n')
    except Exception as _e:
        log_err(f"qsreplace falhou: {_e}")
        Path(f"{cfg.dir_params}/params_fuzz.txt").touch()
    finally:
        if _tq_path:
            try: os.unlink(_tq_path)
            except OSError: pass


    params_alive    = f"{cfg.dir_params}/params_alive.txt"
    params_200_ok   = f"{cfg.dir_params}/params_200_ok.txt"
    params_detailed = f"{cfg.dir_params}/params_httpx_detailed.txt"

    for p in [params_alive, params_200_ok, params_detailed]:
        Path(p).touch()

    if not is_empty(f"{cfg.dir_params}/params.txt"):
        try:
            _tracked_run(
                ['httpx',
                 '-l',       f"{cfg.dir_params}/params.txt",
                 '-silent',
                 '-threads', str(cfg.threads),
                 '-mc',      '200,301,302,403',
                 '-sc',
                 '-o',       params_detailed],
                timeout=300
            )
        except subprocess.TimeoutExpired:
            log_err("httpx params: timeout (300s)")
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"httpx params: {e}")


    alive_urls  : List[str] = []
    ok_200_urls : List[str] = []
    _STATUS_RE = re.compile(r'\s\[(\d{3})\]\s*$')

    for raw_line in safe_read(params_detailed):
        line = raw_line.strip()
        if not line:
            continue
        m = _STATUS_RE.search(line)
        if not m:

            url_part = line.split()[0] if line.split() else ''
            if url_part.startswith('http'):
                alive_urls.append(url_part)
            continue

        status_code = int(m.group(1))
        url_part = line[:m.start()].strip()
        if not url_part.startswith('http'):
            continue


        if status_code in (200, 301, 302, 403):
            alive_urls.append(url_part)


        if status_code == 200:
            ok_200_urls.append(url_part)

    alive_urls  = sorted(set(alive_urls))
    ok_200_urls = sorted(set(ok_200_urls))


    existing_playwright = set(safe_read(params_alive))
    merged_alive = sorted(set(alive_urls) | existing_playwright)

    with open(params_alive, 'w') as f:
        f.write('\n'.join(merged_alive) + '\n')
    with open(params_200_ok, 'w') as f:
        f.write('\n'.join(ok_200_urls) + '\n')

    success(f"Parâmetros com resposta (200/3xx/403): {len(alive_urls)}")
    if existing_playwright:
        success(f"  (+{len(existing_playwright)} do Playwright — total merged: {len(merged_alive)})")
    success(f"Parâmetros 200 OK confirmados:         {len(ok_200_urls)}")


    names = re.findall(r'[?&]([^=&]+)=', '\n'.join(params))
    freq = Counter(names).most_common()
    with open(f"{cfg.dir_params}/param_names.txt", 'w') as f:
        for name, cnt in freq:
            f.write(f"{cnt:6d} {name}\n")


    if cfg.has_arjun and not is_empty(f"{cfg.dir_disc}/alive.txt"):
        arjun_targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_arjun)
        log(f"Rodando Arjun em {len(arjun_targets)} hosts...")
        arjun_tmpdir = tempfile.mkdtemp(prefix="arjun_")
        arjun_raw    = f"{cfg.dir_params}/arjun_raw.txt"

        def run_arjun(url: str):
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url)[:60]
            out_file  = os.path.join(arjun_tmpdir, f"{safe_name}.txt")
            try:
                _tracked_run(
                    ['arjun', '-u', url, '-t', '3', '-oT', out_file],
                    timeout=60
                )
            except subprocess.TimeoutExpired:
                log_err(f"arjun timeout (60s) para {url}")
            except (OSError, subprocess.SubprocessError) as e:
                log_err(f"arjun {url}: {e}")

        arjun_deadline = time.time() + 600
        ex_arjun = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        try:
            futures = {ex_arjun.submit(run_arjun, u): u for u in arjun_targets}
            try:
                for fut in concurrent.futures.as_completed(futures, timeout=600):
                    if time.time() > arjun_deadline:
                        warn("Arjun: timeout global 10min")
                        ex_arjun.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        fut.result()
                    except Exception:
                        pass
            except concurrent.futures.TimeoutError:
                warn("Arjun: as_completed timeout — cancelando futures pendentes")
                ex_arjun.shutdown(wait=False, cancel_futures=True)
        except Exception:
            ex_arjun.shutdown(wait=False, cancel_futures=True)

        all_arjun = []
        for tmp_file in glob.glob(os.path.join(arjun_tmpdir, "*.txt")):
            all_arjun.extend(safe_read(tmp_file))
        shutil.rmtree(arjun_tmpdir, ignore_errors=True)
        unique_arjun = sorted(set(l for l in all_arjun if l.strip()))
        with open(arjun_raw, 'w') as f:
            f.write('\n'.join(unique_arjun) + '\n')
        success(f"Arjun: {len(unique_arjun)} parâmetros descobertos")

def final_summary():
    section("SCAN COMPLETO — RECON")
    elapsed = time.time() - cfg.scan_start
    h, r = divmod(int(elapsed), 3600)
    m, s = divmod(r, 60)

    # Contagens para o sumário e para o DB
    _n_subs    = count_lines(cfg.dir_disc  + '/subs_all.txt')
    _n_alive   = count_lines(cfg.dir_disc  + '/alive.txt')
    _n_urls    = count_lines(cfg.dir_urls  + '/urls_all.txt')
    _n_params  = count_lines(cfg.dir_params+ '/params.txt')
    _n_js      = count_lines(cfg.dir_js    + '/js_files.txt')
    _n_ffuf    = count_lines(cfg.dir_scans + '/ffuf_all.txt')
    _n_errors  = count_lines(cfg.error_log)
    _total_findings = _n_subs + _n_urls + _n_params

    # Registrar no SQLite (bug fix: finished_at e total_findings agora preenchidos)
    if cfg.sqlite_db:
        try:
            with _db_conn() as con:
                now_iso = datetime.now(timezone.utc).isoformat()
                con.execute(
                    "INSERT INTO scan_history(domain,scan_dir,started_at,finished_at,total_findings) "
                    "VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING",
                    (cfg.domain, cfg.scan_dir,
                     datetime.fromtimestamp(cfg.scan_start, tz=timezone.utc).isoformat(),
                     now_iso, _total_findings)
                )
        except Exception as _dbe:
            log_err(f"final_summary: falha ao salvar scan_history — {_dbe}")

    print()
    print(f"{BOLD}{LCYAN}  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║                  RECON — SCAN FINALIZADO                     ║")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  {'Alvo:':<30} {cfg.domain:<29} ║")
    print(f"  ║  {'Duração:':<30} {f'{h:02d}h {m:02d}m {s:02d}s':<29} ║")
    print(f"  ║  {'Profile:':<30} {cfg.scan_profile:<29} ║")
    print(f"  ║  {'Erros log:':<30} {str(_n_errors)+' linhas':<29} ║")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  {'Subdomínios:':<30} {str(_n_subs):<29} ║")
    print(f"  ║  {'Hosts ativos:':<30} {str(_n_alive):<29} ║")
    print(f"  ║  {'URLs coletadas:':<30} {str(_n_urls):<29} ║")
    print(f"  ║  {'Parâmetros:':<30} {str(_n_params):<29} ║")
    print(f"  ║  {'Arquivos JS:':<30} {str(_n_js):<29} ║")
    if _n_ffuf:
        print(f"  ║  {'Paths (ffuf/ferox):':<30} {str(_n_ffuf):<29} ║")
    print(f"  ╚══════════════════════════════════════════════════════════════╝{NC}")
    print()
    success(f"Tudo salvo em: {cfg.scan_dir}/")


def watcher_mode():
    banner()
    validate_domain_whitelist()
    info(f"WATCHER MODE ativado — verificando {cfg.domain} a cada {cfg.watch_interval}s")
    info(f"Pressione Ctrl+C para sair")

    scan_count = 0
    while True:
        scan_count += 1
        info(f"\n══ Watcher scan #{scan_count} ══")
        cfg.delta_mode = (scan_count > 1)
        cfg.scan_start = time.time()

        # Reset de contadores de rate-limit entre ciclos (evita backoff acumulado)
        with _counters_lock:
            cfg._rate_429_count = 0
            cfg._rate_backoff   = 0.0
        with cfg._host_lock:
            cfg._host_429.clear()
            cfg._host_backoff.clear()

        try:
            if _db_worker_thread and _db_worker_thread.is_alive():
                _stop_db_worker()
        except Exception:
            pass
        try:
            http_client_stop()
        except Exception:
            pass

        setup_dirs()
        db_init()
        _start_db_worker()
        http_client_start()
        check_deps()

        step_subdomains()
        _safe_step(step_github_endpoints)
        step_alive()

        if scan_count > 1:
            new_subs_file = f"{cfg.dir_disc}/subs_new.txt"
            if not is_empty(new_subs_file):
                warn(f"WATCHER: {count_lines(new_subs_file)} subdomínios NOVOS detectados!")
                shutil.copy(new_subs_file, f"{cfg.dir_disc}/alive.txt")
            else:
                info("WATCHER: nenhuma novidade neste ciclo")

        _safe_step(step_filter_active_assets)
        step_waf_detect()
        adapt_to_waf()
        _safe_step(step_extra_crawlers)
        step_urls()
        step_filter_urls()
        _safe_step(step_js_mining)
        _safe_step(step_ffuf_dirscan)
        step_params()
        _safe_step(step_param_discovery_extra)

        _stop_db_worker()
        try:
            flush_append_buffer()
        except Exception:
            pass
        info(f"Próximo scan em {cfg.watch_interval}s...")
        time.sleep(cfg.watch_interval)


def validate_domain_whitelist():


    wl_env = os.environ.get('RECON_WHITELIST', '')
    wl_all = list(cfg.whitelist)
    if wl_env:
        wl_all += [d.strip() for d in wl_env.split(',') if d.strip()]

    if not wl_all:
        return

    target = cfg.domain.lower().lstrip('.')
    allowed = False
    for entry in wl_all:
        entry = entry.strip().lower().lstrip('.')

        if target == entry or target.endswith('.' + entry):
            allowed = True
            break

    if not allowed:
        print(f"\n{LRED}╔══════════════════════════════════════════════════════════════╗{NC}")
        print(f"{LRED}║  ⛔ SAFE MODE: DOMÍNIO NÃO AUTORIZADO                        ║{NC}")
        print(f"{LRED}╠══════════════════════════════════════════════════════════════╣{NC}")
        print(f"{LRED}║  Alvo   : {cfg.domain:<51} ║{NC}")
        print(f"{LRED}║  Whitelist: {', '.join(wl_all)[:49]:<49} ║{NC}")
        print(f"{LRED}╚══════════════════════════════════════════════════════════════╝{NC}")
        print(f"\n  Use {BOLD}--whitelist {cfg.domain}{NC} ou defina RECON_WHITELIST={cfg.domain}")
        sys.exit(2)

    success(f"Safe mode: '{cfg.domain}' autorizado na whitelist.")


def encrypt_output_files():

    if not cfg.encrypt_output:
        return
    if not cfg.has_gpg:
        warn("encrypt-output: gpg não encontrado — instale: sudo apt install gnupg"); return
    if not cfg.encrypt_password:
        warn("encrypt-output: --encrypt-pass não definido — pulando criptografia"); return

    sensitive_files = [
        f"{cfg.dir_js}/js_secrets.txt",
        f"{cfg.dir_js}/js_secrets_validated.txt",
        f"{cfg.dir_report}/vuln_urls.txt",
        f"{cfg.dir_report}/vuln_urls.json",
        f"{cfg.dir_report}/ai_triage.txt",
        f"{cfg.dir_report}/credential_leaks.txt",
        f"{cfg.dir_extra}/sensitive_files.txt",
    ]

    log("Criptografando outputs sensíveis com GPG...")
    encrypted = 0
    for fpath in sensitive_files:
        if not os.path.exists(fpath) or os.path.getsize(fpath) == 0:
            continue
        out_enc = fpath + ".gpg"
        try:
            r = subprocess.run(
                ['gpg', '--batch', '--yes', '--symmetric',
                 '--cipher-algo', 'AES256',
                 '--passphrase', cfg.encrypt_password,
                 '--output', out_enc, fpath],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                os.remove(fpath)
                encrypted += 1
                info(f"  Criptografado: {os.path.basename(fpath)}.gpg")
            else:
                warn(f"  GPG falhou para {os.path.basename(fpath)}: {r.stderr[:80]}")
        except Exception as e:
            log_err(f"encrypt {fpath}: {e}")

    if encrypted > 0:
        success(f"Criptografia: {encrypted} arquivos protegidos com AES-256")
        info("  Para descriptografar: gpg --decrypt arquivo.gpg")
    else:
        warn("Criptografia: nenhum arquivo sensível encontrado para criptografar")


def start_live_dashboard(port: int = 8765):


    if not cfg.scan_dir:
        return
    report_dir = cfg.dir_report


    if not report_dir or not Path(report_dir).is_dir():
        log_err(f"start_live_dashboard: dir_report inválido ou inexistente: '{report_dir}'")
        return

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=report_dir, **kwargs)
        def log_message(self, fmt, *args):
            pass

    def _inject_refresh(html: str) -> str:

        refresh = '<meta http-equiv="refresh" content="15">'
        return html.replace('<head>', f'<head>{refresh}', 1) if '<head>' in html else html


    class RefreshHandler(Handler):
        def do_GET(self):
            if self.path in ('/', '/index.html', ''):
                html_path = os.path.join(report_dir, 'index.html')
                if os.path.exists(html_path):
                    try:
                        with open(html_path, 'r', errors='replace') as f:
                            content = _inject_refresh(f.read())
                        encoded = content.encode('utf-8', errors='replace')
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/html; charset=utf-8')
                        self.send_header('Content-Length', str(len(encoded)))
                        self.end_headers()
                        self.wfile.write(encoded)
                        return
                    except Exception:
                        pass
            super().do_GET()

    def _run():
        try:
            with socketserver.TCPServer(('127.0.0.1', port), RefreshHandler) as httpd:
                httpd.serve_forever()
        except OSError:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    info(f"Live Dashboard → http://127.0.0.1:{port}/ (atualiza a cada 15s)")


def step_playwright_crawl():
    section("02b / PLAYWRIGHT CRAWL (SPA — JS real)")

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        warn("Playwright não instalado — pip install playwright && playwright install chromium")
        return

    alive = safe_read(f"{cfg.dir_disc}/alive.txt")
    if not alive:
        warn("Sem hosts para crawl Playwright"); return

    targets  = alive[:min(len(alive), 15)]
    captured: Set[str] = set()
    _cap_lock = threading.Lock()

    log(f"Playwright crawl em {len(targets)} hosts (headless Chromium)...")

    def crawl_host(url: str):
        host_urls: Set[str] = set()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
                try:
                    ctx  = browser.new_context(user_agent=random_ua(), ignore_https_errors=True)
                    page = ctx.new_page()

                    def on_request(req):
                        rurl = req.url
                        if cfg.domain in rurl and ('?' in rurl or '/api/' in rurl.lower()):
                            host_urls.add(rurl)

                    page.on("request", on_request)
                    try:
                        page.goto(url, timeout=20000, wait_until="networkidle")
                        page.wait_for_timeout(3000)
                        links = page.eval_on_selector_all(
                            'a[href]',
                            'els => els.map(e => e.href).filter(h => h.startsWith("http"))'
                        )
                        for link in links[:10]:
                            if cfg.domain in link:
                                try:
                                    page.goto(link, timeout=10000, wait_until="domcontentloaded")
                                    page.wait_for_timeout(1500)
                                except PWTimeout:
                                    pass
                    except PWTimeout:
                        log_err(f"playwright timeout: {url}")
                    finally:
                        ctx.close()
                finally:
                    browser.close()
        except Exception as e:
            log_err(f"playwright error {url}: {e}")

        with _cap_lock:
            captured.update(host_urls)
        if host_urls:
            info(f"  Playwright {url}: {len(host_urls)} URLs capturadas")

    ex_pw = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    try:
        futs = {ex_pw.submit(crawl_host, t): t for t in targets}
        done, not_done = concurrent.futures.wait(futs, timeout=300)
        for f in not_done:
            f.cancel()
        ex_pw.shutdown(wait=False, cancel_futures=True)
        for f in done:
            try:
                f.result()
            except Exception as e:
                log_err(f"playwright future error: {e}")
    except Exception as e:
        log_err(f"playwright executor error: {e}")
        ex_pw.shutdown(wait=False, cancel_futures=True)

    if not captured:
        info("Playwright: nenhuma URL XHR/Fetch capturada"); return

    params_alive = f"{cfg.dir_params}/params_alive.txt"
    pw_out       = f"{cfg.dir_urls}/playwright_urls.txt"
    existing     = set(safe_read(params_alive))
    new_params   = sorted(u for u in captured if '?' in u and '=' in u and u not in existing)

    with open(pw_out, 'w') as f:
        f.write('\n'.join(sorted(captured)) + '\n')

    if new_params:
        with open(params_alive, 'a') as f:
            f.write('\n'.join(new_params) + '\n')
        success(f"Playwright: {len(captured)} URLs | {len(new_params)} novos params → {params_alive}")
    else:
        success(f"Playwright: {len(captured)} URLs capturadas (sem novos params)")


def step_github_endpoints():
    """01b — Busca endpoints e rotas vazadas em repositórios GitHub."""
    section("01b / GITHUB ENDPOINTS (vazamento em repos)")

    if cfg.no_github_endpoints:
        info("--no-github-endpoints ativo — pulando"); return
    if not cfg.has_github_endpoints:
        warn("github-endpoints não encontrado — pulando")
        info("  → go install github.com/gwen001/github-endpoints@latest")
        return

    # github-endpoints usa a GitHub API: sem token, limite de 60 req/h
    _gh_token = os.environ.get('GITHUB_TOKEN', '')
    if not _gh_token:
        warn("GITHUB_TOKEN não definido — rate limit 60 req/h (GitHub API)")
        warn("  → export GITHUB_TOKEN=ghp_... para resultados completos")

    if not circuit_breaker.allow("github-endpoints"):
        return

    out_file = f"{cfg.dir_disc}/github_endpoints.txt"
    Path(out_file).touch()

    log(f"github-endpoints: buscando '{cfg.domain}' em repos públicos...")
    _gh_cmd = ['github-endpoints', '-d', cfg.domain, '-o', out_file]
    if _gh_token:
        _gh_cmd += ['-t', _gh_token]
    try:
        rc, stdout, _ = tool_runner.run("github-endpoints", _gh_cmd, timeout=120)
    except Exception as exc:
        log_err(f"github-endpoints: {exc}"); return

    if rc < 0:
        circuit_breaker.record_failure("github-endpoints")
        warn("github-endpoints falhou ou sem resultados"); return
    circuit_breaker.record_success("github-endpoints")

    found = safe_read(out_file)
    if not found:
        info("github-endpoints: nenhum endpoint vazado encontrado"); return
    success(f"GitHub endpoints: {len(found)} encontrados → {out_file}")

    urls_all  = f"{cfg.dir_urls}/urls_all.txt"
    alive_lst = safe_read(f"{cfg.dir_disc}/alive.txt")[:20]
    existing  = set(safe_read(urls_all))

    http_ep = [u for u in found if u.startswith('http') and cfg.domain in u]
    path_ep = [u for u in found if u.startswith('/')]

    new_urls: List[str] = [u for u in http_ep if u not in existing]
    for path in path_ep:
        for host in alive_lst:
            full = host.rstrip('/') + path
            if full not in existing:
                new_urls.append(full)
    new_urls = sorted(set(new_urls))
    if new_urls:
        with open(urls_all, 'a') as f:
            f.write('\n'.join(new_urls) + '\n')
        info(f"  +{len(new_urls)} endpoints injetados em urls_all.txt")

    high_value = [u for u in found if re.search(
        r'(api|admin|internal|staging|dev\b|test\b|debug|config|secret|'
        r'\.env|key|token|password|auth|login|oauth|graphql|actuator)',
        u, re.I
    )]
    if high_value:
        hv_file = f"{cfg.dir_disc}/github_high_value.txt"
        with open(hv_file, 'w') as f:
            f.write('\n'.join(high_value) + '\n')
        warn(f"  ⚠ {len(high_value)} endpoints de ALTO VALOR → {hv_file}")
        jsonl_log("github_high_value", {
            "domain": cfg.domain, "count": len(high_value), "file": hv_file
        })


def step_extra_crawlers():
    """05b — gospider + hakrawler em paralelo para enriquecer a lista de URLs."""
    section("05b / CRAWLERS EXTRAS (gospider + hakrawler)")

    if not cfg.has_gospider and not cfg.has_hakrawler:
        warn("gospider e hakrawler não encontrados — pulando")
        info("  → go install github.com/jaeles-project/gospider@latest")
        info("  → go install github.com/hakluke/hakrawler@latest")
        return

    alive   = f"{cfg.dir_disc}/alive.txt"
    if is_empty(alive):
        warn("Sem hosts para crawl extra"); return

    targets   = safe_read(alive)[:cfg.limit_gospider]
    urls_out  = f"{cfg.dir_urls}/extra_crawl.txt"
    Path(urls_out).touch()
    extra_set: Set[str] = set()
    _lock = threading.Lock()

    # ── gospider ────────────────────────────────────────────────────────────
    if cfg.has_gospider:
        log(f"gospider em {len(targets)} hosts (robots, sitemap, HTML attrs)...")

        def _run_gospider(url: str):
            if _shutdown_event.is_set():
                return
            if not circuit_breaker.allow("gospider"):
                return
            try:
                rc, stdout, _ = tool_runner.run(
                    "gospider",
                    ['gospider', '-s', url, '-c', '5', '-d', '2',
                     '--robots', '--sitemap', '-q',
                     '--user-agent', random_ua()],
                    timeout=120,
                )
                if rc < 0:
                    circuit_breaker.record_failure("gospider"); return
                circuit_breaker.record_success("gospider")
                for raw in stdout.splitlines():
                    # formato: [linkfinder] - [from] [url]
                    for token in raw.strip().split():
                        if token.startswith('http') and cfg.domain in token:
                            with _lock:
                                extra_set.add(token)
                                append_line(urls_out, token)
            except Exception as exc:
                log_err(f"gospider {url}: {exc}")
            jitter()

        ex_gs = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        try:
            futs = {ex_gs.submit(_run_gospider, t): t for t in targets}
            done, nd = concurrent.futures.wait(futs, timeout=600)
            for f in nd:
                f.cancel()
            ex_gs.shutdown(wait=False, cancel_futures=True)
            for f in done:
                try: f.result()
                except Exception as e: log_err(f"gospider result: {e}")
        except Exception:
            ex_gs.shutdown(wait=False, cancel_futures=True)

    # ── hakrawler ───────────────────────────────────────────────────────────
    if cfg.has_hakrawler:
        log(f"hakrawler em {len(targets)} hosts (depth=2)...")
        alive_input = '\n'.join(targets)
        if not circuit_breaker.allow("hakrawler"):
            pass
        else:
            try:
                rc, stdout, _ = tool_runner.run(
                    "hakrawler",
                    ['hakrawler', '-d', '2', '-insecure', '-subs',
                     '-h', f'User-Agent: {random_ua()}'],
                    timeout=180,
                    input_data=alive_input,
                )
                if rc < 0:
                    circuit_breaker.record_failure("hakrawler")
                else:
                    circuit_breaker.record_success("hakrawler")
                    for line in stdout.splitlines():
                        u = line.strip()
                        if u.startswith('http') and cfg.domain in u:
                            with _lock:
                                extra_set.add(u)
                                append_line(urls_out, u)
            except Exception as exc:
                log_err(f"hakrawler: {exc}")

    flush_append_buffer(urls_out)
    if extra_set:
        success(f"Crawlers extras: {len(extra_set)} URLs → {urls_out}")
        # Mesclar em urls_all.txt
        urls_all = f"{cfg.dir_urls}/urls_all.txt"
        existing = set(safe_read(urls_all))
        new_urls = sorted(u for u in extra_set if u not in existing)
        if new_urls:
            with open(urls_all, 'a') as f:
                f.write('\n'.join(new_urls) + '\n')
            info(f"  +{len(new_urls)} novos em urls_all.txt")
    else:
        info("Crawlers extras: nenhuma URL nova capturada")


def step_ffuf_dirscan():
    """03b — Fuzzing ativo de diretórios e APIs com ffuf (ou feroxbuster como fallback)."""
    section("03b / FUZZING ATIVO DE DIRETÓRIOS (ffuf / feroxbuster)")

    if cfg.no_ffuf:
        info("--no-ffuf ativo — fuzzing ativo desabilitado"); return
    if not cfg.has_ffuf and not cfg.has_feroxbuster:
        warn("ffuf e feroxbuster não encontrados — pulando")
        info("  → go install github.com/ffuf/ffuf/v2@latest")
        return
    if cfg.scan_profile == "stealth":
        warn("Modo stealth ativo — fuzzing ativo pulado (muito barulhento)"); return

    alive = f"{cfg.dir_disc}/alive.txt"
    if is_empty(alive):
        warn("Sem hosts para fuzzing"); return

    # ── Auto-detecção de wordlist ────────────────────────────────────────────
    wl = cfg.ffuf_wordlist
    if not wl or not os.path.exists(wl):
        _wl_candidates = [
            '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
            '/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
            os.path.expanduser('~/SecLists/Discovery/Web-Content/raft-medium-directories.txt'),
            os.path.expanduser('~/SecLists/Discovery/Web-Content/common.txt'),
        ]
        wl = next((c for c in _wl_candidates if os.path.exists(c)), '')
    if not wl:
        warn("ffuf: nenhuma wordlist encontrada")
        warn("  → defina --ffuf-wordlist ou instale SecLists via --install")
        return

    targets   = safe_read(alive)[:cfg.limit_ffuf]
    if not targets:
        warn("ffuf: nenhum host ativo para escanear"); return
    ffuf_all  = f"{cfg.dir_scans}/ffuf_all.txt"
    Path(ffuf_all).touch()
    discovered: Set[str] = set()
    _lock = threading.Lock()

    _threads = cfg.ffuf_threads
    # Stealth: threads reduzidas automaticamente após WAF
    if cfg.waf_detected:
        _threads = min(_threads, 10)
        info(f"WAF detectado — ffuf threads limitado a {_threads}")

    info(f"Wordlist: {os.path.basename(wl)} ({os.path.getsize(wl)//1024} KB) | "
         f"Hosts: {len(targets)} | Threads: {_threads}")

    # ── ffuf ────────────────────────────────────────────────────────────────
    def _run_ffuf(url: str):
        if _shutdown_event.is_set():
            return
        if not circuit_breaker.allow("ffuf"):
            return
        host_safe = re.sub(r'[^a-zA-Z0-9._-]', '_', url)[:60]
        out_json  = f"{cfg.dir_scans}/ffuf_{host_safe}.json"
        fuzz_url  = url.rstrip('/') + '/FUZZ'
        cmd = [
            'ffuf', '-u', fuzz_url, '-w', wl,
            '-mc', '200,201,204,301,302,307,401,403,405,429',
            '-t', str(_threads),
            '-timeout', str(cfg.ffuf_timeout),
            '-ac',               # auto-calibration: elimina false positives por tamanho
            '-o', out_json, '-of', 'json',
            '-H', f'User-Agent: {random_ua()}',
            '-s',                # silent — sem banner
        ]
        if cfg.ffuf_rate > 0:
            cmd += ['-rate', str(cfg.ffuf_rate)]
        if cfg.waf_evasion:
            cmd += ['-H', 'X-Forwarded-For: 127.0.0.1',
                    '-H', 'X-Real-IP: 127.0.0.1']
        try:
            rc, _, _ = tool_runner.run("ffuf", cmd, timeout=300)
            if rc < 0:
                circuit_breaker.record_failure("ffuf"); return
            circuit_breaker.record_success("ffuf")
            if not os.path.exists(out_json) or os.path.getsize(out_json) == 0:
                return
            with open(out_json) as jf:
                data = json.load(jf)
            results = data.get('results', [])
            for r in results:
                found_url = r.get('url', '')
                status    = r.get('status', 0)
                length    = r.get('length', 0)
                words     = r.get('words', 0)
                if found_url:
                    with _lock:
                        discovered.add(found_url)
                        append_line(ffuf_all,
                                    f"{found_url} [{status}] [{length}b] [{words}w]")
            if results:
                success(f"ffuf {url}: {len(results)} paths encontrados")
                jsonl_log("ffuf_results", {
                    "url": url, "count": len(results),
                    "file": out_json,
                })
        except (json.JSONDecodeError, OSError) as exc:
            log_err(f"ffuf parse {url}: {exc}")
        except Exception as exc:
            log_err(f"ffuf {url}: {exc}")
        jitter()

    # ── feroxbuster (fallback) ───────────────────────────────────────────────
    def _run_ferox(url: str):
        if _shutdown_event.is_set():
            return
        if not circuit_breaker.allow("feroxbuster"):
            return
        host_safe = re.sub(r'[^a-zA-Z0-9._-]', '_', url)[:60]
        out_file  = f"{cfg.dir_scans}/ferox_{host_safe}.txt"
        cmd = [
            'feroxbuster', '--url', url, '--wordlist', wl,
            '--threads', str(min(_threads, 50)),
            '--timeout', str(cfg.ffuf_timeout),
            '--status-codes', '200,201,204,301,302,307,401,403,405',
            '--auto-tune',   # calibração automática de false positives
            '--output', out_file,
            '--no-state',
            '--silent',
            '--random-agent',
        ]
        try:
            rc, _, _ = tool_runner.run("feroxbuster", cmd, timeout=300)
            if rc < 0:
                circuit_breaker.record_failure("feroxbuster"); return
            circuit_breaker.record_success("feroxbuster")
            for line in safe_read(out_file):
                found_url = next((p for p in line.split()
                                  if p.startswith('http')), '')
                if found_url:
                    with _lock:
                        discovered.add(found_url)
                        append_line(ffuf_all, line)
            n = count_lines(out_file)
            if n > 0:
                success(f"feroxbuster {url}: {n} paths encontrados")
        except Exception as exc:
            log_err(f"feroxbuster {url}: {exc}")
        jitter()

    tool_fn   = _run_ffuf if cfg.has_ffuf else _run_ferox
    tool_name = "ffuf"    if cfg.has_ffuf else "feroxbuster"

    log(f"Fuzzing ativo com {tool_name} em {len(targets)} hosts...")
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(targets)))
    try:
        futs = {ex.submit(tool_fn, t): t for t in targets}
        done, nd = concurrent.futures.wait(futs, timeout=600)
        for f in nd:
            f.cancel()
            log_err(f"{tool_name} timeout: {futs[f]}")
        ex.shutdown(wait=False, cancel_futures=True)
        for f in done:
            try: f.result()
            except Exception as exc: log_err(f"{tool_name} result: {exc}")
    except Exception as exc:
        log_err(f"{tool_name} executor: {exc}")
        ex.shutdown(wait=False, cancel_futures=True)

    flush_append_buffer(ffuf_all)
    success(f"Fuzzing ativo: {len(discovered)} paths únicos → {ffuf_all}")

    # ── Enriquece urls_clean.txt com os paths descobertos ───────────────────
    if not discovered:
        return
    clean_file = f"{cfg.dir_urls}/urls_clean.txt"
    existing   = set(safe_read(clean_file))
    new_paths  = sorted(u for u in discovered if u not in existing)
    if new_paths:
        with open(clean_file, 'a') as f:
            f.write('\n'.join(new_paths) + '\n')
        info(f"  +{len(new_paths)} paths injetados em urls_clean.txt")

    # Categorizar admin/api descobertos via fuzzing
    _ADMIN_RE = re.compile(
        r'/(admin|dashboard|panel|manager|backend|wp-admin|cpanel|portal|'
        r'internal|console|staff|phpmyadmin|cms)', re.I)
    _API_RE   = re.compile(r'/(api|v[0-9]+|rest|graphql|rpc|soap)', re.I)
    for u in new_paths:
        if _ADMIN_RE.search(u): append_line(f"{cfg.dir_urls}/urls_admin.txt", u)
        if _API_RE.search(u):   append_line(f"{cfg.dir_urls}/urls_api.txt", u)
    flush_append_buffer()


def step_js_mining():
    """05c — Mineração cirúrgica de JavaScript com xnLinkFinder."""
    section("05c / MINERAÇÃO DE JS (xnLinkFinder)")

    if not cfg.has_xnlinkfinder:
        warn("xnLinkFinder não encontrado — pulando")
        info("  → pipx install xnLinkFinder")
        return

    js_list = f"{cfg.dir_js}/js_files.txt"
    if is_empty(js_list):
        warn("Sem arquivos JS para minerar"); return

    js_files      = safe_read(js_list)[:cfg.limit_js_mining]
    endpoints_out = f"{cfg.dir_js}/js_endpoints.txt"
    params_out    = f"{cfg.dir_js}/js_params.txt"
    for p in [endpoints_out, params_out]:
        Path(p).touch()

    found_ep: Set[str] = set()
    found_pm: Set[str] = set()
    _lock = threading.Lock()

    _PARAM_NAME_RE = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_\-]{1,40}$')

    def _mine(js_url: str):
        if _shutdown_event.is_set():
            return
        try:
            rc, stdout, _ = _tracked_run(
                [cfg._xnlinkfinder_bin, '-i', js_url,
                 '-sf', cfg.domain,
                 '-o', 'cli', '-op', 'cli'],
                timeout=60,
            )
            if rc < 0:
                return
            for raw in stdout.splitlines():
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('http') or line.startswith('/'):
                    with _lock:
                        found_ep.add(line)
                        append_line(endpoints_out, line)
                elif _PARAM_NAME_RE.match(line):
                    with _lock:
                        found_pm.add(line)
                        append_line(params_out, line)
        except Exception as exc:
            log_err(f"xnLinkFinder {js_url}: {exc}")

    log(f"xnLinkFinder em {len(js_files)} arquivos JS...")
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=10)
    try:
        futs = {ex.submit(_mine, js): js for js in js_files}
        done, nd = concurrent.futures.wait(futs, timeout=300)
        for f in nd: f.cancel()
        ex.shutdown(wait=False, cancel_futures=True)
    except Exception:
        ex.shutdown(wait=False, cancel_futures=True)

    flush_append_buffer(endpoints_out)
    flush_append_buffer(params_out)
    success(f"JS mining: {len(found_ep)} endpoints, {len(found_pm)} param names")

    # ── Injetar endpoints em urls_clean.txt ─────────────────────────────────
    if found_ep:
        clean_file = f"{cfg.dir_urls}/urls_clean.txt"
        existing   = set(safe_read(clean_file))
        alive_lst  = safe_read(f"{cfg.dir_disc}/alive.txt")[:10]
        new_ep: List[str] = []
        for ep in found_ep:
            if ep.startswith('http') and ep not in existing:
                new_ep.append(ep)
            elif ep.startswith('/'):
                for host in alive_lst:
                    full = host.rstrip('/') + ep
                    if full not in existing:
                        new_ep.append(full)
        new_ep = sorted(set(new_ep))
        if new_ep:
            with open(clean_file, 'a') as f:
                f.write('\n'.join(new_ep) + '\n')
            info(f"  +{len(new_ep)} endpoints JS → urls_clean.txt")

    # ── Enriquecer param_names.txt com nomes descobertos ────────────────────
    if found_pm:
        pn_file = f"{cfg.dir_params}/param_names.txt"
        existing_names: Set[str] = set()
        for raw_line in safe_read(pn_file):
            parts = raw_line.split()
            if len(parts) >= 2:
                existing_names.add(parts[1])
        new_names = found_pm - existing_names
        if new_names:
            with open(pn_file, 'a') as f:
                for name in sorted(new_names):
                    f.write(f"     0 {name}  [js-mining]\n")
            info(f"  +{len(new_names)} param names JS → param_names.txt")


def step_param_discovery_extra():
    """09b — Descoberta extra de parâmetros com x8 (Rust) e ParamSpider (passivo)."""
    section("09b / DESCOBERTA EXTRA DE PARÂMETROS (x8 + ParamSpider)")

    if not cfg.has_x8 and not cfg.has_paramspider:
        warn("x8 e paramspider não encontrados — pulando")
        info("  → cargo install x8 --locked")
        info("  → pipx install paramspider")
        return

    alive       = f"{cfg.dir_disc}/alive.txt"
    params_alive = f"{cfg.dir_params}/params_alive.txt"
    fuzz_file   = f"{cfg.dir_params}/params_fuzz.txt"
    if is_empty(alive):
        warn("Sem hosts para descoberta extra de parâmetros"); return

    targets    = safe_read(alive)[:cfg.limit_arjun]
    discovered: Set[str] = set()
    _lock = threading.Lock()

    # ── x8 — rápido, agressivo, Rust ────────────────────────────────────────
    if cfg.has_x8:
        log(f"x8: descoberta de parâmetros em {len(targets)} hosts...")
        x8_tmpdir = tempfile.mkdtemp(prefix="x8_")

        def _run_x8(url: str):
            if _shutdown_event.is_set():
                return
            host_safe = re.sub(r'[^a-zA-Z0-9._-]', '_', url)[:50]
            out_file  = os.path.join(x8_tmpdir, f"{host_safe}.txt")
            try:
                rc, _, _ = _tracked_run(
                    [cfg._x8_bin, '-u', url,
                     '-o', out_file,
                     '-O', 'url',
                     '-t', '10',
                     '-H', f'User-Agent: {random_ua()}'],
                    timeout=90,
                )
                if rc >= 0 and os.path.exists(out_file):
                    for line in safe_read(out_file):
                        u = line.strip()
                        if u.startswith('http') and '?' in u:
                            with _lock:
                                discovered.add(u)
            except Exception as exc:
                log_err(f"x8 {url}: {exc}")
            jitter()

        ex_x8 = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        try:
            futs = {ex_x8.submit(_run_x8, t): t for t in targets}
            done, nd = concurrent.futures.wait(futs, timeout=600)
            for f in nd: f.cancel()
            ex_x8.shutdown(wait=False, cancel_futures=True)
        except Exception:
            ex_x8.shutdown(wait=False, cancel_futures=True)
        shutil.rmtree(x8_tmpdir, ignore_errors=True)
        success(f"x8: {len(discovered)} URLs com params")

    # ── ParamSpider — mineração passiva (archives, JS, forms) ────────────────
    if cfg.has_paramspider:
        log(f"ParamSpider: mineração passiva para {cfg.domain}...")
        ps_out = f"{cfg.dir_params}/paramspider_raw.txt"
        try:
            rc, _, _ = _tracked_run(
                ['paramspider', '-d', cfg.domain,
                 '--exclude', 'png,jpg,gif,svg,css,woff,woff2,ttf,eot',
                 '--output', ps_out],
                timeout=120,
            )
            if rc >= 0:
                for line in safe_read(ps_out):
                    u = line.strip()
                    if u.startswith('http'):
                        # ParamSpider entrega URLs com FUZZ como placeholder
                        if 'FUZZ' in u:
                            real = u.replace('FUZZ', 'test')
                            with _lock:
                                discovered.add(real)
                        else:
                            with _lock:
                                discovered.add(u)
                success(f"ParamSpider: {count_lines(ps_out)} URLs mineradas → {ps_out}")
        except Exception as exc:
            log_err(f"paramspider: {exc}")

    # ── Mesclar resultados em params_alive.txt e params_fuzz.txt ────────────
    if not discovered:
        info("Descoberta extra: nenhum resultado novo"); return

    existing_alive = set(safe_read(params_alive))
    new_params = sorted(u for u in discovered
                        if u not in existing_alive and '?' in u and '=' in u)
    if new_params:
        with open(params_alive, 'a') as f:
            f.write('\n'.join(new_params) + '\n')
        success(f"Parâmetros extras: +{len(new_params)} → params_alive.txt")

    # Gerar entradas FUZZ para params_fuzz.txt
    existing_fuzz = set(safe_read(fuzz_file))
    new_fuzz: List[str] = []
    for u in new_params:
        try:
            parsed = urllib.parse.urlparse(u)
            qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for key, vals in qs.items():
                val     = vals[0] if vals else ''
                fuzz_u  = u.replace(f"{key}={val}", f"{key}=FUZZ", 1)
                if fuzz_u not in existing_fuzz:
                    new_fuzz.append(fuzz_u)
        except Exception:
            pass
    if new_fuzz:
        with open(fuzz_file, 'a') as f:
            f.write('\n'.join(sorted(set(new_fuzz))) + '\n')
        info(f"  +{len(new_fuzz)} entradas FUZZ → params_fuzz.txt")


def parse_args():
    parser = argparse.ArgumentParser(
        description="RECON.PY  — Full Automated Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 recon.py alvo.com
  python3 recon.py alvo.com --threads 200 --deep
  python3 recon.py alvo.com --api-key sk-ant-... --plan
  python3 recon.py alvo.com --stealth
  python3 recon.py alvo.com --watch --watch-interval 3600
  python3 recon.py --install
"""
    )
    parser.add_argument('domain', nargs='?', default='')
    parser.add_argument('--install',            action='store_true')
    parser.add_argument('--threads',            type=int, default=100)
    parser.add_argument('--deep',               action='store_true')
    parser.add_argument('--skip-scans',         action='store_true')
    parser.add_argument('--no-screenshots',     action='store_true')
    parser.add_argument('--verbose',            action='store_true')
    parser.add_argument('--api-key',            default='')
    parser.add_argument('--plan',               action='store_true', help='AI Attack Planner (requer --api-key)')
    parser.add_argument('--retry',              type=int, default=3)
    parser.add_argument('--jitter',             action='store_true')
    parser.add_argument('--no-waf-evasion',     action='store_true')
    parser.add_argument('--shodan-key',         default='')
    parser.add_argument('--no-adaptive',        action='store_true')
    parser.add_argument('--no-passive-intel',   action='store_true')
    parser.add_argument('--no-scoring',         action='store_true')
    parser.add_argument('--no-validate-secrets', action='store_true')
    parser.add_argument('--stealth',            action='store_true')
    parser.add_argument('--aggressive',         action='store_true')
    parser.add_argument('--timeout',            type=int, default=10)
    parser.add_argument('--curl-delay',         type=int, default=0)
    parser.add_argument('--xss-deadline',       type=int, default=45, help='Segundos por URL no XSS manual')
    parser.add_argument('--watch',              action='store_true', help='Modo watcher contínuo')
    parser.add_argument('--watch-interval',     type=int, default=3600)
    parser.add_argument('--sqlite-db',          default='', help='Caminho do banco SQLite persistente')
    parser.add_argument('--no-delta',           action='store_true')

    parser.add_argument('--limit-cors',         type=int, default=50)
    parser.add_argument('--limit-headers',      type=int, default=30)
    parser.add_argument('--limit-sensitive',    type=int, default=20)
    parser.add_argument('--limit-lfi',          type=int, default=30)
    parser.add_argument('--limit-redirect',     type=int, default=30)
    parser.add_argument('--limit-idor',         type=int, default=30)
    parser.add_argument('--limit-crlf',         type=int, default=30)
    parser.add_argument('--limit-waf',          type=int, default=20)
    parser.add_argument('--limit-403bypass',    type=int, default=30)
    parser.add_argument('--limit-metadata',     type=int, default=20)

    parser.add_argument('--whitelist',          default='',
                        help='Domínios autorizados (separados por vírgula). Ex: alvo.com,staging.alvo.com')
    parser.add_argument('--dry-run',            action='store_true',
                        help='Simula o scan sem enviar requests reais')
    parser.add_argument('--encrypt-output',     action='store_true',
                        help='Criptografa outputs sensíveis com GPG (requer --encrypt-pass)')
    parser.add_argument('--encrypt-pass',       default='',
                        help='Senha para criptografia GPG dos outputs')

    parser.add_argument('--hibp-key',           default='',
                        help='HaveIBeenPwned API key para credential leak check')

    parser.add_argument('--live-dashboard',     action='store_true',
                        help='Inicia servidor local para dashboard em tempo real (porta 8765)')
    parser.add_argument('--dashboard-port',     type=int, default=8765)

    parser.add_argument('--webhook-url',        default='',
                        help='URL de webhook para alertas (Discord/Slack/Telegram)')
    parser.add_argument('--agent',              action='store_true',
                        help='Modo agente OODA — IA decide quais módulos executar (requer API key)')
    parser.add_argument('--playwright',         action='store_true',
                        help='Crawl headless com Playwright para SPAs (React/Vue/Angular)')

    # ── Novas ferramentas ────────────────────────────────────────────────────
    parser.add_argument('--ffuf-wordlist',  default='',
                        help='Wordlist para ffuf/feroxbuster (auto-detecta SecLists se omitido)')
    parser.add_argument('--ffuf-threads',   type=int, default=40,
                        help='Threads do ffuf (padrão 40; reduzido auto em stealth/WAF)')
    parser.add_argument('--ffuf-rate',      type=int, default=0,
                        help='Limite de req/s do ffuf (0 = sem limite)')
    parser.add_argument('--limit-ffuf',     type=int, default=50,
                        help='Máx de hosts para ffuf/feroxbuster (padrão 50)')
    parser.add_argument('--limit-gospider', type=int, default=20,
                        help='Máx de hosts para gospider/hakrawler (padrão 20)')
    parser.add_argument('--limit-js-mining', type=int, default=100,
                        help='Máx de arquivos JS para xnLinkFinder (padrão 100)')
    parser.add_argument('--no-ffuf',        action='store_true',
                        help='Pula o fuzzing ativo (ffuf/feroxbuster)')
    parser.add_argument('--no-github-endpoints', action='store_true',
                        help='Pula a busca de endpoints vazados no GitHub')
    return parser.parse_args()


def main():

    _load_dotenv()
    args = parse_args()
    cfg.scan_start = time.time()

    if args.install:
        banner()
        auto_install()
        sys.exit(0)

    if not args.domain:
        print(f"{RED}Erro: domínio não informado.{NC}")
        print(f"\n  {BOLD}Uso:{NC} python3 recon.py <dominio> [opções]")
        print(f"       python3 recon.py --install\n")
        sys.exit(1)


    cfg.domain            = args.domain
    cfg.threads           = args.threads
    cfg.deep_mode         = args.deep
    cfg.verbose           = args.verbose
    cfg.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY', '') or args.api_key
    cfg.max_retries       = args.retry
    cfg.jitter_mode       = args.jitter
    cfg.waf_evasion       = not args.no_waf_evasion
    cfg.shodan_api_key    = args.shodan_key
    cfg.adaptive_mode     = not args.no_adaptive
    cfg.endpoint_scoring  = not args.no_scoring
    cfg.timeout           = args.timeout
    cfg.curl_delay        = args.curl_delay
    cfg.watcher_mode      = args.watch
    cfg.watch_interval    = args.watch_interval
    cfg.sqlite_db         = args.sqlite_db
    cfg.delta_mode        = not args.no_delta
    cfg.limit_waf         = args.limit_waf
    cfg.whitelist         = [d.strip() for d in args.whitelist.split(',') if d.strip()]
    cfg.dry_run           = args.dry_run
    cfg.encrypt_output    = args.encrypt_output
    cfg.encrypt_password  = args.encrypt_pass
    cfg.webhook_url       = args.webhook_url or os.environ.get('RECON_WEBHOOK_URL', '')
    cfg.playwright_mode   = args.playwright
    cfg.wordlist_path     = os.environ.get('RECON_WORDLIST', '')

    # ── Config das novas ferramentas ─────────────────────────────────────────
    cfg.ffuf_wordlist         = args.ffuf_wordlist or os.environ.get('RECON_FFUF_WORDLIST', '')
    cfg.ffuf_threads          = args.ffuf_threads
    cfg.ffuf_rate             = args.ffuf_rate
    cfg.limit_ffuf            = args.limit_ffuf
    cfg.limit_gospider        = args.limit_gospider
    cfg.limit_js_mining       = args.limit_js_mining
    cfg.no_ffuf               = args.no_ffuf
    cfg.no_github_endpoints   = args.no_github_endpoints


    if args.stealth:
        cfg.scan_profile = "stealth"
        cfg.jitter_mode  = True
        cfg.waf_evasion  = True
        cfg.curl_delay   = 2
        cfg.burst_pause  = 5
        cfg.threads      = 20
        cfg.gau_threads  = 5
        cfg.katana_depth = 2
    elif args.aggressive:
        cfg.scan_profile = "aggressive"
        cfg.threads      = 200
        cfg.gau_threads  = 30
        cfg.katana_depth = 6

    if cfg.deep_mode:
        cfg.katana_depth       = 5
        cfg.gau_threads        = 20
        cfg.limit_js_endpoints = 300
        cfg.limit_arjun        = 50


    if cfg.watcher_mode:
        cfg.sqlite_db = cfg.sqlite_db or os.path.expanduser(
            f"~/.recon_{cfg.domain.replace('.','_')}.db"
        )
        watcher_mode()
        return


    banner()
    setup_dirs()
    step_initial_health_check()
    validate_domain_whitelist()

    if cfg.dry_run:
        print(f"\n  {BOLD}{YELLOW}⚠ DRY-RUN ATIVO — nenhum request será enviado ao alvo.{NC}")
        print(f"  {DIM}  Use este modo para validar configuração e alcance antes do scan real.{NC}\n")

    print(f"  {BOLD}Alvo        :{NC} {LCYAN}{cfg.domain}{NC}")
    print(f"  {BOLD}Threads     :{NC} {cfg.threads}")
    print(f"  {BOLD}Profile     :{NC} {cfg.scan_profile}")
    print(f"  {BOLD}Deep mode   :{NC} {cfg.deep_mode}")
    print(f"  {BOLD}WAF Evasion :{NC} {'ativado' if cfg.waf_evasion else 'desativado'}")
    print(f"  {BOLD}Playwright  :{NC} {'ativado' if cfg.playwright_mode else 'desativado'}")
    print(f"  {BOLD}Scoring     :{NC} {'ativado' if cfg.endpoint_scoring else 'desativado'}")
    print(f"  {BOLD}Dry-run     :{NC} {'SIM ⚠' if cfg.dry_run else 'não'}")
    print(f"  {BOLD}Whitelist   :{NC} {', '.join(cfg.whitelist) if cfg.whitelist else 'não configurada'}")
    print(f"  {BOLD}SQLite      :{NC} {'ativado' if cfg.sqlite_db else 'desativado'}")
    print(f"  {BOLD}Pasta       :{NC} {CYAN}{cfg.scan_dir}{NC}")
    print()


    if cfg.sqlite_db or cfg.delta_mode:
        cfg.sqlite_db = cfg.sqlite_db or os.path.expanduser(
            f"~/.recon_{cfg.domain.replace('.','_')}.db"
        )
        db_init()
        _start_db_worker()


    check_deps()


    step_subdomains()

    # 01b — Endpoints vazados em repos GitHub (passive intel)
    _safe_step(step_github_endpoints)

    step_alive()

    _safe_step(step_filter_active_assets)

    step_waf_detect()
    adapt_to_waf()

    if cfg.playwright_mode:
        step_playwright_crawl()

    # 05b — Crawlers extras (gospider + hakrawler)
    _safe_step(step_extra_crawlers)

    step_urls()

    step_filter_urls()

    # 05c — Mineração cirúrgica de JS com xnLinkFinder
    _safe_step(step_js_mining)

    # 03b — Fuzzing ativo de diretórios (ffuf / feroxbuster)
    _safe_step(step_ffuf_dirscan)

    if cfg.endpoint_scoring:
        info("🎯 Priorizando endpoints por score de risco...")
        prioritize_targets(
            f"{cfg.dir_urls}/urls_clean.txt",
            f"{cfg.dir_urls}/urls_clean_scored.txt"
        )
        scored = f"{cfg.dir_urls}/urls_clean_scored.txt"
        if os.path.exists(scored) and os.path.getsize(scored) > 0:
            shutil.copy(scored, f"{cfg.dir_urls}/urls_clean.txt")


    step_params()

    # 09b — Descoberta extra de parâmetros (x8 + ParamSpider)
    _safe_step(step_param_discovery_extra)

    if cfg.sqlite_db:
        _stop_db_worker()

    try:
        flush_append_buffer()
    except Exception:
        pass

    try:
        http_client_stop()
    except Exception:
        pass

    _close_jsonl_file()
    _close_log_file()
    _close_err_file()
    final_summary()


if __name__ == "__main__":
    main()
