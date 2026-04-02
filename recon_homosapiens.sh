#!/bin/bash

# ============================================================
#  RECON.SH — Full Automated Reconnaissance Framework v2.0
#  Uso: ./recon.sh <dominio> [opções]
#  Exemplo: ./recon.sh alvo.com
#           ./recon.sh alvo.com --threads 200 --deep
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
  echo -e "  ${DIM}Full Automated Reconnaissance Framework v2.0${NC}"
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

# ---------------------------------------------------------------
# LIMITES CONFIGURÁVEIS (corrige escalabilidade — antes hard-coded)
# ---------------------------------------------------------------
limit_cors=50
limit_headers=30
limit_sensitive=20
limit_lfi=30
limit_redirect=30
limit_js_endpoints=100
limit_js_secrets=50
limit_ffuf=20
limit_arjun=20
curl_delay=0          # delay (segundos) entre requests curl manuais (0 = sem delay)

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

# ============================================================
# PARSE DE ARGUMENTOS
# ============================================================
parse_args() {
  if [[ -z "$1" ]]; then
    echo -e "${RED}Erro: domínio não informado.${NC}"
    echo
    echo -e "  ${BOLD}Uso:${NC} ./recon.sh <dominio> [opções]"
    echo
    echo -e "  ${BOLD}Opções:${NC}"
    echo -e "    --threads <n>         Número de threads (padrão: 100)"
    echo -e "    --deep                Modo profundo: mais fontes e profundidade"
    echo -e "    --skip-scans          Pula dalfox, sqlmap e nuclei"
    echo -e "    --no-screenshots      Pula screenshots com gowitness"
    echo -e "    --verbose             Mostra output completo de cada ferramenta"
    echo -e "    --limit-cors <n>      Hosts testados no CORS check (padrão: 50)"
    echo -e "    --limit-headers <n>   Hosts testados no headers check (padrão: 30)"
    echo -e "    --limit-sensitive <n> Hosts testados em arquivos sensíveis (padrão: 20)"
    echo -e "    --limit-lfi <n>       Candidatos testados no LFI (padrão: 30)"
    echo -e "    --limit-redirect <n>  Candidatos testados no redirect (padrão: 30)"
    echo -e "    --curl-delay <s>      Delay entre requests curl manuais (padrão: 0)"
    echo
    exit 1
  fi

  domain="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --threads)          threads="$2";           shift 2 ;;
      --deep)             deep_mode=true;          shift   ;;
      --skip-scans)       skip_scans=true;         shift   ;;
      --no-screenshots)   skip_screenshots=true;   shift   ;;
      --verbose)          verbose=true;            shift   ;;
      --limit-cors)       limit_cors="$2";         shift 2 ;;
      --limit-headers)    limit_headers="$2";      shift 2 ;;
      --limit-sensitive)  limit_sensitive="$2";    shift 2 ;;
      --limit-lfi)        limit_lfi="$2";          shift 2 ;;
      --limit-redirect)   limit_redirect="$2";     shift 2 ;;
      --curl-delay)       curl_delay="$2";         shift 2 ;;
      *) shift ;;
    esac
  done

  if "$deep_mode"; then
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
  error_log="$DIR_ROOT/errors.log"   # ★ novo: log de erros separado
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
log_err() { echo -e "[$(_ts)] $1" >> "$error_log"; }  # ★ novo: grava stderr no errors.log

section() {
  echo | tee -a "$log_file"
  echo -e "${LMAGENTA}[$(_ts)] ══════════════════════════════════════${NC}" | tee -a "$log_file"
  echo -e "${LMAGENTA}[$(_ts)]  $1${NC}"                                    | tee -a "$log_file"
  echo -e "${LMAGENTA}[$(_ts)] ══════════════════════════════════════${NC}" | tee -a "$log_file"
}

count()    { [[ -f "$1" ]] && grep -c "" "$1" 2>/dev/null || echo 0; }
is_empty() { [[ ! -f "$1" ]] || [[ $(count "$1") -eq 0 ]]; }
safe_cat() { [[ -f "$1" ]] && cat "$1" || echo "(nenhum resultado)"; }

# ★ Helper: delay entre requests curl quando configurado
curl_throttle() { [[ "$curl_delay" -gt 0 ]] && sleep "$curl_delay"; }

# ============================================================
# CHECK DEPENDENCIES
# ============================================================
check_deps() {
  section "VERIFICANDO DEPENDÊNCIAS"

  local required=(subfinder httpx waybackurls gau katana gf uro qsreplace dalfox nuclei sqlmap)
  local optional=(gowitness naabu subzy arjun ffuf trufflehog assetfinder amass findomain)
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
      warn "$tool (opcional) → não encontrado, etapa será pulada"
    fi
  done

  if [[ ${#missing_required[@]} -gt 0 ]]; then
    echo
    error "Instale as dependências obrigatórias antes de continuar:"
    echo
    echo -e "  ${BOLD}Go:${NC}"
    echo "    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "    go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    echo "    go install github.com/tomnomnom/waybackurls@latest"
    echo "    go install github.com/lc/gau/v2/cmd/gau@latest"
    echo "    go install github.com/projectdiscovery/katana/cmd/katana@latest"
    echo "    go install github.com/tomnomnom/gf@latest"
    echo "    go install github.com/tomnomnom/qsreplace@latest"
    echo "    go install github.com/hahwul/dalfox/v2@latest"
    echo "    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo
    echo -e "  ${BOLD}Python:${NC}"
    echo "    pip install uro --break-system-packages"
    echo "    pip install arjun --break-system-packages"
    echo
    echo -e "  ${BOLD}Sistema:${NC}"
    echo "    sudo apt install sqlmap"
    echo
    echo -e "  ${BOLD}Opcionais (recomendados):${NC}"
    echo "    go install github.com/sensepost/gowitness@latest"
    echo "    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    echo "    go install github.com/PentestPad/subzy@latest"
    echo "    go install github.com/ffuf/ffuf/v2@latest"
    echo "    go install github.com/tomnomnom/assetfinder@latest"
    echo "    go install github.com/findomain/findomain@latest"
    echo "    sudo apt install amass"
    exit 1
  fi

  # ★ Detecta ferramentas opcionais AQUI (dentro de check_deps, garantido)
  command -v gowitness    &>/dev/null && HAS_GOWITNESS=true
  command -v naabu        &>/dev/null && HAS_NAABU=true
  command -v subzy        &>/dev/null && HAS_SUBZY=true
  command -v arjun        &>/dev/null && HAS_ARJUN=true
  command -v ffuf         &>/dev/null && HAS_FFUF=true
  command -v trufflehog   &>/dev/null && HAS_TRUFFLEHOG=true
  command -v assetfinder  &>/dev/null && HAS_ASSETFINDER=true
  command -v amass        &>/dev/null && HAS_AMASS=true
  command -v findomain    &>/dev/null && HAS_FINDOMAIN=true

  success "Todas as dependências obrigatórias OK"
}

# ============================================================
# 01 — SUBDOMAIN ENUMERATION  ★ múltiplas fontes
# ============================================================
step_subdomains() {
  section "01 / ENUMERAÇÃO DE SUBDOMÍNIOS"

  # ★ FIX: usa array para evitar word-splitting em $domain com caracteres especiais
  local subfinder_args=(-d "$domain" -silent)
  "$deep_mode" && subfinder_args+=(-all)

  log "Rodando subfinder..."
  subfinder "${subfinder_args[@]}" 2>>"$error_log" \
    | sort -u > "$DIR_DISC/subs_subfinder.txt"
  success "subfinder: $(count "$DIR_DISC/subs_subfinder.txt") subdomínios"

  # ★ NOVO: assetfinder como segunda fonte
  if "$HAS_ASSETFINDER"; then
    log "Rodando assetfinder..."
    assetfinder --subs-only "$domain" 2>>"$error_log" \
      | sort -u > "$DIR_DISC/subs_assetfinder.txt"
    success "assetfinder: $(count "$DIR_DISC/subs_assetfinder.txt") subdomínios"
  else
    warn "assetfinder não encontrado — instale: go install github.com/tomnomnom/assetfinder@latest"
    touch "$DIR_DISC/subs_assetfinder.txt"
  fi

  # ★ NOVO: findomain como terceira fonte
  if "$HAS_FINDOMAIN"; then
    log "Rodando findomain..."
    findomain -t "$domain" -q 2>>"$error_log" \
      | sort -u > "$DIR_DISC/subs_findomain.txt"
    success "findomain: $(count "$DIR_DISC/subs_findomain.txt") subdomínios"
  else
    warn "findomain não encontrado — instale: go install github.com/findomain/findomain@latest"
    touch "$DIR_DISC/subs_findomain.txt"
  fi

  # ★ NOVO: amass em modo passive como quarta fonte
  if "$HAS_AMASS"; then
    log "Rodando amass (passive)..."
    local amass_args=(-passive -d "$domain" -silent)
    "$deep_mode" && amass_args=(-d "$domain" -silent)   # modo ativo no deep
    amass enum "${amass_args[@]}" 2>>"$error_log" \
      | sort -u > "$DIR_DISC/subs_amass.txt"
    success "amass: $(count "$DIR_DISC/subs_amass.txt") subdomínios"
  else
    warn "amass não encontrado — instale: sudo apt install amass"
    touch "$DIR_DISC/subs_amass.txt"
  fi

  # ★ Combina TODAS as fontes em subs_all.txt
  cat \
    "$DIR_DISC/subs_subfinder.txt" \
    "$DIR_DISC/subs_assetfinder.txt" \
    "$DIR_DISC/subs_findomain.txt" \
    "$DIR_DISC/subs_amass.txt" \
    2>/dev/null | grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" | sort -u \
    > "$DIR_DISC/subs_all.txt"

  success "Total subdomínios únicos (todas as fontes): $(count "$DIR_DISC/subs_all.txt")"
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

  grep '\[200\]'               "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_200.txt"      2>/dev/null || touch "$DIR_DISC/alive_200.txt"
  grep -E '\[(301|302|307|308)\]' "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_redirect.txt" 2>/dev/null || touch "$DIR_DISC/alive_redirect.txt"
  grep '\[403\]'               "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_403.txt"      2>/dev/null || touch "$DIR_DISC/alive_403.txt"
  grep '\[401\]'               "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_401.txt"      2>/dev/null || touch "$DIR_DISC/alive_401.txt"
  grep -E '\[(500|502|503)\]'  "$DIR_DISC/alive_detailed.txt" > "$DIR_DISC/alive_5xx.txt"      2>/dev/null || touch "$DIR_DISC/alive_5xx.txt"

  info "200 OK       : $(count "$DIR_DISC/alive_200.txt")"
  info "Redirects    : $(count "$DIR_DISC/alive_redirect.txt")"
  info "403 Forbidden: $(count "$DIR_DISC/alive_403.txt")"
  info "401 Unauth   : $(count "$DIR_DISC/alive_401.txt")"
  info "5xx Errors   : $(count "$DIR_DISC/alive_5xx.txt")"

  # ★ FIX: extrai tecnologias corretamente — só colchetes após o status code (campo 2+)
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

  if ! "$HAS_NAABU"; then
    warn "naabu não encontrado — pulando port scan"
    warn "Instale: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
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

  if "$skip_screenshots"; then
    warn "Screenshots desativados via --no-screenshots"
    return
  fi

  if ! "$HAS_GOWITNESS"; then
    warn "gowitness não encontrado — pulando screenshots"
    warn "Instale: go install github.com/sensepost/gowitness@latest"
    return
  fi

  log "Capturando screenshots com gowitness..."
  gowitness scan file \
    -f "$DIR_DISC/alive.txt" \
    --screenshot-path "$DIR_SHOTS" \
    --threads "$threads" \
    --timeout "$timeout" \
    2>>"$error_log" || true

  local shot_count
  shot_count=$(find "$DIR_SHOTS" -name "*.png" 2>/dev/null | wc -l)
  success "Screenshots capturadas: $shot_count"
}

# ============================================================
# 05 — SUBDOMAIN TAKEOVER
# ============================================================
step_takeover() {
  section "05 / SUBDOMAIN TAKEOVER CHECK"

  if ! "$HAS_SUBZY"; then
    warn "subzy não encontrado — pulando takeover check"
    warn "Instale: go install github.com/PentestPad/subzy@latest"
    touch "$DIR_EXTRA/takeover.txt"
    return
  fi

  log "Verificando subdomain takeover com subzy..."
  subzy run \
    --targets "$DIR_DISC/subs_all.txt" \
    --output "$DIR_EXTRA/takeover.txt" \
    --hide-fails \
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

  log "GAU (CommonCrawl + OTX + URLScan)..."
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
  success "URLs limpas (sem estáticos): $(count "$DIR_URLS/urls_clean.txt")"

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
# 08 — JS ANALYSIS
# ============================================================
step_js() {
  section "08 / ANÁLISE DE ARQUIVOS JS"

  if is_empty "$DIR_JS/js_files.txt"; then
    warn "Nenhum arquivo JS encontrado"
    touch "$DIR_JS/js_endpoints.txt" "$DIR_JS/js_secrets.txt"
    return
  fi

  log "Extraindo endpoints de arquivos JS (limit: $limit_js_endpoints arquivos)..."

  while IFS= read -r jsurl; do
    curl -sk --max-time "$timeout" "$jsurl" 2>>"$error_log" \
      | grep -oE "(https?://[^\"\\'> ]+|/[a-zA-Z0-9_/.-]{3,})" \
      | grep -v "^//$" \
      >> "$DIR_JS/js_endpoints_raw.txt" 2>/dev/null || true
    curl_throttle
  done < <(head -n "$limit_js_endpoints" "$DIR_JS/js_files.txt")

  sort -u "$DIR_JS/js_endpoints_raw.txt" > "$DIR_JS/js_endpoints.txt" 2>/dev/null || touch "$DIR_JS/js_endpoints.txt"
  success "Endpoints extraídos de JS: $(count "$DIR_JS/js_endpoints.txt")"

  log "Procurando secrets em JS (limit: $limit_js_secrets arquivos)..."

  local secret_patterns=(
    'api[_-]?key\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{20,}'
    'secret[_-]?key\s*[:=]\s*["'"'"'][a-zA-Z0-9_\-]{20,}'
    'access[_-]?token\s*[:=]\s*["'"'"'][a-zA-Z0-9_.\-]{20,}'
    'password\s*[:=]\s*["'"'"'][^"'"'"']{8,}'
    'bearer\s+[a-zA-Z0-9_.\-]{20,}'
    'AKIA[0-9A-Z]{16}'
    'ghp_[a-zA-Z0-9]{36}'
    'ghs_[a-zA-Z0-9]{36}'
    'eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*'
    'AIza[0-9A-Za-z\-_]{35}'
    'sk-[a-zA-Z0-9]{40,}'
    'SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43,}'
  )

  while IFS= read -r jsurl; do
    local content
    content=$(curl -sk --max-time "$timeout" "$jsurl" 2>>"$error_log")
    for pattern in "${secret_patterns[@]}"; do
      echo "$content" | grep -iE "$pattern" | while IFS= read -r match; do
        echo "[JS: $jsurl]  $match" >> "$DIR_JS/js_secrets.txt"
      done
    done
    curl_throttle
  done < <(head -n "$limit_js_secrets" "$DIR_JS/js_files.txt")

  if ! is_empty "$DIR_JS/js_secrets.txt" 2>/dev/null; then
    success "Possíveis secrets em JS: $(count "$DIR_JS/js_secrets.txt")"
  else
    info "Nenhum secret encontrado em JS"
    touch "$DIR_JS/js_secrets.txt"
  fi

  if "$HAS_TRUFFLEHOG"; then
    log "Rodando TruffleHog nos arquivos JS..."
    while IFS= read -r jsurl; do
      trufflehog --json "$jsurl" 2>>"$error_log" >> "$DIR_JS/trufflehog.txt" || true
    done < <(head -n "$limit_js_secrets" "$DIR_JS/js_files.txt")
    success "TruffleHog: $(count "$DIR_JS/trufflehog.txt") findings"
  fi
}

# ============================================================
# 09 — PARAMETER EXTRACTION
# ============================================================
step_params() {
  section "09 / EXTRAÇÃO DE PARÂMETROS"

  grep "?" "$DIR_URLS/urls_clean.txt" | grep "=" | sort -u > "$DIR_PARAMS/params_raw.txt"
  success "URLs com parâmetros (raw): $(count "$DIR_PARAMS/params_raw.txt")"

  uro < "$DIR_PARAMS/params_raw.txt" | sort -u > "$DIR_PARAMS/params.txt"
  success "Parâmetros únicos (após uro): $(count "$DIR_PARAMS/params.txt")"

  qsreplace FUZZ < "$DIR_PARAMS/params.txt" | sort -u > "$DIR_PARAMS/params_fuzz.txt"
  success "Params normalizados para fuzzing: $(count "$DIR_PARAMS/params_fuzz.txt")"

  log "Validando quais parâmetros ainda respondem..."
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

  if "$HAS_ARJUN" && ! is_empty "$DIR_DISC/alive.txt"; then
    log "Rodando Arjun (descoberta de parâmetros hidden, limit: $limit_arjun hosts)..."
    head -n "$limit_arjun" "$DIR_DISC/alive.txt" | while IFS= read -r url; do
      arjun -u "$url" --stable -oT "$DIR_PARAMS/arjun_raw.txt" 2>>"$error_log" || true
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

  local patterns=(xss sqli lfi rce ssrf redirect ssti idor debug-pages upload interestingparams aws-keys cors)

  for pattern in "${patterns[@]}"; do
    local outfile="$DIR_VULNS/${pattern}.txt"
    gf "$pattern" < "$DIR_PARAMS/params.txt" > "$outfile" 2>>"$error_log" || touch "$outfile"
    local n
    n=$(count "$outfile")
    if [[ "$n" -gt 0 ]]; then
      success "gf $pattern: $n candidatos"
    else
      info    "gf $pattern: 0 candidatos"
    fi
  done
}

# ============================================================
# 11 — DIRECTORY BRUTEFORCE (ffuf)
# ============================================================
step_ffuf() {
  section "11 / DIRECTORY BRUTEFORCE (ffuf)"

  if ! "$HAS_FFUF"; then
    warn "ffuf não encontrado — pulando bruteforce"
    warn "Instale: go install github.com/ffuf/ffuf/v2@latest"
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
    warn "Nenhuma wordlist encontrada para ffuf"
    warn "Instale: sudo apt install seclists"
    return
  fi

  log "Rodando ffuf em $limit_ffuf hosts (wordlist: $wordlist)..."
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
  success "ffuf finalizado: $ffuf_count arquivos gerados"
}

# ============================================================
# 12 — CORS CHECK
# ============================================================
step_cors() {
  section "12 / CORS MISCONFIGURATION CHECK"

  log "Testando CORS em $limit_cors hosts ativos..."
  local found=0

  while IFS= read -r url; do
    local resp
    resp=$(curl -sk --max-time "$timeout" \
      -H "Origin: https://evil.com" \
      -H "Access-Control-Request-Method: GET" \
      -I "$url" 2>>"$error_log")

    local acao
    acao=$(echo "$resp" | grep -i "access-control-allow-origin" | tr -d '\r')

    if echo "$acao" | grep -qiE "(evil\.com|\*)"; then
      echo "[CORS VULN] $url" >> "$DIR_EXTRA/cors_vuln.txt"
      echo "  → $acao"       >> "$DIR_EXTRA/cors_vuln.txt"
      found=$((found + 1))
    fi
    curl_throttle
  done < <(head -n "$limit_cors" "$DIR_DISC/alive.txt")

  if [[ $found -gt 0 ]]; then
    success "CORS vulnerável: $found hosts → $DIR_EXTRA/cors_vuln.txt"
  else
    info "CORS: nenhuma misconfiguração encontrada"
    touch "$DIR_EXTRA/cors_vuln.txt"
  fi
}

# ============================================================
# 13 — SECURITY HEADERS CHECK
# ============================================================
step_headers() {
  section "13 / SECURITY HEADERS CHECK"

  log "Verificando headers de segurança em $limit_headers hosts..."

  while IFS= read -r url; do
    local headers
    headers=$(curl -sk --max-time "$timeout" -I "$url" 2>>"$error_log")

    local issues=()
    echo "$headers" | grep -qi "strict-transport-security" || issues+=("Missing-HSTS")
    echo "$headers" | grep -qi "x-frame-options"           || issues+=("Missing-X-Frame-Options")
    echo "$headers" | grep -qi "x-content-type-options"    || issues+=("Missing-X-Content-Type-Options")
    echo "$headers" | grep -qi "content-security-policy"   || issues+=("Missing-CSP")
    echo "$headers" | grep -qi "referrer-policy"            || issues+=("Missing-Referrer-Policy")
    echo "$headers" | grep -qi "permissions-policy"         || issues+=("Missing-Permissions-Policy")

    local server xpb
    server=$(echo "$headers" | grep -i "^server:"        | tr -d '\r')
    xpb=$(echo    "$headers" | grep -i "^x-powered-by:" | tr -d '\r')
    [[ -n "$server" ]] && issues+=("Info-Disclosure: $server")
    [[ -n "$xpb"    ]] && issues+=("Info-Disclosure: $xpb")

    if [[ ${#issues[@]} -gt 0 ]]; then
      echo "$url" >> "$DIR_EXTRA/headers_issues.txt"
      for issue in "${issues[@]}"; do
        echo "  → $issue" >> "$DIR_EXTRA/headers_issues.txt"
      done
    fi
    curl_throttle
  done < <(head -n "$limit_headers" "$DIR_DISC/alive.txt")

  local n
  n=$(grep -c "^http" "$DIR_EXTRA/headers_issues.txt" 2>/dev/null || echo 0)
  if [[ "$n" -gt 0 ]]; then
    warn "Hosts com problemas de headers: $n → $DIR_EXTRA/headers_issues.txt"
  else
    info "Security headers: sem issues críticos encontrados"
    touch "$DIR_EXTRA/headers_issues.txt"
  fi
}

# ============================================================
# 14 — SENSITIVE FILES CHECK
# ============================================================
step_sensitive() {
  section "14 / ARQUIVOS SENSÍVEIS"

  log "Verificando arquivos e endpoints sensíveis em $limit_sensitive hosts..."

  local sensitive_endpoints=(
    ".git/HEAD" ".git/config" ".svn/entries"
    ".env" ".env.backup" ".env.local" ".env.production"
    "config.php" "wp-config.php" "config.js" "config.json"
    "database.yml" "settings.py" "application.properties"
    "robots.txt" "sitemap.xml" "crossdomain.xml" "security.txt"
    "phpinfo.php" "info.php" "test.php" "debug.php"
    "backup.zip" "backup.sql" "dump.sql" "db.sql" "backup.tar.gz"
    ".htaccess" ".htpasswd" "web.config"
    "composer.json" "package.json" "yarn.lock" "Gemfile"
    "Dockerfile" "docker-compose.yml" ".dockerenv"
    "api-docs" "swagger.json" "swagger.yaml" "openapi.json"
    "graphql" "graphiql" "graphql/playground"
    "adminer.php" "phpmyadmin" "server-status" "server-info"
    "_profiler" "trace" "actuator" "actuator/env" "actuator/health"
    "metrics" "health" "status" "ping" "version"
  )

  local found=0
  while IFS= read -r host; do
    for endpoint in "${sensitive_endpoints[@]}"; do
      local url="${host}/${endpoint}"
      local status
      status=$(curl -sk --max-time "$timeout" -o /dev/null -w "%{http_code}" "$url" 2>>"$error_log")
      if [[ "$status" =~ ^(200|301|302|403)$ ]]; then
        echo "[$status] $url" >> "$DIR_EXTRA/sensitive_files.txt"
        found=$((found + 1))
      fi
      curl_throttle
    done
  done < <(head -n "$limit_sensitive" "$DIR_DISC/alive.txt")

  if [[ $found -gt 0 ]]; then
    success "Arquivos/endpoints sensíveis: $found → $DIR_EXTRA/sensitive_files.txt"
  else
    info "Nenhum arquivo sensível acessível"
    touch "$DIR_EXTRA/sensitive_files.txt"
  fi
}

# ============================================================
# 15 — XSS SCAN (Dalfox)
# ============================================================
step_xss() {
  section "15 / XSS SCAN (Dalfox)"

  if is_empty "$DIR_VULNS/xss.txt"; then
    warn "Nenhum candidato XSS — pulando Dalfox"
    touch "$DIR_SCANS/dalfox.txt"
    return
  fi

  log "Rodando Dalfox em $(count "$DIR_VULNS/xss.txt") candidatos..."
  dalfox file "$DIR_VULNS/xss.txt" \
    --silence \
    --skip-bav \
    --timeout "$timeout" \
    --worker "$max_dalfox_workers" \
    --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
    -o "$DIR_SCANS/dalfox.txt" 2>>"$error_log" || true

  success "Dalfox: $(count "$DIR_SCANS/dalfox.txt") XSS confirmados"
}

# ============================================================
# 16 — SQLi SCAN (SQLMap)  ★ FIX: xargs seguro contra injeção de shell
# ============================================================
step_sqli() {
  section "16 / SQLi SCAN (SQLMap)"

  touch "$DIR_SCANS/sqli_results.txt"

  if is_empty "$DIR_VULNS/sqli.txt"; then
    warn "Nenhum candidato SQLi — pulando SQLMap"
    touch "$DIR_SCANS/sqli_confirmed.txt"
    return
  fi

  local candidates
  candidates=$(count "$DIR_VULNS/sqli.txt")
  local limit=$max_sqli
  [[ $candidates -lt $limit ]] && limit=$candidates

  log "Rodando SQLMap em $limit candidatos (5 paralelo)..."

  local sqli_out="$DIR_SCANS/sqli_results.txt"
  local sqli_dir="$DIR_SCANS/sqli_output"

  # ★ FIX: usa arquivo temporário com NUL-delimitado para evitar injeção de shell via xargs
  local tmp_sqli
  tmp_sqli=$(mktemp)
  head -n "$limit" "$DIR_VULNS/sqli.txt" | while IFS= read -r url; do
    printf '%s\0' "$url"
  done > "$tmp_sqli"

  xargs -0 -P 5 -I{} bash -c '
    sqlmap -u "$1" \
      --batch \
      --level=1 \
      --risk=1 \
      --random-agent \
      --timeout='"$timeout"' \
      --retries=1 \
      --forms \
      --output-dir="'"$sqli_dir"'" \
      >> "'"$sqli_out"'" 2>/dev/null
  ' _ {} < "$tmp_sqli"

  rm -f "$tmp_sqli"

  grep -iE "is vulnerable|Parameter.*injectable|sqlmap identified" \
    "$sqli_out" > "$DIR_SCANS/sqli_confirmed.txt" 2>/dev/null || touch "$DIR_SCANS/sqli_confirmed.txt"

  success "SQLMap finalizado"
  info "SQLi confirmados: $(count "$DIR_SCANS/sqli_confirmed.txt")"
}

# ============================================================
# 17 — LFI CHECK  ★ FIX: trata resposta base64 do php://filter
# ============================================================
step_lfi() {
  section "17 / LFI CHECK"

  touch "$DIR_SCANS/lfi_results.txt"

  if is_empty "$DIR_VULNS/lfi.txt"; then
    warn "Nenhum candidato LFI"
    return
  fi

  log "Testando LFI em $(count "$DIR_VULNS/lfi.txt") candidatos (limit: $limit_lfi)..."

  local payloads=(
    "../../../../etc/passwd"
    "../../../../etc/shadow"
    "../../../../etc/hosts"
    "../../../../proc/self/environ"
    "....//....//....//....//etc/passwd"
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "php://filter/convert.base64-encode/resource=index"
    "/etc/passwd"
  )

  while IFS= read -r url; do
    for payload in "${payloads[@]}"; do
      local test_url
      test_url=$(echo "$url" | sed "s/=[^&]*/=$(printf '%s' "$payload" | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))' 2>/dev/null || echo "$payload")/g")
      local resp
      resp=$(curl -sk --max-time "$timeout" "$test_url" 2>>"$error_log")

      # Detecção clássica (/etc/passwd)
      if echo "$resp" | grep -qE "root:x:|bin:x:|daemon:x:|nobody:x:"; then
        echo "[LFI CONFIRMED] $test_url" >> "$DIR_SCANS/lfi_results.txt"
        warn "LFI CONFIRMADO (passwd): $test_url"

      # ★ FIX: Detecção via php://filter — resposta em base64
      elif [[ "$payload" == *"php://filter"* ]]; then
        local decoded
        decoded=$(echo "$resp" | tr -d '\n' | grep -oE '[A-Za-z0-9+/]{40,}={0,2}' \
          | head -1 | base64 -d 2>/dev/null || true)
        if echo "$decoded" | grep -qE "root:x:|bin:x:|<\?php"; then
          echo "[LFI CONFIRMED via base64-filter] $test_url" >> "$DIR_SCANS/lfi_results.txt"
          warn "LFI CONFIRMADO (php://filter): $test_url"
        fi
      fi
      curl_throttle
    done
  done < <(head -n "$limit_lfi" "$DIR_VULNS/lfi.txt")

  success "LFI confirmados: $(count "$DIR_SCANS/lfi_results.txt")"
}

# ============================================================
# 18 — OPEN REDIRECT CHECK
# ============================================================
step_redirect() {
  section "18 / OPEN REDIRECT CHECK"

  touch "$DIR_SCANS/redirect_results.txt"

  if is_empty "$DIR_VULNS/redirect.txt"; then
    warn "Nenhum candidato open redirect"
    return
  fi

  log "Testando open redirect em $(count "$DIR_VULNS/redirect.txt") candidatos (limit: $limit_redirect)..."

  local payloads=(
    "https://evil.com"
    "//evil.com"
    "//evil.com/%2F%2E%2E"
    "/\\\\evil.com"
    "https:evil.com"
  )

  while IFS= read -r url; do
    for payload in "${payloads[@]}"; do
      local test_url
      test_url=$(echo "$url" | sed "s/=[^&]*/=$payload/g")
      local location
      location=$(curl -sk --max-time "$timeout" -I "$test_url" 2>>"$error_log" \
        | grep -i "^location:" | tr -d '\r')
      if echo "$location" | grep -qiE "evil\.com"; then
        echo "[REDIRECT VULN] $test_url" >> "$DIR_SCANS/redirect_results.txt"
        echo "  → $location"            >> "$DIR_SCANS/redirect_results.txt"
      fi
      curl_throttle
    done
  done < <(head -n "$limit_redirect" "$DIR_VULNS/redirect.txt")

  success "Open redirects confirmados: $(count "$DIR_SCANS/redirect_results.txt")"
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

  echo | tee -a "$log_file"
  [[ $(count "$DIR_SCANS/nuclei_critical.txt") -gt 0 ]] && error  "Nuclei CRITICAL : $(count "$DIR_SCANS/nuclei_critical.txt")"
  [[ $(count "$DIR_SCANS/nuclei_high.txt")     -gt 0 ]] && warn   "Nuclei HIGH     : $(count "$DIR_SCANS/nuclei_high.txt")"
  [[ $(count "$DIR_SCANS/nuclei_medium.txt")   -gt 0 ]] && info   "Nuclei MEDIUM   : $(count "$DIR_SCANS/nuclei_medium.txt")"
}

# ============================================================
# 20 — RELATÓRIO DE URLs VULNERÁVEIS  ★ NOVO
# ============================================================
step_vuln_report() {
  section "20 / RELATÓRIO DE URLs VULNERÁVEIS"

  local report="$DIR_REPORT/vuln_urls.txt"
  local report_json="$DIR_REPORT/vuln_urls.json"
  touch "$report"

  log "Consolidando todas as URLs possivelmente vulneráveis..."

  # ──────────────────────────────────────────────
  # Bloco: XSS confirmados (Dalfox)
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_SCANS/dalfox.txt"; then
    echo "================================================================" >> "$report"
    echo "  [XSS CONFIRMADO — Dalfox]" >> "$report"
    echo "================================================================" >> "$report"
    grep -oP 'https?://[^\s"]+' "$DIR_SCANS/dalfox.txt" | sort -u >> "$report" 2>/dev/null || true
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: SQLi confirmados (SQLMap)
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_SCANS/sqli_confirmed.txt"; then
    echo "================================================================" >> "$report"
    echo "  [SQLi CONFIRMADO — SQLMap]" >> "$report"
    echo "================================================================" >> "$report"
    grep -oP 'https?://[^\s"]+' "$DIR_SCANS/sqli_confirmed.txt" | sort -u >> "$report" 2>/dev/null || true
    cat "$DIR_SCANS/sqli_confirmed.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: LFI confirmados
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_SCANS/lfi_results.txt"; then
    echo "================================================================" >> "$report"
    echo "  [LFI CONFIRMADO]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_SCANS/lfi_results.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Open Redirect confirmados
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_SCANS/redirect_results.txt"; then
    echo "================================================================" >> "$report"
    echo "  [OPEN REDIRECT CONFIRMADO]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_SCANS/redirect_results.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: CORS vulnerável
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_EXTRA/cors_vuln.txt"; then
    echo "================================================================" >> "$report"
    echo "  [CORS MISCONFIGURATION]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_EXTRA/cors_vuln.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Nuclei Critical
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_SCANS/nuclei_critical.txt"; then
    echo "================================================================" >> "$report"
    echo "  [NUCLEI — CRITICAL]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_SCANS/nuclei_critical.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Nuclei High
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_SCANS/nuclei_high.txt"; then
    echo "================================================================" >> "$report"
    echo "  [NUCLEI — HIGH]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_SCANS/nuclei_high.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Secrets em JS
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_JS/js_secrets.txt"; then
    echo "================================================================" >> "$report"
    echo "  [SECRETS EM ARQUIVOS JS]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_JS/js_secrets.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Subdomain Takeover
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_EXTRA/takeover.txt"; then
    echo "================================================================" >> "$report"
    echo "  [SUBDOMAIN TAKEOVER]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_EXTRA/takeover.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Arquivos sensíveis expostos (200 OK)
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_EXTRA/sensitive_files.txt"; then
    echo "================================================================" >> "$report"
    echo "  [ARQUIVOS SENSÍVEIS EXPOSTOS]" >> "$report"
    echo "================================================================" >> "$report"
    grep "^\[200\]" "$DIR_EXTRA/sensitive_files.txt" >> "$report" 2>/dev/null || true
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: Candidatos de alta prioridade (gf)
  # ──────────────────────────────────────────────
  echo "================================================================" >> "$report"
  echo "  [CANDIDATOS DE ALTA PRIORIDADE — GF PATTERNS]" >> "$report"
  echo "  (não confirmados, mas de alto interesse para testes manuais)" >> "$report"
  echo "================================================================" >> "$report"
  for vuln_type in rce ssrf ssti sqli xss lfi; do
    local f="$DIR_VULNS/${vuln_type}.txt"
    if ! is_empty "$f"; then
      echo "" >> "$report"
      echo "  --- $vuln_type ($(count "$f") candidatos) ---" >> "$report"
      head -n 20 "$f" >> "$report"
      [[ $(count "$f") -gt 20 ]] && echo "  ... (ver $f para lista completa)" >> "$report"
    fi
  done
  echo >> "$report"

  # ──────────────────────────────────────────────
  # Bloco: Portas interessantes
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_DISC/ports_interesting.txt"; then
    echo "================================================================" >> "$report"
    echo "  [PORTAS INTERESSANTES ABERTAS]" >> "$report"
    echo "================================================================" >> "$report"
    cat "$DIR_DISC/ports_interesting.txt" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Bloco: URLs Admin / painéis de login
  # ──────────────────────────────────────────────
  if ! is_empty "$DIR_URLS/urls_admin.txt"; then
    echo "================================================================" >> "$report"
    echo "  [PAINÉIS ADMIN / LOGIN ENCONTRADOS]" >> "$report"
    echo "================================================================" >> "$report"
    head -n 50 "$DIR_URLS/urls_admin.txt" >> "$report"
    [[ $(count "$DIR_URLS/urls_admin.txt") -gt 50 ]] && \
      echo "  ... (ver $DIR_URLS/urls_admin.txt para lista completa)" >> "$report"
    echo >> "$report"
  fi

  # ──────────────────────────────────────────────
  # Gera JSON estruturado para integração externa
  # ──────────────────────────────────────────────
  python3 - <<PYEOF > "$report_json" 2>/dev/null || true
import json, os

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
    "confirmed_vulns": {
        "xss":           read_lines("${DIR_SCANS}/dalfox.txt"),
        "sqli":          read_lines("${DIR_SCANS}/sqli_confirmed.txt"),
        "lfi":           read_lines("${DIR_SCANS}/lfi_results.txt"),
        "open_redirect": read_lines("${DIR_SCANS}/redirect_results.txt"),
        "cors":          read_lines("${DIR_EXTRA}/cors_vuln.txt"),
        "takeover":      read_lines("${DIR_EXTRA}/takeover.txt"),
        "nuclei_critical": read_lines("${DIR_SCANS}/nuclei_critical.txt"),
        "nuclei_high":   read_lines("${DIR_SCANS}/nuclei_high.txt"),
    },
    "high_interest_candidates": {
        "rce":  read_lines("${DIR_VULNS}/rce.txt", 50),
        "ssrf": read_lines("${DIR_VULNS}/ssrf.txt", 50),
        "ssti": read_lines("${DIR_VULNS}/ssti.txt", 50),
    },
    "exposures": {
        "js_secrets":       read_lines("${DIR_JS}/js_secrets.txt"),
        "sensitive_files":  read_lines("${DIR_EXTRA}/sensitive_files.txt"),
        "admin_panels":     read_lines("${DIR_URLS}/urls_admin.txt", 100),
        "interesting_ports": read_lines("${DIR_DISC}/ports_interesting.txt"),
    }
}

print(json.dumps(data, indent=2, ensure_ascii=False))
PYEOF

  # ──────────────────────────────────────────────
  # Exibe resumo na tela
  # ──────────────────────────────────────────────
  local total_confirmed=0
  local n_xss n_sqli n_lfi n_redir n_cors n_crit n_high n_secrets n_takeover n_sensitive n_admin

  n_xss=$(grep -c "https://" "$DIR_SCANS/dalfox.txt" 2>/dev/null || echo 0)
  n_sqli=$(count "$DIR_SCANS/sqli_confirmed.txt")
  n_lfi=$(count "$DIR_SCANS/lfi_results.txt")
  n_redir=$(grep -c "REDIRECT VULN" "$DIR_SCANS/redirect_results.txt" 2>/dev/null || echo 0)
  n_cors=$(grep -c "CORS VULN" "$DIR_EXTRA/cors_vuln.txt" 2>/dev/null || echo 0)
  n_crit=$(count "$DIR_SCANS/nuclei_critical.txt")
  n_high=$(count "$DIR_SCANS/nuclei_high.txt")
  n_secrets=$(count "$DIR_JS/js_secrets.txt")
  n_takeover=$(count "$DIR_EXTRA/takeover.txt")
  n_sensitive=$(grep -c "^\[200\]" "$DIR_EXTRA/sensitive_files.txt" 2>/dev/null || echo 0)
  n_admin=$(count "$DIR_URLS/urls_admin.txt")

  total_confirmed=$((n_xss + n_sqli + n_lfi + n_redir + n_cors + n_crit + n_high))

  echo | tee -a "$log_file"
  echo -e "${BOLD}${LRED}" | tee -a "$log_file"
  echo "  ╔══════════════════════════════════════════════════════════════╗" | tee -a "$log_file"
  echo "  ║              URLs POSSIVELMENTE VULNERÁVEIS                 ║" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  echo -e "${NC}${BOLD}" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "VULNERABILIDADES CONFIRMADAS" "" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "XSS confirmados (Dalfox):"   "$n_xss"      | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "SQLi confirmados (SQLMap):"  "$n_sqli"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "LFI confirmados:"            "$n_lfi"      | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Open Redirect confirmados:"  "$n_redir"    | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "CORS vulnerável:"            "$n_cors"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Nuclei CRITICAL:"            "$n_crit"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Nuclei HIGH:"                "$n_high"     | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Subdomain Takeover:"         "$n_takeover" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "EXPOSIÇÕES E ALVOS DE INTERESSE" ""         | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Secrets em JS:"              "$n_secrets"  | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Arquivos sensíveis (200 OK):" "$n_sensitive"| tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Painéis Admin/Login:"        "$n_admin"    | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "TOTAL CONFIRMADOS:"  "$total_confirmed"    | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Relatório TXT:"  "$report"                 | tee -a "$log_file"
  printf "  ║  %-40s %-19s ║\n" "Relatório JSON:" "$report_json"            | tee -a "$log_file"
  echo "  ╚══════════════════════════════════════════════════════════════╝" | tee -a "$log_file"
  echo -e "${NC}" | tee -a "$log_file"

  if [[ $total_confirmed -gt 0 ]]; then
    error "⚠  $total_confirmed vulnerabilidades confirmadas! Veja: $report"
  else
    info "Nenhuma vulnerabilidade diretamente confirmada. Analise os candidatos GF manualmente."
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
  echo "  ║                  RECON FINALIZADO — RESUMO                  ║" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Alvo:"      "$domain"      | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Duração:"   "$elapsed_fmt" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Modo deep:" "$deep_mode"   | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Erros no errors.log:" "$errors_count linhas" | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Subdomínios:"         "$(count "$DIR_DISC/subs_all.txt")"          | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Hosts ativos:"        "$(count "$DIR_DISC/alive.txt")"             | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "URLs coletadas:"      "$(count "$DIR_URLS/urls_all.txt")"          | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "URLs PHP:"            "$(count "$DIR_URLS/urls_php.txt")"          | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "URLs Admin/Login:"    "$(count "$DIR_URLS/urls_admin.txt")"        | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Arquivos JS:"         "$(count "$DIR_JS/js_files.txt")"            | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Parâmetros únicos:"   "$(count "$DIR_PARAMS/params.txt")"          | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Arquivos sensíveis:"  "$(count "$DIR_EXTRA/sensitive_files.txt")"  | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Secrets em JS:"       "$(count "$DIR_JS/js_secrets.txt")"          | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "XSS candidatos (gf):"      "$(count "$DIR_VULNS/xss.txt")"         | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "SQLi candidatos (gf):"     "$(count "$DIR_VULNS/sqli.txt")"        | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "LFI candidatos (gf):"      "$(count "$DIR_VULNS/lfi.txt")"         | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "SSRF candidatos (gf):"     "$(count "$DIR_VULNS/ssrf.txt")"        | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "RCE candidatos (gf):"      "$(count "$DIR_VULNS/rce.txt")"         | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "SSTI candidatos (gf):"     "$(count "$DIR_VULNS/ssti.txt")"        | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Redirect candidatos (gf):" "$(count "$DIR_VULNS/redirect.txt")"    | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "XSS confirmados (Dalfox):"  "$(count "$DIR_SCANS/dalfox.txt")"          | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "SQLi confirmados:"           "$(count "$DIR_SCANS/sqli_confirmed.txt")"  | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "LFI confirmados:"            "$(count "$DIR_SCANS/lfi_results.txt")"     | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Open redirect confirmados:"  "$(count "$DIR_SCANS/redirect_results.txt")"| tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "CORS vulneráveis:"           "$(count "$DIR_EXTRA/cors_vuln.txt")"       | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Nuclei CRITICAL:"            "$(count "$DIR_SCANS/nuclei_critical.txt")" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Nuclei HIGH:"                "$(count "$DIR_SCANS/nuclei_high.txt")"     | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Nuclei MEDIUM:"              "$(count "$DIR_SCANS/nuclei_medium.txt")"   | tee -a "$log_file"
  echo "  ╠══════════════════════════════════════════════════════════════╣" | tee -a "$log_file"
  printf "  ║  %-30s %-29s ║\n" "Pasta do scan:" "$scan_dir" | tee -a "$log_file"
  echo "  ╚══════════════════════════════════════════════════════════════╝" | tee -a "$log_file"
  echo -e "${NC}" | tee -a "$log_file"

  echo -e "${BOLD}  ESTRUTURA DA PASTA:${NC}"
  echo -e "  ${CYAN}${scan_dir}/${NC}"
  echo -e "  ├── ${GREEN}01_discovery/${NC}    subdomínios (subfinder+assetfinder+findomain+amass), hosts, ports"
  echo -e "  ├── ${GREEN}02_urls/${NC}         todas as URLs (wayback, gau, katana, filtros)"
  echo -e "  ├── ${GREEN}03_params/${NC}       parâmetros, fuzzing, arjun"
  echo -e "  ├── ${GREEN}04_vulns/${NC}        candidatos gf (xss, sqli, lfi, rce, ssrf...)"
  echo -e "  ├── ${GREEN}05_scans/${NC}        resultados dalfox, sqlmap, nuclei, lfi, redirect"
  echo -e "  ├── ${GREEN}06_screenshots/${NC}  capturas de tela dos hosts"
  echo -e "  ├── ${GREEN}07_js/${NC}           arquivos JS, endpoints, secrets"
  echo -e "  ├── ${GREEN}08_extra/${NC}        CORS, headers, ffuf, takeover, arquivos sensíveis"
  echo -e "  ├── ${GREEN}09_report/${NC}       ★ vuln_urls.txt + vuln_urls.json (URLs vulneráveis)"
  echo -e "  ├── ${GREEN}recon.log${NC}        log completo do scan"
  echo -e "  └── ${GREEN}errors.log${NC}       ★ erros de ferramentas (antes ocultos)"
  echo
  success "Tudo salvo em: $(pwd)/$scan_dir"
  echo
}

# ============================================================
# MAIN
# ============================================================
main() {
  scan_start=$(date +%s)

  parse_args "$@"
  banner
  setup_dirs

  echo -e "  ${BOLD}Alvo     :${NC} ${LCYAN}${domain}${NC}"
  echo -e "  ${BOLD}Threads  :${NC} ${threads}"
  echo -e "  ${BOLD}Deep mode:${NC} ${deep_mode}"
  echo -e "  ${BOLD}Scans    :${NC} $( "$skip_scans" && echo "desativados (--skip-scans)" || echo "ativados" )"
  echo -e "  ${BOLD}Pasta    :${NC} ${CYAN}${scan_dir}${NC}"
  echo -e "  ${BOLD}Limits   :${NC} cors=${limit_cors} headers=${limit_headers} sensitive=${limit_sensitive} lfi=${limit_lfi} redirect=${limit_redirect}"
  echo

  check_deps

  step_subdomains
  step_alive
  step_ports
  step_screenshots
  step_takeover
  step_urls
  step_filter_urls
  step_js
  step_params
  step_gf
  step_ffuf
  step_cors
  step_headers
  step_sensitive

  if ! "$skip_scans"; then
    step_xss
    step_sqli
    step_lfi
    step_redirect
    step_nuclei
  else
    warn "Scans ativos pulados via --skip-scans"
    touch "$DIR_SCANS/dalfox.txt" "$DIR_SCANS/sqli_confirmed.txt" \
          "$DIR_SCANS/lfi_results.txt" "$DIR_SCANS/redirect_results.txt" \
          "$DIR_SCANS/nuclei_all.txt" "$DIR_SCANS/nuclei_critical.txt" \
          "$DIR_SCANS/nuclei_high.txt" "$DIR_SCANS/nuclei_medium.txt"
  fi

  step_vuln_report   # ★ sempre roda, independente de --skip-scans
  final_summary
}

main "$@"
