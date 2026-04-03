<div align="center">

**Full Automated Reconnaissance Framework v2.0 (Python)**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com)
[![Version](https://img.shields.io/badge/Version-2.0-red?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com)

> **⚠ USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA. Uso não autorizado é ilegal.**

[Funcionalidades](#-funcionalidades) · [O que há de novo](#-o-que-há-de-novo-na-v20) · [Instalação](#-instalação) · [Uso](#-uso) · [Módulos](#-módulos-de-scan) · [Relatório](#-relatório-de-saída) · [FAQ](#-faq)

</div>

---

## 📋 Sobre

**recon.py** é um framework de reconhecimento ofensivo totalmente automatizado, desenvolvido para profissionais de segurança, pentesters e bug bounty hunters. Com um único comando, executa uma cadeia completa de recon — desde enumeração de subdomínios até detecção de vulnerabilidades — entregando um relatório consolidado pronto para exploração.

A v2.0 é uma reescrita completa da v1.0 (Bash) para **Python nativo**, trazendo concorrência real via `ThreadPoolExecutor`, gerenciamento de estado robusto com `dataclass`, melhor tratamento de erros, retries com backoff exponencial e integração nativa com JSON e APIs externas.

---

## 🆕 O que há de novo na v2.0

### Migração Bash → Python

| Aspecto | v1.0 (Bash) | v2.0 (Python) |
|--------|------------|--------------|
| Concorrência | subshells & `&` | `ThreadPoolExecutor` nativo |
| Estado global | variáveis de ambiente | `dataclass Config` tipado |
| Tratamento de erros | `set -e` frágil | `try/except` granular por etapa |
| Retries | loop manual bash | backoff exponencial com jitter |
| JSON/APIs | `jq` externo | `json` stdlib nativo |
| Portabilidade | Linux/macOS limitado | Python 3.8+ em qualquer plataforma |

### Novidades e melhorias da v2.0

| # | Feature | Descrição |
|---|---------|-----------|
| 🧠 | **Inteligência Adaptativa** | Detecta WAF e ajusta automaticamente toda a estratégia: delays, jitter, tampers, limites |
| 🎯 | **Endpoint Scoring** | Pontuação de risco que prioriza endpoints com maior probabilidade de vulnerabilidade |
| 🔇 | **Noise Reduction** | Shuffling de targets, burst pauses e variação de padrões para reduzir fingerprint |
| 🌐 | **Passive Intel** | Recon via crt.sh, ASN/BGP, AlienVault OTX e Shodan sem tocar o alvo |
| ⚡ | **Arjun Paralelo** | Descoberta de parâmetros em múltiplos hosts simultaneamente (5 workers, timeout global) |
| 🔧 | **Bug Fixes Críticos** | 7 bugs corrigidos vs. versão anterior (ver seção abaixo) |

### 🐛 Bugs corrigidos na v2.0

<details>
<summary><b>Ver todos os 7 bugs corrigidos</b></summary>

| Severidade | Bug | Correção |
|-----------|-----|---------|
| 🔴 Crítico | **Arjun travava horas** — loop sequencial sem paralelismo; `timeout=180` por URL × 20 hosts = até 60 min bloqueados | Paralelizado com `ThreadPoolExecutor(5)`, timeout por URL reduzido para 60s, timeout global de 10 min |
| 🔴 Crítico | **Arjun sobrescrevia output** — flag `-oT` com arquivo único causava cada URL sobrescrever o resultado da anterior | Arquivos temporários por URL + merge final deduplicado |
| 🔴 Crítico | **`--stable` no Arjun** — flag que reduz drasticamente as threads internas, agravando o travamento | Substituída por `-t 3` para paralelismo interno controlado |
| 🟠 Alto | **`jitter()` após falha final** — delay desnecessário chamado mesmo após esgotarem todas as tentativas de retry | Movido para dentro do bloco de retry, apenas entre tentativas |
| 🟠 Alto | **Extração de URL frágil no `step_alive()`** — `split()[0]` quebrava com variações de formato do httpx | Substituído por `re.search(r'https?://\S+')` robusto |
| 🟡 Médio | **File handle leaks** — `open(log,'a').write()` sem `with` em `auto_install()` vazava file descriptors | Refatorado com helper `_ilog()` usando `with open()` |
| 🟡 Médio | **Ghauri e wafw00f sequenciais** — loops `for url in targets` sem paralelismo para ferramentas lentas | Paralelizados com `ThreadPoolExecutor` (wafw00f: 5 workers; ghauri: 3 workers) |

</details>

---

## ✨ Funcionalidades

<details>
<summary><b>🔍 Reconhecimento & Descoberta</b></summary>

- **Enumeração de subdomínios** com subfinder, assetfinder, amass, findomain
- **Passive Intel** via crt.sh (Certificate Transparency), AlienVault OTX, HackerTarget, ASN/BGP lookup
- **Shodan** integrado (opcional, com `--shodan-key`)
- **Alive check** com httpx (status, título, tech-detect, content-length, categorização por código HTTP)
- **Port scan** com naabu (top 1000 portas + destaque de portas interessantes)
- **Screenshot** automático com gowitness
- **Subdomain takeover** com subzy
- **Coleta de URLs** via waybackurls + GAU + katana (crawl ativo)
- **Filtragem e categorização** de URLs (PHP, ASP, API, Admin, sensíveis, JS)

</details>

<details>
<summary><b>🛡 Detecção de WAF & Evasão</b></summary>

- **wafw00f** (paralelo, 5 workers) + fingerprint manual (Cloudflare, Akamai, Imperva, F5, ModSecurity, Fortinet…)
- **Inteligência Adaptativa**: após detectar WAF, ajusta automaticamente todo o perfil de scan
- **Jitter** automático (80–430ms) ao detectar WAF ou via `--jitter`
- **User-Agent rotation** com 9 UAs reais (Chrome, Firefox, Safari, mobile, Googlebot, Bingbot)
- **Payload mutation**: variação de encoding, case-mixing, null-byte, alternativas de sintaxe
- **Tamper selection** por fabricante de WAF (tampers específicos para sqlmap)
- **Retry com backoff exponencial** (padrão: 3 tentativas, jitter apenas entre tentativas)

</details>

<details>
<summary><b>⚔ Scanning de Vulnerabilidades</b></summary>

| Vuln | Método |
|------|--------|
| XSS | Manual per-param (12 payloads) + DOM sink analysis + Header injection + Dalfox pipe |
| SQLi | Error-based + Blind time-based (mediana 3 amostras + dupla confirmação) + POST body + SQLMap + Ghauri |
| LFI | 14 payloads (Linux/Windows/PHP Filters/Wrappers) + per-param inject |
| SSRF | Cloud metadata (AWS/GCP/Azure) + canary interno + interactsh OOB |
| SSTI | 8 templates (Jinja2, Twig, ERB, Freemarker, Velocity, Smarty…) |
| XXE | 3 payloads (file read Linux/Windows, blind) via POST XML |
| IDOR | Parâmetros numéricos com PII detection (email, CPF, SSN, credit_card) |
| CRLF | 7 variantes de encoding (URL, Unicode, combinações) |
| Host Header | Body reflection + redirect poisoning (X-Forwarded-Host, X-Host) |
| CORS | Origin reflection + credentials=true detection |
| NoSQL | MongoDB operators (GET `$gt/$ne/$regex` + POST JSON) |
| GraphQL | Introspection + deep schema dump + tipos/campos expostos |
| Open Redirect | 9 variantes de bypass (proto-relative, slashes, @, javascript:) |
| Nuclei | Critical + High + Medium (templates oficiais em hosts + params) |

</details>

<details>
<summary><b>🤖 AI Triage (Anthropic API)</b></summary>

Ao final do scan, todos os findings são coletados e enviados para a API da Anthropic. O modelo retorna:

- **TOP 3 vulnerabilidades críticas** priorizadas por impacto
- **Severidade classificada** para cada finding individual
- **Próximos passos** com comandos específicos prontos para executar
- **Falsos positivos prováveis** identificados e descartados
- **Vetores não testados** sugeridos com base nas tecnologias detectadas

Ative com `--api-key sk-ant-...`

</details>

<details>
<summary><b>📊 Análise de JavaScript</b></summary>

- Extração de endpoints (`https://...` e paths `/...`) de todos os arquivos JS
- Detecção de 16 padrões de secrets: AWS keys (`AKIA`), GitHub tokens (`ghp_`), JWTs, API keys genéricas, Stripe, SendGrid, Slack, Google API, Anthropic, etc.
- **TruffleHog v3** integrado para varredura profunda de secrets
- Análise de **DOM XSS sinks**: `document.write`, `innerHTML`, `eval`, `location.href`, `setTimeout`, etc.

</details>

---

## 🚀 Instalação

### Auto-instalação (recomendado)

```bash
git clone https://github.com/seu-usuario/recon.py
cd recon.py
python3 recon.py --install
```

O `--install` instala automaticamente **tudo** — detecta o gerenciador de pacotes do sistema (apt/yum/pacman/brew) e instala:

- Go language (se não instalado)
- Ferramentas Go obrigatórias: subfinder, httpx, waybackurls, gau, katana, gf, qsreplace, dalfox, nuclei, interactsh-client
- Ferramentas Go opcionais: gowitness, naabu, subzy, ffuf, assetfinder, trufflehog
- Ferramentas Python: uro, arjun, wafw00f, ghauri
- GF Patterns (1ndianl33t)
- Nuclei templates (auto-update)
- SecLists

### Instalação manual

<details>
<summary>Clique para expandir</summary>

**Pré-requisitos:**
```bash
# Python 3.8+
python3 --version

# Go 1.18+
go version
```

**Dependências obrigatórias:**
```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python tools
pip3 install uro arjun wafw00f ghauri --break-system-packages

# System
sudo apt install sqlmap curl python3
```

**Dependências opcionais:**
```bash
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/PentestPad/subzy@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

**GF Patterns:**
```bash
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns
cp /tmp/gf-patterns/*.json ~/.gf/
```

**Certifique-se que o Go bin está no PATH:**
```bash
export PATH=$PATH:$HOME/go/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
```

</details>

---

## 🎯 Uso

### Comandos básicos

```bash
# Scan padrão
python3 recon.py alvo.com

# Modo profundo (máxima cobertura)
python3 recon.py alvo.com --deep

# Stealth (low-and-slow, anti-WAF)
python3 recon.py alvo.com --stealth

# Modo agressivo (máximo throughput)
python3 recon.py alvo.com --aggressive

# Com AI Triage (requer chave Anthropic)
python3 recon.py alvo.com --api-key sk-ant-xxxxxxx

# Com Shodan para passive intel
python3 recon.py alvo.com --shodan-key XXXXXXXXXXXXXXXX

# Pular scans ativos (só recon + coleta)
python3 recon.py alvo.com --skip-scans

# Instalar todas as dependências
python3 recon.py --install
```

### Combinações de flags úteis

```bash
# Bug bounty — cobertura máxima com AI report
python3 recon.py alvo.com --deep --threads 150 --api-key sk-ant-xxx

# Pentest stealth com Shodan
python3 recon.py alvo.com --stealth --shodan-key XXXXX --jitter

# Recon silencioso sem screenshots (CI/CD)
python3 recon.py alvo.com --skip-scans --no-screenshots --no-passive-intel

# Alta velocidade em ambiente sem WAF
python3 recon.py alvo.com --aggressive --threads 200 --deep
```

### Todas as opções

```
Uso: python3 recon.py <dominio> [opções]

  GERAIS
    --threads <n>           Número de threads (padrão: 100)
    --deep                  Modo profundo (mais crawl, mais targets)
    --skip-scans            Pula todos os scans ativos (dalfox, sqlmap, nuclei, etc.)
    --no-screenshots        Pula capturas de tela
    --verbose               Output detalhado
    --timeout <s>           Timeout HTTP em segundos (padrão: 10)
    --api-key <key>         Chave Anthropic API (AI triage)
    --shodan-key <key>      Chave Shodan (passive intel)

  RESILIÊNCIA / WAF
    --retry <n>             Tentativas por request (padrão: 3)
    --jitter                Ativa delays aleatórios 80–430ms (anti-WAF)
    --no-waf-evasion        Desativa mutação de payloads
    --no-adaptive           Desativa inteligência adaptativa
    --curl-delay <s>        Delay fixo entre requests (padrão: 0)

  PERFIS DE SCAN
    --stealth               Low-and-slow (delays=2s, threads=20, workers=5)
    --aggressive            Máxima cobertura (threads=200, targets ampliados)

  CONTROLE DE RECON
    --no-passive-intel      Desativa crt.sh, ASN, BGP, OTX lookup
    --no-scoring            Desativa priorização de endpoints por risco

  LIMITES POR MÓDULO
    --limit-cors <n>        Hosts para CORS check (padrão: 50)
    --limit-headers <n>     Hosts para header check (padrão: 30)
    --limit-sensitive <n>   Hosts para sensitive files (padrão: 20)
    --limit-lfi <n>         Candidatos LFI (padrão: 30)
    --limit-redirect <n>    Candidatos redirect (padrão: 30)
    --limit-idor <n>        Candidatos IDOR (padrão: 30)
    --limit-crlf <n>        Candidatos CRLF (padrão: 30)
    --limit-waf <n>         Hosts para WAF detection (padrão: 20)
```

---

## 📁 Módulos de Scan

O scan segue um pipeline ordenado de **20 etapas**:

```
00  → Enumeração de subdomínios      (subfinder + assetfinder + amass + findomain)
00b → Passive Intel                  (crt.sh, AlienVault OTX, HackerTarget, ASN, Shodan)
01  → Alive check                    (httpx — status, título, tech-detect, content-length)
02  → Port scan                      (naabu — top 1000 + portas interessantes)
03  → Screenshots                    (gowitness)
04  → Subdomain takeover             (subzy)
05  → Coleta de URLs                 (waybackurls + gau + katana crawl ativo)
06  → Filtragem de URLs              (php, api, admin, js, sensitive)
07  → WAF Detection                  (wafw00f paralelo + fingerprint manual)
07b → Adaptive Strategy              (auto-tuning automático baseado no WAF detectado)
08  → Priorização de endpoints       (endpoint scoring por risco — antes dos scans ativos)
09  → Análise de JS                  (endpoints, 16 padrões de secrets, TruffleHog, DOM sinks)
10  → Extração de parâmetros         (uro dedup + qsreplace + httpx alive + arjun PARALELO)
11  → GF pattern filtering           (xss, sqli, lfi, rce, ssrf, ssti, idor, cors, aws-keys…)
12  → Directory bruteforce           (ffuf + SecLists common.txt)
13  → CORS check                     (paralelo, 30 workers)
14  → Security headers               (HSTS, CSP, X-Frame-Options, Referrer-Policy…)
15  → Sensitive files                (paralelo, 30 workers — .git, .env, backup, phpinfo…)
16  → XSS                            (manual per-param + DOM analysis + headers + dalfox)
17  → SQLi                           (error-based + blind time-based + POST + sqlmap + ghauri PARALELO)
18  → LFI / Redirect / NoSQL / SSTI / SSRF / XXE / IDOR / CRLF / Host Injection / GraphQL
19  → Nuclei                         (critical + high + medium em hosts e params)
19b → AI Triage                      (Anthropic Claude API — análise e priorização)
20  → Relatório consolidado          (TXT + JSON)
```

---

## 📊 Relatório de Saída

Toda a saída é organizada em pastas com timestamp:

```
alvo.com_2025-01-15_14-30-00/
├── 01_discovery/
│   ├── subs_all.txt             ← todos os subdomínios únicos
│   ├── subs_subfinder.txt       ← resultados por ferramenta
│   ├── alive.txt                ← hosts ativos (httpx)
│   ├── alive_200.txt            ← 200 OK
│   ├── alive_403.txt            ← 403 Forbidden
│   ├── alive_5xx.txt            ← 5xx Errors
│   ├── ports.txt                ← portas abertas
│   ├── ports_interesting.txt    ← 8080, 9200, 6379, 27017…
│   └── passive/
│       ├── passive_subs_clean.txt  ← subdomínios via passive intel
│       └── asn_info.txt            ← ASN + IP principal
├── 02_urls/
│   ├── urls_all.txt             ← todas as URLs coletadas
│   ├── urls_clean.txt           ← sem assets estáticos
│   ├── urls_php.txt             ← PHP endpoints
│   ├── urls_api.txt             ← API endpoints
│   ├── urls_admin.txt           ← painéis admin
│   └── urls_sensitive.txt       ← arquivos .env, .bak, .sql…
├── 03_params/
│   ├── params.txt               ← parâmetros únicos (após uro)
│   ├── params_fuzz.txt          ← normalizados com FUZZ (qsreplace)
│   ├── params_alive.txt         ← endpoints com resposta ativa
│   ├── params_alive_scored.txt  ← ordenados por score de risco
│   ├── param_names.txt          ← frequência de nomes de parâmetros
│   └── arjun_raw.txt            ← parâmetros descobertos pelo arjun
├── 04_vulns/                    ← candidatos por categoria (gf)
│   ├── xss.txt
│   ├── sqli.txt
│   ├── lfi.txt
│   ├── ssrf.txt
│   ├── ssti.txt
│   └── ...
├── 05_scans/
│   ├── dalfox.txt               ← XSS confirmados (dalfox)
│   ├── xss_manual.txt           ← XSS reflected (pre-check manual)
│   ├── xss_dom.txt              ← DOM XSS suspeitos
│   ├── xss_headers.txt          ← XSS via headers
│   ├── sqli_confirmed.txt       ← SQLi confirmados (sqlmap)
│   ├── sqli_error_based.txt     ← SQLi error-based (pre-check)
│   ├── sqli_blind.txt           ← SQLi blind time-based (2x confirmado)
│   ├── sqli_post.txt            ← SQLi via POST body
│   ├── ghauri_results.txt       ← Ghauri findings
│   ├── lfi_results.txt          ← LFI confirmados
│   ├── redirect_results.txt     ← Open redirects
│   ├── ssti_results.txt         ← SSTI confirmados
│   ├── ssrf_results.txt         ← SSRF findings
│   ├── xxe_results.txt          ← XXE findings
│   ├── nosql_results.txt        ← NoSQL injection
│   ├── idor_results.txt         ← IDOR suspeitos
│   ├── crlf_results.txt         ← CRLF injection
│   ├── host_injection_results.txt
│   ├── graphql_results.txt      ← Introspection + schema dump
│   ├── nuclei_critical.txt
│   ├── nuclei_high.txt
│   └── nuclei_medium.txt
├── 06_screenshots/              ← capturas de tela (gowitness)
├── 07_js/
│   ├── js_files.txt             ← URLs de arquivos JS
│   ├── js_endpoints.txt         ← endpoints extraídos dos JS
│   ├── js_secrets.txt           ← secrets encontrados
│   └── trufflehog.txt           ← TruffleHog findings
├── 08_extra/
│   ├── cors_vuln.txt            ← CORS misconfigurations
│   ├── headers_issues.txt       ← headers de segurança ausentes
│   ├── sensitive_files.txt      ← arquivos sensíveis acessíveis (200)
│   ├── waf_detected.txt         ← WAF detectado + perfil adaptado
│   ├── takeover.txt             ← subdomain takeover vulneráveis
│   └── ffuf/                   ← resultados por host (JSON)
├── 09_report/
│   ├── vuln_urls.txt            ← relatório consolidado (texto)
│   ├── vuln_urls.json           ← relatório estruturado (JSON)
│   └── ai_triage.txt            ← análise de IA (se --api-key usado)
├── recon.log                    ← log completo do scan
└── errors.log                   ← log de erros e exceções
```

### Exemplo de relatório JSON

```json
{
  "target": "alvo.com",
  "version": "2.0",
  "scan_date": "2025-01-15T14:30:00",
  "profile": "normal",
  "confirmed_vulns": {
    "xss_dalfox": ["https://alvo.com/search?q=..."],
    "xss_manual": ["https://alvo.com/comment?text=..."],
    "sqli_confirmed": ["https://alvo.com/user?id=..."],
    "sqli_error_based": [],
    "sqli_blind": [],
    "lfi": [],
    "ssrf": [],
    "ssti": [],
    "xxe": [],
    "idor": ["https://alvo.com/api/user?id=1"],
    "crlf": [],
    "cors": ["https://api.alvo.com — credenciais refletidas"],
    "graphql": ["https://alvo.com/graphql — introspection habilitada"]
  },
  "exposures": {
    "js_secrets": ["[JS: https://alvo.com/app.js]  apiKey: \"AIza...\""],
    "sensitive_files": ["[200] https://alvo.com/.env"],
    "headers_issues": ["https://alvo.com → Missing-HSTS Missing-CSP"],
    "takeover": []
  },
  "stats": {
    "subdomains": 47,
    "alive_hosts": 23,
    "urls_collected": 8341,
    "params_unique": 412,
    "js_files": 89
  }
}
```

---

## 🔬 Detalhes Técnicos

### Concorrência (v2.0)

A v2.0 usa `ThreadPoolExecutor` para paralelismo real em Python, substituindo os subshells do Bash:

| Módulo | Workers | Proteção de concorrência |
|--------|---------|--------------------------|
| CORS check | 30 | `threading.Lock()` no append |
| Security headers | 30 | `threading.Lock()` no append |
| Sensitive files | 30 | `threading.Lock()` no append |
| XSS manual | 10 | `threading.Lock()` no append |
| Arjun | 5 + timeout global 10min | Arquivos temp por URL → merge |
| wafw00f | 5 | `threading.Lock()` no append |
| ffuf | 5 | Arquivos por host (JSON) |
| SQLi error-based | 5 | `threading.Lock()` no append |
| SQLi sqlmap | 5 | Arquivos por URL → merge |
| Ghauri | 3 | Arquivos temp por URL → merge |
| JS analysis | 10 | `threading.Lock()` no append |
| Open redirect | 10 | `threading.Lock()` no append |

### Endpoint Scoring

O sistema de pontuação atribui risco a cada URL antes dos scans, garantindo que os targets mais promissores sejam testados primeiro:

| Critério | Pontos |
|----------|--------|
| Parâmetros de alto risco (`id`, `token`, `file`, `cmd`, `exec`, `key`…) | +30 |
| Paths de admin/dashboard/console/backend | +25 |
| Endpoints de API / GraphQL / REST | +20 |
| Extensões de risco (`.php`, `.asp`, `.jsp`, `.cfm`) | +15 |
| Upload / file handling | +15 |
| Por parâmetro adicional na URL | +5 cada |
| Palavras-chave sensíveis (login, auth, pay, billing, config…) | +10 |

### Adaptive Intelligence

Após detectar um WAF, o framework automaticamente recalibra todo o perfil:

```
Cloudflare / Akamai / Imperva  →  curl_delay=2s  burst_pause=5s  workers=5   profile=stealth
ModSecurity / Fortinet / F5    →  curl_delay=1s  burst_pause=3s  workers=10  profile=stealth
WAF desconhecido               →  curl_delay=1s  burst_pause=2s  profile=stealth
```

Além disso: ativa jitter (80–430ms), força WAF evasion nos payloads, reduz todos os limites de request e seleciona tampers específicos por fabricante para o sqlmap.

### Passive Intel

Coleta de subdomínios e contexto **sem enviar um único request direto ao alvo**:

| Fonte | Dados coletados |
|-------|----------------|
| **crt.sh** | Subdomínios via Certificate Transparency |
| **HackerTarget** | Subdomínios + DNS records |
| **AlienVault OTX** | Passive DNS histórico |
| **ASN / BGP** | IP principal, organização, range de IPs |
| **Shodan** | Subdomínios indexados, portas (requer `--shodan-key`) |

### Retry & Resilência

```python
# Backoff exponencial com jitter apenas entre tentativas
tentativa 1  →  falha  →  aguarda 1.0s + jitter(80-430ms)
tentativa 2  →  falha  →  aguarda 2.0s + jitter(80-430ms)
tentativa 3  →  falha  →  retorna (0, "")  # sem delay extra
```

---

## ⚡ Exemplos de Cenários Reais

### Bug Bounty — Scan completo com AI report

```bash
python3 recon.py alvo.com --deep --threads 150 --api-key sk-ant-xxx --shodan-key XXXXX
```

### Pentest — Ambiente com WAF detectado

```bash
python3 recon.py alvo.com --stealth --jitter --retry 5 --shodan-key XXXXX
```

### Reconhecimento puro, sem scans ativos

```bash
python3 recon.py alvo.com --skip-scans --deep --no-screenshots
```

### CI/CD — Output JSON para pipeline automatizado

```bash
python3 recon.py alvo.com --skip-scans --no-screenshots 2>/dev/null
cat alvo.com_*/09_report/vuln_urls.json | python3 -m json.tool
```

### Scan rápido de validação (sem overhead)

```bash
python3 recon.py alvo.com --threads 50 --timeout 5 --no-passive-intel --no-screenshots --limit-cors 10
```

---

## 🛠 FAQ

<details>
<summary><b>Quais ferramentas são obrigatórias?</b></summary>

As ferramentas **obrigatórias** são: `subfinder`, `httpx`, `waybackurls`, `gau`, `katana`, `gf`, `uro`, `qsreplace`, `dalfox`, `nuclei`, `sqlmap`.

Se alguma estiver faltando, o script lista exatamente o que está ausente e encerra com sugestão do `--install`.

</details>

<details>
<summary><b>O scan é muito barulhento. Como reduzir o noise?</b></summary>

Use o perfil `--stealth`:

```bash
python3 recon.py alvo.com --stealth
```

Isso ativa automaticamente: jitter, delays de 2s, threads reduzidas para 20, workers para 5 e WAF evasion em todos os payloads. Para ajuste fino manual:

```bash
python3 recon.py alvo.com --curl-delay 2 --jitter --retry 5 --threads 20 --limit-cors 10
```

</details>

<details>
<summary><b>Como o AI Triage funciona?</b></summary>

Ao final do scan, todos os findings são coletados (`vuln_urls.txt`) e enviados para a API da Anthropic (Claude). O modelo retorna análise priorizada com as 3 vulnerabilidades mais críticas, elimina falsos positivos prováveis e sugere próximos passos com comandos específicos.

Requer conta na [Anthropic](https://console.anthropic.com/) e chave de API válida (`sk-ant-...`).

</details>

<details>
<summary><b>O --install funciona em macOS?</b></summary>

Sim, com Homebrew. O script detecta automaticamente `brew` e usa os comandos corretos. Em Apple Silicon (M1/M2), o Go é instalado para `arm64` automaticamente. Após instalação, pode ser necessário:

```bash
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin
```

</details>

<details>
<summary><b>O scan cobre apenas o domínio raiz ou também subdomínios?</b></summary>

Cobre tudo. A etapa 00 enumera todos os subdomínios via múltiplas ferramentas. A etapa 00b (passive intel) complementa via crt.sh e OTX. Todos os subdomínios encontrados passam pelo alive check e por todas as etapas de scan subsequentes.

</details>

<details>
<summary><b>Como funciona a priorização de endpoints?</b></summary>

Antes de iniciar os scans ativos, o sistema de **Endpoint Scoring** pontua cada URL com base em parâmetros de alto risco, paths sensíveis, extensões e quantidade de parâmetros. Os endpoints com maior pontuação são testados primeiro, garantindo que mesmo com limites de tempo os targets mais promissores sejam cobertos.

</details>

<details>
<summary><b>Por que o Arjun era tão lento e como foi corrigido?</b></summary>

Na versão anterior, o Arjun rodava **sequencialmente** com `timeout=180s` por URL e a flag `--stable` (que reduz as threads internas). Com 20 hosts e `timeout=180`, o pior caso era **60 minutos** travados nessa única etapa.

Na v2.0: execução paralela com 5 workers, timeout por URL reduzido para 60s, timeout global de 10 minutos para toda a etapa, e remoção da flag `--stable`. Além disso, o bug de output sobrescrito foi corrigido — cada URL agora escreve em arquivo temporário próprio, com merge final deduplicado.

</details>

---

## ⚖️ Legal & Ética

Este framework é disponibilizado **exclusivamente para uso legal e autorizado**:

- ✅ Testes em sistemas próprios
- ✅ Bug bounty em programas que você está inscrito
- ✅ Pentests com contrato e escopo definido
- ❌ Sistemas sem autorização explícita do proprietário

O uso não autorizado contra sistemas de terceiros é **crime** em praticamente todas as jurisdições (Brasil: Lei 12.737/2012 — Lei Carolina Dieckmann; EUA: CFAA; UE: Diretiva 2013/40/EU). Os autores não se responsabilizam por uso indevido.

---

## 🤝 Contribuindo

PRs são bem-vindos! Para contribuir:

1. Fork o repositório
2. Crie uma branch (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'feat: adiciona X'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

Áreas onde contribuições são especialmente bem-vindas:

- Novos módulos de detecção de vulnerabilidades
- Melhorias no sistema de endpoint scoring
- Novas fontes de passive intel
- Suporte a novas ferramentas (integração)
- Melhoria na qualidade do AI triage prompt
- Correções de falsos positivos
- Testes unitários

---

<div align="center">

**Desenvolvido para a comunidade de segurança ofensiva**

*Use com responsabilidade.*

</div>
