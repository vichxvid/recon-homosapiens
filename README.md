<div align="center">

**Full Automated Reconnaissance Framework v1.0**

[![Shell](https://img.shields.io/badge/Shell-Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com)
[![Version](https://img.shields.io/badge/Version-1.0-red?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com)

> **⚠ USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA. Uso não autorizado é ilegal.**

[Funcionalidades](#-funcionalidades) · [Instalação](#-instalação) · [Uso](#-uso) · [Módulos](#-módulos-de-scan) · [Relatório](#-relatório-de-saída) · [FAQ](#-faq)

</div>

---

## 📋 Sobre

**recon.sh** é um framework de reconhecimento ofensivo totalmente automatizado, desenvolvido para profissionais de segurança, pentesters e bug bounty hunters. Com um único comando, ele executa uma cadeia completa de recon — desde enumeração de subdomínios até detecção de vulnerabilidades — entregando um relatório consolidado pronto para exploração.

### O que há de novo?

| # | Feature | Descrição |
|---|---------|-----------|
| 🧠 | **Inteligência Adaptativa** | Detecta WAF e adapta *automaticamente* toda a estratégia: delays, jitter, tampers, limites de request |
| 🎯 | **Endpoint Scoring** | Sistema de pontuação de risco que prioriza endpoints com maior probabilidade de vulnerability |
| 🔇 | **Noise Reduction** | Shuffling de targets, burst pauses e variação de padrões para reduzir fingerprint sequencial |
| 🌐 | **Passive Intel** | Recon externo via crt.sh, ASN/BGP lookup, AlienVault OTX e Shodan (sem tocar o alvo) |

---

## ✨ Funcionalidades

<details>
<summary><b>🔍 Reconhecimento & Descoberta</b></summary>

- **Enumeração de subdomínios** com subfinder, assetfinder, amass, findomain
- **Passive Intel** via crt.sh (Certificate Transparency), AlienVault OTX, HackerTarget, ASN/BGP lookup
- **Shodan** integrado (opcional, com `--shodan-key`)
- **Alive check** com httpx (status, título, tech-detect, content-length)
- **Port scan** com naabu (top 1000 portas)
- **Screenshot** automático com gowitness
- **Subdomain takeover** com subzy
- **Coleta de URLs** via waybackurls + GAU + katana (crawl ativo)
- **Filtragem e categorização** de URLs (PHP, ASP, API, Admin, sensitivos, JS)

</details>

<details>
<summary><b>🛡 Detecção de WAF & Evasão</b></summary>

- **wafw00f** + fingerprint manual (Cloudflare, Akamai, Imperva, F5, ModSecurity, Fortinet…)
- **Inteligência Adaptativa**: após detectar WAF, ajusta automaticamente todo o perfil de scan
- **Jitter** automático (80–430ms) ao detectar WAF ou via `--jitter`
- **User-Agent rotation** com 9 UAs reais (Chrome, Firefox, Safari, mobile, Googlebot)
- **Payload mutation**: variação de encoding, case, null-byte, alternativas de sintaxe
- **Tamper selection** por fabricante de WAF (tampers específicos para sqlmap)
- **Retry com backoff exponencial** (padrão: 3 tentativas)

</details>

<details>
<summary><b>⚔ Scanning de Vulnerabilidades</b></summary>

| Vuln | Método |
|------|--------|
| XSS | Manual per-param + DOM analysis + Header injection + Dalfox |
| SQLi | Error-based + Blind time-based + POST body + SQLMap + Ghauri |
| LFI | 22 payloads (Linux/Windows/PHP Filters/Wrappers) + per-param |
| SSRF | Canary interno + interactsh OOB + cloud metadata |
| SSTI | 9 templates (Jinja2, Twig, Freemarker, ERB, Velocity…) |
| XXE | 5 payloads (file read, SSRF, blind) |
| IDOR | Parâmetros numéricos com PII detection |
| CRLF | 9 variantes de encoding |
| Host Header | Body reflection + redirect poisoning |
| CORS | Origin reflection + credentials=true |
| NoSQL | MongoDB operators (GET + POST JSON) |
| GraphQL | Introspection + schema dump |
| Open Redirect | 14 variantes de bypass |
| Nuclei | Critical + High (templates oficiais + fuzz) |

</details>

<details>
<summary><b>🤖 AI Triage (Anthropic API)</b></summary>

- Coleta todos os findings e envia para a API da Anthropic
- Retorna: TOP 3 vulns críticas, severidade de cada finding, próximos passos (com comandos), false positives prováveis e vetores não testados com base nas tecnologias detectadas
- Usa `--api-key sk-ant-...` para ativar

</details>

---

## 🚀 Instalação

### Auto-instalação (recomendado)

```bash
git clone https://github.com/vichxvid/recon-homosapiens
cd recon.sh
chmod +x recon.sh
./recon.sh --install
```

O `--install` instala automaticamente **todas** as dependências:
- Ferramentas Go (subfinder, httpx, katana, dalfox, nuclei, ffuf…)
- Ferramentas Python (uro, arjun, wafw00f, ghauri)
- Go language (se não instalado)
- GF Patterns
- Nuclei templates
- SecLists

### Instalação manual

<details>
<summary>Clique para expandir</summary>

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
pip install uro arjun wafw00f ghauri --break-system-packages

# System
sudo apt install sqlmap curl python3
```

**Dependências opcionais (Recomendado instalar):**
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
git clone https://github.com/1ndianl33t/Gf-Patterns
cp Gf-Patterns/*.json ~/.gf/
```

</details>

---

## 🎯 Uso

### Comandos básicos

```bash
# Scan padrão
./recon.sh alvo.com

# Modo profundo (máxima cobertura)
./recon.sh alvo.com --deep

# Stealth (low-and-slow, anti-WAF)
./recon.sh alvo.com --stealth

# Com AI Triage (requer chave Anthropic)
./recon.sh alvo.com --api-key sk-ant-xxxxxxx

# Com Shodan para passive intel
./recon.sh alvo.com --shodan-key XXXXXXXXXXXXXXXX

# Pular scans ativos (só recon)
./recon.sh alvo.com --skip-scans

# Instalar todas as dependências
./recon.sh --install
```

### Todas as opções

```
Uso: ./recon.sh <dominio> [opções]

  GERAIS
    --threads <n>           Número de threads (padrão: 100)
    --deep                  Modo profundo (mais crawl, mais targets)
    --skip-scans            Pula dalfox, sqlmap e nuclei
    --no-screenshots        Pula capturas de tela
    --verbose               Output completo
    --api-key <key>         Chave Anthropic API (AI triage)
    --shodan-key <key>      Chave Shodan (passive intel)

  RESILIÊNCIA / WAF
    --retry <n>             Tentativas curl (padrão: 3)
    --jitter                Ativa delays aleatórios (anti-WAF)
    --no-waf-evasion        Desativa mutação de payloads
    --no-adaptive           Desativa inteligência adaptativa

  PERFIS DE SCAN
    --stealth               Low-and-slow (delays altos, menos requests)
    --aggressive            Máxima cobertura (threads altas, mais targets)

  CONTROLE DE RECON
    --no-passive-intel      Desativa crt.sh, ASN, BGP lookup
    --no-scoring            Desativa priorização de endpoints por risco
    --curl-delay <s>        Delay entre requests curl (padrão: 0)

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
00  → Enumeração de subdomínios      (subfinder, assetfinder, amass, findomain)
00b → Passive Intel                  (crt.sh, OTX, HackerTarget, ASN, Shodan)
01  → Alive check                    (httpx)
02  → Port scan                      (naabu)
03  → Screenshots                    (gowitness)
04  → Subdomain takeover             (subzy)
05  → Coleta de URLs                 (waybackurls + gau + katana)
06  → Filtragem de URLs              (categorias: php, api, admin, js, sensitive)
07  → WAF Detection                  (wafw00f + fingerprint manual)
07b → Adaptive Strategy              ← NOVO: auto-tuning baseado no WAF
08  → Priorização de endpoints       ← NOVO: endpoint scoring por risco
09  → Análise de JS                  (endpoints, secrets, TruffleHog)
10  → Extração de parâmetros         (uro, arjun, httpx)
11  → GF pattern filtering           (xss, sqli, lfi, rce, ssrf, ssti, idor…)
12  → Directory bruteforce           (ffuf + SecLists)
13  → CORS check                     (paralelo, 30 workers)
14  → Security headers               (HSTS, CSP, X-Frame-Options…)
15  → Sensitive files                (paralelo: .git, .env, backup, phpinfo…)
16  → XSS                            (manual + DOM + headers + dalfox)
17  → SQLi                           (error-based + blind + POST + sqlmap + ghauri)
18  → LFI / Redirect / NoSQL / SSTI / SSRF / XXE / IDOR / CRLF / Host Injection / GraphQL
19  → Nuclei                         (critical + high)
19b → AI Triage                      (Anthropic API)
20  → Relatório consolidado          (TXT + JSON)
```

---

## 📊 Relatório de Saída

Ao final do scan, toda a saída é organizada em:

```
alvo.com_2025-01-15_14-30-00/
├── 01_discovery/
│   ├── subs_all.txt          ← todos os subdomínios únicos
│   ├── alive.txt             ← hosts ativos (httpx)
│   ├── alive_200.txt         ← 200 OK
│   ├── alive_403.txt         ← 403 Forbidden
│   ├── ports.txt             ← portas abertas
│   └── passive/              ← crt.sh, ASN, BGP
├── 02_urls/
│   ├── urls_all.txt          ← todas as URLs coletadas
│   ├── urls_php.txt          ← PHP endpoints
│   ├── urls_api.txt          ← API endpoints
│   └── urls_admin.txt        ← painéis administrativos
├── 03_params/
│   ├── params.txt            ← parâmetros únicos (após uro)
│   └── params_alive_scored.txt ← endpoints ordenados por risco
├── 04_vulns/                 ← candidatos por categoria (gf)
├── 05_scans/
│   ├── dalfox.txt            ← XSS confirmados
│   ├── sqli_confirmed.txt    ← SQLi confirmados (sqlmap)
│   ├── sqli_error_based.txt  ← SQLi error-based
│   ├── sqli_blind.txt        ← SQLi blind time-based
│   ├── lfi_results.txt       ← LFI confirmados
│   ├── idor_results.txt      ← IDOR suspeitos
│   └── ...                   ← todos os outros módulos
├── 06_screenshots/           ← capturas de tela
├── 07_js/
│   ├── js_secrets.txt        ← API keys, tokens, secrets
│   └── trufflehog.txt        ← TruffleHog findings
├── 08_extra/
│   ├── cors_vuln.txt         ← CORS misconfigurations
│   ├── sensitive_files.txt   ← arquivos expostos (200 OK)
│   └── waf_detected.txt      ← WAF detectado + perfil adaptado
└── 09_report/
    ├── vuln_urls.txt         ← relatório consolidado (texto)
    ├── vuln_urls.json        ← relatório estruturado (JSON)
    └── ai_triage.txt         ← análise de IA (se --api-key usado)
```

### Exemplo de relatório JSON

```json
{
  "target": "alvo.com",
  "version": "1.0",
  "confirmed_vulns": {
    "xss_dalfox": ["https://alvo.com/search?q=..."],
    "sqli": ["https://alvo.com/user?id=..."],
    "lfi": []
  },
  "exposures": {
    "js_secrets": ["[JS: https://alvo.com/app.js]  apiKey: \"AIza...\""],
    "sensitive_files": ["[200] https://alvo.com/.env"]
  }
}
```

---

## 🔬 Detalhes Técnicos

### Endpoint Scoring (v1.0)

O sistema de pontuação atribui risco a cada URL antes dos scans, garantindo que os targets mais promissores sejam testados primeiro:

| Critério | Pontos |
|----------|--------|
| Parâmetros de alto risco (`id`, `token`, `file`, `cmd`…) | +30 |
| Paths de admin/dashboard/console | +25 |
| Endpoints de API / GraphQL | +20 |
| Extensões de risco (PHP, ASP, JSP) | +15 |
| Upload / file handling | +15 |
| Por parâmetro adicional na URL | +5 |
| Palavras-chave sensíveis | +10 |

### Adaptive Intelligence (v1.0)

Após detectar um WAF, o framework automaticamente:

```
Cloudflare / Akamai / Imperva → curl_delay=2s, burst_pause=5s, workers=5,  profile=stealth
ModSecurity / Fortinet / F5   → curl_delay=1s, burst_pause=3s, workers=10, profile=stealth
WAF desconhecido              → curl_delay=1s, burst_pause=2s, profile=stealth
```

Além disso, ativa jitter (80–430ms), força WAF evasion, reduz limites de request e seleciona tampers específicos por fabricante para o sqlmap.

### Passive Intel (v1.0)

Coleta de subdomínios e contexto **sem enviar um único request ao alvo**:

| Fonte | Dados coletados |
|-------|----------------|
| **crt.sh** | Subdomínios via Certificate Transparency |
| **HackerTarget** | Subdomínios + DNS lookup |
| **AlienVault OTX** | Passive DNS historical |
| **ASN / BGP** | IP principal, organização, range de IPs |
| **Shodan** | Subdomínios indexados, portas abertas (requer `--shodan-key`) |

---

## ⚡ Exemplos de Cenários Reais

### Bug Bounty — Scan rápido inicial

```bash
./recon.sh alvo.com --threads 100 --deep --api-key sk-ant-xxx
```

### Pentest — Stealth em ambiente com WAF

```bash
./recon.sh alvo.com --stealth --shodan-key XXXXXX
```

### Reconhecimento puro sem scans ativos

```bash
./recon.sh alvo.com --skip-scans --deep
```

### CI/CD — Scan automatizado com output JSON

```bash
./recon.sh alvo.com --skip-scans --no-screenshots 2>/dev/null
cat alvo.com_*/09_report/vuln_urls.json | jq .confirmed_vulns
```

---

## 🛠 FAQ

<details>
<summary><b>Quais ferramentas são obrigatórias?</b></summary>

As ferramentas **obrigatórias** são: `subfinder`, `httpx`, `waybackurls`, `gau`, `katana`, `gf`, `uro`, `qsreplace`, `dalfox`, `nuclei`, `sqlmap`.

Se alguma estiver faltando, o script lista o que está ausente e oferece o comando `--install` para resolver tudo automaticamente.

</details>

<details>
<summary><b>O scan é muito barulhento. Como reduzir o noise?</b></summary>

Use o perfil `--stealth`:

```bash
./recon.sh alvo.com --stealth
```

Isso ativa jitter, aumenta delays, reduz threads e targets por módulo, e ativa WAF evasion. Alternativamente, ajuste manualmente com `--curl-delay 2 --jitter --retry 5`.

</details>

<details>
<summary><b>Como o AI Triage funciona?</b></summary>

Ao final do scan, todos os findings são coletados e enviados para a API da Anthropic (Claude). O modelo retorna uma análise priorizando as 3 vulnerabilidades mais críticas, eliminando falsos positivos prováveis e sugerindo próximos passos com comandos específicos.

</details>

<details>
<summary><b>O --install funciona em macOS?</b></summary>

Sim, com Homebrew. O script detecta automaticamente `brew` e usa os comandos corretos. Alguns ajustes manuais podem ser necessários para ferramentas Go em Apple Silicon.

</details>

<details>
<summary><b>O scan cobre subdomínios ou só o domínio raiz?</b></summary>

Cobre tudo. A etapa 01 enumera todos os subdomínios; a etapa 00b (passive intel) complementa via crt.sh e OTX. Todos os subdomínios encontrados passam pelo alive check e pelos scans subsequentes.

</details>

---

## ⚖️ Legal & Ética

Este framework é disponibilizado **exclusivamente para uso legal e autorizado**:

- ✅ Testes em sistemas próprios
- ✅ Bug bounty em programas que você está inscrito
- ✅ Pentests com contrato e escopo definido
- ❌ Sistemas sem autorização explícita

O uso não autorizado contra sistemas de terceiros é **crime** em praticamente todas as jurisdições. Os autores não se responsabilizam por uso indevido.

---

## 🤝 Contribuindo

PRs são bem-vindos! Para contribuir:

1. Fork o repositório
2. Crie uma branch (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'feat: adiciona X'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

Áreas onde contribuições são especialmente bem-vindas:
- Novos módulos de detecção
- Melhorias no endpoint scoring
- Suporte a novas fontes de passive intel
- Wordlists customizadas
- Correções de falsos positivos

---

<div align="center">

**Desenvolvido para a comunidade de segurança ofensiva**

*Use com responsabilidade.*

</div>
