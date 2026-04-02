**AVISO: AINDA ESTÁ NA V2...**

**Full Automated Reconnaissance Framework v3.0**

[![Bash](https://img.shields.io/badge/Shell-Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0-red?style=for-the-badge)](https://github.com/vichxvid/recon-homosapiens)
[![Stars](https://img.shields.io/github/stars/vichxvid/recon-homosapiens?style=for-the-badge&color=yellow)](https://github.com/vichxvid/recon-homosapiens/stargazers)

> ⚠️ **USE APENAS EM SISTEMAS COM AUTORIZAÇÃO EXPLÍCITA** ⚠️
>
> Este projeto destina-se exclusivamente a testes de segurança autorizados, bug bounty e pesquisa ofensiva legal.

</div>

---

## 📌 Sobre o Projeto

O **recon-homosapiens** é um framework de reconhecimento web totalmente automatizado escrito em Bash puro. Em uma única execução, ele encadeia mais de **20 ferramentas** para mapear subdomínios, coletar URLs, extrair parâmetros, detectar WAFs, analisar JavaScript, verificar arquivos expostos e escanear ativamente por vulnerabilidades — tudo organizado em uma estrutura de pastas limpa e um relatório final consolidado (TXT + JSON).

A v3.0 adiciona detecção de WAF, scans completos de NoSQL, SSTI, SSRF e XXE, um motor SQLi reescrito do zero, e integração com a **API da Anthropic** para análise de findings por IA.

---

## ✨ Features

| Módulo | O que faz |
|--------|-----------|
| 🔍 **Subdomain Enum** | subfinder + assetfinder + findomain + amass com deduplicação |
| 🟢 **Alive Check** | httpx com status, título, tecnologias e content-length |
| 🔌 **Port Scan** | naabu top-1000, destaque para portas não convencionais |
| 📸 **Screenshots** | gowitness em todos os hosts ativos |
| 🎯 **Takeover Check** | subzy com detecção de subdomain takeover |
| 🌐 **URL Collection** | waybackurls + gau + katana (crawl ativo com suporte JS) |
| 🛡️ **WAF Detection** | wafw00f + fingerprint manual (Cloudflare, Akamai, ModSecurity, F5, Imperva...) |
| 📜 **JS Analysis** | Extração de endpoints + 17 padrões de secrets + TruffleHog v3 |
| 🔧 **Param Extraction** | uro + qsreplace + arjun com timeout por host |
| 🎯 **GF Patterns** | xss, sqli, lfi, ssrf, ssti, rce, idor, cors, redirect e mais |
| 📂 **Dir Bruteforce** | ffuf com SecLists/dirb em múltiplos hosts |
| 🔒 **CORS Check** | Detecta reflect + distingue crítico (credentials=true) de informativo |
| 🧢 **Headers Check** | HSTS, CSP, X-Frame-Options, info disclosure via Server/X-Powered-By |
| 📁 **Sensitive Files** | +55 endpoints clássicos (.env, .git, actuator, swagger, .ssh, ...) |
| 💥 **XSS** | Dalfox com modo silence e workers configuráveis |
| 🗃️ **SQLi** | Pre-check error-based + sqlmap (level 3, risk 2, tampers anti-WAF) + ghauri |
| 📂 **LFI** | 21 payloads (traversal, php://filter, expect://, data://, Windows) |
| ↗️ **Open Redirect** | 14 payloads com bypass de encoding |
| 🍃 **NoSQL Injection** | MongoDB operators via GET e POST JSON |
| 🧩 **SSTI Ativo** | 9 payloads por engine (Jinja2, Twig, Freemarker, ERB, Thymeleaf) |
| 🔁 **SSRF** | Metadata cloud (AWS/GCP/Alibaba) + detecção OOB via interactsh |
| 📦 **XXE** | Busca endpoints XML/SOAP e testa 5 payloads |
| ⚡ **Nuclei** | medium/high/critical em hosts e URLs com parâmetros |
| 🤖 **AI Triage** | Análise dos findings pela API da Anthropic (priorização + próximos passos) |
| 📊 **Relatório** | TXT consolidado + JSON estruturado + resumo no terminal |

---

## 🚀 Instalação

### Dependências Obrigatórias

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
pip install uro --break-system-packages
pip install arjun --break-system-packages
pip install wafw00f --break-system-packages
pip install ghauri --break-system-packages

# Sistema
sudo apt install sqlmap
```

### Dependências Opcionais (ampliam o escopo)

```bash
# Go
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/PentestPad/subzy@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Apt
sudo apt install amass findomain trufflehog
```

### GF Patterns

```bash
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
cp Gf-Patterns/*.json ~/.gf/
```

### Clonar e configurar

```bash
git clone https://github.com/vichxvid/recon-homosapiens.git
cd recon-homosapiens
chmod +x recon_homosapiens_v3.sh
```

---

## ⚙️ Uso

### Básico

```bash
./recon_homosapiens_v3.sh alvo.com
```

### Com opções

```bash
# Modo profundo (mais threads, mais URLs, mais payloads)
./recon_homosapiens_v3.sh alvo.com --deep

# Personalizar threads e pular screenshots
./recon_homosapiens_v3.sh alvo.com --threads 200 --no-screenshots

# Apenas recon passivo (sem dalfox, sqlmap, nuclei)
./recon_homosapiens_v3.sh alvo.com --skip-scans

# Com AI Triage via Anthropic API
./recon_homosapiens_v3.sh alvo.com --api-key sk-ant-...

# Controle de rate (útil em alvos sensíveis)
./recon_homosapiens_v3.sh alvo.com --threads 50 --curl-delay 1
```

### Todas as opções

```
Uso: ./recon_homosapiens_v3.sh <dominio> [opções]

  --threads <n>         Número de threads (padrão: 100)
  --deep                Modo profundo (mais crawling, mais payloads)
  --skip-scans          Pula dalfox, sqlmap, nuclei e scans ativos
  --no-screenshots      Pula capturas com gowitness
  --verbose             Output detalhado
  --api-key <key>       Chave Anthropic API (ativa AI Triage)
  --limit-cors <n>      Hosts para CORS check (padrão: 50)
  --limit-headers <n>   Hosts para header check (padrão: 30)
  --limit-sensitive <n> Hosts para sensitive files (padrão: 20)
  --limit-lfi <n>       Candidatos LFI (padrão: 30)
  --limit-redirect <n>  Candidatos redirect (padrão: 30)
  --curl-delay <s>      Delay entre requests curl em segundos (padrão: 0)
```

---

## 📁 Estrutura de Saída

Cada execução cria um diretório `<dominio>_<timestamp>/`:

```
alvo.com_2025-01-15_14-32-01/
├── 01_discovery/
│   ├── subs_all.txt          # Todos os subdomínios únicos
│   ├── alive.txt             # Hosts ativos (URLs)
│   ├── alive_detailed.txt    # Status + título + tecnologias
│   ├── alive_200.txt         # Somente 200 OK
│   ├── ports.txt             # Portas abertas (naabu)
│   └── ports_interesting.txt # Portas não convencionais
│
├── 02_urls/
│   ├── urls_all.txt          # Todas as URLs coletadas
│   ├── urls_clean.txt        # Sem extensões de assets
│   ├── urls_php.txt          # PHP endpoints
│   ├── urls_api.txt          # Endpoints de API
│   └── urls_admin.txt        # Painéis admin
│
├── 03_params/
│   ├── params.txt            # URLs únicas com parâmetros
│   ├── params_fuzz.txt       # Normalizadas com FUZZ
│   └── params_alive.txt      # Validadas com httpx
│
├── 04_vulns/                 # Candidatos GF por tipo
│   ├── xss.txt
│   ├── sqli.txt
│   ├── lfi.txt
│   ├── ssrf.txt
│   ├── ssti.txt
│   ├── rce.txt
│   └── idor.txt
│
├── 05_scans/                 # Resultados dos scanners ativos
│   ├── dalfox.txt            # XSS confirmados
│   ├── sqli_error_based.txt  # SQLi error-based (pre-check)
│   ├── sqli_confirmed.txt    # SQLi confirmados (sqlmap)
│   ├── ghauri_results.txt    # SQLi via ghauri
│   ├── lfi_results.txt       # LFI confirmados
│   ├── ssti_results.txt      # SSTI confirmados
│   ├── ssrf_results.txt      # SSRF findings
│   ├── xxe_results.txt       # XXE confirmados
│   ├── nosql_results.txt     # NoSQL injection
│   ├── redirect_results.txt  # Open redirects
│   ├── nuclei_critical.txt   # Nuclei CRITICAL
│   └── nuclei_high.txt       # Nuclei HIGH
│
├── 06_screenshots/           # PNGs via gowitness
│
├── 07_js/
│   ├── js_files.txt          # URLs de arquivos JS
│   ├── js_endpoints.txt      # Endpoints extraídos
│   ├── js_secrets.txt        # Possíveis secrets/tokens
│   └── trufflehog.txt        # TruffleHog findings
│
├── 08_extra/
│   ├── cors_vuln.txt         # CORS misconfigurations
│   ├── headers_issues.txt    # Problemas de security headers
│   ├── sensitive_files.txt   # Arquivos expostos (200 OK)
│   ├── waf_detected.txt      # WAFs identificados
│   ├── takeover.txt          # Subdomain takeover
│   └── technologies.txt      # Tech stack mapeada
│
├── 09_report/
│   ├── vuln_urls.txt         # Relatório TXT consolidado ★
│   ├── vuln_urls.json        # Relatório JSON estruturado ★
│   └── ai_triage.txt         # Análise IA (se --api-key) ★
│
├── recon.log                 # Log completo da execução
└── errors.log                # Erros de ferramentas
```

---

## 🤖 AI Triage

Com a flag `--api-key`, o framework envia todos os findings para a API da Anthropic ao final do scan e recebe:

- **TOP 3 vulnerabilidades** mais críticas para explorar primeiro
- **Análise de severidade** de cada finding confirmado
- **Próximos passos** específicos (com comandos quando possível)
- **Falsos positivos** prováveis para descartar
- **Vetores não testados** com base nas tecnologias detectadas

```bash
./recon_homosapiens_v3.sh alvo.com --api-key sk-ant-api03-...
```

O relatório é salvo em `09_report/ai_triage.txt` e exibido no terminal ao final do scan.

---

## 🛡️ Detecção de WAF e Tampers

O script detecta automaticamente WAFs antes dos scans ativos:

- **Ferramentas:** wafw00f + fingerprint via headers HTTP
- **WAFs suportados:** Cloudflare, Akamai, Imperva/Incapsula, Sucuri, Barracuda, F5 BIG-IP, ModSecurity, Fortinet
- **Resposta automática:** Se WAF detectado, os scans SQLi passam a usar tamper scripts:
  ```
  --tamper=space2comment,between,charencode,randomcase
  ```

---

## 📊 Comparativo de Modos

| Parâmetro | Normal | Deep (`--deep`) |
|-----------|--------|-----------------|
| Katana depth | 3 | 5 |
| GAU threads | 10 | 20 |
| Candidatos SQLi | 30 | 60 |
| Hosts CORS | 50 | 200 |
| Hosts headers | 30 | 100 |
| Hosts sensitive | 20 | 100 |
| URLs LFI | 30 | 100 |
| URLs redirect | 30 | 100 |
| JS endpoints | 100 | 300 |
| JS secrets | 50 | 200 |

---

## 🔐 Secrets Detectados em JavaScript

O engine de análise de JS detecta os seguintes padrões:

| Padrão | Exemplo |
|--------|---------|
| AWS Access Key | `AKIA...` / `ASIA...` |
| GitHub Token | `ghp_...` / `ghs_...` |
| JWT Token | `eyJ...` |
| Google API Key | `AIza...` |
| OpenAI API Key | `sk-[40+ chars]` |
| SendGrid | `SG.[22].[43]` |
| Slack Token | `xoxb-...` / `xoxp-...` |
| Stripe Key | `sk_live_...` / `pk_live_...` |
| Bearer Token | `Bearer [20+ chars]` |
| Generic API Key | `api_key: "..."` |
| Generic Secret | `secret_key: "..."` |
| Generic Password | `password: "..."` |

---

## 📋 Checklist de Vulnerabilidades Testadas

- [x] XSS Refletido / DOM (Dalfox)
- [x] SQL Injection — Error Based, Boolean, Time, UNION, Stacked
- [x] Local File Inclusion + PHP Wrappers
- [x] Open Redirect
- [x] NoSQL Injection (MongoDB operators)
- [x] Server-Side Template Injection (Jinja2, Twig, ERB, Freemarker)
- [x] Server-Side Request Forgery (metadata + OOB interactsh)
- [x] XML External Entity
- [x] CORS Misconfiguration
- [x] Subdomain Takeover
- [x] Security Headers ausentes
- [x] Arquivos sensíveis expostos (.env, .git, swagger, actuator...)
- [x] Secrets em JavaScript
- [x] Portas e serviços não convencionais
- [x] Nuclei — CVEs, default logins, misconfigs, exposures

---

## ⚠️ Disclaimer

```
Este software é fornecido para fins educacionais e de pesquisa de segurança legítima.
O uso não autorizado contra sistemas de terceiros é ILEGAL e pode resultar em
penalidades criminais. O autor não se responsabiliza por qualquer uso indevido.

Sempre obtenha autorização explícita por escrito antes de realizar qualquer teste.
```

---

## 🤝 Contribuindo

Pull requests são bem-vindos. Para mudanças maiores, abra uma issue primeiro para discutir o que você gostaria de mudar.

1. Fork o projeto
2. Crie sua branch (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Add: nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

---

## 📄 Changelog

### v3.0
- **NEW** WAF Detection automático com ativação de tampers
- **NEW** SQLi engine reescrito (pre-check + sqlmap + ghauri)
- **NEW** NoSQL Injection (MongoDB GET/POST)
- **NEW** SSTI probe ativo por engine
- **NEW** SSRF com suporte a interactsh OOB
- **NEW** XXE em endpoints XML/SOAP
- **NEW** AI Triage via Anthropic API
- **FIX** `count()` — trocado `grep -c` por `wc -l`
- **FIX** `subzy --hide_fails` (underscore)
- **FIX** TruffleHog v3 — sintaxe `filesystem`
- **FIX** GF — verifica pattern instalado antes de executar
- **FIX** `sed` com delimitador `|` no step de redirect
- **FIX** Spinner do dalfox não polui `errors.log`
- **FIX** JS fetch unificado (era duplo por arquivo)
- **OPT** Arjun com timeout individual por host
- **OPT** `parse_args` com validação de tipo nos argumentos

### v2.0
- Pipeline base com subfinder, httpx, gau, katana, dalfox, sqlmap, nuclei
- Análise de JS, CORS, headers e arquivos sensíveis
- Relatório TXT + JSON

---

<div align="center">

Feito com 🔴 para a comunidade de segurança ofensiva

**[⭐ Star no GitHub](https://github.com/vichxvid/recon-homosapiens)** • **[🐛 Reportar Bug](https://github.com/vichxvid/recon-homosapiens/issues)** • **[💡 Sugerir Feature](https://github.com/vichxvid/recon-homosapiens/issues)**

</div>
