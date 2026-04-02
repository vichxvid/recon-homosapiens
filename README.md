## Índice

- [Recursos](#recursos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Flags e opções](#flags-e-opções)
- [Exemplos de uso](#exemplos-de-uso)
- [Pipeline de etapas](#pipeline-de-etapas)
- [Estrutura de saída](#estrutura-de-saída)
- [Relatório de vulnerabilidades](#relatório-de-vulnerabilidades)
- [Sistemas suportados](#sistemas-suportados)

---

## Recursos

- **20 etapas automatizadas** do discovery até confirmação de vuln
- **4 fontes de subdomínios** combinadas: subfinder, assetfinder, findomain, amass
- **Coleta de URLs** via Wayback Machine, GAU e Katana (crawl ativo)
- **Detecção de vulnerabilidades**: XSS, SQLi, LFI, Open Redirect, CORS, SSRF, RCE, SSTI
- **Análise de JS**: extração de endpoints e secrets (AWS keys, tokens GitHub, JWTs, Google API keys, OpenAI, SendGrid)
- **Relatório final** em `.txt` e `.json` com todas as URLs possivelmente vulneráveis
- **Limites configuráveis** via argumento — sem valores fixos no código
- **Ferramentas opcionais** não bloqueiam o script — etapas são puladas com aviso
- **Log de erros separado** (`errors.log`) para diagnóstico de falhas silenciosas

---

## Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/vichxvid/recon-homosapiens
cd recon-homosapiens
chmod +x recon_homosapiens.sh
```

### 2. Instale as dependências obrigatórias

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

# Sistema
sudo apt install sqlmap       # Debian/Ubuntu
sudo pacman -S sqlmap         # Arch Linux
```

Certifique-se de que `~/go/bin` está no PATH:

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc
```

### 3. Instale as dependências opcionais (recomendadas)

```bash
# Go tools opcionais
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/PentestPad/subzy@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest

# Amass
sudo apt install amass        # Debian/Ubuntu
yay -S amass                  # Arch Linux (AUR)

# Findomain
yay -S findomain              # Arch Linux (AUR)
# ou: https://github.com/findomain/findomain/releases

# TruffleHog (instalar via build manual)
git clone https://github.com/trufflesecurity/trufflehog.git
cd trufflehog && go build -o trufflehog . && sudo mv trufflehog /usr/local/bin/
cd .. && rm -rf trufflehog

# Wordlists para ffuf
sudo apt install seclists     # Debian/Ubuntu
yay -S seclists               # Arch Linux (AUR)
```

---

## Uso

```bash
./recon_homosapiens.sh <dominio> [opções]
```

**Uso básico:**

```bash
./recon_homosapiens.sh alvo.com
```

---

## Flags e opções

| Flag | Argumento | Padrão | Descrição |
|---|---|---|---|
| *(posicional)* | `<dominio>` | — | **Obrigatório.** Domínio alvo |
| `--threads` | `<n>` | `100` | Número de threads para ferramentas paralelas |
| `--deep` | — | `false` | Modo profundo: aumenta profundidade, limites e fontes |
| `--skip-scans` | — | `false` | Pula Dalfox, SQLMap e Nuclei (apenas discovery) |
| `--no-screenshots` | — | `false` | Pula capturas de tela com gowitness |
| `--verbose` | — | `false` | Exibe output completo das ferramentas |
| `--limit-cors` | `<n>` | `50` | Quantos hosts testar no CORS check |
| `--limit-headers` | `<n>` | `30` | Quantos hosts verificar os security headers |
| `--limit-sensitive` | `<n>` | `20` | Quantos hosts checar por arquivos sensíveis |
| `--limit-lfi` | `<n>` | `30` | Quantos candidatos testar no LFI check |
| `--limit-redirect` | `<n>` | `30` | Quantos candidatos testar no Open Redirect |
| `--curl-delay` | `<s>` | `0` | Segundos de espera entre requests curl manuais (anti-WAF) |

> No modo `--deep`, todos os limites são automaticamente dobrados e as ferramentas operam com maior profundidade.

---

## Exemplos de uso

**Scan padrão:**
```bash
./recontop.sh exemplo.com
```

**Scan rápido — apenas discovery, sem scans ativos:**
```bash
./recontop.sh exemplo.com --skip-scans
```

**Scan rápido sem screenshots:**
```bash
./recontop.sh exemplo.com --skip-scans --no-screenshots
```

**Scan completo em modo profundo com mais threads:**
```bash
./recontop.sh exemplo.com --deep --threads 200
```

**Scan com delay entre requests (alvo com WAF):**
```bash
./recontop.sh exemplo.com --curl-delay 2
```

**Scan profundo cobrindo todos os hosts sem limite:**
```bash
./recontop.sh exemplo.com --deep --limit-cors 9999 --limit-sensitive 9999 --limit-lfi 9999
```

**Reconhecimento rápido + relatório de vulnerabilidades:**
```bash
./recontop.sh exemplo.com --threads 150 --no-screenshots
```

---

## Pipeline de etapas

O script executa as seguintes etapas em sequência:

| Etapa | Nome | Ferramentas |
|---|---|---|
| 01 | Enumeração de subdomínios | subfinder, assetfinder, findomain, amass |
| 02 | Verificação de hosts ativos | httpx |
| 03 | Port scan | naabu *(opcional)* |
| 04 | Screenshots | gowitness *(opcional)* |
| 05 | Subdomain Takeover | subzy *(opcional)* |
| 06 | Coleta de URLs | waybackurls, gau, katana |
| 07 | Filtragem e categorização de URLs | grep, sort |
| 08 | Análise de arquivos JS | curl, regex, trufflehog *(opcional)* |
| 09 | Extração de parâmetros | uro, qsreplace, httpx, arjun *(opcional)* |
| 10 | Filtragem por padrões de vuln | gf |
| 11 | Bruteforce de diretórios | ffuf *(opcional)* |
| 12 | CORS misconfiguration | curl |
| 13 | Security headers check | curl |
| 14 | Arquivos sensíveis expostos | curl |
| 15 | XSS scan | dalfox |
| 16 | SQLi scan | sqlmap |
| 17 | LFI check | curl + payloads manuais |
| 18 | Open Redirect check | curl + payloads manuais |
| 19 | Nuclei scan | nuclei |
| 20 | **Relatório de URLs vulneráveis** | python3 (geração de .txt e .json) |

---

## Estrutura de saída

Cada scan gera uma pasta com timestamp. Exemplo: `exemplo.com_2025-06-01_14-32-00/`

```
exemplo.com_2025-06-01_14-32-00/
├── 01_discovery/
│   ├── subs_subfinder.txt      subdomínios do subfinder
│   ├── subs_assetfinder.txt    subdomínios do assetfinder
│   ├── subs_findomain.txt      subdomínios do findomain
│   ├── subs_amass.txt          subdomínios do amass
│   ├── subs_all.txt            todos combinados e deduplicados
│   ├── alive.txt               hosts que responderam
│   ├── alive_detailed.txt      hosts com status, título e tecnologia
│   ├── alive_200.txt           apenas 200 OK
│   ├── alive_403.txt           apenas 403
│   ├── alive_401.txt           apenas 401
│   ├── alive_5xx.txt           erros de servidor
│   └── ports.txt / ports_interesting.txt
│
├── 02_urls/
│   ├── wayback.txt             URLs do Wayback Machine
│   ├── gau.txt                 URLs do GAU
│   ├── katana.txt              URLs do Katana
│   ├── urls_all.txt            todas combinadas
│   ├── urls_clean.txt          sem arquivos estáticos
│   ├── urls_php.txt            apenas .php
│   ├── urls_asp.txt            apenas .asp/.aspx
│   ├── urls_api.txt            endpoints de API
│   ├── urls_admin.txt          painéis admin e login
│   └── urls_sensitive.txt      extensões sensíveis (.env, .bak, .sql...)
│
├── 03_params/
│   ├── params_raw.txt          URLs com parâmetros
│   ├── params.txt              deduplicados via uro
│   ├── params_fuzz.txt         normalizados com qsreplace FUZZ
│   ├── params_alive.txt        que ainda respondem
│   ├── param_names.txt         nomes mais comuns de parâmetros
│   └── arjun_raw.txt           parâmetros hidden descobertos pelo arjun
│
├── 04_vulns/
│   ├── xss.txt                 candidatos XSS (gf)
│   ├── sqli.txt                candidatos SQLi (gf)
│   ├── lfi.txt                 candidatos LFI (gf)
│   ├── rce.txt                 candidatos RCE (gf)
│   ├── ssrf.txt                candidatos SSRF (gf)
│   ├── ssti.txt                candidatos SSTI (gf)
│   ├── redirect.txt            candidatos Open Redirect (gf)
│   ├── cors.txt                candidatos CORS (gf)
│   └── idor.txt / aws-keys.txt / ...
│
├── 05_scans/
│   ├── dalfox.txt              XSS confirmados
│   ├── sqli_results.txt        output bruto do SQLMap
│   ├── sqli_confirmed.txt      SQLi confirmados
│   ├── sqli_output/            pasta de sessões do SQLMap
│   ├── lfi_results.txt         LFI confirmados
│   ├── redirect_results.txt    Open Redirects confirmados
│   ├── nuclei_all.txt          todos os findings do Nuclei
│   ├── nuclei_critical.txt     apenas Critical
│   ├── nuclei_high.txt         apenas High
│   └── nuclei_medium.txt       apenas Medium
│
├── 06_screenshots/             PNGs dos hosts (gowitness)
│
├── 07_js/
│   ├── js_files.txt            lista de arquivos JS encontrados
│   ├── js_endpoints_raw.txt    endpoints brutos extraídos
│   ├── js_endpoints.txt        endpoints deduplicados
│   ├── js_secrets.txt          possíveis secrets encontrados
│   └── trufflehog.txt          findings do TruffleHog
│
├── 08_extra/
│   ├── technologies.txt        tecnologias detectadas
│   ├── cors_vuln.txt           hosts com CORS vulnerável
│   ├── headers_issues.txt      hosts com headers ausentes
│   ├── sensitive_files.txt     arquivos sensíveis acessíveis
│   ├── takeover.txt            subdomínios vulneráveis a takeover
│   └── ffuf/                   resultados de bruteforce por host
│
├── 09_report/
│   ├── vuln_urls.txt           relatório completo de URLs vulneráveis
│   └── vuln_urls.json          mesmo relatório em JSON estruturado
│
├── recon.log                   log completo com timestamps
└── errors.log                  erros de ferramentas (antes ocultos)
```

---

## Relatório de vulnerabilidades

Ao final do scan, a **etapa 20** gera automaticamente dois arquivos em `09_report/`:

**`vuln_urls.txt`** — relatório legível dividido em seções:
- XSS confirmados (Dalfox)
- SQLi confirmados (SQLMap)
- LFI confirmados
- Open Redirect confirmados
- CORS misconfiguration
- Nuclei Critical / High
- Secrets em arquivos JS
- Subdomain Takeover
- Arquivos sensíveis com status 200
- Candidatos de alta prioridade por categoria (RCE, SSRF, SSTI...)
- Painéis admin/login encontrados
- Portas interessantes abertas

**`vuln_urls.json`** — estrutura JSON para integração com outras ferramentas:
```json
{
  "target": "exemplo.com",
  "confirmed_vulns": {
    "xss": [...],
    "sqli": [...],
    "lfi": [...],
    "open_redirect": [...],
    "cors": [...],
    "nuclei_critical": [...]
  },
  "high_interest_candidates": {
    "rce": [...],
    "ssrf": [...],
    "ssti": [...]
  },
  "exposures": {
    "js_secrets": [...],
    "sensitive_files": [...],
    "admin_panels": [...],
    "interesting_ports": [...]
  }
}
```

---
