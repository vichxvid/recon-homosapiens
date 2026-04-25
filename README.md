# recon.py

> **Full Automated Reconnaissance Framework**  
> Python 3.8+ · ~4 800 linhas · Pipeline multi-etapa para reconhecimento ofensivo de aplicações web

---

> ⚠️ **AVISO LEGAL**  
> Este software é destinado exclusivamente a testes de segurança em sistemas para os quais você possui **autorização explícita e documentada**. O uso não autorizado é ilegal e de responsabilidade total do usuário. O autor não se responsabiliza por qualquer uso indevido.

---

## Índice

- [Visão Geral](#visão-geral)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso Rápido](#uso-rápido)
- [Pipeline de Scan](#pipeline-de-scan)
- [Opções de Linha de Comando](#opções-de-linha-de-comando)
- [Modos Operacionais](#modos-operacionais)
- [Saída e Estrutura de Pastas](#saída-e-estrutura-de-pastas)
- [Variáveis de Ambiente](#variáveis-de-ambiente)
- [Arquitetura Interna](#arquitetura-interna)

---

## Visão Geral

`recon.py` é um framework de reconhecimento automatizado que orquestra mais de 20 ferramentas externas em um pipeline coeso. Ele cobre enumeração de subdomínios, detecção de WAF, crawling, coleta de URLs históricas, mineração de JavaScript, fuzzing de diretórios e descoberta de parâmetros — tudo com mecanismos de resiliência, rate-limiting adaptativo e suporte a múltiplos perfis de agressividade.

**Destaques:**

- Cliente HTTP assíncrono (httpx + HTTP/2) com fallback para `curl`
- Circuit Breaker por ferramenta — falhas não travam o pipeline
- Adaptação automática ao WAF detectado (Cloudflare, Akamai, ModSecurity, etc.)
- Score de risco por endpoint para priorização de alvos
- Persistência em SQLite com modo delta (diff entre scans)
- Modo watcher para monitoramento contínuo
- Rotação de User-Agent com 25+ perfis reais (Chrome, Firefox, Safari, Googlebot…)
- Saída estruturada em JSONL para integração com outras ferramentas
- Criptografia GPG opcional dos outputs sensíveis

---

## Requisitos

**Python:** 3.8 ou superior

**Ferramentas obrigatórias** (o script não inicia sem elas):

| Ferramenta | Origem |
|---|---|
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `waybackurls` | `go install github.com/tomnomnom/waybackurls@latest` |
| `gau` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |

**Ferramentas opcionais** (expandem as capacidades):

`arjun` · `assetfinder` · `amass` · `findomain` · `wafw00f` · `dnsx` · `ffuf` · `feroxbuster` · `gospider` · `hakrawler` · `github-endpoints` · `xnLinkFinder` · `paramspider` · `x8` · `uro` · `qsreplace` · `sqlmap` · `curl` · `gpg`

**Pacotes Python opcionais:**

```
pip install httpx[http2] tqdm playwright
playwright install chromium  # se usar --playwright
```

---

## Instalação

### Automática (recomendado)

O script inclui um instalador que detecta o gerenciador de pacotes (apt, brew, yum, pacman), instala Go, baixa todas as ferramentas Go e Rust, e configura o PATH automaticamente:

```bash
python3 recon.py --install
```

O instalador também clona o SecLists para uso com ffuf/feroxbuster e executa um health check pós-instalação.

### Manual

1. Clone ou baixe `recon.py`
2. Instale as ferramentas obrigatórias listadas acima
3. Instale as opcionais conforme necessário
4. Opcionalmente, crie um arquivo `.env` na mesma pasta (veja [Variáveis de Ambiente](#variáveis-de-ambiente))

---

## Uso Rápido

```bash
# Scan básico
python3 recon.py alvo.com

# Scan profundo com mais threads
python3 recon.py alvo.com --deep --threads 200

# Modo furtivo (jitter, delays, perfil stealth)
python3 recon.py alvo.com --stealth

# Modo agressivo
python3 recon.py alvo.com --aggressive

# Somente hosts autorizados (safe mode)
python3 recon.py alvo.com --whitelist alvo.com,staging.alvo.com

# Simular sem enviar requests reais
python3 recon.py alvo.com --dry-run

# Monitoramento contínuo (rescan a cada hora)
python3 recon.py alvo.com --watch --watch-interval 3600

# Crawl headless para SPAs (React/Vue/Angular)
python3 recon.py alvo.com --playwright

# Com integração Anthropic (AI triage)
python3 recon.py alvo.com --api-key sk-ant-...

# Pular fuzzing ativo
python3 recon.py alvo.com --no-ffuf
```

---

## Pipeline de Scan

O scan executa as etapas na seguinte ordem. Etapas marcadas com `[opt]` rodam em processo filho isolado — um crash ou timeout não interrompe o pipeline.

| Etapa | Descrição | Ferramentas |
|---|---|---|
| `00` | Health check inicial | curl, git, SQLite, ulimit |
| `01` | Enumeração de subdomínios | subfinder, assetfinder, findomain, amass + dnsx |
| `01b` `[opt]` | Endpoints vazados no GitHub | github-endpoints |
| `02` | Hosts ativos + tech-detect | httpx |
| `02b` `[opt]` | Crawl headless SPA | Playwright/Chromium |
| `03` | Filtro hosts 200 OK real | curl |
| `07b` | Detecção de WAF | wafw00f, sqlmap, fingerprint de headers |
| `adapt` | Adaptação ao WAF | ajuste automático de perfil |
| `03b` `[opt]` | Fuzzing de diretórios | ffuf / feroxbuster + SecLists |
| `05b` `[opt]` | Crawlers extras | gospider, hakrawler |
| `06` | Coleta de URLs | waybackurls, gau, katana |
| `07` | Filtragem e categorização | uro, filtro de mídia |
| `05c` `[opt]` | Mineração de JavaScript | xnLinkFinder |
| `scoring` | Priorização de endpoints | score_endpoint() |
| `09` | Extração de parâmetros | uro, qsreplace, arjun |
| `09b` `[opt]` | Descoberta extra de params | x8, ParamSpider |

---

## Opções de Linha de Comando

```
python3 recon.py [domínio] [opções]
```

### Gerais

| Flag | Padrão | Descrição |
|---|---|---|
| `--install` | — | Instala todas as dependências automaticamente |
| `--threads N` | 100 | Threads para operações paralelas |
| `--deep` | false | Profundidade máxima (katana depth=5, mais fontes) |
| `--timeout N` | 10 | Timeout por request HTTP (segundos) |
| `--retry N` | 3 | Tentativas por request com falha |
| `--verbose` | false | Output detalhado |
| `--dry-run` | false | Simula o scan sem enviar requests reais |

### Perfis de Scan

| Flag | Descrição |
|---|---|
| `--stealth` | 20 threads, jitter ativado, delays, perfil furtivo |
| `--aggressive` | 200 threads, katana depth=6, sem pausas |
| `--jitter` | Adiciona delays aleatórios entre requests |
| `--curl-delay N` | Delay fixo (segundos) entre chamadas curl |
| `--no-waf-evasion` | Desativa cabeçalhos de evasão de WAF |
| `--no-adaptive` | Não adapta perfil automaticamente ao WAF detectado |

### Ferramentas e Limites

| Flag | Padrão | Descrição |
|---|---|---|
| `--ffuf-wordlist PATH` | auto | Wordlist para ffuf/feroxbuster |
| `--ffuf-threads N` | 40 | Threads do ffuf |
| `--ffuf-rate N` | 0 | Limite de req/s do ffuf (0 = sem limite) |
| `--no-ffuf` | false | Pula fuzzing ativo |
| `--no-github-endpoints` | false | Pula busca no GitHub |
| `--limit-ffuf N` | 50 | Máx de hosts para ffuf/feroxbuster |
| `--limit-gospider N` | 20 | Máx de hosts para gospider/hakrawler |
| `--limit-js-mining N` | 100 | Máx de arquivos JS para xnLinkFinder |

### Persistência e Saída

| Flag | Descrição |
|---|---|
| `--sqlite-db PATH` | Caminho do banco SQLite (delta mode e watcher) |
| `--no-delta` | Desativa comparação com scan anterior |
| `--encrypt-output` | Criptografa outputs sensíveis com GPG AES-256 |
| `--encrypt-pass SENHA` | Senha para criptografia GPG |
| `--live-dashboard` | Inicia servidor HTTP local para dashboard em tempo real |
| `--dashboard-port N` | Porta do dashboard (padrão: 8765) |
| `--webhook-url URL` | Webhook para alertas (Discord/Slack/Telegram) |

### Segurança e Controle

| Flag | Descrição |
|---|---|
| `--whitelist DOMÍNIOS` | Domínios autorizados separados por vírgula |
| `--playwright` | Crawl headless com Chromium para SPAs |
| `--api-key KEY` | Anthropic API key para AI triage / modo agente |
| `--shodan-key KEY` | Shodan API key para inteligência passiva extra |
| `--hibp-key KEY` | HaveIBeenPwned API key para leak check |
| `--watch` | Modo watcher — rescan periódico |
| `--watch-interval N` | Intervalo entre scans em modo watcher (padrão: 3600s) |

---

## Modos Operacionais

### Normal
Configuração padrão. 100 threads, perfil balanceado.

### Stealth
Ativado com `--stealth`. Reduz threads para 20, ativa jitter gaussiano entre requests (70% dos delays: 100–2000ms, 30%: 800–8000ms), adiciona delay de 2s entre chamadas curl, pausa de 5s entre bursts. Fuzzing ativo é automaticamente desabilitado.

### Aggressive
Ativado com `--aggressive`. 200 threads, katana depth=6, sem pausas entre requests.

### Deep
Ativado com `--deep`. Habilita flags extras no katana (`-aff -xhr`), aumenta limites de JS endpoints e arjun, ativa subfinder `-all`.

### Adaptive (padrão ativo)
Detecta WAF automaticamente e ajusta o perfil. Cloudflare/Akamai → delay 2s, burst 5s, xss deadline 30s. ModSecurity/F5 → delay 1s, burst 3s. Todos os limites de módulos são reduzidos proporcionalmente. Pode ser desabilitado com `--no-adaptive`.

### Watcher
Ativado com `--watch`. Loop infinito que re-executa o pipeline completo a cada `--watch-interval` segundos. A partir do segundo ciclo, opera em modo delta comparando subdomínios com o scan anterior. Rate-limit counters são resetados entre ciclos.

### Dry-run
Ativado com `--dry-run`. Todas as chamadas HTTP retornam `200 [DRY-RUN] <url>` sem enviar requests. Útil para validar configuração e alcance antes do scan real.

---

## Saída e Estrutura de Pastas

Cada execução cria uma pasta com o nome `<domínio>_<timestamp>/`:

```
alvo.com_2025-01-15_14-30-00/
├── 01_discovery/
│   ├── subs_all.txt          # todos os subdomínios encontrados
│   ├── subs_new.txt          # novos desde o último scan (delta mode)
│   ├── alive.txt             # hosts com resposta HTTP
│   ├── alive_detailed.txt    # httpx com status, título, tecnologias
│   ├── live_targets_200.txt  # hosts confirmados 200 OK
│   ├── github_endpoints.txt  # endpoints vazados no GitHub
│   └── github_high_value.txt # endpoints de alto valor do GitHub
├── 02_urls/
│   ├── urls_all.txt          # todas as URLs coletadas
│   ├── urls_clean.txt        # URLs filtradas (sem mídia, deduplicadas)
│   ├── urls_php.txt          # categorias por tecnologia
│   ├── urls_asp.txt
│   ├── urls_api.txt
│   ├── urls_admin.txt
│   └── urls_js.txt
├── 03_params/
│   ├── params.txt            # URLs com parâmetros (após uro)
│   ├── params_fuzz.txt       # URLs com FUZZ como placeholder
│   ├── params_alive.txt      # parâmetros que respondem
│   ├── params_200_ok.txt     # parâmetros com 200 OK confirmado
│   ├── param_names.txt       # nomes de parâmetros por frequência
│   └── arjun_raw.txt         # parâmetros descobertos pelo Arjun
├── 04_extra/
│   ├── waf_detected.txt      # WAFs identificados por host
│   └── technologies_httpx.txt
├── 05_js/
│   ├── js_files.txt          # URLs de arquivos JS
│   ├── js_endpoints.txt      # endpoints extraídos dos JS
│   └── js_params.txt         # nomes de parâmetros extraídos dos JS
├── 06_report/
│   └── (relatórios gerados)
├── 07_vulns/
│   └── (vulnerabilidades encontradas)
├── 08_scans/
│   ├── ffuf_all.txt          # resultados consolidados do ffuf
│   └── ffuf_<host>.json      # output JSON individual por host
├── 09_screenshots/
│   └── (capturas de tela se habilitado)
├── findings.jsonl            # log estruturado de todos os eventos
├── recon.log                 # log principal da execução
└── errors.log                # erros técnicos de baixo nível
```

---

## Variáveis de Ambiente

Podem ser definidas no arquivo `.env` na pasta do script ou em `~/.recon.env`:

| Variável | Descrição |
|---|---|
| `ANTHROPIC_API_KEY` | API key da Anthropic para AI triage |
| `GITHUB_TOKEN` | Token GitHub (sem ele: limite de 60 req/h) |
| `RECON_WEBHOOK_URL` | URL de webhook para alertas |
| `RECON_WHITELIST` | Domínios autorizados separados por vírgula |
| `RECON_WORDLIST` | Caminho para wordlist padrão |
| `RECON_FFUF_WORDLIST` | Wordlist específica para ffuf/feroxbuster |
| `RECON_HTTP_MAX_CONN` | Conexões simultâneas máximas (padrão: 150) |
| `RECON_HTTP_TIMEOUT` | Timeout HTTP em segundos (padrão: 15) |
| `RECON_HTTP_RETRIES` | Retentativas por request (padrão: 3) |
| `RECON_UA_ROTATE` | Rotação de User-Agent, `0` para desabilitar |
| `RECON_HOST_WINDOW` | Janela de amostras do HostHealthMonitor (padrão: 100) |
| `RECON_HOST_THRESHOLD` | Taxa de bloqueio para pausar host (padrão: 0.15) |
| `RECON_HOST_PAUSE` | Segundos de pausa quando host bloqueado (padrão: 120) |
| `RECON_STEP_TIMEOUT` | Timeout máximo por etapa em segundos (padrão: 1800) |

**Exemplo `.env`:**
```env
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_TOKEN=ghp_...
RECON_WEBHOOK_URL=https://hooks.slack.com/...
RECON_WHITELIST=alvo.com,staging.alvo.com
RECON_FFUF_WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

---

## Arquitetura Interna

### Camadas principais

**HTTP Client** — `AsyncScannerClient` roda num event loop asyncio dedicado em thread separada. Chamadas síncronas do restante do código são ponteadas via `asyncio.run_coroutine_threadsafe()`. Suporte a HTTP/2 se a biblioteca `h2` estiver instalada. Fallback automático para subprocess `curl` quando httpx não está disponível.

**CircuitBreaker** — cada ferramenta externa tem um disjuntor independente. Após 3 falhas (ou 6 timeouts), o módulo é desabilitado por 300 segundos e depois entra em estado half-open para nova tentativa.

**HostHealthMonitor** — mantém uma janela deslizante de 100 requests por host. Se mais de 15% retornarem 403/429/503, o host é pausado automaticamente por 120 segundos.

**feedback_hook** — chamado após cada request. Incrementa um backoff global a cada 429, reduz gradualmente em respostas de sucesso. Opera também por host individualmente.

**TokenBucket** — rate limiting global com suporte a burst. Taxa ajustada dinamicamente de acordo com o backoff acumulado.

**_safe_step** — cada etapa opcional é executada em um processo filho forked com timeout de 1800 segundos. Se o processo travar, é terminado e o pipeline continua sem perda de estado.

**DB Worker** — fila assíncrona com thread dedicada para escritas SQLite em batch. Commits a cada 50 inserts ou 2 segundos. Modo WAL para leituras concorrentes sem bloqueio.

**append_line / flush buffer** — buffer em memória para escritas em arquivo. Flush automático a cada 25 linhas ou 1 segundo, usando file descriptors abertos persistentemente para evitar syscalls repetitivas.

### Scoring de endpoints

Cada URL recebe uma pontuação de risco baseada em padrões de regex:

| Padrão | Pontos |
|---|---|
| Arquivos sensíveis (`.bak`, `.sql`, `.env`, `.key`, `.pem`) | 50 |
| Endpoints GraphQL | 40 |
| Endpoints internos (actuator, swagger, heapdump) | 35 |
| Parâmetros críticos (`id`, `token`, `cmd`, `file`, `redirect`) | 30 |
| OAuth / SSO / SAML | 30 |
| Painéis administrativos | 25 |
| APIs e versões | 20 |
| Upload / arquivos | 15 |
| Extensões dinâmicas (`.php`, `.asp`, `.jsp`) | 15 |
| Cada parâmetro adicional | +5 |
| Keywords sensíveis (login, pay, config, export) | 10 |

URLs são ordenadas por score decrescente antes de serem passadas para os módulos de exploração.

### WAF Detection (3 métodos)

1. **wafw00f** — fingerprinting passivo
2. **sqlmap --identify-waf** — spot-check em 3 hosts
3. **Fingerprint manual de headers** — 13 assinaturas (Cloudflare, Akamai, Imperva, ModSecurity, AWS WAF, F5, Sucuri, Barracuda, Fastly, StackPath, DDoS-Guard, Fortinet, Incapsula) + detecção por resposta anômala (payload de injeção → mudança de 200 para 403/503)

---

## Licença

Este projeto é disponibilizado para fins educacionais e de pesquisa em segurança. Consulte o arquivo `LICENSE` para os termos completos.
