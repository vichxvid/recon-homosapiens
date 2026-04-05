# recon.py

```
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
 Full Automated Reconnaissance Framework  v6.0
```

**Recon.py** é um framework de reconhecimento e varredura de vulnerabilidades totalmente automatizado, escrito em Python 3. Ele orquestra mais de 30 ferramentas externas em um pipeline estruturado que cobre enumeração de subdomínios, coleta de URLs, análise de JS, descoberta de parâmetros, detecção de WAF, testes ativos de exploração e relatórios assistidos por IA — tudo a partir de um único comando.

> **COM CONTRIBUIÇÃO DE: EU MESMO**

---

## Índice

- [Visão Geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Pipeline](#pipeline)
- [Perfis de Scan](#perfis-de-scan)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Referência de Configuração](#referência-de-configuração)
- [Estrutura de Saída](#estrutura-de-saída)
- [Funcionalidades de IA](#funcionalidades-de-ia)
- [Segurança e Ética](#segurança-e-ética)
- [Changelog](#changelog)

---

## Visão Geral

O Recon.py foi desenvolvido em torno de três princípios: **robustez**, **escalabilidade** e **relação sinal-ruído**. Todo componente que se comunica com ferramentas externas passa por uma camada de execução centralizada que trata timeouts, remoção de escape ANSI, classificação de erros e saída diretamente em disco para evitar esgotamento de memória em alvos grandes.

O framework é autossuficiente. Ele detecta automaticamente quais ferramentas opcionais estão instaladas, adapta a intensidade do scan com base nas respostas de WAF observadas e pode persistir resultados entre sessões via SQLite com modo WAL e um worker dedicado de inserção para evitar race conditions em alta concorrência.

A API da Anthropic (Claude) é integrada opcionalmente em múltiplos pontos: planejamento de ataque com IA, triagem inteligente de vulnerabilidades, geração de payloads de bypass de WAF e geração de resumo executivo em linguagem natural para stakeholders não técnicos.

---

## Arquitetura

### ToolRunner

Todas as chamadas de subprocesso passam por uma única instância de `ToolRunner`. Ela padroniza:

- Normalização de código de retorno (`-1` timeout, `-2` binário não encontrado, `-3` OSError)
- Remoção automática de escapes ANSI de stdout/stderr
- Timeout configurável por chamada
- Modo de saída direta em disco para ferramentas de alto consumo de memória (nuclei, katana, ffuf)
- Passagem transparente em modo dry-run, que pula a execução real preservando o grafo de chamadas

### CircuitBreaker

Cada módulo de scan (XSS, SQLi, LFI, etc.) é envolto por um `CircuitBreaker`. Após 3 falhas consecutivas, o circuito abre e o módulo é ignorado pelo restante da execução. Isso previne loops silenciosos onde ferramentas quebradas produzem arquivos vazios que aparentam ser resultados limpos.

### Persistência SQLite

Os achados são gravados em um banco SQLite com modo de journal WAL e uma thread de background dedicada que drena uma `queue.Queue`. Isso elimina a contenção de escrita quando dezenas de threads de scan tentam persistir achados simultaneamente.

Tabelas: `subdomains`, `vulns`, `blocked_ips`, `scan_history`.

### Sistema de Rate e Feedback

O framework rastreia respostas HTTP 429 em dois níveis:

- **Backoff global** — compartilhado entre todas as threads, aumenta automaticamente em 429s repetidos e decai em respostas bem-sucedidas.
- **Backoff por host** — isolado ao host específico que retorna 429, mantendo os demais hosts em velocidade total.

Ambos os contadores são protegidos por locks dedicados de threading (correção da v6 para race conditions sob GIL).

### Deduplicação de URLs

Antes dos scans ativos, `url_signature()` normaliza cada URL (parâmetros de query ordenados, valores removidos) para gerar uma assinatura estrutural. `deduplicate_by_signature()` remove então URLs semanticamente idênticas, reduzindo a carga de scan em aproximadamente 80% em alvos típicos.

### Loop de Feedback de Payloads

Cada resposta HTTP alimenta de volta o mecanismo de seleção de payloads. Payloads que consistentemente retornam 403 são registrados (indexados por prefixo normalizado) e despriorizados nas requisições seguintes, reduzindo ruído e queima de assinaturas WAF.

---

## Pipeline

O scan é executado em ordem rigorosa de etapas. Cada etapa grava sua saída em um arquivo definido para que as etapas seguintes possam consumi-la de forma independente.

| Etapa | Nome | Ferramentas |
|-------|------|-------------|
| 00 | Health Check | validação de binários, ping de API, probe SQLite |
| 01 | Enumeração de Subdomínios | subfinder, amass, assetfinder, findomain, dnsx, shuffledns |
| 02 | Inteligência Passiva | Shodan API, crt.sh, SecurityTrails |
| 03 | Hosts Ativos | httpx |
| 03b | Crawling de SPA | Playwright (headless) |
| 04 | Port Scanning | naabu |
| 05 | Screenshots | gowitness |
| 05b | Subdomain Takeover | subzy |
| 05c | Technology Profiler | whatweb, análise de headers |
| 05d | Cloud Recon | AWS S3, GCS, Azure Blob, Kubernetes, Docker API |
| 06 | Coleta de URLs | waybackurls, gau, katana |
| 07 | Filtragem de URLs | uro, divisão por categoria (php/api/admin/js) |
| 07b | Detecção de WAF | wafw00f, fingerprinting manual por headers |
| 08 | Análise de JS | regex de secrets, TruffleHog v3, validação de JWT |
| 09 | Extração de Parâmetros | uro, qsreplace, arjun, verificação alive com httpx |
| 10 | Padrões GF | gf (xss/sqli/lfi/ssrf/redirect/ssti/idor/cors) |
| 11 | Brute-force de Diretórios | ffuf |
| 12 | Bypass de 403 | manipulação de headers e caminhos |
| 13 | CORS | reflexão de origin, null origin, confiança em subdomínio |
| 14 | Headers de Segurança | strict-transport, csp, x-frame, referrer-policy |
| 15 | Arquivos Sensíveis | exposição de backup, config, git, env |
| 16 | Coleta de Metadados | exiftool, vazamento de autor/GPS em documentos |
| 17 | XSS | dalfox, refletido manual, DOM, injeção em headers |
| 18 | SQL Injection | ghauri, error-based, blind, body POST |
| 19 | LFI / Path Traversal | lista de payloads com validação de contexto |
| 19b | Open Redirect | via parâmetro, via header |
| 19c | NoSQL Injection | injeção de operadores MongoDB |
| 19d | SSTI | detecção de Jinja2/Twig/Freemarker |
| 19e | SSRF | callback via interactsh, probe de IPs internos |
| 19f | XXE | entidade externa, OOB cego |
| 19g | IDOR | enumeração de parâmetros numéricos/UUID |
| 19h | CRLF Injection | injeção de headers via sequências CRLF |
| 19i | Host Header Injection | manipulação via X-Forwarded-Host, X-Host |
| 19j | GraphQL | introspecção, abuso de batch query |
| 20 | Nuclei | templates de CVE, misconfigs, exposições |
| 20b | Triagem por IA | classificação de severidade pela API Claude |
| 20c | Vazamento de Credenciais | API HaveIBeenPwned |
| 20d | Gerador de PoC | scripts Python gerados automaticamente por achado |
| 20e | Resumo Executivo | relatório em linguagem natural pela API Claude |
| 20f | Criptografia de Saída | GPG AES-256 em arquivos sensíveis |

---

## Perfis de Scan

Quatro perfis controlam contagem de threads, limites de profundidade e comportamento de temporização. Podem ser selecionados por flags ou sobrescritos granularmente com argumentos individuais de limite.

| Perfil | Flag | Threads | Intenção |
|--------|------|---------|----------|
| Normal | (padrão) | 100 | Cobertura e velocidade equilibradas |
| Stealth | `--stealth` | 20 | Baixo ruído, jitter ativado, evasão de WAF, delays estendidos |
| Agressivo | `--aggressive` | 200 | Cobertura máxima, alta concorrência, listas de payloads estendidas |
| Deep | `--deep` | 100 | Maior profundidade de crawl, limites ampliados de URL/param/JS |

O modo dry-run (`--dry-run`) simula o pipeline inteiro sem enviar nenhuma requisição ao alvo. Útil para validar configuração, escopo e disponibilidade de ferramentas antes de um engagement autorizado.

---

## Pré-requisitos

### Python

- Python 3.9+
- Nenhuma dependência Python de terceiros (somente stdlib)

### Pacotes Python opcionais (para modo Playwright)

```
pip install playwright
playwright install chromium
```

### Ferramentas Externas

As ferramentas abaixo ampliam a funcionalidade quando instaladas. O Recon.py detecta disponibilidade automaticamente e pula módulos para ferramentas ausentes.

**Core (fortemente recomendadas)**

```
subfinder   httpx       katana      gau         waybackurls
nuclei      dalfox      ffuf        uro          qsreplace
gf          dnsx        wafw00f     gowitness    naabu
```

**Opcionais mas valiosas**

```
amass       assetfinder findomain   shuffledns   subzy
arjun       trufflehog  sqlmap      ghauri       exiftool
gpg         interactsh  whatweb
```

---

## Instalação

### Automatizada

A flag `--install` tenta instalar todas as ferramentas baseadas em Go, dependências Python e padrões GF automaticamente.

```bash
python3 recon.py --install
```

Requer Go 1.21+ no `PATH` e executará `go install` para cada ferramenta. Ferramentas Python e Playwright são instaladas via pip.

### Manual

Instale as ferramentas Go individualmente, por exemplo:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/gf@latest
go install github.com/shenwei356/uro@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/sensepost/gowitness@latest
go install github.com/PentestPad/subzy@latest
```

---

## Uso

### Básico

```bash
python3 recon.py alvo.com
```

### Flags comuns

```bash
# Multithread com crawl profundo
python3 recon.py alvo.com --threads 200 --deep

# Planejamento assistido por IA + agente OODA
python3 recon.py alvo.com --plan --agent --api-key $ANTHROPIC_API_KEY

# Crawl headless de SPA (React, Vue, Angular)
python3 recon.py alvo.com --playwright

# Alertas em tempo real via Discord/Slack/Telegram
python3 recon.py alvo.com --webhook-url https://hooks.slack.com/...

# Restringir escopo e simular (sem enviar requisições)
python3 recon.py alvo.com --whitelist alvo.com --dry-run

# Criptografar arquivos sensíveis ao final do scan
python3 recon.py alvo.com --encrypt-output --encrypt-pass 'SuaSenha'

# Modo watcher: re-executa o scan em intervalo, reporta somente novos achados
python3 recon.py alvo.com --watch --watch-interval 3600

# Perfil stealth com inteligência passiva via Shodan
python3 recon.py alvo.com --stealth --shodan-key $SHODAN_API_KEY

# Dashboard HTML ao vivo durante o scan
python3 recon.py alvo.com --live-dashboard --dashboard-port 8765
```

### Referência completa de opções

```
posicional:
  domain                   Domínio alvo

controle de scan:
  --threads N              Threads concorrentes (padrão: 100)
  --deep                   Maior profundidade de crawl e limites de payload
  --stealth                Perfil silencioso: jitter, evasão WAF, velocidade reduzida
  --aggressive             Cobertura e concorrência máximas
  --skip-scans             Pula todas as etapas de exploração ativa
  --skip-screenshots       Pula capturas de tela do gowitness
  --dry-run                Simula sem enviar requisições
  --no-adaptive            Desativa ajuste adaptativo de scan
  --timeout N              Timeout de requisição HTTP em segundos (padrão: 10)
  --curl-delay N           Delay entre chamadas curl em segundos
  --xss-deadline N         Limite de tempo por URL nos scans manuais de XSS (padrão: 45s)

inteligência:
  --plan                   Ativa o planejador de ataque por IA (requer --api-key)
  --agent                  Ativa o agente OODA com function calling
  --api-key KEY            Chave de API Anthropic (ou defina ANTHROPIC_API_KEY)
  --shodan-key KEY         Chave de API Shodan para inteligência passiva
  --playwright             Ativa crawling headless de SPA via Playwright
  --no-passive-intel       Pula Shodan e lookups passivos

limites (caps de URL/param por módulo):
  --limit-cors N           Limite de verificações CORS (padrão: 50)
  --limit-headers N        Limite de verificações de headers (padrão: 30)
  --limit-lfi N            Limite de payloads LFI (padrão: 30)
  --limit-idor N           Limite de testes IDOR (padrão: 30)
  --limit-sqli N           Limite de URLs SQLi (padrão: 30)
  ...

saída:
  --sqlite-db CAMINHO      Caminho para o banco SQLite de persistência
  --no-delta               Desativa modo delta (reporta tudo, não só o novo)
  --encrypt-output         Criptografa arquivos sensíveis de saída com GPG
  --encrypt-pass SENHA     Passphrase GPG para criptografia
  --live-dashboard         Inicia servidor HTTP local para relatório HTML ao vivo
  --dashboard-port N       Porta do dashboard (padrão: 8765)
  --webhook-url URL        Webhook para alertas em tempo real Discord/Slack/Telegram

escopo e segurança:
  --whitelist DOMINIOS     Domínios permitidos separados por vírgula (modo seguro)
  --hibp-key KEY           Chave de API HaveIBeenPwned para verificação de credenciais

watcher:
  --watch                  Modo watcher: repete o scan em intervalo
  --watch-interval N       Segundos entre execuções do watcher (padrão: 3600)

setup:
  --install                Instala todas as dependências automaticamente
```

---

## Referência de Configuração

### Variáveis de ambiente

| Variável | Descrição |
|----------|-----------|
| `ANTHROPIC_API_KEY` | Chave de API Claude da Anthropic |
| `SHODAN_API_KEY` | Chave de API Shodan |
| `RECON_WORDLIST` | Caminho para wordlist personalizada (sobrescreve a padrão) |
| `RECON_WEBHOOK_URL` | URL de webhook padrão |

As variáveis podem ser definidas em um arquivo `.env` no diretório de trabalho ou em `~/.recon.env`. Ambos são carregados automaticamente na inicialização.

### Exemplo de .env

```env
ANTHROPIC_API_KEY=sk-ant-...
SHODAN_API_KEY=...
RECON_WORDLIST=/opt/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt
RECON_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## Estrutura de Saída

Cada scan cria um diretório com timestamp no diretório de trabalho atual.

```
alvo.com_AAAAMMDD_HHMMSS/
├── disc/
│   ├── subdomains.txt          Todos os subdomínios descobertos
│   ├── alive.txt               Hosts respondendo via HTTP
│   └── takeover.txt            Candidatos a subdomain takeover
├── urls/
│   ├── urls_all.txt            Lista de URLs brutas consolidadas
│   ├── urls_clean.txt          URLs deduplicadas e filtradas
│   ├── urls_php.txt            Endpoints PHP
│   ├── urls_api.txt            Endpoints de API
│   ├── urls_admin.txt          Caminhos de admin/dashboard
│   └── urls_js.txt             Arquivos JavaScript
├── params/
│   ├── params.txt              URLs parametrizadas únicas
│   ├── params_alive.txt        URLs parametrizadas com resposta ativa
│   ├── params_fuzz.txt         Substituídas por FUZZ para uso direto em ferramentas
│   ├── param_names.txt         Análise de frequência de nomes de parâmetros
│   └── arjun_raw.txt           Parâmetros descobertos via Arjun
├── js/
│   ├── js_secrets.txt          Possíveis secrets (API keys, tokens, senhas)
│   ├── js_secrets_validated.txt Status de expiração de JWT, validação de tokens
│   ├── js_endpoints.txt        Endpoints extraídos de bundles JS
│   └── trufflehog.txt          Saída JSON do TruffleHog v3
├── vulns/
│   ├── xss.txt / sqli.txt ...  Correspondências de padrões GF por classe de vuln
│   └── *.txt                   Listas de URLs por categoria
├── scans/
│   ├── dalfox.txt              XSS confirmado (dalfox)
│   ├── xss_manual.txt          XSS refletido (manual)
│   ├── xss_dom.txt             Candidatos a DOM XSS
│   ├── sqli_confirmed.txt      SQL injection confirmado
│   ├── sqli_error_based.txt    SQLi error-based
│   ├── sqli_blind.txt          Candidatos a SQLi blind
│   ├── lfi_results.txt         Caminhos LFI confirmados
│   ├── ssrf_results.txt        Callbacks SSRF
│   ├── ssti_results.txt        SSTI confirmado
│   ├── xxe_results.txt         Achados XXE
│   ├── idor_results.txt        Candidatos a IDOR
│   ├── nuclei_critical.txt     Achados críticos do Nuclei
│   ├── nuclei_high.txt         Achados high do Nuclei
│   └── ...
├── extra/
│   ├── waf_detected.txt        Identificação de WAF por host
│   ├── cors_results.txt        Políticas CORS mal configuradas
│   ├── header_issues.txt       Headers de segurança ausentes ou fracos
│   ├── sensitive_files.txt     Arquivos de backup/config/git expostos
│   ├── metadata.txt            Achados do exiftool
│   └── cloud_recon.txt         S3/GCS/Azure/K8s/Docker expostos
├── screenshots/                Capturas do gowitness
├── report/
│   ├── index.html              Relatório HTML autocontido
│   ├── vuln_urls.txt           Todos os achados confirmados
│   ├── vuln_urls.json          Achados estruturados (JSON)
│   ├── ai_triage.txt           Análise de severidade por Claude
│   ├── executive_summary.txt   Resumo não técnico gerado por IA
│   ├── credential_leaks.txt    Resultados do HaveIBeenPwned
│   └── poc/
│       ├── poc_xss.py          Script de prova de conceito XSS
│       ├── poc_sqli.py         PoC SQLi (wrapper sqlmap)
│       ├── poc_ssrf.py         PoC SSRF (probe via interactsh)
│       └── poc_idor.py         PoC IDOR (teste com header de autenticação)
├── recon.log                   Log completo de execução com timestamps
└── error.log                   Log de erros no nível das ferramentas
```

Arquivos sensíveis (`js_secrets.txt`, `ai_triage.txt`, `credential_leaks.txt`, etc.) podem ser criptografados com GPG AES-256 ao término do scan usando `--encrypt-output`. Os originais são removidos após a criptografia.

Para descriptografar:

```bash
gpg --decrypt report/ai_triage.txt.gpg
```

---

## Funcionalidades de IA

Todas as funcionalidades de IA requerem uma chave de API Anthropic e utilizam `claude-sonnet-4-20250514`.

### Planejador de Ataque por IA (`--plan`)

Antes dos scans ativos, o planejador envia o stack tecnológico descoberto, status de WAF e categorias de URL para a API. O modelo retorna uma lista priorizada de vetores de ataque adequados às tecnologias identificadas — alvos PHP recebem payloads LFI com maior prioridade; endpoints GraphQL disparam verificações de introspecção primeiro.

### Agente OODA (`--agent`)

Quando `--agent` está ativo, o loop OODA (Observar, Orientar, Decidir, Agir) substitui o pipeline sequencial estático para os scans ativos. O agente recebe o contexto pós-reconhecimento e utiliza function calling da Anthropic para decidir quais módulos executar, em qual ordem e com quais parâmetros. Ele pode se adaptar durante a execução com base em achados intermediários.

### Bypass de WAF por IA

Quando um scan ativo recebe um 403, o framework opcionalmente consulta a API para gerar 3 payloads de bypass estruturalmente variados. As respostas são armazenadas em cache pela chave `(tipo_de_ataque, vendor_do_WAF)` para que a mesma pergunta nunca seja feita duas vezes em uma única execução. Este cache é uma adição da v6 que reduz significativamente o custo de API em alvos com comportamento de WAF consistente.

### Triagem por IA

Após a conclusão de todos os scans ativos, os achados confirmados são enviados à API para classificação de severidade e filtragem de falsos positivos. A saída inclui pontuações de confiança e avaliações de CVSS recomendadas.

### Resumo Executivo

Uma chamada de API separada gera um resumo em linguagem natural para audiências de gestão. O prompt instrui explicitamente o modelo a evitar jargões técnicos e enquadrar cada achado em termos de impacto nos negócios e prioridade de risco.

---

## Segurança e Ética

- **Autorização obrigatória.** Executar esta ferramenta contra sistemas sem autorização explícita por escrito é ilegal na maioria das jurisdições. A ferramenta é destinada para uso durante testes de penetração autorizados, programas de bug bounty dentro do escopo definido e avaliações de segurança de sistemas próprios.
- **Modo whitelist** (`--whitelist alvo.com`) faz o framework recusar o scan de qualquer hostname que não corresponda à lista aprovada. Use ao trabalhar dentro de uma grande organização com muitos subdomínios e escopo definido.
- **Modo dry-run** (`--dry-run`) permite validação completa do pipeline — incluindo planejamento por IA, detecção de ferramentas e configuração de diretórios — sem enviar uma única requisição ao alvo.
- **Scripts de PoC** são gerados com etapas de execução manual. São projetados como ferramentas de confirmação, não como scripts de ataque, e incluem comentários instruindo operadores a não automatizá-los contra sistemas em produção.
- **Dados de vazamento de credenciais** do HIBP são gravados somente em disco e nunca transmitidos além da API do HIBP e da saída opcionalmente criptografada com GPG.

---

## Changelog

### v6.0 — Robustez e Escalabilidade

**Correções críticas**
- Race condition em `_rate_429_count` e `_rate_backoff` — agora protegidos por lock dedicado de threading
- `except Exception: pass` substituído em todo o código por tipos específicos de exceção com logging estruturado
- Padrão Circuit Breaker implementado — módulos são desabilitados após 3 falhas consecutivas
- WAF AI Bypass integrado ao fluxo XSS/SQLi com cache de resposta por vendor de WAF

**Adições arquiteturais**
- `ToolRunner` — execução centralizada de subprocessos (logging, remoção de ANSI, timeout, escrita em disco)
- `CircuitBreaker` — previne loops de falha silenciosa em módulos quebrados
- `url_signature()` + `deduplicate_by_signature()` — reduz processamento redundante de URLs em ~80%
- `step_initial_health_check()` — valida binários, conectividade de API e SQLite antes de qualquer etapa de scan
- Cache do WAF AI Bypass por chave `(tipo_de_ataque, vendor_WAF)` — evita chamadas repetidas à API para cenários idênticos

### v5.0

- Agente OODA com function calling da Anthropic
- Crawling headless com Playwright para alvos SPA
- Suporte nativo a webhooks (Discord, Slack, Telegram)
- WAF AI Bypass (implementação inicial)
- Fila assíncrona de inserção SQLite com worker dedicado
- Suporte a variáveis via `.env` e `RECON_WORDLIST`
- Correção do `host_throttle()` — backoff por host não bloqueia mais o ThreadPoolExecutor global

### v4.0

- Reconhecimento em nuvem: S3, GCS, Azure Blob, Kubernetes API, Docker API
- Gerador de PoC para XSS, SQLi, SSRF e IDOR confirmados
- Verificação de vazamento de credenciais via API HaveIBeenPwned
- Relatório de Resumo Executivo por IA
- Criptografia de saída GPG AES-256
- Rate limiting por host
- Live Dashboard (servidor HTTP local com auto-refresh)
- Modo whitelist / Safe Mode
- Modo dry-run

### v3.0

- Technology Profiler (detecção de stack antes do scan)
- Planejador de Ataque por IA
- Loop de Feedback de Payloads (rastreamento de 403, despriorização de payloads)
- Persistência SQLite com modo delta
- Módulo de Bypass de 403
- Coleta de Metadados (exiftool)
- Relatório HTML autocontido
- Modo Watcher (re-scan agendado com relatório delta)
- Validação de Secrets JS (expiração de JWT, probe de token ativo)
- Integração de padrões GF

---

## Licença

Apenas para testes de segurança autorizados. Consulte [LICENSE](LICENSE) para os termos.
