# Worker Local do AegisDAST

Este worker roda **fora da Vercel** — no seu notebook, ou em qualquer máquina
onde você controle o ambiente o suficiente para instalar as ferramentas de
verdade. A API na Vercel só enfileira (`LPUSH aegis_jobs`) e lê o resultado
(`HGETALL scan:<id>`); este processo é quem de fato faz o reconhecimento
passivo real, o crawl (Katana), o DAST baseado em templates (Nuclei), o
spider/active scan (OWASP ZAP, se houver um daemon local) e chama o Gemini
para triagem. Ver os comentários no topo de `worker.py` e em `server/queue.ts`
para o desenho completo.

## Pré-requisitos

1. **Python 3.9+** instalado e no PATH.
2. **Nuclei** instalado e no PATH (ou aponte `NUCLEI_PATH` no `.env` para o
   executável). Este projeto não instala nenhuma dessas ferramentas por você —
   são de terceiros e a instalação é responsabilidade de quem opera o worker.
   Veja a documentação oficial do ProjectDiscovery para o método de instalação
   atual da sua plataforma. Sem o Nuclei, o worker continua funcionando
   normalmente: a Etapa 2 simplesmente roda sem achados de template, com um
   log claro avisando que o binário não foi encontrado — nunca finge ter rodado.
3. **Katana** (opcional, mesmo fabricante do Nuclei) instalado e no PATH (ou
   `KATANA_PATH` no `.env`). Sem ele, o Nuclei escaneia só a URL raiz do alvo
   em vez dos endpoints descobertos por crawl — degradação honesta, não erro.
4. **OWASP ZAP** (opcional) rodando localmente como daemon, com a API REST
   habilitada — este worker é só um *cliente* da API do ZAP, nunca sobe nem
   gerencia esse processo. Configure `ZAP_PROXY_URL` (padrão
   `http://127.0.0.1:8080`) e `ZAP_API_KEY` no `.env`. Sem um ZAP acessível
   nessa URL, a etapa é pulada com um aviso — nunca derruba o job.
5. Uma instância Redis no Upstash (a mesma cujas credenciais já estão
   configuradas na Vercel).

## Configuração

```bash
cd worker
copy .env.example .env
# edite .env com:
#   UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN (as mesmas da Vercel)
#   GEMINI_API_KEY (opcional — sem ela, a Etapa 3 roda em modo fallback)
#   NUCLEI_PATH (opcional — só se o nuclei não estiver no PATH)
#   KATANA_PATH (opcional — só se o katana não estiver no PATH)
#   ZAP_PROXY_URL / ZAP_API_KEY (opcional — só se você for rodar um ZAP local)
```

## Rodando

```bash
start_worker.bat
```

Na primeira execução isso cria um venv em `worker/.venv`, instala
`requirements.txt` e inicia o loop. Deixe a janela aberta — o worker fica
escutando a fila continuamente (`RPOP aegis_jobs` a cada poucos segundos) e
processa um job por vez assim que o botão "Iniciar Varredura" for usado no
site (com o Redis configurado na Vercel, esse clique enfileira em vez de
rodar na própria função serverless).

Para rodar manualmente sem o `.bat`:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python worker.py
```

## O que este worker NÃO faz

- Não instala nem atualiza Nuclei, Katana ou OWASP ZAP sozinho.
- Não sobe nem gerencia o processo do OWASP ZAP — só se conecta como cliente
  a um daemon que já esteja rodando.
- Não deixa um crawl do Katana escanear domínios fora do alvo verificado: todo
  endpoint descoberto é filtrado pelo próprio domínio antes de chegar ao
  Nuclei (ver `is_in_scope()` em `worker.py`).
- Não decide quais alvos são válidos — isso já foi resolvido pelo lado Node
  antes do job chegar na fila (só alvos com `verificationStatus: VERIFIED`
  passam por `POST /api/scans`). O worker confia na fila.
- Não substitui o pipeline síncrono do lado Node (`server/scanOrchestrator.ts`)
  — aquele continua existindo como fallback para quando o Redis não está
  configurado (dev local sem depender deste worker).
