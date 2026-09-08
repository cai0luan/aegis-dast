// Todas as rotas da API vivem AQUI e só aqui. server.ts (dev local) e api/index.ts
// (função serverless da Vercel) são dois cascos finos que chamam registerRoutes(app)
// sobre a mesma instância Express — nenhum dos dois registra rota própria. Isso evita
// a classe de bug onde um endpoint existe em dev e some em produção (ou o inverso),
// porque as duas entradas literalmente compartilham este arquivo.
import express, { NextFunction, Request, Response } from 'express';
import crypto from 'crypto';
// Extensão .js em todo import relativo deste arquivo: é o entrypoint que a
// função serverless da Vercel de fato transpila e roda como ESM puro (ver o
// comentário em api/index.ts). Sem isto, cada um destes vira
// ERR_MODULE_NOT_FOUND em produção mesmo funcionando localmente via tsx/Vite.
import * as db from './db.js';
import * as targets from './targets.js';
import { verifyDomainOwnership, sandboxVerify, isSandboxDemoAllowed, generateVerificationToken } from './domainVerification.js';
import { startScan, cancelScan, buildInitialJob } from './scanOrchestrator.js';
import { triageVulnerability, isAiConfigured } from './aiTriage.js';
import { isRedisConfigured, enqueueScanJob, getScanFromRedis } from './queue.js';
import type { TargetDomain, VerificationMethod, ScanProfile, ScanConfiguration } from '../src/types';

// Express 4 não encaminha sozinho a rejeição de uma Promise para o middleware
// de erro (isso só chegou nativamente no Express 5) — sem isto, um handler
// async que lança some em silêncio: a requisição nunca responde. `wrap` fecha
// essa lacuna sem trazer uma dependência nova (`express-async-errors` faria a
// mesma coisa, mas isto é três linhas). Combinado com o handler de erro no
// fim deste arquivo, é o que garante que NENHUMA rota consiga devolver algo
// que não seja JSON válido — nem para um erro que ninguém previu.
type Handler = (req: Request, res: Response, next: NextFunction) => unknown;
function wrap(fn: Handler): Handler {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function sanitizeDomain(input: unknown): string {
  if (typeof input !== 'string') return '';
  return input.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim().toLowerCase();
}

export function registerRoutes(app: express.Express) {
  app.use(express.json());

  // 1. Health check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      time: new Date().toISOString(),
      engine: 'AegisDAST-Core-v3',
      aiConfigured: isAiConfigured(),
      sandboxDemoAllowed: isSandboxDemoAllowed(),
      redisConfigured: isRedisConfigured()
    });
  });

  // 2. Targets CRUD — server/targets.ts decide sozinho entre Redis (Upstash) e
  // o arquivo local/tmp (server/db.ts); nada aqui sabe ou precisa saber qual
  // dos dois está ativo. Ver o comentário no topo de server/targets.ts.
  app.get('/api/targets', wrap(async (req: Request, res: Response) => {
    res.json({ targets: await targets.listTargets() });
  }));

  app.get('/api/targets/:id', wrap(async (req: Request, res: Response) => {
    const target = await targets.getTarget(req.params.id);
    if (!target) return res.status(404).json({ error: 'Alvo não encontrado.' });
    res.json({ target });
  }));

  app.post('/api/targets', wrap(async (req: Request, res: Response) => {
    const { domain, organizationName, verificationMethod } = req.body || {};
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'O campo "domain" é obrigatório.' });
    }
    // Aceita tanto "example.com" quanto "https://example.com/algum/caminho" —
    // protocolo, caminho e barra final são descartados; só o host sobrevive.
    const cleanDomain = sanitizeDomain(domain);
    if (!cleanDomain) {
      return res.status(400).json({ error: 'Domínio inválido.' });
    }

    const target: TargetDomain = {
      id: `tgt-${crypto.randomUUID()}`,
      domain: cleanDomain,
      url: `https://${cleanDomain}`,
      organizationName: (organizationName && String(organizationName).trim()) || 'Minha Organização',
      verificationStatus: 'UNVERIFIED',
      verificationMethod: (verificationMethod as VerificationMethod) || 'DNS_TXT',
      verificationToken: generateVerificationToken(cleanDomain),
      createdAt: new Date().toISOString(),
      riskScore: 0,
      totalVulns: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };

    const created = await targets.createTarget(target);
    res.status(201).json({ target: created });
  }));

  // 3. Domain Ownership Verification (Anti-Abuse) — sem atalhos ocultos.
  app.post('/api/verify-domain', wrap(async (req: Request, res: Response) => {
    const { targetId, domain, method, token } = req.body || {};

    if (!domain || !token || !method) {
      return res.status(400).json({ error: 'domain, method e token são obrigatórios.' });
    }

    const result = await verifyDomainOwnership(domain, method as VerificationMethod, token);
    if (result.verified && targetId) {
      await targets.updateTarget(targetId, {
        verificationStatus: 'VERIFIED',
        verificationMethod: result.method,
        verifiedAt: new Date().toISOString()
      });
    }
    res.json(result);
  }));

  // 3b. Verificação de sandbox/demo — explicitamente NÃO criptográfica, gravada com
  // método 'SANDBOX_DEMO', e só ativa quando ALLOW_DEMO_VERIFICATION=true.
  app.post('/api/verify-domain/sandbox', wrap(async (req: Request, res: Response) => {
    if (!isSandboxDemoAllowed()) {
      return res.status(403).json({
        error: 'Verificação de sandbox desabilitada. Defina ALLOW_DEMO_VERIFICATION=true no .env para habilitar este atalho apenas em ambiente de demonstração.'
      });
    }
    const { targetId, domain } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'domain é obrigatório.' });

    const result = sandboxVerify(domain);
    if (targetId) {
      await targets.updateTarget(targetId, {
        verificationStatus: 'VERIFIED',
        verificationMethod: 'SANDBOX_DEMO',
        verifiedAt: new Date().toISOString()
      });
    }
    res.json(result);
  }));

  // 4. Scans — dois caminhos, escolhidos por isRedisConfigured() (ver server/queue.ts):
  //
  //   COM Redis (UPSTASH_REDIS_REST_URL/TOKEN configuradas): enfileira o job e
  //   responde imediatamente com status QUEUED. O worker Python local
  //   (worker/worker.py) é quem de fato roda o recon real, o Nuclei e a triagem
  //   por IA, atualizando o hash no Upstash a cada etapa — é ESSE hash que este
  //   arquivo lê depois. Isto é o que faz o polling do frontend voltar a ser
  //   seguro em produção: tanto a invocação que recebeu o POST quanto a que
  //   atende cada GET de polling enxergam o mesmo estado, porque ele mora fora
  //   das duas (no Upstash), não na memória de nenhuma instância da Vercel.
  //
  //   SEM Redis: cai para o pipeline síncrono em processo — a rota bloqueia até
  //   o scanOrchestrator terminar (recon real + amostra simulada de DAST + IA)
  //   e devolve o resultado já completo. É o estado suportado para dev local sem
  //   depender do Upstash nem do worker Python estarem de pé (mesma filosofia de
  //   "rodar sem X é um estado suportado" usada em toda a camada de persistência).
  app.post('/api/scans', wrap(async (req: Request, res: Response) => {
    const { targetId, profile, config } = req.body || {};
    const target = await targets.getTarget(targetId);
    if (!target) return res.status(404).json({ error: 'Alvo não encontrado.' });
    if (target.verificationStatus !== 'VERIFIED') {
      return res.status(403).json({ error: 'Posse do domínio precisa estar validada antes de iniciar uma varredura.' });
    }

    if (isRedisConfigured()) {
      const job = buildInitialJob(target, (profile as ScanProfile) || 'NORMAL', config as ScanConfiguration);
      await enqueueScanJob(job);
      return res.status(202).json({ scan: job });
    }
    const job = await startScan(target, (profile as ScanProfile) || 'NORMAL', config as ScanConfiguration);
    res.status(200).json({ scan: job });
  }));

  app.get('/api/scans/:id', wrap(async (req: Request, res: Response) => {
    const job = isRedisConfigured() ? await getScanFromRedis(req.params.id) : db.getScan(req.params.id);
    if (!job) return res.status(404).json({ error: 'Scan não encontrado.' });

    // O worker Python não tem como enxergar o alvo local (targets.ts vive só no
    // lado Node/Vercel) — então é aqui, ao ler um scan concluído vindo do
    // Redis, que sincronizamos o score/contagens do alvo. Idempotente: repetir
    // a mesma escrita em polls seguintes ao já concluído é inofensivo.
    if (isRedisConfigured() && job.status === 'COMPLETED' && job.executiveSummary) {
      const confirmed = job.vulnerabilities.filter(v => v.status === 'CONFIRMED');
      await targets.updateTarget(job.targetId, {
        lastScanAt: job.completedAt || new Date().toISOString(),
        riskScore: job.executiveSummary.riskScore,
        totalVulns: {
          critical: confirmed.filter(v => v.severity === 'CRITICAL').length,
          high: confirmed.filter(v => v.severity === 'HIGH').length,
          medium: confirmed.filter(v => v.severity === 'MEDIUM').length,
          low: confirmed.filter(v => v.severity === 'LOW').length,
          info: confirmed.filter(v => v.severity === 'INFO').length
        }
      });
    }

    res.json({ scan: job });
  }));

  app.get('/api/scans', wrap(async (req: Request, res: Response) => {
    const targetId = typeof req.query.targetId === 'string' ? req.query.targetId : undefined;
    res.json({ scans: db.listScans(targetId) });
  }));

  // Mantido por compatibilidade e para o caso local (processo único, várias
  // requisições concorrentes no mesmo event loop): ainda pode interromper um job
  // que esteja no meio do await de uma etapa. Numa invocação serverless isolada da
  // Vercel isto não tem efeito prático, já que o pipeline roda por inteiro dentro
  // da mesma requisição que o disparou — não há uma segunda invocação concorrente
  // para interromper a primeira.
  app.post('/api/scans/:id/stop', wrap(async (req: Request, res: Response) => {
    const ok = cancelScan(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Scan não encontrado.' });
    res.json({ stopped: true });
  }));

  // 5. AI Triage manual (re-executar a triagem de um achado específico pela UI)
  app.post('/api/ai/triage', wrap(async (req: Request, res: Response) => {
    const { vulnerability, targetDomain, rawHttpTrace } = req.body || {};
    const result = await triageVulnerability(vulnerability || {}, targetDomain || 'alvo-desconhecido', rawHttpTrace);
    res.json(result);
  }));

  // 6. WAF & Bypass Configuration Generator
  app.get('/api/waf/config', (req: Request, res: Response) => {
    const domain = (req.query.domain as string) || 'app.empresa.com.br';
    const authHeaderName = 'X-Aegis-Scan-Authorization';
    const authHeaderValue = `Bearer aegis_sec_auth_${Buffer.from(domain).toString('hex').slice(0, 16)}_${Date.now().toString(36)}`;
    const egressIps = ['198.51.100.24', '198.51.100.25', '198.51.100.26', '203.0.113.88'];

    res.json({
      authHeaderName,
      authHeaderValue,
      egressIps,
      rules: {
        cloudflareExpression: `(http.request.headers["${authHeaderName}"][0] eq "${authHeaderValue}") or (ip.src in {${egressIps.join(' ')}})`,
        awsWafJson: {
          Name: 'AllowAegisSecurityScanner',
          Priority: 0,
          Action: { Allow: {} },
          VisibilityConfig: { SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: 'AegisScanAllow' },
          Statement: {
            OrStatement: {
              Statements: [
                {
                  ByteMatchStatement: {
                    SearchString: authHeaderValue,
                    FieldToMatch: { SingleHeader: { Name: authHeaderName.toLowerCase() } },
                    TextTransformations: [{ Priority: 0, Type: 'NONE' }],
                    PositionalConstraint: 'EXACTLY'
                  }
                },
                {
                  IPSetReferenceStatement: {
                    ARN: 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/AegisScannerIPs'
                  }
                }
              ]
            }
          }
        },
        nginxSnippet: `
# Aegis Security Scanner Bypass Rule
set $aegis_scan_allow 0;
if ($http_x_aegis_scan_authorization = "${authHeaderValue}") {
    set $aegis_scan_allow 1;
}
# Bypass rate-limit zone if aegis scan token is present
limit_req_whitelist $aegis_scan_allow;
`
      }
    });
  });

  // Rede de segurança final: qualquer erro que escape dos try/catch acima (ou
  // de um throw síncrono) cai aqui — nunca na página de erro genérica da
  // plataforma, que devolve HTML/texto e é exatamente o que quebrava
  // response.json() no frontend com "Unexpected token... is not valid JSON".
  // Precisa dos 4 parâmetros — é assim que o Express reconhece um error handler.
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error('[routes] Erro não tratado:', err);
    if (res.headersSent) return next(err);
    res.status(500).json({ error: err?.message || 'Erro interno do servidor.' });
  });
}
