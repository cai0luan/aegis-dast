// Todas as rotas da API vivem AQUI e só aqui. server.ts (dev local) e api/index.ts
// (função serverless da Vercel) são dois cascos finos que chamam registerRoutes(app)
// sobre a mesma instância Express — nenhum dos dois registra rota própria. Isso evita
// a classe de bug onde um endpoint existe em dev e some em produção (ou o inverso),
// porque as duas entradas literalmente compartilham este arquivo.
import express, { Request, Response } from 'express';
import crypto from 'crypto';
import * as db from './db';
import { verifyDomainOwnership, sandboxVerify, isSandboxDemoAllowed, generateVerificationToken } from './domainVerification';
import { startScan, cancelScan } from './scanOrchestrator';
import { triageVulnerability, isAiConfigured } from './aiTriage';
import type { TargetDomain, VerificationMethod, ScanProfile, ScanConfiguration } from '../src/types';

export function registerRoutes(app: express.Express) {
  app.use(express.json());

  // 1. Health check
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      time: new Date().toISOString(),
      engine: 'AegisDAST-Core-v3',
      aiConfigured: isAiConfigured(),
      sandboxDemoAllowed: isSandboxDemoAllowed()
    });
  });

  // 2. Targets CRUD
  app.get('/api/targets', (req: Request, res: Response) => {
    res.json({ targets: db.listTargets() });
  });

  app.get('/api/targets/:id', (req: Request, res: Response) => {
    const target = db.getTarget(req.params.id);
    if (!target) return res.status(404).json({ error: 'Alvo não encontrado.' });
    res.json({ target });
  });

  app.post('/api/targets', (req: Request, res: Response) => {
    const { domain, organizationName, verificationMethod } = req.body || {};
    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'O campo "domain" é obrigatório.' });
    }
    const cleanDomain = domain.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim().toLowerCase();
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

    db.createTarget(target);
    res.status(201).json({ target });
  });

  // 3. Domain Ownership Verification (Anti-Abuse) — sem atalhos ocultos.
  app.post('/api/verify-domain', async (req: Request, res: Response) => {
    const { targetId, domain, method, token } = req.body || {};

    if (!domain || !token || !method) {
      return res.status(400).json({ error: 'domain, method e token são obrigatórios.' });
    }

    try {
      const result = await verifyDomainOwnership(domain, method as VerificationMethod, token);
      if (result.verified && targetId) {
        db.updateTarget(targetId, {
          verificationStatus: 'VERIFIED',
          verificationMethod: result.method,
          verifiedAt: new Date().toISOString()
        });
      }
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: err?.message || 'Verification error' });
    }
  });

  // 3b. Verificação de sandbox/demo — explicitamente NÃO criptográfica, gravada com
  // método 'SANDBOX_DEMO', e só ativa quando ALLOW_DEMO_VERIFICATION=true.
  app.post('/api/verify-domain/sandbox', (req: Request, res: Response) => {
    if (!isSandboxDemoAllowed()) {
      return res.status(403).json({
        error: 'Verificação de sandbox desabilitada. Defina ALLOW_DEMO_VERIFICATION=true no .env para habilitar este atalho apenas em ambiente de demonstração.'
      });
    }
    const { targetId, domain } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'domain é obrigatório.' });

    const result = sandboxVerify(domain);
    if (targetId) {
      db.updateTarget(targetId, {
        verificationStatus: 'VERIFIED',
        verificationMethod: 'SANDBOX_DEMO',
        verifiedAt: new Date().toISOString()
      });
    }
    res.json(result);
  });

  // 4. Scans — síncrono de propósito (ver server/scanOrchestrator.ts): a função
  // serverless da Vercel é congelada assim que a resposta sai, então um job em
  // segundo plano com polling entre invocações não é confiável ali (cada poll pode
  // cair numa instância sem memória nenhuma do job). A rota bloqueia até o pipeline
  // de 3 etapas terminar e devolve o resultado final direto — mesmo comportamento
  // em dev local e na Vercel, para não ter um caminho testado e outro não.
  app.post('/api/scans', async (req: Request, res: Response) => {
    const { targetId, profile, config } = req.body || {};
    const target = db.getTarget(targetId);
    if (!target) return res.status(404).json({ error: 'Alvo não encontrado.' });
    if (target.verificationStatus !== 'VERIFIED') {
      return res.status(403).json({ error: 'Posse do domínio precisa estar validada antes de iniciar uma varredura.' });
    }

    try {
      const job = await startScan(target, (profile as ScanProfile) || 'NORMAL', config as ScanConfiguration);
      res.status(200).json({ scan: job });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Falha ao executar a varredura.' });
    }
  });

  app.get('/api/scans/:id', (req: Request, res: Response) => {
    const job = db.getScan(req.params.id);
    if (!job) return res.status(404).json({ error: 'Scan não encontrado.' });
    res.json({ scan: job });
  });

  app.get('/api/scans', (req: Request, res: Response) => {
    const targetId = typeof req.query.targetId === 'string' ? req.query.targetId : undefined;
    res.json({ scans: db.listScans(targetId) });
  });

  // Mantido por compatibilidade e para o caso local (processo único, várias
  // requisições concorrentes no mesmo event loop): ainda pode interromper um job
  // que esteja no meio do await de uma etapa. Numa invocação serverless isolada da
  // Vercel isto não tem efeito prático, já que o pipeline roda por inteiro dentro
  // da mesma requisição que o disparou — não há uma segunda invocação concorrente
  // para interromper a primeira.
  app.post('/api/scans/:id/stop', (req: Request, res: Response) => {
    const ok = cancelScan(req.params.id);
    if (!ok) return res.status(404).json({ error: 'Scan não encontrado.' });
    res.json({ stopped: true });
  });

  // 5. AI Triage manual (re-executar a triagem de um achado específico pela UI)
  app.post('/api/ai/triage', async (req: Request, res: Response) => {
    const { vulnerability, targetDomain, rawHttpTrace } = req.body || {};
    try {
      const result = await triageVulnerability(vulnerability || {}, targetDomain || 'alvo-desconhecido', rawHttpTrace);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Triage error' });
    }
  });

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
}
