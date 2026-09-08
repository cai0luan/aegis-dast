// O pacote "dotenv" já era uma dependência declarada, mas nunca era importado —
// fora do runtime da AI Studio (que injeta as env vars diretamente), o .env local
// era silenciosamente ignorado e GEMINI_API_KEY/ALLOW_DEMO_VERIFICATION nunca chegavam.
import 'dotenv/config';
import express, { Request, Response } from 'express';
import path from 'path';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import * as db from './server/db';
import { verifyDomainOwnership, sandboxVerify, isSandboxDemoAllowed, generateVerificationToken } from './server/domainVerification';
import { startScan, cancelScan } from './server/scanOrchestrator';
import { triageVulnerability, isAiConfigured } from './server/aiTriage';
import type { TargetDomain, VerificationMethod, ScanProfile, ScanConfiguration } from './src/types';

const PORT = Number(process.env.PORT) || 3000;

async function startServer() {
  const app = express();
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

  // 4. Scans — inicia, consulta e cancela o pipeline real de 3 etapas.
  app.post('/api/scans', (req: Request, res: Response) => {
    const { targetId, profile, config } = req.body || {};
    const target = db.getTarget(targetId);
    if (!target) return res.status(404).json({ error: 'Alvo não encontrado.' });
    if (target.verificationStatus !== 'VERIFIED') {
      return res.status(403).json({ error: 'Posse do domínio precisa estar validada antes de iniciar uma varredura.' });
    }

    const job = startScan(target, (profile as ScanProfile) || 'NORMAL', config as ScanConfiguration);
    res.status(202).json({ scan: job });
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

  // Vite middleware setup
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AegisDAST] Server running on http://localhost:${PORT}`);
    console.log(`[AegisDAST] AI Triage: ${isAiConfigured() ? 'Gemini real (chave configurada)' : 'fallback heurístico (GEMINI_API_KEY ausente)'}`);
    console.log(`[AegisDAST] Verificação sandbox: ${isSandboxDemoAllowed() ? 'HABILITADA (ALLOW_DEMO_VERIFICATION=true)' : 'desabilitada'}`);
  });
}

startServer();
