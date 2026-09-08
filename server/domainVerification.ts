// Validação de propriedade de domínio (Anti-Abuso).
//
// IMPORTANTE: a versão anterior deste arquivo (dentro de server.ts) tinha um atalho
// que auto-verificava qualquer domínio contendo "fintech-pay", "ecommerce-fashion"
// ou "example.com", incondicionalmente, sem checar DNS/HTTP nenhum. Isso é
// exatamente o buraco que esta camada existe para fechar: um "verified: true" que
// não corresponde a nenhuma posse real. Foi removido. O único caminho não-criptográfico
// que resta é o sandbox explícito abaixo, que grava um método distinto
// ('SANDBOX_DEMO', nunca 'DNS_TXT'/'HTTP_FILE'/'HTML_META') e só funciona quando
// ALLOW_DEMO_VERIFICATION=true está setado — nunca por padrão em produção.
import dns from 'dns/promises';
import crypto from 'crypto';
import type { VerificationMethod } from '../src/types';

export interface VerificationResult {
  verified: boolean;
  method: VerificationMethod;
  domain: string;
  message: string;
  details?: Record<string, unknown>;
  error?: string;
}

export function generateVerificationToken(domain: string): string {
  return `aegis-sec-${crypto.randomBytes(12).toString('hex')}`;
}

export function isSandboxDemoAllowed(): boolean {
  return process.env.ALLOW_DEMO_VERIFICATION === 'true';
}

function cleanDomain(input: string): string {
  return input.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim().toLowerCase();
}

async function verifyDnsTxt(domain: string, token: string): Promise<VerificationResult> {
  const txtTarget = `_aegis-challenge.${domain}`;
  try {
    const records = await dns.resolveTxt(txtTarget);
    const flat = records.map(r => r.join(''));
    if (flat.some(v => v.includes(token))) {
      return {
        verified: true,
        method: 'DNS_TXT',
        domain,
        message: 'Registro DNS TXT encontrado e correspondente ao token!',
        details: { queriedTarget: txtTarget, foundRecords: flat, matchedToken: token }
      };
    }
    return {
      verified: false,
      method: 'DNS_TXT',
      domain,
      message: `Registro DNS TXT encontrado em ${txtTarget}, mas o valor não corresponde ao token esperado.`,
      details: { queriedTarget: txtTarget, foundRecords: flat }
    };
  } catch (err: any) {
    return {
      verified: false,
      method: 'DNS_TXT',
      domain,
      message: `Nenhum registro TXT encontrado para ${txtTarget}. Verifique se o TTL do DNS propagou (pode levar alguns minutos).`,
      error: err?.code || err?.message || 'DNS_LOOKUP_FAILED'
    };
  }
}

async function verifyHttpFile(domain: string, token: string): Promise<VerificationResult> {
  const fileUrl = `https://${domain}/.well-known/aegis-verify.txt`;
  try {
    const res = await fetch(fileUrl, {
      signal: AbortSignal.timeout(5000),
      headers: { 'User-Agent': 'AegisDAST-DomainVerifier/1.0' }
    });
    if (res.ok) {
      const content = await res.text();
      if (content.includes(token)) {
        return {
          verified: true,
          method: 'HTTP_FILE',
          domain,
          message: 'Arquivo de validação HTTP encontrado e validado com sucesso!',
          details: { url: fileUrl, matchedToken: token }
        };
      }
    }
    return {
      verified: false,
      method: 'HTTP_FILE',
      domain,
      message: `O arquivo em ${fileUrl} retornou código ${res.status} ou não contém o token correto.`,
      details: { url: fileUrl, httpStatus: res.status }
    };
  } catch (err: any) {
    return {
      verified: false,
      method: 'HTTP_FILE',
      domain,
      message: `Não foi possível conectar a ${fileUrl}.`,
      error: err?.message || 'FETCH_FAILED'
    };
  }
}

async function verifyHtmlMeta(domain: string, token: string): Promise<VerificationResult> {
  const pageUrl = `https://${domain}/`;
  try {
    const res = await fetch(pageUrl, {
      signal: AbortSignal.timeout(5000),
      headers: { 'User-Agent': 'AegisDAST-DomainVerifier/1.0' }
    });
    if (!res.ok) {
      return {
        verified: false,
        method: 'HTML_META',
        domain,
        message: `A página ${pageUrl} retornou código HTTP ${res.status}.`,
        details: { url: pageUrl, httpStatus: res.status }
      };
    }
    const html = await res.text();
    // Aceita qualquer ordem de atributos (name antes ou depois de content) e aspas simples/duplas.
    const metaRegex = /<meta[^>]+name=["']aegis-site-verification["'][^>]+content=["']([^"']+)["'][^>]*>|<meta[^>]+content=["']([^"']+)["'][^>]+name=["']aegis-site-verification["'][^>]*>/i;
    const match = html.match(metaRegex);
    const foundContent = match ? (match[1] || match[2]) : undefined;
    if (foundContent === token) {
      return {
        verified: true,
        method: 'HTML_META',
        domain,
        message: 'Meta tag de verificação encontrada e validada com sucesso!',
        details: { url: pageUrl, matchedToken: token }
      };
    }
    return {
      verified: false,
      method: 'HTML_META',
      domain,
      message: foundContent
        ? `Meta tag encontrada, mas o conteúdo não corresponde ao token esperado.`
        : `Nenhuma tag <meta name="aegis-site-verification"> encontrada em ${pageUrl}.`,
      details: { url: pageUrl }
    };
  } catch (err: any) {
    return {
      verified: false,
      method: 'HTML_META',
      domain,
      message: `Não foi possível carregar ${pageUrl}.`,
      error: err?.message || 'FETCH_FAILED'
    };
  }
}

export async function verifyDomainOwnership(
  rawDomain: string,
  method: VerificationMethod,
  token: string
): Promise<VerificationResult> {
  const domain = cleanDomain(rawDomain);
  if (!domain || !token) {
    return { verified: false, method, domain, message: 'Domínio e token de verificação são obrigatórios.' };
  }

  switch (method) {
    case 'DNS_TXT':
      return verifyDnsTxt(domain, token);
    case 'HTTP_FILE':
      return verifyHttpFile(domain, token);
    case 'HTML_META':
      return verifyHtmlMeta(domain, token);
    default:
      return { verified: false, method, domain, message: 'Método de validação não suportado.' };
  }
}

// Caminho explícito de demonstração/sandbox: nunca cripto-verificado de verdade.
// Persistido com o método 'SANDBOX_DEMO' para que nunca seja confundido com uma
// validação real na UI, no relatório ou em uma auditoria posterior.
export function sandboxVerify(rawDomain: string): VerificationResult {
  const domain = cleanDomain(rawDomain);
  return {
    verified: true,
    method: 'SANDBOX_DEMO',
    domain,
    message: 'Verificação simulada (modo sandbox). Nenhuma checagem criptográfica real foi realizada — não use isto como prova de posse.',
    details: { note: 'ALLOW_DEMO_VERIFICATION=true habilitou este atalho de demonstração.' }
  };
}
