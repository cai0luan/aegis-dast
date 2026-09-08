// Motor de Reconhecimento Passivo — a única etapa do pipeline que executa E2E
// contra a internet real. Tudo aqui é estritamente passivo/somente-leitura:
// resolução DNS, uma requisição HTTP GET à raiz do site, um handshake TLS padrão
// na porta 443 (o mesmo que qualquer navegador faz) e uma consulta a um espelho
// público de Certificate Transparency (crt.sh) — nada disso envia payload de
// ataque, não varre portas arbitrárias e não é diferente do que qualquer visitante
// comum do site já faz. Por isso pode rodar de verdade neste ambiente sem risco de
// causar indisponibilidade ou ser interpretado como exploração ativa.
//
// A Etapa 2 (DAST ativo: Nuclei/OWASP ZAP) permanece fora de escopo aqui de propósito
// — esta sandbox não tem esses binários nem Docker, e rodar exploração real contra
// um domínio arbitrário sem essa infraestrutura dedicada seria irresponsável.
// scanOrchestrator.ts mantém aquela etapa como simulação claramente rotulada.
import dns from 'dns/promises';
import tls from 'tls';
import type { DnsRecordSet, HttpProbeResult, ReconFindings, TlsCertificateInfo, Vulnerability } from '../src/types';

const RECON_TIMEOUT_MS = 6000;

async function safeResolve<T>(fn: () => Promise<T[]>): Promise<T[]> {
  try {
    return await fn();
  } catch {
    return [];
  }
}

async function resolveDnsRecords(domain: string): Promise<DnsRecordSet> {
  const [a, aaaa, cname, mxRaw, ns, txtRaw] = await Promise.all([
    safeResolve(() => dns.resolve4(domain)),
    safeResolve(() => dns.resolve6(domain)),
    safeResolve(() => dns.resolveCname(domain)),
    safeResolve(() => dns.resolveMx(domain)),
    safeResolve(() => dns.resolveNs(domain)),
    safeResolve(() => dns.resolveTxt(domain))
  ]);

  return {
    a,
    aaaa,
    cname,
    mx: mxRaw.map((r: any) => `${r.exchange} (prioridade ${r.priority})`),
    ns,
    txt: txtRaw.map((r: any) => (Array.isArray(r) ? r.join('') : r))
  };
}

async function fetchCrtShSubdomains(domain: string): Promise<{ subdomains: string[]; source: 'crt.sh' | 'unavailable' }> {
  try {
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000), headers: { 'User-Agent': 'AegisDAST-Recon/1.0' } });
    if (!res.ok) return { subdomains: [], source: 'unavailable' };
    const data: Array<{ name_value?: string }> = await res.json();
    const names = new Set<string>();
    for (const entry of data) {
      if (!entry.name_value) continue;
      for (const raw of entry.name_value.split('\n')) {
        const name = raw.trim().toLowerCase().replace(/^\*\./, '');
        if (name.endsWith(domain) && name !== domain) {
          names.add(name);
        }
      }
    }
    return { subdomains: Array.from(names).slice(0, 40), source: 'crt.sh' };
  } catch {
    return { subdomains: [], source: 'unavailable' };
  }
}

const SECURITY_HEADERS_CHECKLIST = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy'
];

async function probeHttp(domain: string): Promise<HttpProbeResult> {
  for (const scheme of ['https', 'http']) {
    const url = `${scheme}://${domain}/`;
    try {
      const startedAt = Date.now();
      const res = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(RECON_TIMEOUT_MS),
        headers: { 'User-Agent': 'AegisDAST-Recon/1.0 (+passive-recon)' }
      });
      const responseTimeMs = Date.now() - startedAt;
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
      const missingSecurityHeaders = SECURITY_HEADERS_CHECKLIST.filter(h => !(h in headers));

      return {
        reachable: true,
        finalUrl: res.url,
        statusCode: res.status,
        responseTimeMs,
        headers,
        missingSecurityHeaders
      };
    } catch (err: any) {
      if (scheme === 'http') {
        return { reachable: false, error: err?.message || 'HTTP_PROBE_FAILED' };
      }
      // https falhou, tenta http antes de desistir
    }
  }
  return { reachable: false, error: 'HTTP_PROBE_FAILED' };
}

function certName(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function probeTls(domain: string): Promise<TlsCertificateInfo> {
  return new Promise(resolve => {
    let settled = false;
    const socket = tls.connect(
      { host: domain, port: 443, servername: domain, timeout: RECON_TIMEOUT_MS, rejectUnauthorized: false },
      () => {
        if (settled) return;
        settled = true;
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || undefined;
          const validTo = cert?.valid_to ? new Date(cert.valid_to) : undefined;
          const daysUntilExpiry = validTo ? Math.round((validTo.getTime() - Date.now()) / 86_400_000) : undefined;
          resolve({
            reachable: true,
            protocol,
            subject: certName(cert?.subject?.CN),
            issuer: certName(cert?.issuer?.CN),
            validFrom: cert?.valid_from,
            validTo: cert?.valid_to,
            daysUntilExpiry,
            selfSigned: !!cert && cert.issuer?.CN === cert.subject?.CN
          });
        } catch (err: any) {
          resolve({ reachable: false, error: err?.message || 'TLS_PARSE_FAILED' });
        } finally {
          socket.end();
        }
      }
    );
    socket.on('error', (err) => {
      if (settled) return;
      settled = true;
      resolve({ reachable: false, error: err.message });
    });
    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      resolve({ reachable: false, error: 'TLS_HANDSHAKE_TIMEOUT' });
      socket.destroy();
    });
  });
}

function fingerprintTechnologies(headers: Record<string, string> | undefined): string[] {
  if (!headers) return [];
  const found = new Set<string>();
  const server = headers['server'] || '';
  const poweredBy = headers['x-powered-by'] || '';
  const setCookie = headers['set-cookie'] || '';

  const signatures: Array<[RegExp, string]> = [
    [/cloudflare/i, 'Cloudflare CDN/WAF'],
    [/nginx/i, 'Nginx'],
    [/apache/i, 'Apache HTTP Server'],
    [/microsoft-iis/i, 'Microsoft IIS'],
    [/vercel/i, 'Vercel'],
    [/express/i, 'Node.js / Express'],
    [/php/i, 'PHP'],
    [/asp\.net/i, 'ASP.NET'],
    [/next\.js/i, 'Next.js']
  ];

  for (const [pattern, label] of signatures) {
    if (pattern.test(server) || pattern.test(poweredBy)) found.add(label);
  }

  if (/phpsessid/i.test(setCookie)) found.add('PHP (via cookie de sessão)');
  if (/jsessionid/i.test(setCookie)) found.add('Java / JSP (via cookie de sessão)');
  if ('cf-ray' in headers) found.add('Cloudflare CDN/WAF');
  if (Object.keys(headers).some(h => h.startsWith('x-vercel-'))) found.add('Vercel');

  return Array.from(found);
}

async function checkWellKnownFile(domain: string, filePath: string): Promise<boolean> {
  try {
    const res = await fetch(`https://${domain}${filePath}`, {
      signal: AbortSignal.timeout(4000),
      headers: { 'User-Agent': 'AegisDAST-Recon/1.0' }
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function runPassiveRecon(domain: string): Promise<ReconFindings> {
  const [dnsRecords, crtSh, httpProbe, tlsInfo, robotsTxtFound, securityTxtFound] = await Promise.all([
    resolveDnsRecords(domain),
    fetchCrtShSubdomains(domain),
    probeHttp(domain),
    probeTls(domain),
    checkWellKnownFile(domain, '/robots.txt'),
    checkWellKnownFile(domain, '/.well-known/security.txt')
  ]);

  return {
    domain,
    executedAt: new Date().toISOString(),
    dns: dnsRecords,
    subdomains: crtSh.subdomains,
    subdomainsSource: crtSh.source,
    httpProbe,
    tls: tlsInfo,
    technologies: fingerprintTechnologies(httpProbe.headers),
    robotsTxtFound,
    securityTxtFound
  };
}

let vulnCounter = 0;
function nextVulnId(prefix: string): string {
  vulnCounter += 1;
  return `${prefix}-${Date.now().toString(36)}-${vulnCounter}`;
}

// Converte observações reais do recon em achados no formato Vulnerability — cada um
// aqui é verificável de novo com um `curl -I` manual, nunca uma inferência ou palpite.
export function deriveVulnerabilitiesFromRecon(findings: ReconFindings, targetUrl: string): Vulnerability[] {
  const out: Vulnerability[] = [];
  const { httpProbe, tls: tlsInfo } = findings;

  if (httpProbe.reachable && httpProbe.missingSecurityHeaders && httpProbe.missingSecurityHeaders.length > 0) {
    const missing = httpProbe.missingSecurityHeaders;
    out.push({
      id: nextVulnId('recon-headers'),
      title: `Cabeçalhos de Segurança HTTP Ausentes (${missing.length} de ${SECURITY_HEADERS_CHECKLIST.length})`,
      severity: missing.length >= 4 ? 'MEDIUM' : 'LOW',
      cvssScore: missing.length >= 4 ? 5.3 : 3.1,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
      owaspCategory: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-16: Configuration',
      matchedUrl: httpProbe.finalUrl || targetUrl,
      toolSource: 'Aegis Passive Recon',
      description: `A resposta HTTP da página inicial não inclui os seguintes cabeçalhos de segurança recomendados: ${missing.join(', ')}.`,
      impact: 'Ausência de defesas em profundidade no navegador (ex: sem CSP o site fica mais exposto a XSS residual; sem HSTS há janela para downgrade para HTTP).',
      status: 'CONFIRMED',
      aiConfidenceScore: 100,
      aiTriageReasoning: 'Observação direta e determinística: os cabeçalhos ausentes foram lidos na resposta HTTP real, sem inferência.',
      dataSource: 'REAL_PASSIVE_RECON',
      proofOfConcept: {
        attackPayload: 'N/A (observação passiva, não é uma exploração)',
        curlCommand: `curl -sI ${httpProbe.finalUrl || targetUrl}`,
        httpRequest: `GET / HTTP/1.1\nHost: ${findings.domain}`,
        httpResponse: Object.entries(httpProbe.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n'),
        evidenceText: `Cabeçalhos ausentes na resposta real: ${missing.join(', ')}.`
      },
      remediation: {
        recommendation: 'Configure o servidor web/CDN para emitir os cabeçalhos de segurança ausentes. Comece por Content-Security-Policy e Strict-Transport-Security, que têm o maior impacto defensivo.',
        language: 'nginx',
        codeSnippetBefore: '# Sem cabeçalhos de segurança configurados',
        codeSnippetAfter: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "DENY" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
        references: ['https://owasp.org/www-project-secure-headers/']
      }
    });
  }

  if (tlsInfo.reachable && typeof tlsInfo.daysUntilExpiry === 'number' && tlsInfo.daysUntilExpiry < 30) {
    out.push({
      id: nextVulnId('recon-tls-expiry'),
      title: `Certificado TLS Expirando em ${tlsInfo.daysUntilExpiry} dia(s)`,
      severity: tlsInfo.daysUntilExpiry < 7 ? 'HIGH' : 'MEDIUM',
      cvssScore: tlsInfo.daysUntilExpiry < 7 ? 7.4 : 5.9,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      owaspCategory: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-298: Improper Validation of Certificate Expiration',
      matchedUrl: `https://${findings.domain}`,
      toolSource: 'Aegis Passive Recon',
      description: `O certificado TLS apresentado por ${findings.domain} expira em ${tlsInfo.validTo}.`,
      impact: 'Após a expiração, navegadores bloquearão o acesso ao site com um alerta de segurança, causando indisponibilidade efetiva.',
      status: 'CONFIRMED',
      aiConfidenceScore: 100,
      aiTriageReasoning: 'Data de expiração lida diretamente do certificado apresentado no handshake TLS real.',
      dataSource: 'REAL_PASSIVE_RECON',
      proofOfConcept: {
        attackPayload: 'N/A (observação passiva)',
        curlCommand: `openssl s_client -connect ${findings.domain}:443 -servername ${findings.domain} </dev/null 2>/dev/null | openssl x509 -noout -enddate`,
        httpRequest: 'TLS ClientHello (handshake, sem payload HTTP)',
        httpResponse: `Subject: ${tlsInfo.subject || 'N/A'}\nIssuer: ${tlsInfo.issuer || 'N/A'}\nValid To: ${tlsInfo.validTo}`,
        evidenceText: `Certificado real expira em ${tlsInfo.validTo}.`
      },
      remediation: {
        recommendation: 'Renove o certificado TLS antes do vencimento e configure renovação automática (ex: Let\'s Encrypt + certbot com cron, ou o renovador nativo do seu provedor de CDN).',
        references: ['https://letsencrypt.org/docs/faq/']
      }
    });
  }

  if (!tlsInfo.reachable) {
    out.push({
      id: nextVulnId('recon-tls-unreachable'),
      title: 'Não Foi Possível Estabelecer Handshake TLS na Porta 443',
      severity: 'INFO',
      cvssScore: 0,
      cvssVector: 'N/A',
      owaspCategory: 'A05:2021-Security Misconfiguration',
      cwe: 'N/A',
      matchedUrl: `https://${findings.domain}`,
      toolSource: 'Aegis Passive Recon',
      description: `A tentativa de handshake TLS na porta 443 falhou: ${tlsInfo.error}.`,
      impact: 'Pode indicar que o serviço não expõe HTTPS diretamente, um firewall bloqueando a porta, ou uma falha de configuração de certificado.',
      status: 'CONFIRMED',
      aiConfidenceScore: 100,
      aiTriageReasoning: 'Resultado direto da tentativa de conexão TLS real.',
      dataSource: 'REAL_PASSIVE_RECON',
      proofOfConcept: {
        attackPayload: 'N/A',
        curlCommand: `openssl s_client -connect ${findings.domain}:443 -servername ${findings.domain}`,
        httpRequest: 'TLS ClientHello',
        httpResponse: `Erro: ${tlsInfo.error}`,
        evidenceText: `Handshake TLS falhou: ${tlsInfo.error}`
      },
      remediation: {
        recommendation: 'Confirme se o serviço realmente deveria expor HTTPS na porta 443 e se não há firewall/security group bloqueando a conexão.',
        references: []
      }
    });
  }

  return out;
}
