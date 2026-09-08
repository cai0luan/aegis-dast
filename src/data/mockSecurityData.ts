import { TargetDomain, Vulnerability, ScanJob } from '../types';

export const STATIC_EGRESS_IPS = [
  '198.51.100.24',
  '198.51.100.25',
  '198.51.100.26',
  '203.0.113.88'
];

export const INITIAL_TARGETS: TargetDomain[] = [
  {
    id: 'tgt-alpha-01',
    domain: 'app.fintech-pay.com.br',
    url: 'https://app.fintech-pay.com.br',
    organizationName: 'Fintech Payments S.A.',
    verificationStatus: 'VERIFIED',
    verificationMethod: 'DNS_TXT',
    verificationToken: 'aegis-sec-9a4f21b7d83c9901e',
    verifiedAt: '2026-08-28T14:30:00Z',
    createdAt: '2026-08-28T14:00:00Z',
    lastScanAt: '2026-09-01T10:15:00Z',
    riskScore: 78,
    totalVulns: {
      critical: 1,
      high: 2,
      medium: 3,
      low: 2,
      info: 4
    }
  },
  {
    id: 'tgt-beta-02',
    domain: 'portal.saude-med.com.br',
    url: 'https://portal.saude-med.com.br',
    organizationName: 'Saúde & Vida Digital',
    verificationStatus: 'UNVERIFIED',
    verificationMethod: 'DNS_TXT',
    verificationToken: 'aegis-sec-4e1b87c20a9143df1',
    createdAt: '2026-09-02T18:20:00Z',
    riskScore: 0,
    totalVulns: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    }
  },
  {
    id: 'tgt-gamma-03',
    domain: 'ecommerce-fashion.com.br',
    url: 'https://ecommerce-fashion.com.br',
    organizationName: 'Nova Moda E-commerce',
    verificationStatus: 'VERIFIED',
    verificationMethod: 'HTTP_FILE',
    verificationToken: 'aegis-sec-7c890f14ba332ef55',
    verifiedAt: '2026-09-01T09:00:00Z',
    createdAt: '2026-09-01T08:45:00Z',
    lastScanAt: '2026-09-01T11:45:00Z',
    riskScore: 42,
    totalVulns: {
      critical: 0,
      high: 1,
      medium: 4,
      low: 3,
      info: 5
    }
  }
];

export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'vuln-01',
    title: 'SQL Injection Cega Baseada em Tempo (Time-Based Blind SQLi)',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    owaspCategory: 'A03:2021-Injection',
    cwe: 'CWE-89: SQL Injection',
    matchedUrl: 'https://app.fintech-pay.com.br/api/v1/transactions/export?filter_status=PENDING',
    toolSource: 'Nuclei',
    description: 'O endpoint de exportação de transações concatena parâmetros diretamente na query SQL do PostgreSQL sem parametrização ou sanitização via ORM/Prepared Statements.',
    impact: 'Um atacante não autenticado pode extrair o banco de dados completo (hashes de senhas, dados de cartão de crédito e PII de clientes) ou obter execução de comandos no servidor via COPY FROM PROGRAM.',
    status: 'CONFIRMED',
    aiConfidenceScore: 99,
    aiTriageReasoning: 'Confirmado por teste de atraso estatístico de tempo (sleep de 5.02s vs 0.08s em requisição baseline) e verificação diferencial de carga útil.',
    dataSource: 'SIMULATED_DAST',
    proofOfConcept: {
      parameter: 'filter_status',
      attackPayload: "' OR (SELECT 4821 FROM PG_SLEEP(5))--",
      curlCommand: `curl -i -s -k -X $'GET' \\\n  -H $'Host: app.fintech-pay.com.br' \\\n  -H $'X-Aegis-Scan-Authorization: Bearer aegis_sec_auth_live_prod_key_77a' \\\n  $'https://app.fintech-pay.com.br/api/v1/transactions/export?filter_status=PENDING%27%20OR%20(SELECT%204821%20FROM%20PG_SLEEP(5))--'`,
      httpRequest: `GET /api/v1/transactions/export?filter_status=PENDING' OR (SELECT 4821 FROM PG_SLEEP(5))-- HTTP/1.1
Host: app.fintech-pay.com.br
User-Agent: AegisDAST-SecurityScanner/2.4 (Security-Audit)
X-Aegis-Scan-Authorization: Bearer aegis_sec_auth_live_prod_key_77a
Accept: application/json`,
      httpResponse: `HTTP/1.1 200 OK
Date: Wed, 02 Sep 2026 20:10:05 GMT
Content-Type: application/json
Content-Length: 142
Connection: keep-alive
X-Response-Time: 5028ms

{"status":"success","data":[],"query_time_ms":5024}`,
      evidenceText: 'Tempo de resposta excedeu 5000ms com consistência após injeção da função PG_SLEEP(5).'
    },
    remediation: {
      recommendation: 'Utilize consultas parametrizadas (Prepared Statements) ou o query builder do seu ORM (ex: Prisma/TypeORM/SQLAlchemy) garantindo que nenhum input seja concatenado diretamente na cláusula WHERE.',
      language: 'typescript',
      codeSnippetBefore: `// INSEGURO: Concatenação direta de query
const result = await db.query(
  \`SELECT * FROM transactions WHERE status = '\${req.query.filter_status}'\`
);`,
      codeSnippetAfter: `// SEGURO: Utilização de Prepared Statements parametrizados
const result = await db.query(
  'SELECT * FROM transactions WHERE status = $1',
  [req.query.filter_status]
);`,
      references: [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html'
      ]
    }
  },
  {
    id: 'vuln-02',
    title: 'Server-Side Request Forgery (SSRF) no Mecanismo de Webhook Preview',
    severity: 'HIGH',
    cvssScore: 8.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N',
    owaspCategory: 'A10:2021-Server-Side Request Forgery (SSRF)',
    cwe: 'CWE-918: Server-Side Request Forgery',
    matchedUrl: 'https://app.fintech-pay.com.br/api/v1/webhooks/test-endpoint',
    toolSource: 'OWASP ZAP',
    description: 'A funcionalidade de teste de webhooks permite fornecer URLs arbitrárias. O backend faz requisições HTTP internas sem validar faixas privadas (RFC 1918) ou o endpoint de metadados da AWS Cloud.',
    impact: 'Leitura de credenciais temporárias do IAM Instance Profile da AWS (169.254.169.254) permitindo movimentação lateral e controle da infraestrutura em nuvem.',
    status: 'CONFIRMED',
    aiConfidenceScore: 97,
    aiTriageReasoning: 'O servidor retornou o JSON do metadados da instância EC2 (security-credentials) no corpo da resposta do teste de webhook.',
    dataSource: 'SIMULATED_DAST',
    proofOfConcept: {
      parameter: 'webhook_url',
      attackPayload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      curlCommand: `curl -i -s -k -X $'POST' \\\n  -H $'Host: app.fintech-pay.com.br' \\\n  -H $'Content-Type: application/json' \\\n  -H $'X-Aegis-Scan-Authorization: Bearer aegis_sec_auth_live_prod_key_77a' \\\n  --data-binary $'{"webhook_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}' \\\n  $'https://app.fintech-pay.com.br/api/v1/webhooks/test-endpoint'`,
      httpRequest: `POST /api/v1/webhooks/test-endpoint HTTP/1.1
Host: app.fintech-pay.com.br
Content-Type: application/json
X-Aegis-Scan-Authorization: Bearer aegis_sec_auth_live_prod_key_77a

{"webhook_url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}`,
      httpResponse: `HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 78

{"status":"webhook_reachable","response_body":"fintech-prod-ecs-task-role"}`,
      evidenceText: 'Nome do perfil IAM (fintech-prod-ecs-task-role) refletido no response_body retornado pelo backend.'
    },
    remediation: {
      recommendation: 'Implemente uma lista de permissão estrita de esquemas (apenas https) e bloqueie a resolução e conexão para IPs privados (0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) utilizando um resolvedor DNS seguro com validação pré-conexão (anti-DNS Rebinding).',
      language: 'typescript',
      codeSnippetBefore: `// INSEGURO: Requisição direta para URL fornecida pelo usuário
const response = await fetch(req.body.webhook_url);
const body = await response.text();`,
      codeSnippetAfter: `// SEGURO: Validação de URL e bloqueio de IPs privados
import { isPrivateIP } from './network-security';
import dns from 'dns/promises';

const parsed = new URL(req.body.webhook_url);
if (parsed.protocol !== 'https:') throw new Error('Apenas HTTPS é permitido');

const lookup = await dns.lookup(parsed.hostname);
if (isPrivateIP(lookup.address)) {
  throw new Error('Acesso a endereços de rede interna bloqueado');
}`,
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
      ]
    }
  },
  {
    id: 'vuln-03',
    title: 'Cross-Site Scripting Refletido (Reflected XSS) no Mecanismo de Busca',
    severity: 'HIGH',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N',
    owaspCategory: 'A03:2021-Injection',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    matchedUrl: 'https://app.fintech-pay.com.br/search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E',
    toolSource: 'OWASP ZAP',
    description: 'O parâmetro de busca "q" é renderizado diretamente no template HTML retornado sem escape de caracteres HTML especiais e sem política CSP restritiva.',
    impact: 'Um atacante pode induzir uma vítima a clicar em um link malicioso e sequestrar o token de sessão ou executar ações em nome do usuário autenticado.',
    status: 'CONFIRMED',
    aiConfidenceScore: 94,
    aiTriageReasoning: 'Tags <script> e atributos HTML injetados foram refletidos sem codificação em contexto de execução JavaScript no DOM.',
    dataSource: 'SIMULATED_DAST',
    proofOfConcept: {
      parameter: 'q',
      attackPayload: '"><svg/onload=alert(1)>',
      curlCommand: `curl -i -s -k -X $'GET' \\\n  -H $'Host: app.fintech-pay.com.br' \\\n  $'https://app.fintech-pay.com.br/search?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E'`,
      httpRequest: `GET /search?q="><svg/onload=alert(1)> HTTP/1.1
Host: app.fintech-pay.com.br
User-Agent: Mozilla/5.0 (Security-Scanner)`,
      httpResponse: `HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<div>Resultados para: "><svg/onload=alert(1)></div>`,
      evidenceText: 'Payload "><svg/onload=alert(1)> refletido raw no corpo da resposta HTML sem entidades HTML (&quot;&gt;).'
    },
    remediation: {
      recommendation: 'Codifique todos os dados originados do usuário antes de renderizá-los em contextos HTML (HTML Entity Encoding) e adicione um cabeçalho Content-Security-Policy com nonce ou hashes estritos.',
      language: 'html',
      codeSnippetBefore: `<!-- INSEGURO: Inserção raw de parâmetro -->
<p>Resultados para: <%= req.query.q %></p>`,
      codeSnippetAfter: `<!-- SEGURO: Encode automático de caracteres HTML -->
<p>Resultados para: <%= htmlEncode(req.query.q) %></p>`,
      references: [
        'https://owasp.org/www-community/attacks/xss/'
      ]
    }
  },
  {
    id: 'vuln-04',
    title: 'Exposição de Arquivo Sensível de Ambiente (.env) e Configuração Git',
    severity: 'MEDIUM',
    cvssScore: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    owaspCategory: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
    matchedUrl: 'https://app.fintech-pay.com.br/.env.backup',
    toolSource: 'Nuclei',
    description: 'Um arquivo `.env.backup` deixado por engano no diretório raiz do web server responde com código 200 e contém chaves de API parciais.',
    impact: 'Vazamento de segredos de configuração e identificadores de integração de serviços de terceiros.',
    status: 'CONFIRMED',
    aiConfidenceScore: 92,
    aiTriageReasoning: 'O arquivo contém strings típicas como JWT_SECRET e DATABASE_URL com cabeçalho text/plain.',
    dataSource: 'SIMULATED_DAST',
    proofOfConcept: {
      attackPayload: 'GET /.env.backup',
      curlCommand: 'curl -i -s -k https://app.fintech-pay.com.br/.env.backup',
      httpRequest: `GET /.env.backup HTTP/1.1\nHost: app.fintech-pay.com.br`,
      httpResponse: `HTTP/1.1 200 OK\nContent-Type: text/plain\n\nNODE_ENV=production\nAPP_NAME=FintechCore\nPORT=3000\nREDIS_HOST=10.0.4.12`,
      evidenceText: 'Corpo da resposta expôs variáveis de ambiente de produção em texto claro.'
    },
    remediation: {
      recommendation: 'Configure o Nginx / Cloudflare para bloquear expressamente qualquer requisição a arquivos ocultos (iniciados por ponto) ou extensões de backup (.env, .git, .bak, .swp).',
      language: 'nginx',
      codeSnippetBefore: `# Nginx sem bloqueio de arquivos ocultos`,
      codeSnippetAfter: `location ~ /\\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}`,
      references: ['https://cwe.mitre.org/data/definitions/200.html']
    }
  },
  {
    id: 'vuln-05-fp',
    title: 'Possível Apache HTTP Request Smuggling (Descartado: Falso Positivo)',
    severity: 'HIGH',
    cvssScore: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N',
    owaspCategory: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-444: Inconsistent Interpretation of HTTP Requests',
    matchedUrl: 'https://app.fintech-pay.com.br/health',
    toolSource: 'OWASP ZAP',
    description: 'O scanner sinalizou uma anomalia de Transfer-Encoding chunked vs Content-Length.',
    impact: 'Descartado na camada de pós-processamento: a aplicação está atrás de um proxy HTTP/2 estrito que normaliza todos os cabeçalhos.',
    status: 'FALSE_POSITIVE',
    aiConfidenceScore: 98,
    aiTriageReasoning: 'Triagem com IA detectou que o servidor responde HTTP/2 diretamente e o socket foi encerrado de maneira graciosa sem pipeline desbalanceado.',
    dataSource: 'SIMULATED_DAST',
    proofOfConcept: {
      attackPayload: 'Transfer-Encoding: chunked (smuggling probe)',
      curlCommand: 'curl -i -k --http1.1 -H "Transfer-Encoding: chunked" https://app.fintech-pay.com.br/health',
      httpRequest: 'POST /health HTTP/1.1\nTransfer-Encoding: chunked\nContent-Length: 4\n\n0\n\n',
      httpResponse: 'HTTP/1.1 400 Bad Request\nServer: envoy',
      evidenceText: 'Proxy Envoy normalizou e rejeitou com 400 Bad Request antes de alcançar a aplicação.'
    },
    remediation: {
      recommendation: 'Nenhuma ação necessária. O proxy perimetral já realiza a sanitização e normalização segura de cabeçalhos HTTP.',
      references: []
    }
  }
];

export const SAMPLE_COMPLETED_SCAN: ScanJob = {
  id: 'scan-job-enterprise-991',
  targetId: 'tgt-alpha-01',
  targetDomain: 'app.fintech-pay.com.br',
  status: 'COMPLETED',
  profile: 'NORMAL',
  config: {
    targetId: 'tgt-alpha-01',
    profile: 'NORMAL',
    rateLimit: 15,
    concurrency: 5,
    maxDepth: 3,
    tools: {
      subfinder: true,
      naabu: true,
      wappalyzer: true,
      nuclei: true,
      zap: true,
      nmap: true
    },
    wafBypass: {
      enabled: true,
      authHeaderName: 'X-Aegis-Scan-Authorization',
      authHeaderValue: 'Bearer aegis_sec_auth_live_prod_key_77a',
      useStaticEgressIps: true
    },
    timeoutMinutes: 30,
    autoThrottleOnHttpErrors: true
  },
  createdAt: '2026-09-01T09:45:00Z',
  startedAt: '2026-09-01T09:45:10Z',
  completedAt: '2026-09-01T10:15:22Z',
  currentStageIndex: 3,
  stages: [
    {
      id: 'stg-1',
      name: 'Reconhecimento & Descoberta Ativa',
      tool: 'Subfinder + Naabu + Wappalyzer',
      status: 'COMPLETED',
      startedAt: '2026-09-01T09:45:12Z',
      completedAt: '2026-09-01T09:52:40Z',
      progress: 100,
      findingsCount: 14,
      summary: 'Mapeados 8 subdomínios, 4 portas abertas (80, 443, 8080, 8443) e stack identificada (Node.js/Express, PostgreSQL, Envoy/Cloudflare).'
    },
    {
      id: 'stg-2',
      name: 'Análise Ativa de Vulnerabilidades (DAST)',
      tool: 'Nuclei v3 + OWASP ZAP + Nmap NSE',
      status: 'COMPLETED',
      startedAt: '2026-09-01T09:52:45Z',
      completedAt: '2026-09-01T10:08:15Z',
      progress: 100,
      findingsCount: 19,
      summary: 'Executados 2.450 templates de segurança (OWASP Top 10, CVEs recentes, Misconfigurations, Injection).'
    },
    {
      id: 'stg-3',
      name: 'Pós-Processamento & Triagem de Falsos Positivos (AI Engine)',
      tool: 'Aegis Core Correlation + Gemini AI Triage',
      status: 'COMPLETED',
      startedAt: '2026-09-01T10:08:20Z',
      completedAt: '2026-09-01T10:15:20Z',
      progress: 100,
      findingsCount: 5,
      summary: 'Descartados 14 alertas com ruído/falso positivo. Validadas 5 vulnerabilidades reais com geração automática de PoC e remediação.'
    }
  ],
  logs: [
    { timestamp: '09:45:10', level: 'INFO', stage: 'Orchestrator', message: 'Iniciando container worker task-worker-pod-04 via Celery/Redis.' },
    { timestamp: '09:45:11', level: 'SUCCESS', stage: 'Ownership', message: 'Token de posse validado via DNS TXT (_aegis-challenge.app.fintech-pay.com.br).' },
    { timestamp: '09:45:15', level: 'INFO', stage: 'Recon', message: '[Subfinder] Descobertos subdomínios: api.app.fintech-pay.com.br, cdn.app.fintech-pay.com.br' },
    { timestamp: '09:48:20', level: 'INFO', stage: 'Recon', message: '[Naabu] Portas abertas detectadas: 80/tcp, 443/tcp, 8080/tcp, 8443/tcp' },
    { timestamp: '09:51:00', level: 'INFO', stage: 'Recon', message: '[Wappalyzer] Tecnologias detectadas: Express 4.x, PostgreSQL, Tailwind, React 19' },
    { timestamp: '09:52:45', level: 'INFO', stage: 'DAST', message: '[Nuclei] Executando 2.450 templates com Rate Limit de 15 req/s e Header de Autorização...' },
    { timestamp: '09:58:30', level: 'WARN', stage: 'DAST', message: '[Nuclei] Alerta crítico detectado: postgresql-time-based-sqli em /api/v1/transactions/export' },
    { timestamp: '10:02:10', level: 'WARN', stage: 'DAST', message: '[OWASP ZAP] Alerta alto detectado: SSRF em /api/v1/webhooks/test-endpoint' },
    { timestamp: '10:08:20', level: 'INFO', stage: 'AI Triage', message: '[AI Post-Processing] Iniciando correlação estatística e análise de payloads...' },
    { timestamp: '10:12:40', level: 'SUCCESS', stage: 'AI Triage', message: 'Descartados 14 falsos positivos gerados por 404 customizados e normalização de proxy.' },
    { timestamp: '10:15:20', level: 'SUCCESS', stage: 'Reporter', message: 'Relatório Executivo e Técnico gerado com sucesso. CVSS Score: 78/100 (Risco Alto).' }
  ],
  vulnerabilities: INITIAL_VULNERABILITIES,
  rawFindingsTotal: 19,
  filteredFalsePositivesTotal: 14,
  executiveSummary: {
    overallRisk: 'HIGH',
    riskScore: 78,
    businessImpactSummary: 'A análise identificou 1 vulnerabilidade CRÍTICA (Injeção de SQL) e 2 vulnerabilidades de ALTO impacto (SSRF e Reflected XSS). A presença de SQLi no módulo de exportação permite a exfiltração integral do banco de dados de clientes e transações financeiras, gerando alto risco de conformidade com a LGPD e perda de confiança de mercado.',
    topThreats: [
      'Exfiltração de dados financeiros de clientes via SQL Injection no endpoint /api/v1/transactions/export.',
      'Acesso não autorizado aos metadados internos da AWS (IAM Credentials) via Server-Side Request Forgery no webhook preview.',
      'Possibilidade de sequestro de sessão de usuários administrativos via XSS refletido no buscador.'
    ],
    quickWins: [
      'Migrar a query SQL do endpoint /api/v1/transactions/export para Prepared Statements com placeholders parametrizados ($1).',
      'Bloquear a resolução de endereços IP privados (10.0.0.0/8, 169.254.0.0/16, 127.0.0.0/8) no serviço de envio de webhooks.',
      'Bloquear acesso público a arquivos ocultos (.env, .git) diretamente na camada do CDN / Web Server.'
    ],
    complianceImpact: 'Alto risco perante a LGPD (Lei 13.709/2018) devido à exposição em potencial de PII e credenciais financeiras.'
  }
};

export const POSTGRESQL_SCHEMA_DDL = `-- =========================================================================
-- AegisDAST Platform - Database Architecture Schema (PostgreSQL 16+)
-- Multi-Tenant Security SaaS with Anti-Abuse, Scan Queue & Vulnerability Engine
-- =========================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. ENUMS
CREATE TYPE user_role AS ENUM ('SUPERADMIN', 'SECURITY_ANALYST', 'ORG_ADMIN', 'DEVELOPER');
CREATE TYPE verification_status AS ENUM ('UNVERIFIED', 'PENDING', 'VERIFIED', 'FAILED', 'REVOKED');
CREATE TYPE verification_method AS ENUM ('DNS_TXT', 'HTTP_FILE', 'HTML_META');
CREATE TYPE scan_profile AS ENUM ('PASSIVE', 'NORMAL', 'AGGRESSIVE');
CREATE TYPE scan_status AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED');
CREATE TYPE vuln_severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');
CREATE TYPE vuln_triage_status AS ENUM ('CONFIRMED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'FIXED');

-- 3. ORGANIZATIONS (Multi-Tenancy)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    plan_tier VARCHAR(50) DEFAULT 'ENTERPRISE_TRIAL',
    max_monthly_scans INT DEFAULT 50,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. USERS
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role user_role DEFAULT 'ORG_ADMIN',
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. TARGET DOMAINS & OWNERSHIP VALIDATION (Anti-Abuse Core)
CREATE TABLE target_domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain VARCHAR(255) NOT NULL,
    base_url VARCHAR(500) NOT NULL,
    verification_status verification_status DEFAULT 'UNVERIFIED',
    verification_method verification_method DEFAULT 'DNS_TXT',
    verification_token VARCHAR(128) NOT NULL, -- e.g. aegis-sec-9a4f21b7d83c9901e
    verified_at TIMESTAMP WITH TIME ZONE,
    verified_by_user_id UUID REFERENCES users(id),
    dns_txt_record_name VARCHAR(255), -- _aegis-challenge.domain.com
    waf_auth_header_name VARCHAR(100) DEFAULT 'X-Aegis-Scan-Authorization',
    waf_auth_header_value VARCHAR(255), -- Bearer aegis_sec_auth_live_key
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_org_domain UNIQUE (org_id, domain)
);

-- 6. DOMAIN VALIDATION AUDIT LOGS
CREATE TABLE domain_validation_audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES target_domains(id) ON DELETE CASCADE,
    attempted_method verification_method NOT NULL,
    status verification_status NOT NULL,
    queried_dns_target VARCHAR(255),
    resolved_txt_values TEXT[],
    queried_http_url VARCHAR(500),
    http_response_code INT,
    http_response_body_snippet TEXT,
    error_message TEXT,
    client_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 7. SCAN JOBS (Task Pipeline)
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES target_domains(id) ON DELETE CASCADE,
    triggered_by_user_id UUID REFERENCES users(id),
    status scan_status DEFAULT 'QUEUED',
    profile scan_profile DEFAULT 'NORMAL',
    rate_limit_rps INT DEFAULT 15,
    concurrency_threads INT DEFAULT 5,
    max_crawl_depth INT DEFAULT 3,
    tools_selected JSONB NOT NULL DEFAULT '{"subfinder":true,"naabu":true,"wappalyzer":true,"nuclei":true,"zap":true,"nmap":true}',
    celery_task_id VARCHAR(100),
    worker_node_id VARCHAR(100),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_requests_sent INT DEFAULT 0,
    http_429_backoff_count INT DEFAULT 0,
    raw_findings_count INT DEFAULT 0,
    triaged_findings_count INT DEFAULT 0,
    risk_score INT DEFAULT 0, -- 0 to 100
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 8. VULNERABILITIES & FINDINGS
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES target_domains(id) ON DELETE CASCADE,
    title VARCHAR(300) NOT NULL,
    severity vuln_severity NOT NULL,
    cvss_score NUMERIC(3,1) NOT NULL,
    cvss_vector VARCHAR(150),
    owasp_category VARCHAR(150) NOT NULL,
    cwe_id VARCHAR(50),
    matched_url VARCHAR(1000) NOT NULL,
    http_method VARCHAR(10) DEFAULT 'GET',
    tool_source VARCHAR(100) NOT NULL, -- Nuclei, OWASP ZAP, Nmap
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    triage_status vuln_triage_status DEFAULT 'CONFIRMED',
    ai_confidence_score INT DEFAULT 95, -- 0-100%
    ai_triage_reasoning TEXT,
    
    -- Technical Proof-of-Concept
    vulnerable_param VARCHAR(150),
    attack_payload TEXT,
    curl_poc TEXT,
    raw_http_request TEXT,
    raw_http_response TEXT,
    evidence_snippet TEXT,
    
    -- Remediation Guidance
    remediation_guide TEXT NOT NULL,
    code_snippet_before TEXT,
    code_snippet_after TEXT,
    code_language VARCHAR(50),
    reference_urls TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 9. AUDIT LOGS & SCAN TIMELINE
CREATE TABLE scan_logs (
    id BIGSERIAL PRIMARY KEY,
    scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    log_level VARCHAR(20) NOT NULL, -- INFO, WARN, ERROR, DEBUG, SUCCESS
    stage_name VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 10. INDEXES FOR HIGH-THROUGHPUT ANALYTICS & SECURITY QUERIES
CREATE INDEX idx_targets_org ON target_domains(org_id);
CREATE INDEX idx_targets_verified ON target_domains(verification_status);
CREATE INDEX idx_scans_target ON scan_jobs(target_id);
CREATE INDEX idx_scans_status ON scan_jobs(status);
CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_job_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_triage ON vulnerabilities(triage_status);
CREATE INDEX idx_logs_scan ON scan_logs(scan_job_id, created_at);
`;

export const CELERY_PYTHON_WORKER_CODE = `# =========================================================================
# AegisDAST - Distributed Celery & Docker Worker Pipeline (Python 3.12)
# Orchestrating Subfinder, Naabu, Wappalyzer, Nuclei, ZAP & AI Triage
# =========================================================================

import os
import time
import json
import subprocess
import requests
from celery import Celery, chain
from typing import Dict, Any, List

CELERY_BROKER = os.getenv("REDIS_URL", "redis://localhost:6379/0")
app = Celery("aegis_scanner", broker=CELERY_BROKER, backend=CELERY_BROKER)

@app.task(bind=True, max_retries=3)
def verify_ownership_gate(self, scan_job_id: str, target_domain: str, token: str) -> bool:
    """Gatekeeper anti-abuso: Garante que o domínio está validado no DNS antes de iniciar o scan."""
    import dns.resolver
    try:
        query_target = f"_aegis-challenge.{target_domain}"
        answers = dns.resolver.resolve(query_target, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                if token in txt_string.decode("utf-8"):
                    return True
        raise PermissionError(f"Domínio {target_domain} não possui TXT válido com token {token}")
    except Exception as exc:
        raise self.retry(exc=exc, countdown=10)

@app.task
def stage_1_reconnaissance(target_domain: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Etapa 1: Reconhecimento de subdomínios, portas e tecnologias."""
    # 1. Subfinder
    subdomains_cmd = ["subfinder", "-d", target_domain, "-silent", "-json"]
    sub_res = subprocess.run(subdomains_cmd, capture_output=True, text=True)
    
    # 2. Naabu (Port Discovery com Rate Limit Seguro)
    rate = config.get("rate_limit_rps", 15)
    naabu_cmd = ["naabu", "-host", target_domain, "-rate", str(rate), "-silent", "-json"]
    naabu_res = subprocess.run(naabu_cmd, capture_output=True, text=True)
    
    return {
        "domain": target_domain,
        "subdomains_raw": sub_res.stdout,
        "open_ports_raw": naabu_res.stdout,
        "timestamp": time.time()
    }

@app.task
def stage_2_active_dast_scanning(recon_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Etapa 2: Execução de Nuclei e OWASP ZAP com Header de Autorização e Rate Limiting."""
    target_url = f"https://{recon_data['domain']}"
    auth_header = f"{config['waf_header_name']}: {config['waf_header_value']}"
    rate_limit = config.get("rate_limit_rps", 15)
    concurrency = config.get("concurrency_threads", 5)
    
    # Nuclei v3 CLI com rate-limit e header customizado
    nuclei_cmd = [
        "nuclei",
        "-u", target_url,
        "-H", auth_header,
        "-rate-limit", str(rate_limit),
        "-c", str(concurrency),
        "-severity", "critical,high,medium",
        "-json-export", "/tmp/nuclei_output.json",
        "-silent"
    ]
    subprocess.run(nuclei_cmd, check=True)
    
    with open("/tmp/nuclei_output.json", "r") as f:
        findings = [json.loads(line) for line in f if line.strip()]
    return findings

@app.task
def stage_3_ai_false_positive_triage(raw_findings: List[Dict[str, Any]], target_url: str) -> Dict[str, Any]:
    """Etapa 3: Pós-processamento e descarte de falsos positivos via correlação e LLM."""
    confirmed_findings = []
    discarded_fps = []
    
    for item in raw_findings:
        # Heurística 1: Validar se o código de status é coerente
        # Heurística 2: Teste de reflexão diferencial e resposta à baseline
        # Heurística 3: Triagem por IA para validar prova de conceito
        is_real = post_process_and_verify(item, target_url)
        if is_real:
            confirmed_findings.append(item)
        else:
            discarded_fps.append(item)
            
    return {
        "confirmed": confirmed_findings,
        "false_positives_filtered": len(discarded_fps),
        "total_analyzed": len(raw_findings)
    }

def orchestrate_scan_workflow(scan_job_id: str, target: str, token: str, config: dict):
    """Encadeamento Celery assíncrono à prova de falhas."""
    workflow = chain(
        verify_ownership_gate.s(scan_job_id, target, token),
        stage_1_reconnaissance.s(target, config),
        stage_2_active_dast_scanning.s(config),
        stage_3_ai_false_positive_triage.s(f"https://{target}")
    )
    return workflow.apply_async()
`;
