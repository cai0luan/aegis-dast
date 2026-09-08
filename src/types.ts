export type VerificationMethod = 'DNS_TXT' | 'HTTP_FILE' | 'HTML_META' | 'SANDBOX_DEMO';

export type VerificationStatus = 'UNVERIFIED' | 'PENDING' | 'VERIFIED' | 'FAILED';

export type ScanProfile = 'PASSIVE' | 'NORMAL' | 'AGGRESSIVE';

export type ScanStatus = 'IDLE' | 'QUEUED' | 'RECON' | 'ACTIVE_SCAN' | 'TRIAGE' | 'COMPLETED' | 'FAILED';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type OwaspCategory = 
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable and Outdated Components'
  | 'A07:2021-Identification and Authentication Failures'
  | 'A08:2021-Software and Data Integrity Failures'
  | 'A09:2021-Security Logging and Monitoring Failures'
  | 'A10:2021-Server-Side Request Forgery (SSRF)';

export interface TargetDomain {
  id: string;
  domain: string;
  url: string;
  organizationName: string;
  verificationStatus: VerificationStatus;
  verificationMethod: VerificationMethod;
  verificationToken: string;
  verifiedAt?: string;
  createdAt: string;
  lastScanAt?: string;
  riskScore?: number; // 0 - 100
  totalVulns?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface VerificationChallenge {
  token: string;
  dnsRecord: {
    type: 'TXT';
    host: string;
    value: string;
  };
  httpFile: {
    path: string;
    url: string;
    expectedContent: string;
  };
  htmlMeta: {
    tag: string;
  };
}

export interface ScanConfiguration {
  targetId: string;
  profile: ScanProfile;
  rateLimit: number; // requests per second (1 to 100)
  concurrency: number; // concurrent threads (1 to 20)
  maxDepth: number;
  tools: {
    subfinder: boolean;
    naabu: boolean;
    wappalyzer: boolean;
    nuclei: boolean;
    zap: boolean;
    nmap: boolean;
  };
  wafBypass: {
    enabled: boolean;
    authHeaderName: string;
    authHeaderValue: string;
    useStaticEgressIps: boolean;
  };
  timeoutMinutes: number;
  autoThrottleOnHttpErrors: boolean; // 429 / 503 backoff
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  cvssScore: number;
  cvssVector: string;
  owaspCategory: OwaspCategory;
  cwe: string;
  matchedUrl: string;
  toolSource: 'Nuclei' | 'OWASP ZAP' | 'Nmap' | 'Wappalyzer' | 'Custom Probe' | 'Aegis Passive Recon';
  description: string;
  impact: string;
  status: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_REVIEW';
  aiConfidenceScore: number; // 0 to 100
  aiTriageReasoning: string;
  // REAL_PASSIVE_RECON = observado ao vivo (DNS/HTTP/TLS) contra o alvo verificado.
  // REAL_ACTIVE_DAST = achado real do Nuclei, executado de verdade pelo worker Python
  // local (ver worker/worker.py) — nunca confundir com a amostra simulada abaixo.
  // SIMULATED_DAST = amostra ilustrativa do formato de saída; usada apenas no caminho
  // síncrono de fallback (sem Redis configurado, ver server/routes.ts), quando não há
  // worker real disponível para executar a Etapa 2. Nunca reclassifique sem trocar a
  // fonte de dado real.
  dataSource: 'REAL_PASSIVE_RECON' | 'REAL_ACTIVE_DAST' | 'SIMULATED_DAST';
  proofOfConcept: {
    parameter?: string;
    attackPayload: string;
    curlCommand: string;
    httpRequest: string;
    httpResponse: string;
    evidenceText: string;
  };
  remediation: {
    recommendation: string;
    codeSnippetBefore?: string;
    codeSnippetAfter?: string;
    language?: string;
    references: string[];
  };
}

export interface ScanStage {
  id: string;
  name: string;
  tool: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'SKIPPED' | 'FAILED';
  startedAt?: string;
  completedAt?: string;
  progress: number;
  findingsCount: number;
  summary: string;
  // Rotula se esta etapa executou de verdade (recon passivo real, IA real) ou é
  // uma amostra simulada (ex: DAST ativo, que exigiria Nuclei/ZAP/Docker reais).
  dataSource?: 'REAL' | 'SIMULATED' | 'AI_REAL' | 'AI_FALLBACK';
}

export interface DnsRecordSet {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  ns: string[];
  txt: string[];
}

export interface TlsCertificateInfo {
  reachable: boolean;
  protocol?: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  selfSigned?: boolean;
  error?: string;
}

export interface HttpProbeResult {
  reachable: boolean;
  finalUrl?: string;
  statusCode?: number;
  responseTimeMs?: number;
  headers?: Record<string, string>;
  missingSecurityHeaders?: string[];
  error?: string;
}

// Resultado do motor de reconhecimento passivo — cada campo aqui é uma
// observação real feita em tempo de execução contra o alvo (DNS/HTTP/TLS/crt.sh),
// nunca um valor fabricado ou de exemplo.
export interface ReconFindings {
  domain: string;
  executedAt: string;
  dns: DnsRecordSet;
  subdomains: string[];
  subdomainsSource: 'crt.sh' | 'unavailable';
  httpProbe: HttpProbeResult;
  tls: TlsCertificateInfo;
  technologies: string[];
  robotsTxtFound: boolean;
  securityTxtFound: boolean;
}

export interface ScanJob {
  id: string;
  targetId: string;
  targetDomain: string;
  status: ScanStatus;
  profile: ScanProfile;
  config: ScanConfiguration;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  currentStageIndex: number;
  stages: ScanStage[];
  logs: Array<{
    timestamp: string;
    level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'DEBUG';
    stage: string;
    message: string;
  }>;
  vulnerabilities: Vulnerability[];
  rawFindingsTotal: number;
  filteredFalsePositivesTotal: number;
  reconFindings?: ReconFindings;
  cancelled?: boolean;
  executiveSummary?: {
    overallRisk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE';
    riskScore: number; // 0 to 100
    businessImpactSummary: string;
    topThreats: string[];
    quickWins: string[];
    complianceImpact: string;
  };
}

export interface ArchitectureComponent {
  title: string;
  category: 'Frontend' | 'Backend / API' | 'Queue & Tasks' | 'Scan Workers' | 'Egress & WAF' | 'AI & Triage';
  tech: string;
  description: string;
  rationale: string;
  securityControls: string[];
}
