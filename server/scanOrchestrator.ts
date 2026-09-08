// Orquestrador do pipeline de 3 etapas.
//
// Honestidade de dados é o requisito central deste módulo: a Etapa 1 (Recon) é
// real e executa de verdade contra o alvo verificado; a Etapa 2 (DAST ativo) é uma
// amostra simulada, claramente rotulada como tal em cada vulnerabilidade e log
// (esta sandbox não tem Nuclei/OWASP ZAP/Docker reais, e rodar exploração real
// sem essa infraestrutura dedicada seria irresponsável); a Etapa 3 (Triagem por
// IA) é real sempre que GEMINI_API_KEY estiver configurada, com fallback
// heurístico transparente quando não estiver. Nenhuma etapa promove um dado
// simulado a "real" — ver Vulnerability.dataSource e ScanStage.dataSource.
import type { ScanJob, ScanConfiguration, ScanProfile, TargetDomain, Vulnerability, ScanStage } from '../src/types';
import { createScan, updateScan, getScan, updateTarget } from './db';
import { runPassiveRecon, deriveVulnerabilitiesFromRecon } from './reconEngine';
import { triageVulnerability, isAiConfigured } from './aiTriage';
import { INITIAL_VULNERABILITIES } from '../src/data/mockSecurityData';

function nowIso() { return new Date().toISOString(); }
function nowClock() { return new Date().toLocaleTimeString('pt-BR'); }
function delay(ms: number) { return new Promise(resolve => setTimeout(resolve, ms)); }

type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'DEBUG';

function appendLog(jobId: string, level: LogLevel, stage: string, message: string) {
  const job = getScan(jobId);
  if (!job) return;
  updateScan(jobId, { logs: [...job.logs, { timestamp: nowClock(), level, stage, message }] });
}

function patchStage(jobId: string, stageIndex: number, patch: Partial<ScanStage>) {
  const job = getScan(jobId);
  if (!job) return;
  const stages = job.stages.map((s, i) => (i === stageIndex ? { ...s, ...patch } : s));
  updateScan(jobId, { stages });
}

function isCancelled(jobId: string): boolean {
  return !!getScan(jobId)?.cancelled;
}

export function buildInitialJob(target: TargetDomain, profile: ScanProfile, config: ScanConfiguration): ScanJob {
  const id = `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
  return {
    id,
    targetId: target.id,
    targetDomain: target.domain,
    status: 'QUEUED',
    profile,
    config,
    createdAt: nowIso(),
    startedAt: nowIso(),
    currentStageIndex: 0,
    stages: [
      {
        id: 'stg-1', name: 'Recon & Discovery', tool: 'DNS + crt.sh + HTTP + TLS (execução real)',
        status: 'PENDING', progress: 0, findingsCount: 0, summary: 'Na fila...', dataSource: 'REAL'
      },
      {
        id: 'stg-2', name: 'DAST & Análise Ativa', tool: 'Amostra Simulada — Nuclei/OWASP ZAP não disponíveis nesta sandbox',
        status: 'PENDING', progress: 0, findingsCount: 0, summary: 'Aguardando etapa 1', dataSource: 'SIMULATED'
      },
      {
        id: 'stg-3', name: 'Pós-Processamento & Triagem AI', tool: isAiConfigured() ? 'Gemini AI (execução real)' : 'Heurística de fallback (GEMINI_API_KEY não configurada)',
        status: 'PENDING', progress: 0, findingsCount: 0, summary: 'Aguardando etapa 2', dataSource: isAiConfigured() ? 'AI_REAL' : 'AI_FALLBACK'
      }
    ],
    logs: [
      { timestamp: nowClock(), level: 'INFO', stage: 'Orchestrator', message: `Job de varredura criado para o alvo verificado ${target.domain}.` },
      { timestamp: nowClock(), level: 'SUCCESS', stage: 'Anti-Abuse', message: `Posse do domínio confirmada via ${target.verificationMethod}.` }
    ],
    vulnerabilities: [],
    rawFindingsTotal: 0,
    filteredFalsePositivesTotal: 0
  };
}

function cloneSimulatedTemplates(targetDomain: string): Vulnerability[] {
  // As entradas de INITIAL_VULNERABILITIES são o exemplo/formato de saída
  // ilustrativo; aqui elas ganham IDs novos por execução e a URL é adaptada
  // ao domínio do alvo, mas permanecem marcadas dataSource: 'SIMULATED_DAST'.
  return INITIAL_VULNERABILITIES.map((v, idx) => ({
    ...v,
    id: `sim-${Date.now().toString(36)}-${idx}`,
    matchedUrl: v.matchedUrl.replace(/app\.fintech-pay\.com\.br/g, targetDomain),
    proofOfConcept: {
      ...v.proofOfConcept,
      curlCommand: v.proofOfConcept.curlCommand.replace(/app\.fintech-pay\.com\.br/g, targetDomain),
      httpRequest: v.proofOfConcept.httpRequest.replace(/app\.fintech-pay\.com\.br/g, targetDomain),
      httpResponse: v.proofOfConcept.httpResponse
    }
  }));
}

function computeExecutiveSummary(vulnerabilities: Vulnerability[], hasSimulatedFindings: boolean) {
  const confirmed = vulnerabilities.filter(v => v.status === 'CONFIRMED');
  const weights: Record<string, number> = { CRITICAL: 30, HIGH: 18, MEDIUM: 8, LOW: 3, INFO: 0 };
  const riskScore = Math.min(100, confirmed.reduce((sum, v) => sum + (weights[v.severity] || 0), 0));
  const overallRisk = riskScore >= 70 ? 'CRITICAL' : riskScore >= 45 ? 'HIGH' : riskScore >= 20 ? 'MEDIUM' : riskScore > 0 ? 'LOW' : 'SECURE';

  const bySeverityRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const topThreats = [...confirmed]
    .sort((a, b) => (bySeverityRank[b.severity] || 0) - (bySeverityRank[a.severity] || 0))
    .slice(0, 3)
    .map(v => `${v.title} (${v.matchedUrl})`);
  const quickWins = [...confirmed]
    .sort((a, b) => (bySeverityRank[b.severity] || 0) - (bySeverityRank[a.severity] || 0))
    .slice(0, 3)
    .map(v => v.remediation.recommendation);

  const disclaimer = hasSimulatedFindings
    ? ' Parte destes achados (Etapa 2 — DAST ativo) é uma AMOSTRA ILUSTRATIVA do formato de saída, não uma exploração real executada contra o alvo; esta sandbox ainda não integra Nuclei/OWASP ZAP reais. Os achados da Etapa 1 (Recon) e a triagem de IA, quando aplicável, são reais.'
    : '';

  return {
    overallRisk: overallRisk as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SECURE',
    riskScore,
    businessImpactSummary: confirmed.length > 0
      ? `A varredura identificou ${confirmed.length} achado(s) confirmado(s), incluindo ${confirmed.filter(v => v.severity === 'CRITICAL').length} crítico(s) e ${confirmed.filter(v => v.severity === 'HIGH').length} de alto impacto.${disclaimer}`
      : `Nenhuma vulnerabilidade confirmada foi identificada nesta execução.${disclaimer}`,
    topThreats: topThreats.length > 0 ? topThreats : ['Nenhuma ameaça de alta prioridade identificada nesta execução.'],
    quickWins: quickWins.length > 0 ? quickWins : ['Continue monitorando o alvo periodicamente.'],
    complianceImpact: confirmed.some(v => v.severity === 'CRITICAL' || v.severity === 'HIGH')
      ? 'Risco potencial perante a LGPD (Lei 13.709/2018) caso os achados envolvam exposição de dados pessoais — recomenda-se avaliação jurídica/DPO.'
      : 'Impacto de conformidade baixo com base nos achados atuais.'
  };
}

async function runScan(jobId: string): Promise<void> {
  const job = getScan(jobId);
  if (!job) return;
  const targetDomain = job.targetDomain;

  // ---- Etapa 1: Recon Passivo Real ----
  updateScan(jobId, { status: 'RECON', currentStageIndex: 0 });
  patchStage(jobId, 0, { status: 'RUNNING', progress: 20, summary: 'Executando DNS, crt.sh, probe HTTP e handshake TLS reais...' });
  appendLog(jobId, 'INFO', 'Recon', `Iniciando reconhecimento passivo real contra ${targetDomain} (DNS, Certificate Transparency, HTTP, TLS)...`);

  let reconVulns: Vulnerability[] = [];
  try {
    const recon = await runPassiveRecon(targetDomain);
    reconVulns = deriveVulnerabilitiesFromRecon(recon, `https://${targetDomain}`);
    updateScan(jobId, {
      reconFindings: recon,
      vulnerabilities: [...getScan(jobId)!.vulnerabilities, ...reconVulns],
      rawFindingsTotal: getScan(jobId)!.rawFindingsTotal + reconVulns.length
    });

    appendLog(jobId, 'SUCCESS', 'Recon', `[DNS] ${recon.dns.a.length} registro(s) A, ${recon.dns.ns.length} NS, ${recon.dns.mx.length} MX encontrados.`);
    appendLog(jobId, 'SUCCESS', 'Recon', `[crt.sh] ${recon.subdomains.length} subdomínio(s) real(is) descoberto(s) via Certificate Transparency${recon.subdomainsSource === 'unavailable' ? ' (fonte indisponível no momento)' : ''}.`);
    if (recon.httpProbe.reachable) {
      appendLog(jobId, 'INFO', 'Recon', `[HTTP] ${recon.httpProbe.finalUrl} respondeu ${recon.httpProbe.statusCode} em ${recon.httpProbe.responseTimeMs}ms.`);
    } else {
      appendLog(jobId, 'WARN', 'Recon', `[HTTP] Não foi possível alcançar o alvo via HTTP: ${recon.httpProbe.error}`);
    }
    if (recon.tls.reachable) {
      appendLog(jobId, 'INFO', 'Recon', `[TLS] Certificado real: emissor ${recon.tls.issuer}, válido até ${recon.tls.validTo}.`);
    } else {
      appendLog(jobId, 'WARN', 'Recon', `[TLS] Handshake TLS falhou: ${recon.tls.error}`);
    }
    if (recon.technologies.length > 0) {
      appendLog(jobId, 'INFO', 'Recon', `[Fingerprint] Tecnologias detectadas via headers reais: ${recon.technologies.join(', ')}.`);
    }
    appendLog(jobId, 'SUCCESS', 'Recon', `Etapa 1 concluída. ${reconVulns.length} achado(s) real(is) gerados a partir da observação direta.`);
    patchStage(jobId, 0, { status: 'COMPLETED', progress: 100, findingsCount: reconVulns.length, summary: `${recon.subdomains.length} subdomínios e ${reconVulns.length} achados reais de configuração/exposição.` });
  } catch (err: any) {
    appendLog(jobId, 'ERROR', 'Recon', `Falha inesperada no motor de recon: ${err?.message || err}`);
    patchStage(jobId, 0, { status: 'FAILED', progress: 100, summary: 'Falha na execução do recon passivo.' });
  }

  if (isCancelled(jobId)) return finalizeCancelled(jobId);

  // ---- Etapa 2: DAST Ativo (SIMULADO) ----
  updateScan(jobId, { status: 'ACTIVE_SCAN', currentStageIndex: 1 });
  patchStage(jobId, 1, { status: 'RUNNING', progress: 30, summary: 'Gerando amostra ilustrativa de saída (Nuclei/OWASP ZAP reais não disponíveis nesta sandbox)...' });
  appendLog(jobId, 'WARN', 'DAST', '[SIMULAÇÃO] Esta etapa não executa Nuclei/OWASP ZAP reais neste ambiente. Os achados abaixo são uma amostra ilustrativa do formato de saída esperado, não uma exploração real.');
  await delay(1800);

  const simulatedVulns = cloneSimulatedTemplates(targetDomain);
  const afterStage2 = getScan(jobId)!;
  updateScan(jobId, {
    vulnerabilities: [...afterStage2.vulnerabilities, ...simulatedVulns],
    rawFindingsTotal: afterStage2.rawFindingsTotal + simulatedVulns.length
  });
  appendLog(jobId, 'INFO', 'DAST', `[SIMULAÇÃO] ${simulatedVulns.length} achado(s) de amostra gerados para ilustrar o formato do relatório.`);
  patchStage(jobId, 1, { status: 'COMPLETED', progress: 100, findingsCount: simulatedVulns.length, summary: `${simulatedVulns.length} achados de amostra (simulados) gerados.` });

  if (isCancelled(jobId)) return finalizeCancelled(jobId);

  // ---- Etapa 3: Triagem por IA ----
  updateScan(jobId, { status: 'TRIAGE', currentStageIndex: 2 });
  patchStage(jobId, 2, { status: 'RUNNING', progress: 40, summary: isAiConfigured() ? 'Consultando Gemini AI para cada achado...' : 'GEMINI_API_KEY ausente — aplicando heurística de fallback...' });
  appendLog(jobId, 'INFO', 'AI Triage', isAiConfigured()
    ? '[Gemini] Iniciando triagem real de cada achado (falso positivo vs. confirmado)...'
    : '[Fallback] Nenhuma chave de IA configurada; mantendo classificação heurística do motor de correlação.');

  const currentJob = getScan(jobId)!;
  let anyRealModelUsed = false;
  const triagedVulns: Vulnerability[] = [];
  for (const vuln of currentJob.vulnerabilities) {
    try {
      const result = await triageVulnerability(vuln, targetDomain, `REQUEST:\n${vuln.proofOfConcept.httpRequest}\n\nRESPONSE:\n${vuln.proofOfConcept.httpResponse}`);
      if (result.usedRealModel) anyRealModelUsed = true;
      triagedVulns.push({
        ...vuln,
        status: result.isFalsePositive ? 'FALSE_POSITIVE' : vuln.status,
        aiConfidenceScore: result.confidenceScore,
        aiTriageReasoning: result.reasoning
      });
    } catch {
      triagedVulns.push(vuln);
    }
  }

  const falsePositives = triagedVulns.filter(v => v.status === 'FALSE_POSITIVE').length;
  const hasSimulated = triagedVulns.some(v => v.dataSource === 'SIMULATED_DAST');
  const executiveSummary = computeExecutiveSummary(triagedVulns, hasSimulated);

  updateScan(jobId, {
    vulnerabilities: triagedVulns,
    filteredFalsePositivesTotal: falsePositives,
    status: 'COMPLETED',
    currentStageIndex: 3,
    completedAt: nowIso(),
    executiveSummary
  });
  patchStage(jobId, 2, {
    status: 'COMPLETED', progress: 100, findingsCount: triagedVulns.length - falsePositives,
    summary: `${falsePositives} falso(s) positivo(s) descartado(s). Score de risco: ${executiveSummary.riskScore}/100.`,
    dataSource: anyRealModelUsed ? 'AI_REAL' : 'AI_FALLBACK'
  });
  appendLog(jobId, 'SUCCESS', 'AI Triage', `Triagem concluída (${anyRealModelUsed ? 'modelo real' : 'fallback heurístico'}). ${falsePositives} descartado(s), ${triagedVulns.length - falsePositives} confirmado(s).`);
  appendLog(jobId, 'SUCCESS', 'Reporter', `Relatório Executivo e Técnico gerado. Score de Risco: ${executiveSummary.riskScore}/100 (${executiveSummary.overallRisk}).`);

  updateTarget(currentJob.targetId, {
    lastScanAt: nowIso(),
    riskScore: executiveSummary.riskScore,
    totalVulns: {
      critical: triagedVulns.filter(v => v.status === 'CONFIRMED' && v.severity === 'CRITICAL').length,
      high: triagedVulns.filter(v => v.status === 'CONFIRMED' && v.severity === 'HIGH').length,
      medium: triagedVulns.filter(v => v.status === 'CONFIRMED' && v.severity === 'MEDIUM').length,
      low: triagedVulns.filter(v => v.status === 'CONFIRMED' && v.severity === 'LOW').length,
      info: triagedVulns.filter(v => v.status === 'CONFIRMED' && v.severity === 'INFO').length
    }
  });
}

function finalizeCancelled(jobId: string) {
  appendLog(jobId, 'WARN', 'Orchestrator', 'Varredura cancelada pelo usuário.');
  updateScan(jobId, { status: 'FAILED', completedAt: nowIso() });
}

export function startScan(target: TargetDomain, profile: ScanProfile, config: ScanConfiguration): ScanJob {
  const job = createScan(buildInitialJob(target, profile, config));
  // Roda em segundo plano — a rota HTTP responde imediatamente com status QUEUED
  // e o frontend faz polling em GET /api/scans/:id para acompanhar o progresso real.
  void runScan(job.id).catch(err => {
    console.error(`[scanOrchestrator] Falha não tratada no job ${job.id}:`, err);
    updateScan(job.id, { status: 'FAILED', completedAt: nowIso() });
    appendLog(job.id, 'ERROR', 'Orchestrator', `Falha inesperada: ${err?.message || err}`);
  });
  return job;
}

export function cancelScan(jobId: string): boolean {
  const job = getScan(jobId);
  if (!job) return false;
  updateScan(jobId, { cancelled: true });
  return true;
}
