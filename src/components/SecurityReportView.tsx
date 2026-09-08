import React, { useState } from 'react';
import { 
  FileText, 
  Printer, 
  Download, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  ChevronDown, 
  ChevronRight, 
  Code, 
  Terminal, 
  ExternalLink, 
  Copy, 
  Check, 
  Building, 
  Calendar, 
  Flame,
  Layers,
  Sparkles,
  ArrowDownToLine
} from 'lucide-react';
import { ScanJob, Vulnerability } from '../types';
import { SAMPLE_COMPLETED_SCAN } from '../data/mockSecurityData';

interface SecurityReportViewProps {
  scan?: ScanJob;
}

const RISK_LABELS: Record<string, string> = {
  CRITICAL: 'Risco Crítico',
  HIGH: 'Risco Alto',
  MEDIUM: 'Risco Médio',
  LOW: 'Risco Baixo',
  SECURE: 'Sem Risco Relevante'
};

export const SecurityReportView: React.FC<SecurityReportViewProps> = ({ scan = SAMPLE_COMPLETED_SCAN }) => {
  const [reportViewMode, setReportViewMode] = useState<'ALL' | 'EXECUTIVE' | 'TECHNICAL'>('ALL');
  const [expandedVulns, setExpandedVulns] = useState<Record<string, boolean>>({
    'vuln-01': true,
    'vuln-02': true
  });
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const toggleVuln = (id: string) => {
    setExpandedVulns(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const confirmedVulns = scan.vulnerabilities.filter(v => v.status === 'CONFIRMED');
  const criticalCount = confirmedVulns.filter(v => v.severity === 'CRITICAL').length;
  const highCount = confirmedVulns.filter(v => v.severity === 'HIGH').length;
  const mediumCount = confirmedVulns.filter(v => v.severity === 'MEDIUM').length;
  const lowCount = confirmedVulns.filter(v => v.severity === 'LOW').length;

  const riskScore = scan.executiveSummary?.riskScore ?? 0;
  const riskLevel = RISK_LABELS[scan.executiveSummary?.overallRisk || 'SECURE'];
  const reportDate = new Date(scan.completedAt || scan.createdAt).toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' });
  const hasSimulatedFindings = scan.vulnerabilities.some(v => v.dataSource === 'SIMULATED_DAST');

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-16 print:p-0 print:m-0 print:space-y-6">
      {/* Top Action Bar (hidden in print) */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-5 flex flex-col sm:flex-row items-center justify-between gap-4 no-print shadow-sm">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-cyan-950/80 text-cyan-400 rounded-xl border border-cyan-800/60">
            <FileText className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white tracking-tight">Relatório de Avaliação de Segurança Web</h2>
            <p className="text-xs text-[#A1A1AA]">ID da Análise: <span className="font-mono text-cyan-300">{scan.id}</span></p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {/* View Filter */}
          <div className="flex bg-[#0E0E10] p-1 rounded-xl border border-[#262626] text-xs">
            {[
              { id: 'ALL', label: 'Completo' },
              { id: 'EXECUTIVE', label: '1. Executivo' },
              { id: 'TECHNICAL', label: '2. Técnico' }
            ].map((m) => (
              <button
                key={m.id}
                onClick={() => setReportViewMode(m.id as any)}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  reportViewMode === m.id
                    ? 'bg-[#1C1C1F] text-cyan-400 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>

          <button
            id="btn-print-report"
            onClick={handlePrint}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs sm:text-sm rounded-xl transition flex items-center space-x-2 shadow-lg shadow-cyan-500/20"
          >
            <Printer className="w-4 h-4" />
            <span>Exportar PDF / Imprimir</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION A: EXECUTIVE SUMMARY (Resumo Executivo sem Jargões para Gestores) */}
      {/* ========================================================================= */}
      {(reportViewMode === 'ALL' || reportViewMode === 'EXECUTIVE') && (
        <div className="bg-[#161618] border border-[#262626] rounded-3xl p-8 space-y-8 print:bg-white print:border-slate-300 print:text-slate-900 print:p-6 print:rounded-none shadow-sm">
          {/* Executive Header */}
          <div className="flex flex-col sm:flex-row justify-between items-start border-b border-[#262626] pb-6 print:border-slate-300">
            <div>
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-widest print:text-cyan-800">
                Seção A • Resumo Executivo
              </span>
              <h1 className="text-2xl sm:text-3xl font-extrabold text-white mt-1 tracking-tight print:text-slate-950">
                Relatório Executivo de Cibersegurança & Risco
              </h1>
              <div className="flex flex-wrap items-center gap-4 text-xs text-[#A1A1AA] mt-2 print:text-slate-600">
                <span className="flex items-center gap-1.5 font-medium">
                  <Building className="w-3.5 h-3.5" /> Alvo Auditado
                </span>
                <span>•</span>
                <span className="font-mono text-[#E4E4E7] print:text-slate-900">
                  {scan.targetDomain}
                </span>
                <span>•</span>
                <span className="flex items-center gap-1.5">
                  <Calendar className="w-3.5 h-3.5" /> {reportDate}
                </span>
              </div>
            </div>

            {/* Overall Risk Score Badge */}
            <div className="mt-4 sm:mt-0 flex items-center space-x-4 bg-[#0E0E10] border border-[#262626] p-4 rounded-2xl print:bg-slate-100 print:border-slate-300">
              <div className="text-right">
                <div className="text-[11px] text-[#A1A1AA] uppercase tracking-wider font-semibold">Índice de Risco Global</div>
                <div className="text-2xl font-black text-rose-400 print:text-rose-700">{riskScore} / 100</div>
                <div className="text-[10px] text-rose-300 font-bold uppercase">Nível: {riskLevel}</div>
              </div>
              <div className="w-12 h-12 rounded-xl bg-rose-950/80 border border-rose-800 flex items-center justify-center text-rose-400 font-extrabold text-lg">
                ⚠
              </div>
            </div>
          </div>

          {hasSimulatedFindings && (
            <div className="p-4 rounded-xl border border-amber-800/60 bg-amber-950/30 text-amber-200 text-xs leading-relaxed print:border-amber-700 print:bg-amber-50 print:text-amber-900">
              <strong className="text-amber-300 print:text-amber-800">Nota de honestidade de dados:</strong> parte dos achados abaixo (marcados "Simulado") são uma amostra ilustrativa do formato de saída da Etapa 2 (DAST ativo) — esta instância não executa Nuclei/OWASP ZAP reais. Achados sem essa marcação (Reconhecimento Passivo) foram observados ao vivo contra o alvo.
            </div>
          )}

          {/* Severity Metrics Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-[#0E0E10] border border-rose-900/60 rounded-2xl print:border-slate-300 print:bg-slate-50">
              <div className="text-xs text-rose-400 font-bold uppercase">Crítico</div>
              <div className="text-3xl font-black text-white mt-1 print:text-slate-900">{criticalCount}</div>
              <div className="text-[11px] text-[#A1A1AA] mt-0.5">Ação imediata necessária</div>
            </div>

            <div className="p-4 bg-[#0E0E10] border border-orange-900/60 rounded-2xl print:border-slate-300 print:bg-slate-50">
              <div className="text-xs text-orange-400 font-bold uppercase">Alto</div>
              <div className="text-3xl font-black text-white mt-1 print:text-slate-900">{highCount}</div>
              <div className="text-[11px] text-[#A1A1AA] mt-0.5">Risco de sequestro/dados</div>
            </div>

            <div className="p-4 bg-[#0E0E10] border border-amber-900/60 rounded-2xl print:border-slate-300 print:bg-slate-50">
              <div className="text-xs text-amber-400 font-bold uppercase">Médio</div>
              <div className="text-3xl font-black text-white mt-1 print:text-slate-900">{mediumCount}</div>
              <div className="text-[11px] text-[#A1A1AA] mt-0.5">Exposição de configs</div>
            </div>

            <div className="p-4 bg-[#0E0E10] border border-emerald-900/60 rounded-2xl print:border-slate-300 print:bg-slate-50">
              <div className="text-xs text-emerald-400 font-bold uppercase">Falsos Positivos</div>
              <div className="text-3xl font-black text-emerald-400 mt-1">{scan.filteredFalsePositivesTotal}</div>
              <div className="text-[11px] text-[#A1A1AA] mt-0.5">Filtrados com precisão</div>
            </div>
          </div>

          {/* Executive Overview Text (Non-technical / Business language) */}
          <div className="space-y-4">
            <h3 className="text-base font-bold text-white tracking-tight flex items-center space-x-2 print:text-slate-950">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              <span>Visão Geral para a Diretoria & Impacto no Negócio</span>
            </h3>
            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 text-sm text-[#E4E4E7] leading-relaxed space-y-3 print:bg-slate-50 print:border-slate-300 print:text-slate-800">
              <p>{scan.executiveSummary?.businessImpactSummary || 'Nenhum resumo executivo disponível para esta execução.'}</p>
              <p className="text-xs text-[#A1A1AA] print:text-slate-600">
                Impacto de conformidade: {scan.executiveSummary?.complianceImpact || 'Não avaliado.'}
              </p>
            </div>
          </div>

          {/* Top Threat Points & Quick Wins */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 space-y-3 print:bg-slate-50 print:border-slate-300">
              <h4 className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4" /> Principais Ameaças Identificadas
              </h4>
              <ul className="space-y-2 text-xs text-[#E4E4E7] print:text-slate-700">
                {scan.executiveSummary?.topThreats.map((t, idx) => (
                  <li key={idx} className="flex items-start space-x-2">
                    <span className="text-rose-400 font-bold">•</span>
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 space-y-3 print:bg-slate-50 print:border-slate-300">
              <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> Ações Rápidas Recomendadas (Quick Wins)
              </h4>
              <ul className="space-y-2 text-xs text-[#E4E4E7] print:text-slate-700">
                {scan.executiveSummary?.quickWins.map((w, idx) => (
                  <li key={idx} className="flex items-start space-x-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span>{w}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Page break for printing */}
      <div className="page-break-after" />

      {/* ========================================================================= */}
      {/* SECTION B: TECHNICAL DEEP DIVE (Detalhamento Técnico para Desenvolvedores) */}
      {/* ========================================================================= */}
      {(reportViewMode === 'ALL' || reportViewMode === 'TECHNICAL') && (
        <div className="bg-[#161618] border border-[#262626] rounded-3xl p-8 space-y-8 print:bg-white print:border-slate-300 print:text-slate-900 print:p-6 print:rounded-none shadow-sm">
          <div className="border-b border-[#262626] pb-6 print:border-slate-300">
            <span className="text-xs font-bold text-indigo-400 uppercase tracking-widest print:text-indigo-800">
              Seção B • Detalhamento Técnico & DevSecOps
            </span>
            <h2 className="text-2xl sm:text-3xl font-extrabold text-white mt-1 tracking-tight print:text-slate-950">
              Provas de Conceito (PoC), Traces HTTP & Correção
            </h2>
            <p className="text-xs text-[#A1A1AA] mt-1 print:text-slate-600">
              Instruções detalhadas com payloads de exploração, headers HTTP afetados e trechos de código para mitigação direta.
            </p>
          </div>

          {/* Vulnerability Technical Accordions */}
          <div className="space-y-6">
            {confirmedVulns.map((vuln, index) => {
              const isExpanded = expandedVulns[vuln.id] ?? true;

              return (
                <div 
                  key={vuln.id}
                  className="bg-[#0E0E10] border border-[#262626] rounded-2xl overflow-hidden print:border-slate-300 print:bg-slate-50 page-break-inside-avoid"
                >
                  {/* Card Header */}
                  <button
                    onClick={() => toggleVuln(vuln.id)}
                    className="w-full text-left p-5 flex items-start justify-between gap-4 hover:bg-[#161618] transition border-b border-[#262626] print:border-slate-200"
                  >
                    <div className="flex items-start space-x-3">
                      <span className={`px-2.5 py-1 text-xs font-black rounded-lg uppercase shrink-0 ${
                        vuln.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : vuln.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-400 border border-orange-800'
                          : 'bg-amber-950 text-amber-400 border border-amber-800'
                      }`}>
                        {vuln.severity}
                      </span>
                      <div>
                        <div className="flex items-center space-x-2 text-xs text-[#A1A1AA] font-mono mb-1">
                          <span>#{index + 1}</span>
                          <span>•</span>
                          <span>CVSS {vuln.cvssScore}</span>
                          <span>•</span>
                          <span>{vuln.cwe}</span>
                          <span>•</span>
                          <span className="text-cyan-400">{vuln.owaspCategory}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-base text-white print:text-slate-900">{vuln.title}</h3>
                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase shrink-0 ${
                            vuln.dataSource !== 'SIMULATED_DAST'
                              ? 'bg-emerald-950 text-emerald-400 border-emerald-800 print:bg-emerald-50 print:text-emerald-800'
                              : 'bg-amber-950 text-amber-400 border-amber-800 print:bg-amber-50 print:text-amber-800'
                          }`}>
                            {vuln.dataSource === 'REAL_ACTIVE_DAST' ? 'Nuclei Real' : vuln.dataSource === 'REAL_PASSIVE_RECON' ? 'Real' : 'Simulado'}
                          </span>
                        </div>
                        <div className="text-xs text-[#A1A1AA] font-mono mt-1 break-all">{vuln.matchedUrl}</div>
                      </div>
                    </div>

                    <div className="shrink-0 text-[#71717A] no-print">
                      {isExpanded ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
                    </div>
                  </button>

                  {/* Expanded Technical Body */}
                  {isExpanded && (
                    <div className="p-6 space-y-6 text-xs text-[#E4E4E7]">
                      {/* Description & Impact */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-1 bg-[#161618] p-4 rounded-xl border border-[#262626] print:bg-white print:border-slate-200">
                          <span className="font-bold text-white uppercase tracking-wider text-[11px] print:text-slate-900">Descrição Técnica:</span>
                          <p className="text-[#A1A1AA] leading-relaxed print:text-slate-700">{vuln.description}</p>
                        </div>

                        <div className="space-y-1 bg-[#161618] p-4 rounded-xl border border-[#262626] print:bg-white print:border-slate-200">
                          <span className="font-bold text-rose-400 uppercase tracking-wider text-[11px]">Impacto no Sistema:</span>
                          <p className="text-[#A1A1AA] leading-relaxed print:text-slate-700">{vuln.impact}</p>
                        </div>
                      </div>

                      {/* Proof of Concept: cURL & HTTP Raw Traces */}
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-cyan-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                            <Terminal className="w-4 h-4" /> Prova de Conceito (PoC) & Reprodução
                          </span>
                          <span className="text-[11px] font-mono text-amber-400">
                            Payload Injetado: <code className="bg-[#0A0A0B] px-1.5 py-0.5 rounded border border-[#262626]">{vuln.proofOfConcept.attackPayload}</code>
                          </span>
                        </div>

                        {/* cURL Command */}
                        <div className="space-y-1">
                          <div className="flex justify-between text-[11px] text-[#A1A1AA]">
                            <span>Comando cURL de Reprodução Direta:</span>
                            <button
                              onClick={() => copyToClipboard(vuln.proofOfConcept.curlCommand, `curl-${vuln.id}`)}
                              className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 no-print font-medium"
                            >
                              {copiedKey === `curl-${vuln.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              <span>{copiedKey === `curl-${vuln.id}` ? 'Copiado' : 'Copiar cURL'}</span>
                            </button>
                          </div>
                          <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-xl text-[#E4E4E7] font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                            {vuln.proofOfConcept.curlCommand}
                          </pre>
                        </div>

                        {/* Side by Side HTTP Raw Request / Response */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
                          <div className="space-y-1">
                            <span className="text-[#A1A1AA] text-[10px] font-semibold">Requisição HTTP Afetada:</span>
                            <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-xl text-cyan-300 overflow-x-auto h-40">
                              {vuln.proofOfConcept.httpRequest}
                            </pre>
                          </div>

                          <div className="space-y-1">
                            <span className="text-[#A1A1AA] text-[10px] font-semibold">Evidência / Resposta do Servidor:</span>
                            <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-xl text-emerald-300 overflow-x-auto h-40">
                              {vuln.proofOfConcept.httpResponse}
                            </pre>
                          </div>
                        </div>
                      </div>

                      {/* Remediation & Code Diff Snippets */}
                      <div className="pt-4 border-t border-[#262626] space-y-3">
                        <span className="font-bold text-emerald-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                          <Code className="w-4 h-4" /> Como Corrigir (Guia para Desenvolvedores)
                        </span>
                        <p className="text-[#A1A1AA] leading-relaxed">{vuln.remediation.recommendation}</p>

                        {vuln.remediation.codeSnippetBefore && vuln.remediation.codeSnippetAfter && (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px] mt-3">
                            <div className="space-y-1">
                              <span className="text-rose-400 font-bold text-[10px]">❌ CÓDIGO VULNERÁVEL (BEFORE):</span>
                              <pre className="p-3 bg-rose-950/20 border border-rose-900/40 rounded-xl text-rose-200 overflow-x-auto">
                                {vuln.remediation.codeSnippetBefore}
                              </pre>
                            </div>

                            <div className="space-y-1">
                              <span className="text-emerald-400 font-bold text-[10px]">✅ CÓDIGO SEGURO (AFTER):</span>
                              <pre className="p-3 bg-emerald-950/20 border border-emerald-900/40 rounded-xl text-emerald-200 overflow-x-auto">
                                {vuln.remediation.codeSnippetAfter}
                              </pre>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
