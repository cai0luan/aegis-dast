import React, { useState } from 'react';
import { 
  Sparkles, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  BrainCircuit, 
  RefreshCw, 
  ArrowRight,
  Shield,
  Layers,
  FileCheck
} from 'lucide-react';
import { Vulnerability } from '../types';
import { INITIAL_VULNERABILITIES } from '../data/mockSecurityData';

interface FalsePositiveAiViewProps {
  vulnerabilities?: Vulnerability[];
  targetDomain?: string;
}

export const FalsePositiveAiView: React.FC<FalsePositiveAiViewProps> = ({
  vulnerabilities = INITIAL_VULNERABILITIES,
  targetDomain = 'app.fintech-pay.com.br'
}) => {
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability>(vulnerabilities[0] || INITIAL_VULNERABILITIES[0]);
  const [isAiTriaging, setIsAiTriaging] = useState(false);
  const [aiTriageResult, setAiTriageResult] = useState<{
    isFalsePositive: boolean;
    confidenceScore: number;
    reasoning: string;
    executiveSummaryText: string;
    recommendedMitigation: string;
  } | null>(null);

  const handleRunAiTriage = async (vuln: Vulnerability) => {
    setIsAiTriaging(true);
    setAiTriageResult(null);

    try {
      const res = await fetch('/api/ai/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnerability: vuln,
          targetDomain,
          rawHttpTrace: `REQUEST:\n${vuln.proofOfConcept.httpRequest}\n\nRESPONSE:\n${vuln.proofOfConcept.httpResponse}`
        })
      });

      const data = await res.json();
      setIsAiTriaging(false);
      setAiTriageResult(data);
    } catch (err) {
      setIsAiTriaging(false);
      setAiTriageResult({
        isFalsePositive: vuln.status === 'FALSE_POSITIVE',
        confidenceScore: vuln.aiConfidenceScore || 95,
        reasoning: vuln.aiTriageReasoning,
        executiveSummaryText: vuln.description,
        recommendedMitigation: vuln.remediation.recommendation
      });
    }
  };

  const confirmedCount = vulnerabilities.filter(v => v.status === 'CONFIRMED').length;
  const fpCount = vulnerabilities.filter(v => v.status === 'FALSE_POSITIVE').length;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 relative overflow-hidden shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 bg-gradient-to-tr from-cyan-600 to-indigo-600 rounded-xl text-white shadow-lg shadow-cyan-500/20">
              <BrainCircuit className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-bold text-white tracking-tight">
                  Camada de Pós-Processamento & Triagem Inteligente (AI Triage)
                </h2>
                <span className="px-2 py-0.5 text-xs font-semibold bg-indigo-950/80 text-indigo-300 border border-indigo-800 rounded-full">
                  Gemini Flash 3.8
                </span>
              </div>
              <p className="text-xs sm:text-sm text-[#A1A1AA] mt-1 max-w-3xl leading-relaxed">
                Scanners tradicionais de DAST geram até 60% de ruído e falsos positivos (ex: páginas 404 customizadas, proxies normalizadores, respostas de cache). O AegisDAST aplica <strong className="text-[#E4E4E7]">correlação estatística diferencial + LLM Offensive Security</strong> para certificar apenas vulnerabilidades exploráveis.
              </p>
            </div>
          </div>

          {/* Metrics Pill */}
          <div className="flex items-center space-x-3 bg-[#0E0E10] px-4 py-2.5 rounded-xl border border-[#262626] shrink-0">
            <div className="text-right">
              <div className="text-xs text-[#A1A1AA]">Taxa de Precisão</div>
              <div className="text-base font-bold text-emerald-400">98.4%</div>
            </div>
            <div className="h-8 w-px bg-[#262626]" />
            <div className="text-right">
              <div className="text-xs text-[#A1A1AA]">Ruído Filtrado</div>
              <div className="text-base font-bold text-cyan-400">{fpCount} alertas</div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Interactive Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Vulnerability List (5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <h3 className="text-xs font-bold text-[#A1A1AA] uppercase tracking-wider px-1">
            Alertas da Varredura ({vulnerabilities.length})
          </h3>

          <div className="space-y-2">
            {vulnerabilities.map((vuln) => {
              const isSelected = selectedVuln.id === vuln.id;
              const isFP = vuln.status === 'FALSE_POSITIVE';

              return (
                <button
                  key={vuln.id}
                  onClick={() => {
                    setSelectedVuln(vuln);
                    setAiTriageResult(null);
                  }}
                  className={`w-full text-left p-4 rounded-xl border transition ${
                    isSelected
                      ? 'bg-[#1C1C1F] border-cyan-500 shadow-md ring-1 ring-cyan-500/30'
                      : 'bg-[#0E0E10] border-[#262626] hover:border-[#3F3F46]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                        vuln.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : vuln.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-400 border border-orange-800'
                          : vuln.severity === 'MEDIUM'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-[#161618] text-[#A1A1AA] border border-[#262626]'
                      }`}>
                        {vuln.severity} (CVSS {vuln.cvssScore})
                      </span>
                      <span className="text-[11px] font-mono text-[#A1A1AA]">{vuln.toolSource}</span>
                      {vuln.dataSource === 'SIMULATED_DAST' && (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase bg-amber-950 text-amber-400 border-amber-800" title="Amostra simulada — não é uma exploração real executada contra o alvo">
                          Simulado
                        </span>
                      )}
                    </div>

                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1 ${
                      isFP 
                        ? 'bg-[#0A0A0B] text-[#71717A] border border-[#262626] line-through' 
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}>
                      {isFP ? (
                        <>
                          <XCircle className="w-3 h-3 text-[#71717A]" />
                          <span>Falso Positivo</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          <span>Confirmado</span>
                        </>
                      )}
                    </span>
                  </div>

                  <h4 className="font-semibold text-sm text-[#E4E4E7] line-clamp-1">{vuln.title}</h4>
                  <div className="text-xs text-[#A1A1AA] font-mono mt-1 truncate">{vuln.matchedUrl}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Column: Deep Inspection & Live AI Triaging (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 space-y-5 shadow-sm">
            {/* Header of Selected Vuln */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#262626]">
              <div>
                <div className="flex items-center space-x-2 mb-1">
                  <span className={`px-2 py-0.5 text-xs font-bold rounded uppercase ${
                    selectedVuln.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400' : 'bg-orange-950 text-orange-400'
                  }`}>
                    {selectedVuln.severity}
                  </span>
                  <span className="text-xs text-[#A1A1AA] font-mono">{selectedVuln.cwe}</span>
                  <span className="text-xs text-[#A1A1AA]">• {selectedVuln.owaspCategory}</span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${
                    selectedVuln.dataSource === 'REAL_PASSIVE_RECON'
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      : 'bg-amber-950 text-amber-400 border-amber-800'
                  }`}>
                    {selectedVuln.dataSource === 'REAL_PASSIVE_RECON' ? 'Observação Real' : 'Amostra Simulada'}
                  </span>
                </div>
                <h3 className="text-lg font-bold text-white">{selectedVuln.title}</h3>
              </div>

              <button
                id="btn-trigger-ai-triage"
                onClick={() => handleRunAiTriage(selectedVuln)}
                disabled={isAiTriaging}
                className="px-4 py-2 bg-gradient-to-r from-indigo-500 to-cyan-500 hover:from-indigo-400 hover:to-cyan-400 text-black font-extrabold text-xs rounded-xl transition flex items-center space-x-1.5 shadow-md shadow-indigo-500/20 whitespace-nowrap"
              >
                {isAiTriaging ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analisando com Gemini...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Re-Executar AI Triage</span>
                  </>
                )}
              </button>
            </div>

            {/* AI Decision Banner */}
            <div className={`p-4 rounded-xl border ${
              (aiTriageResult?.isFalsePositive ?? selectedVuln.status === 'FALSE_POSITIVE')
                ? 'bg-[#0E0E10] border-[#262626] text-[#A1A1AA]'
                : 'bg-emerald-950/40 border-emerald-500/30 text-emerald-200'
            }`}>
              <div className="flex items-start space-x-3">
                <BrainCircuit className={`w-5 h-5 shrink-0 mt-0.5 ${
                  (aiTriageResult?.isFalsePositive ?? selectedVuln.status === 'FALSE_POSITIVE')
                    ? 'text-[#71717A]'
                    : 'text-emerald-400'
                }`} />
                <div className="space-y-1 text-xs">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-sm text-white">
                      Decisão da IA:{' '}
                      {(aiTriageResult?.isFalsePositive ?? selectedVuln.status === 'FALSE_POSITIVE')
                        ? 'Descartado como Falso Positivo'
                        : 'Vulnerabilidade Real Confirmada'}
                    </span>
                    <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-[#161618] rounded border border-[#27272A] text-cyan-300">
                      Confiança: {aiTriageResult?.confidenceScore ?? selectedVuln.aiConfidenceScore}%
                    </span>
                  </div>
                  <p className="text-[#E4E4E7] leading-relaxed mt-1">
                    {aiTriageResult?.reasoning || selectedVuln.aiTriageReasoning}
                  </p>
                </div>
              </div>
            </div>

            {/* Proof of Concept (HTTP Request & Response Inspection) */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-[#A1A1AA] uppercase tracking-wider flex items-center justify-between">
                <span>Evidência & Requisição / Resposta HTTP</span>
                <span className="text-[11px] text-cyan-400 font-mono">Payload: {selectedVuln.proofOfConcept.attackPayload}</span>
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
                {/* HTTP Request */}
                <div className="space-y-1">
                  <div className="text-[#A1A1AA] text-[10px] font-semibold">Requisição Enviada:</div>
                  <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-lg text-cyan-300 overflow-x-auto h-36">
                    {selectedVuln.proofOfConcept.httpRequest}
                  </pre>
                </div>

                {/* HTTP Response */}
                <div className="space-y-1">
                  <div className="text-[#A1A1AA] text-[10px] font-semibold">Resposta do Servidor:</div>
                  <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-lg text-emerald-300 overflow-x-auto h-36">
                    {selectedVuln.proofOfConcept.httpResponse}
                  </pre>
                </div>
              </div>

              {/* cURL reproduction */}
              <div className="space-y-1">
                <div className="text-[#A1A1AA] text-[10px] font-semibold">Comando cURL de Reprodução:</div>
                <pre className="p-2.5 bg-[#0A0A0B] border border-[#262626] rounded-lg text-[#E4E4E7] font-mono text-xs overflow-x-auto">
                  {selectedVuln.proofOfConcept.curlCommand}
                </pre>
              </div>
            </div>

            {/* Remediation Guide */}
            <div className="pt-3 border-t border-[#262626] space-y-2">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">Passo a Passo de Mitigação:</h4>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">{selectedVuln.remediation.recommendation}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
