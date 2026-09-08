import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Square, 
  Terminal, 
  CheckCircle2, 
  AlertCircle, 
  Clock, 
  Flame, 
  Layers, 
  Search, 
  ShieldAlert, 
  Cpu, 
  Activity, 
  Sliders, 
  Sparkles,
  ArrowRight,
  ExternalLink
} from 'lucide-react';
import { TargetDomain, ScanJob, ScanProfile, Vulnerability } from '../types';
import { SAMPLE_COMPLETED_SCAN, INITIAL_VULNERABILITIES } from '../data/mockSecurityData';

interface PipelineOrchestratorViewProps {
  target: TargetDomain | null;
  activeScan: ScanJob | null;
  isScanning: boolean;
  onStartScan: (target: TargetDomain, profile: ScanProfile, config: any) => void;
  onStopScan: () => void;
  onViewReport: (scan: ScanJob) => void;
  onOpenScanConfig: () => void;
  onSelectTab: (tab: string) => void;
}

export const PipelineOrchestratorView: React.FC<PipelineOrchestratorViewProps> = ({
  target,
  activeScan,
  isScanning,
  onStartScan,
  onStopScan,
  onViewReport,
  onOpenScanConfig,
  onSelectTab
}) => {
  const [selectedProfile, setSelectedProfile] = useState<ScanProfile>('NORMAL');
  const [rateLimit, setRateLimit] = useState(15);
  const [autoScroll, setAutoScroll] = useState(true);
  const logTerminalRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (autoScroll && logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
    }
  }, [activeScan?.logs, autoScroll]);

  const displayScan = activeScan || SAMPLE_COMPLETED_SCAN;
  const isVerified = target?.verificationStatus === 'VERIFIED';
  const isRunning = isScanning || activeScan?.status === 'RECON' || activeScan?.status === 'ACTIVE_SCAN' || activeScan?.status === 'TRIAGE' || activeScan?.status === 'QUEUED';

  const DATA_SOURCE_BADGES: Record<string, { label: string; className: string }> = {
    REAL: { label: 'DADOS REAIS', className: 'bg-emerald-950 text-emerald-400 border-emerald-800' },
    SIMULATED: { label: 'AMOSTRA SIMULADA', className: 'bg-amber-950 text-amber-400 border-amber-800' },
    AI_REAL: { label: 'IA REAL (GEMINI)', className: 'bg-emerald-950 text-emerald-400 border-emerald-800' },
    AI_FALLBACK: { label: 'FALLBACK HEURÍSTICO', className: 'bg-amber-950 text-amber-400 border-amber-800' }
  };

  const stages = [
    {
      id: 'stg-1',
      number: '1',
      title: 'Recon & Discovery',
      subtitle: 'Mapeamento de Superfície de Ataque',
      tools: ['DNS', 'crt.sh', 'HTTP Probe', 'TLS Handshake'],
      description: activeScan?.stages[0]?.summary || 'Enumeração passiva de subdomínios (crt.sh), resolução DNS, probe HTTP e handshake TLS reais contra o alvo verificado.',
      icon: Search,
      dataSource: activeScan?.stages[0]?.dataSource || 'REAL',
      state: activeScan?.status === 'RECON' ? 'RUNNING' : (activeScan?.currentStageIndex || 0) > 0 ? 'COMPLETED' : 'PENDING'
    },
    {
      id: 'stg-2',
      number: '2',
      title: 'DAST & Análise Ativa',
      subtitle: 'Exploração Controlada de Falhas (Amostra Simulada)',
      tools: ['Nuclei v3*', 'OWASP ZAP*', 'Nmap NSE*'],
      description: activeScan?.stages[1]?.summary || 'Esta sandbox não executa Nuclei/OWASP ZAP/Docker reais. Esta etapa gera uma amostra ilustrativa do formato de saída esperado, claramente rotulada como simulada.',
      icon: Flame,
      dataSource: activeScan?.stages[1]?.dataSource || 'SIMULATED',
      state: activeScan?.status === 'ACTIVE_SCAN' ? 'RUNNING' : (activeScan?.currentStageIndex || 0) > 1 ? 'COMPLETED' : 'PENDING'
    },
    {
      id: 'stg-3',
      number: '3',
      title: 'Pós-Processamento & Triagem AI',
      subtitle: 'Eliminação de Falsos Positivos',
      tools: ['Aegis Correlation', 'Gemini AI Triage'],
      description: activeScan?.stages[2]?.summary || 'Correlação de anomalias e triagem de falsos positivos via Gemini AI (real, se GEMINI_API_KEY estiver configurada) ou heurística de fallback.',
      icon: Sparkles,
      dataSource: activeScan?.stages[2]?.dataSource,
      state: activeScan?.status === 'TRIAGE' ? 'RUNNING' : (activeScan?.currentStageIndex || 0) >= 3 || activeScan?.status === 'COMPLETED' ? 'COMPLETED' : 'PENDING'
    }
  ];

  const handleStart = () => {
    if (!target || !isVerified) return;
    onStartScan(target, selectedProfile, {
      rateLimit,
      wafBypass: {
        enabled: true,
        authHeaderName: 'X-Aegis-Scan-Authorization',
        authHeaderValue: `Bearer ${target.verificationToken}`,
        useStaticEgressIps: true
      }
    });
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner / Engine Status */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 relative overflow-hidden shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <span className="p-2 rounded-xl bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
                <Cpu className="w-6 h-6" />
              </span>
              <div>
                <h2 className="text-xl font-bold text-white tracking-tight">Motor de Varredura DAST & Orquestrador</h2>
                <p className="text-xs text-[#A1A1AA]">Arquitetura de Contêineres Efêmeros (Celery/Redis + Docker Workers)</p>
              </div>
            </div>
            <p className="text-sm text-[#A1A1AA] max-w-2xl">
              Alvo selecionado: <span className="font-mono text-cyan-400 font-semibold">{target?.domain || 'Nenhum'}</span>
              {!isVerified && (
                <span className="ml-2 text-amber-400 text-xs font-semibold">(Posse não comprovada - Início bloqueado)</span>
              )}
            </p>
          </div>

          {/* Controls Bar */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Profile Picker */}
            <div className="flex items-center bg-[#0E0E10] p-1 rounded-xl border border-[#262626] text-xs">
              {(['PASSIVE', 'NORMAL', 'AGGRESSIVE'] as ScanProfile[]).map((p) => (
                <button
                  key={p}
                  onClick={() => setSelectedProfile(p)}
                  disabled={isRunning}
                  className={`px-3 py-1.5 rounded-lg font-medium transition ${
                    selectedProfile === p
                      ? 'bg-[#1C1C1F] text-cyan-400 shadow-sm'
                      : 'text-[#A1A1AA] hover:text-[#E4E4E7]'
                  }`}
                >
                  {p === 'PASSIVE' ? 'Passivo (5 req/s)' : p === 'NORMAL' ? 'Normal (15 req/s)' : 'Agressivo (50 req/s)'}
                </button>
              ))}
            </div>

            <button
              id="btn-open-advanced-config"
              onClick={onOpenScanConfig}
              className="p-2.5 bg-[#1C1C1F] hover:bg-[#27272A] text-[#E4E4E7] rounded-xl border border-[#27272A] transition shadow-sm"
              title="Configurações Avançadas de Varredura & WAF"
            >
              <Sliders className="w-4 h-4" />
            </button>

            {isRunning ? (
              <button
                id="btn-stop-scan"
                onClick={onStopScan}
                className="px-5 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-bold text-sm rounded-xl transition flex items-center space-x-2 shadow-lg shadow-rose-600/20"
              >
                <Square className="w-4 h-4 fill-current" />
                <span>Interromper Varredura</span>
              </button>
            ) : (
              <button
                id="btn-trigger-scan"
                onClick={handleStart}
                disabled={!isVerified}
                className={`px-6 py-2.5 font-bold text-sm rounded-xl transition flex items-center space-x-2 shadow-lg ${
                  isVerified 
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold shadow-cyan-500/20'
                    : 'bg-[#1C1C1F] text-[#71717A] cursor-not-allowed border border-[#27272A]'
                }`}
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Executar Pipeline Completo</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {isScanning ? (
        // Enquanto a requisição síncrona de /api/scans está em voo, `activeScan`
        // ainda é o valor ANTERIOR (nulo ou de um scan já concluído) — renderizar
        // os cards/terminal aqui embaixo mostraria um relatório antigo com cara de
        // atual. Este painel existe só para nunca mentir sobre o que está
        // acontecendo enquanto a resposta de verdade não chega.
        <div className="bg-[#161618] border border-[#262626] rounded-2xl p-10 flex flex-col items-center justify-center text-center space-y-4 shadow-sm">
          <Activity className="w-10 h-10 text-cyan-400 animate-spin" />
          <div>
            <h3 className="text-base font-bold text-white">Executando varredura ao vivo...</h3>
            <p className="text-xs text-[#A1A1AA] mt-1 max-w-md">
              Reconhecimento passivo real (DNS, crt.sh, HTTP, TLS) contra {target?.domain}, seguido de amostra simulada e triagem por IA. Isto roda numa única requisição — pode levar alguns segundos.
            </p>
          </div>
        </div>
      ) : (
      <>
      {/* 3-Stage Pipeline Visualizer */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {stages.map((stg) => {
          const Icon = stg.icon;
          const isCurrent = stg.state === 'RUNNING';
          const isDone = stg.state === 'COMPLETED';

          return (
            <div
              key={stg.id}
              className={`p-5 rounded-2xl border transition relative overflow-hidden ${
                isCurrent
                  ? 'bg-[#1C1C1F] border-cyan-500 ring-1 ring-cyan-500/30 shadow-lg shadow-cyan-500/10'
                  : isDone
                  ? 'bg-[#161618] border-emerald-500/40 text-[#E4E4E7]'
                  : 'bg-[#0E0E10] border-[#262626] text-[#71717A]'
              }`}
            >
              {isCurrent && (
                <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-blue-500 animate-pulse" />
              )}

              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2.5">
                  <span className={`w-7 h-7 rounded-lg flex items-center justify-center font-bold text-xs ${
                    isCurrent 
                      ? 'bg-cyan-500 text-black font-black' 
                      : isDone 
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                      : 'bg-[#1C1C1F] text-[#A1A1AA]'
                  }`}>
                    {isDone ? '✓' : stg.number}
                  </span>
                  <span className="font-bold text-sm text-white">{stg.title}</span>
                </div>

                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full uppercase tracking-wider ${
                  isCurrent 
                    ? 'bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse' 
                    : isDone 
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' 
                    : 'bg-[#0A0A0B] text-[#71717A] border border-[#262626]'
                }`}>
                  {isCurrent ? 'Em Execução' : isDone ? 'Concluído' : 'Aguardando'}
                </span>
              </div>

              <div className="flex items-center flex-wrap gap-1.5 mb-2">
                <span className="text-xs font-medium text-cyan-400">{stg.subtitle}</span>
                {stg.dataSource && DATA_SOURCE_BADGES[stg.dataSource] && (
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider ${DATA_SOURCE_BADGES[stg.dataSource].className}`}>
                    {DATA_SOURCE_BADGES[stg.dataSource].label}
                  </span>
                )}
              </div>
              <p className="text-xs text-[#A1A1AA] leading-relaxed mb-4">{stg.description}</p>

              {/* Tools Tags */}
              <div className="flex flex-wrap gap-1.5 pt-3 border-t border-[#262626]">
                {stg.tools.map((t) => (
                  <span key={t} className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#0E0E10] text-[#E4E4E7] border border-[#262626]">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      {/* Main Execution Arena: Terminal Logs & Findings Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Terminal Output (2 Cols) */}
        <div className="lg:col-span-2 bg-[#0A0A0B] border border-[#262626] rounded-2xl overflow-hidden shadow-2xl flex flex-col h-[520px]">
          {/* Terminal Header */}
          <div className="bg-[#111113] px-4 py-3 border-b border-[#262626] flex items-center justify-between text-xs text-[#A1A1AA] font-mono">
            <div className="flex items-center space-x-2">
              <div className="flex space-x-1.5">
                <div className="w-3 h-3 rounded-full bg-rose-500/80" />
                <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
              </div>
              <span className="text-white font-semibold ml-2 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                worker-pod-04:~/aegis-engine
              </span>
            </div>

            <div className="flex items-center space-x-3">
              <label className="flex items-center space-x-1.5 cursor-pointer text-[11px] text-[#A1A1AA] hover:text-white">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="rounded bg-[#1C1C1F] border-[#27272A] text-cyan-500 focus:ring-0"
                />
                <span>Auto-scroll</span>
              </label>
              <span className="text-cyan-400 font-bold">{displayScan.logs.length} linhas</span>
            </div>
          </div>

          {/* Terminal Stream Box */}
          <div 
            ref={logTerminalRef}
            className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1.5 text-[#E4E4E7] scrollbar-thin scrollbar-thumb-[#27272A] scrollbar-track-transparent"
          >
            {displayScan.logs.map((log, idx) => (
              <div key={idx} className="flex items-start space-x-2 leading-relaxed">
                <span className="text-[#71717A] select-none">[{log.timestamp}]</span>
                <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold uppercase ${
                  log.level === 'CRITICAL' || log.level === 'ERROR'
                    ? 'bg-rose-950 text-rose-400 border border-rose-800'
                    : log.level === 'WARN'
                    ? 'bg-amber-950 text-amber-400 border border-amber-800'
                    : log.level === 'SUCCESS'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : 'bg-[#161618] text-cyan-400 border border-[#262626]'
                }`}>
                  {log.stage}
                </span>
                <span className={
                  log.level === 'CRITICAL' || log.level === 'ERROR'
                    ? 'text-rose-300 font-semibold'
                    : log.level === 'WARN'
                    ? 'text-amber-300'
                    : log.level === 'SUCCESS'
                    ? 'text-emerald-300 font-medium'
                    : 'text-[#E4E4E7]'
                }>
                  {log.message}
                </span>
              </div>
            ))}

            {isRunning && (
              <div className="flex items-center space-x-2 text-cyan-400 pt-2 animate-pulse">
                <Activity className="w-3.5 h-3.5 animate-spin" />
                <span>Escaneando alvos e processando árvore de requisições HTTP...</span>
              </div>
            )}
          </div>

          {/* Terminal Footer Telemetry */}
          <div className="bg-[#111113] px-4 py-2.5 border-t border-[#262626] flex items-center justify-between text-[11px] text-[#A1A1AA] font-mono">
            <div className="flex items-center space-x-4">
              <span>Task ID: <strong className="text-white">{displayScan.id.slice(0, 16)}</strong></span>
              <span>Rate Limit: <strong className="text-cyan-400">{displayScan.config.rateLimit} req/s</strong></span>
              <span>WAF Bypass: <strong className="text-emerald-400">{displayScan.config.wafBypass.enabled ? 'ATIVO' : 'DESATIVADO'}</strong></span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              <span>Worker Docker: Online</span>
            </div>
          </div>
        </div>

        {/* Live Findings & Metrics Side Panel (1 Col) */}
        <div className="space-y-4">
          {/* Quick Metrics */}
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-5 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center justify-between">
              <span>Métricas da Varredura</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </h3>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 bg-[#0E0E10] rounded-xl border border-[#262626]">
                <div className="text-xs text-[#A1A1AA]">Total Analisado</div>
                <div className="text-2xl font-bold text-white mt-1">{displayScan.rawFindingsTotal}</div>
                <div className="text-[10px] text-[#71717A]">alertas brutos de ferramentas</div>
              </div>

              <div className="p-3 bg-[#0E0E10] rounded-xl border border-[#262626]">
                <div className="text-xs text-[#A1A1AA]">Falsos Positivos</div>
                <div className="text-2xl font-bold text-cyan-400 mt-1">{displayScan.filteredFalsePositivesTotal}</div>
                <div className="text-[10px] text-emerald-400">descartados pelo AI Triage</div>
              </div>
            </div>

            {/* Severity Distribution */}
            <div className="space-y-2 pt-2 border-t border-[#262626]">
              <div className="text-xs text-[#A1A1AA] font-medium">Vulnerabilidades Confirmadas por Severidade:</div>
              <div className="space-y-1.5 text-xs">
                {(['CRITICAL', 'HIGH', 'MEDIUM'] as const).map(sev => {
                  const count = displayScan.vulnerabilities.filter(v => v.status === 'CONFIRMED' && v.severity === sev).length;
                  const labels: Record<string, string> = { CRITICAL: 'Crítico (CVSS 9.0+)', HIGH: 'Alto (CVSS 7.0-8.9)', MEDIUM: 'Médio (CVSS 4.0-6.9)' };
                  const colors: Record<string, string> = {
                    CRITICAL: 'bg-rose-950/40 border-rose-900/40 text-rose-400 text-rose-300',
                    HIGH: 'bg-orange-950/40 border-orange-900/40 text-orange-400 text-orange-300',
                    MEDIUM: 'bg-amber-950/40 border-amber-900/40 text-amber-400 text-amber-300'
                  };
                  const [bg, border, labelColor, valueColor] = colors[sev].split(' ');
                  return (
                    <div key={sev} className={`flex items-center justify-between p-2 rounded-lg ${bg} border ${border}`}>
                      <span className={`font-bold ${labelColor}`}>{labels[sev]}</span>
                      <span className={`font-mono font-black ${valueColor}`}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Call to Action: View Report */}
            {displayScan.status === 'COMPLETED' && (
              <button
                id="btn-view-scan-report"
                onClick={() => onViewReport(displayScan)}
                className="w-full mt-2 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs sm:text-sm rounded-xl transition flex items-center justify-center space-x-2 shadow-lg shadow-cyan-500/20"
              >
                <span>Ver Relatório Executivo & Técnico</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Pipeline Technical Safeguards */}
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-5 text-xs text-[#E4E4E7] space-y-3 shadow-sm">
            <h4 className="font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-emerald-400" />
              <span>Garantias Anti-DDoS</span>
            </h4>
            <p className="text-[#A1A1AA] leading-relaxed">
              O motor monitora ativamente códigos <strong className="text-amber-300">429 (Too Many Requests)</strong> e <strong className="text-amber-300">503 (Service Unavailable)</strong>. Caso detecte lentidão, o algoritmo de <em>Adaptive Backoff</em> reduz a taxa instantaneamente.
            </p>
          </div>
        </div>
      </div>
      </>
      )}
    </div>
  );
};
