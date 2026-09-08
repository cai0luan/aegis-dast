import React from 'react';
import { 
  ShieldCheck, 
  Flame, 
  Lock, 
  CheckCircle2, 
  AlertTriangle, 
  ArrowRight, 
  Globe2, 
  Activity, 
  Terminal, 
  Sparkles, 
  FileText,
  Server,
  Plus
} from 'lucide-react';
import { TargetDomain, ScanJob } from '../types';

interface DashboardOverviewProps {
  targets: TargetDomain[];
  selectedTarget: TargetDomain | null;
  onSelectTarget: (t: TargetDomain) => void;
  onOpenNewTarget: () => void;
  onOpenScanConfig: () => void;
  onNavigateTab: (tabId: string) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  targets,
  selectedTarget,
  onSelectTarget,
  onOpenNewTarget,
  onOpenScanConfig,
  onNavigateTab
}) => {
  const verifiedTargets = targets.filter(t => t.verificationStatus === 'VERIFIED');
  const pendingTargets = targets.filter(t => t.verificationStatus !== 'VERIFIED');

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Hero SaaS Banner */}
      <div className="relative overflow-hidden bg-gradient-to-br from-[#111113] via-[#161618] to-[#121216] border border-[#262626] rounded-3xl p-8 sm:p-10 shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-3 max-w-3xl">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-800 text-cyan-300 text-xs font-semibold">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Plataforma SaaS DAST / Breach & Attack Simulation</span>
            </div>
            <h1 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
              Testes Automatizados de Segurança Web com <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">Validação de Posse & AI Triage</span>
            </h1>
            <p className="text-sm text-[#A1A1AA] leading-relaxed">
              Plataforma completa para contratação de análises de vulnerabilidades, orquestração de contêineres DAST (Nuclei, ZAP, Nmap), mitigação de impacto via Rate Limiting e geração de relatórios Executivo e Técnico auditados.
            </p>
          </div>

          <div className="flex flex-wrap sm:flex-nowrap gap-3 shrink-0">
            <button
              id="btn-dash-new-target"
              onClick={onOpenNewTarget}
              className="px-5 py-3 bg-[#1C1C1F] hover:bg-[#27272A] text-[#E4E4E7] font-semibold text-xs sm:text-sm rounded-xl border border-[#27272A] transition flex items-center space-x-2 shadow-sm"
            >
              <Plus className="w-4 h-4" />
              <span>Cadastrar Novo Alvo</span>
            </button>

            {selectedTarget?.verificationStatus === 'VERIFIED' ? (
              <button
                id="btn-dash-start-scan"
                onClick={onOpenScanConfig}
                className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs sm:text-sm rounded-xl transition flex items-center space-x-2 shadow-lg shadow-cyan-500/25"
              >
                <Flame className="w-4 h-4" />
                <span>Iniciar Nova Varredura</span>
              </button>
            ) : (
              <button
                id="btn-dash-verify-target"
                onClick={() => onNavigateTab('verification')}
                className="px-6 py-3 bg-amber-500 hover:bg-amber-400 text-black font-extrabold text-xs sm:text-sm rounded-xl transition flex items-center space-x-2 shadow-lg shadow-amber-500/25"
              >
                <Lock className="w-4 h-4" />
                <span>Validar Posse do Alvo</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 4 Core Pillars Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          {
            tab: 'verification',
            title: '1. Validação de Posse',
            sub: 'Anti-Abuse Core',
            desc: 'DNS TXT & HTTP File upload. Previne scans contra alvos não autorizados.',
            icon: Lock,
            color: 'text-amber-400',
            bg: 'bg-amber-950/40 border-amber-900/40'
          },
          {
            tab: 'pipeline',
            title: '2. Pipeline & Scanner',
            sub: 'Orquestrador Docker/Celery',
            desc: 'Recon passivo/ativo + DAST com Nuclei, ZAP e Nmap em contêineres efêmeros.',
            icon: Terminal,
            color: 'text-cyan-400',
            bg: 'bg-cyan-950/40 border-cyan-900/40'
          },
          {
            tab: 'waf-ai',
            title: '3. Falsos Positivos & WAF',
            sub: 'AI Triage + Header Seguro',
            desc: 'Eliminação de ruídos via Gemini e allowlist de IPs estáticos com headers customizados.',
            icon: Sparkles,
            color: 'text-indigo-400',
            bg: 'bg-indigo-950/40 border-indigo-900/40'
          },
          {
            tab: 'reports',
            title: '4. Relatório Executivo/Técnico',
            sub: 'CVSS & OWASP Top 10',
            desc: 'Visão para diretoria sem jargão + Provas de Conceito (PoC) e diffs para devs.',
            icon: FileText,
            color: 'text-emerald-400',
            bg: 'bg-emerald-950/40 border-emerald-900/40'
          }
        ].map(pillar => {
          const Icon = pillar.icon;
          return (
            <button
              key={pillar.tab}
              onClick={() => onNavigateTab(pillar.tab)}
              className="p-5 bg-[#161618] border border-[#262626] hover:border-[#3F3F46] rounded-2xl text-left transition group space-y-3 shadow-sm"
            >
              <div className="flex items-center justify-between">
                <div className={`p-2.5 rounded-xl border ${pillar.bg} ${pillar.color}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <ArrowRight className="w-4 h-4 text-[#71717A] group-hover:text-cyan-400 group-hover:translate-x-1 transition" />
              </div>
              <div>
                <span className="text-[11px] font-bold text-[#A1A1AA] uppercase tracking-wider">{pillar.sub}</span>
                <h3 className="text-sm font-bold text-white group-hover:text-cyan-300 transition mt-0.5">{pillar.title}</h3>
                <p className="text-xs text-[#A1A1AA] leading-relaxed mt-1">{pillar.desc}</p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Target Domains Table / Cards */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#262626] pb-4">
          <div>
            <h3 className="text-base font-bold text-white tracking-tight flex items-center space-x-2">
              <Globe2 className="w-5 h-5 text-cyan-400" />
              <span>Aplicações Web & Domínios Cadastrados</span>
            </h3>
            <p className="text-xs text-[#A1A1AA] mt-0.5">Gerencie os alvos e seus respectivos status de posse e auditoria</p>
          </div>

          <button
            onClick={onOpenNewTarget}
            className="text-xs bg-[#1C1C1F] hover:bg-[#27272A] text-[#E4E4E7] px-3.5 py-2 rounded-xl border border-[#27272A] transition flex items-center space-x-1.5 self-start sm:self-auto"
          >
            <span>+ Adicionar Alvo</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {targets.map(target => {
            const isSelected = selectedTarget?.id === target.id;
            const isVer = target.verificationStatus === 'VERIFIED';

            return (
              <div
                key={target.id}
                onClick={() => onSelectTarget(target)}
                className={`p-5 rounded-2xl border cursor-pointer transition relative ${
                  isSelected 
                    ? 'bg-[#1C1C1F] border-cyan-500 ring-1 ring-cyan-500/30 shadow-lg shadow-cyan-500/10' 
                    : 'bg-[#0E0E10] border-[#262626] hover:border-[#3F3F46]'
                }`}
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-[11px] font-semibold text-[#A1A1AA] font-mono">
                    {target.organizationName}
                  </span>
                  <span className={`px-2 py-0.5 text-[10px] font-bold rounded-full border flex items-center gap-1 ${
                    isVer
                      ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      : 'bg-amber-950 text-amber-400 border-amber-800'
                  }`}>
                    {isVer ? <CheckCircle2 className="w-3 h-3" /> : <Lock className="w-3 h-3" />}
                    <span>{isVer ? 'Posse Validada' : 'Posse Pendente'}</span>
                  </span>
                </div>

                <h4 className="text-base font-bold text-white font-mono truncate">{target.domain}</h4>

                {/* Score & Vulnerabilities preview */}
                <div className="mt-4 pt-3 border-t border-[#262626] flex items-center justify-between text-xs">
                  <div>
                    <span className="text-[#A1A1AA]">Score de Risco:</span>
                    <div className="font-bold text-sm text-rose-400">{target.riskScore || 0}/100</div>
                  </div>

                  <div className="flex items-center space-x-2">
                    {isVer ? (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectTarget(target);
                          onNavigateTab('pipeline');
                        }}
                        className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-black font-extrabold text-xs rounded-lg transition shadow-sm"
                      >
                        Abrir Scanner
                      </button>
                    ) : (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectTarget(target);
                          onNavigateTab('verification');
                        }}
                        className="px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-black font-extrabold text-xs rounded-lg transition shadow-sm"
                      >
                        Validar Posse
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
