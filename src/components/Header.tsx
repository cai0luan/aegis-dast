import React from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Sparkles, 
  FileText, 
  Layers, 
  CheckCircle2, 
  Flame,
  Globe2,
  Lock,
  Cpu
} from 'lucide-react';
import { TargetDomain } from '../types';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  targets: TargetDomain[];
  selectedTarget: TargetDomain | null;
  onSelectTarget: (target: TargetDomain) => void;
  onOpenNewTarget: () => void;
  onOpenScanConfig: () => void;
  isScanning: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  targets,
  selectedTarget,
  onSelectTarget,
  onOpenNewTarget,
  onOpenScanConfig,
  isScanning
}) => {
  const tabs = [
    { id: 'dashboard', label: 'Painel & Alvos', icon: Globe2 },
    { id: 'verification', label: '1. Validação de Posse', icon: Lock, badge: selectedTarget?.verificationStatus === 'VERIFIED' ? 'OK' : 'Pendente' },
    { id: 'pipeline', label: '2. Pipeline & Scanner', icon: Terminal, pulse: isScanning },
    { id: 'waf-ai', label: '3. Falsos Positivos & WAF', icon: Sparkles },
    { id: 'reports', label: '4. Relatório (Executivo/Técnico)', icon: FileText },
    { id: 'architecture', label: 'Arquitetura & Schema DDL', icon: Layers }
  ];

  return (
    <header className="bg-[#0E0E10] border-b border-[#262626] sticky top-0 z-40 no-print">
      {/* Top Banner */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg text-white tracking-tight">AEGIS<span className="text-cyan-400">DAST</span></span>
                <span className="px-2 py-0.5 text-[10px] font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 rounded-full uppercase tracking-wider">
                  Enterprise BAS
                </span>
              </div>
              <p className="text-xs text-[#A1A1AA] hidden sm:block">Automated Offensive Security & Attack Simulation SaaS</p>
            </div>
          </div>

          {/* Target Selector & Quick Actions */}
          <div className="flex items-center space-x-3">
            {/* Active Target Picker */}
            <div className="relative flex items-center">
              <span className="text-xs text-[#A1A1AA] mr-2 font-medium hidden md:inline">Alvo Ativo:</span>
              <select
                aria-label="Selecionar Alvo Ativo"
                value={selectedTarget?.id || ''}
                onChange={(e) => {
                  const found = targets.find(t => t.id === e.target.value);
                  if (found) onSelectTarget(found);
                }}
                className="bg-[#161618] border border-[#27272A] text-[#E4E4E7] text-xs sm:text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent font-mono"
              >
                {targets.map(t => (
                  <option key={t.id} value={t.id} className="bg-[#161618] text-[#E4E4E7]">
                    {t.verificationStatus === 'VERIFIED' ? '✓' : '⚠'} {t.domain} ({t.organizationName})
                  </option>
                ))}
              </select>
            </div>

            {/* Verification Indicator */}
            {selectedTarget && (
              <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-[#27272A] bg-[#161618]">
                {selectedTarget.verificationStatus === 'VERIFIED' ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-400">Posse Validada</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5 text-amber-400" />
                    <span className="text-amber-400">Posse Não Validada</span>
                  </>
                )}
              </div>
            )}

            {/* Quick Actions */}
            <button
              id="btn-quick-new-target"
              onClick={onOpenNewTarget}
              className="text-xs bg-[#1C1C1F] hover:bg-[#27272A] text-[#E4E4E7] px-3 py-1.5 rounded-lg border border-[#27272A] transition flex items-center space-x-1.5 shadow-sm"
            >
              <span>+ Novo Alvo</span>
            </button>

            <button
              id="btn-quick-start-scan"
              onClick={onOpenScanConfig}
              disabled={selectedTarget?.verificationStatus !== 'VERIFIED' || isScanning}
              className={`text-xs font-semibold px-3.5 py-1.5 rounded-lg flex items-center space-x-1.5 transition shadow-sm ${
                selectedTarget?.verificationStatus === 'VERIFIED' && !isScanning
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold shadow-cyan-500/20'
                  : 'bg-[#1C1C1F] text-[#71717A] cursor-not-allowed border border-[#27272A]'
              }`}
              title={selectedTarget?.verificationStatus !== 'VERIFIED' ? 'Validação de posse obrigatória antes de iniciar varredura' : ''}
            >
              {isScanning ? (
                <>
                  <div className="w-2 h-2 rounded-full bg-cyan-400 animate-ping mr-1" />
                  <span>Escaneando...</span>
                </>
              ) : (
                <>
                  <Flame className="w-3.5 h-3.5" />
                  <span>Iniciar Varredura</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-1 sm:space-x-2 overflow-x-auto py-2 border-t border-[#262626] scrollbar-none">
          {tabs.map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3.5 py-2 text-xs sm:text-sm font-medium rounded-lg whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-[#1C1C1F] text-cyan-400 border border-cyan-500/30 shadow-inner'
                    : 'text-[#A1A1AA] hover:text-[#E4E4E7] hover:bg-[#161618]'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-[#71717A]'}`} />
                <span>{tab.label}</span>
                {tab.pulse && (
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                )}
                {tab.badge && (
                  <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                    tab.badge === 'OK' ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800' : 'bg-amber-950/80 text-amber-400 border border-amber-800'
                  }`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
