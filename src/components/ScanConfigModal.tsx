import React, { useState } from 'react';
import { X, Sliders, ShieldCheck, Flame, Gauge, Lock } from 'lucide-react';
import { TargetDomain, ScanProfile, ScanConfiguration } from '../types';

interface ScanConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  target: TargetDomain | null;
  onStartScan: (target: TargetDomain, profile: ScanProfile, config: ScanConfiguration) => void;
}

export const ScanConfigModal: React.FC<ScanConfigModalProps> = ({
  isOpen,
  onClose,
  target,
  onStartScan
}) => {
  const [profile, setProfile] = useState<ScanProfile>('NORMAL');
  const [rateLimit, setRateLimit] = useState(15);
  const [concurrency, setConcurrency] = useState(5);
  const [tools, setTools] = useState({
    subfinder: true,
    naabu: true,
    wappalyzer: true,
    nuclei: true,
    zap: true,
    nmap: true
  });
  const [wafBypassEnabled, setWafBypassEnabled] = useState(true);
  const [autoThrottle, setAutoThrottle] = useState(true);

  if (!isOpen || !target) return null;

  const handleProfileChange = (p: ScanProfile) => {
    setProfile(p);
    if (p === 'PASSIVE') {
      setRateLimit(5);
      setConcurrency(2);
    } else if (p === 'NORMAL') {
      setRateLimit(15);
      setConcurrency(5);
    } else if (p === 'AGGRESSIVE') {
      setRateLimit(50);
      setConcurrency(12);
    }
  };

  const handleLaunch = () => {
    const config: ScanConfiguration = {
      targetId: target.id,
      profile,
      rateLimit,
      concurrency,
      maxDepth: 3,
      tools,
      wafBypass: {
        enabled: wafBypassEnabled,
        authHeaderName: 'X-Aegis-Scan-Authorization',
        authHeaderValue: `Bearer ${target.verificationToken}`,
        useStaticEgressIps: true
      },
      timeoutMinutes: 30,
      autoThrottleOnHttpErrors: autoThrottle
    };

    onStartScan(target, profile, config);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#161618] border border-[#262626] rounded-3xl max-w-2xl w-full overflow-hidden shadow-2xl space-y-6 p-6 relative">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[#262626] pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-cyan-950/80 text-cyan-400 rounded-xl border border-cyan-800/60">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Configurar Nova Varredura de Segurança</h3>
              <p className="text-xs text-[#A1A1AA]">Alvo: <span className="font-mono text-cyan-300 font-semibold">{target.domain}</span></p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-[#A1A1AA] hover:text-white hover:bg-[#262626] rounded-lg transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Profile Selector */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-[#A1A1AA] uppercase tracking-wider">
            Perfil de Escaneamento
          </label>
          <div className="grid grid-cols-3 gap-3">
            {[
              { id: 'PASSIVE', label: 'Passivo / Furtivo', desc: '5 req/s • Baixo impacto' },
              { id: 'NORMAL', label: 'Normal (Padrão)', desc: '15 req/s • Recomendado' },
              { id: 'AGGRESSIVE', label: 'Agressivo / Dev', desc: '50 req/s • Análise profunda' }
            ].map(p => (
              <button
                key={p.id}
                onClick={() => handleProfileChange(p.id as ScanProfile)}
                className={`p-3.5 rounded-xl border text-left transition ${
                  profile === p.id 
                    ? 'bg-[#1C1C1F] border-cyan-500 ring-1 ring-cyan-500 text-white' 
                    : 'bg-[#0E0E10] border-[#262626] text-[#A1A1AA] hover:border-[#3F3F46]'
                }`}
              >
                <div className="font-bold text-xs text-[#E4E4E7]">{p.label}</div>
                <div className="text-[11px] text-[#71717A] mt-0.5">{p.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Rate Limiting & Concurrency */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-[#0E0E10] p-4 rounded-2xl border border-[#262626]">
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-[#E4E4E7] font-medium">Taxa de Requisições (RPS):</span>
              <span className="font-mono text-cyan-400 font-bold">{rateLimit} req/s</span>
            </div>
            <input
              type="range"
              min="1"
              max="100"
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
              className="w-full h-2 bg-[#1C1C1F] rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-[#E4E4E7] font-medium">Concorrência de Threads:</span>
              <span className="font-mono text-cyan-400 font-bold">{concurrency} threads</span>
            </div>
            <input
              type="range"
              min="1"
              max="20"
              value={concurrency}
              onChange={(e) => setConcurrency(Number(e.target.value))}
              className="w-full h-2 bg-[#1C1C1F] rounded-lg appearance-none cursor-pointer accent-cyan-400"
            />
          </div>
        </div>

        {/* Tools Selection */}
        <div className="space-y-2">
          <label className="text-xs font-bold text-[#A1A1AA] uppercase tracking-wider">
            Ferramentas Open-Source Habilitadas
          </label>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
            {Object.entries(tools).map(([key, val]) => (
              <label key={key} className="flex items-center space-x-2 p-2.5 bg-[#0E0E10] rounded-xl border border-[#262626] cursor-pointer hover:border-[#3F3F46] transition">
                <input
                  type="checkbox"
                  checked={val}
                  onChange={(e) => setTools({ ...tools, [key]: e.target.checked })}
                  className="rounded bg-[#1C1C1F] border-[#3F3F46] text-cyan-500 focus:ring-0"
                />
                <span className="text-[#E4E4E7] font-semibold uppercase">{key}</span>
              </label>
            ))}
          </div>
        </div>

        {/* WAF Bypass & Safeguards Checkboxes */}
        <div className="space-y-2 pt-2 border-t border-[#262626] text-xs">
          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={wafBypassEnabled}
              onChange={(e) => setWafBypassEnabled(e.target.checked)}
              className="rounded bg-[#1C1C1F] border-[#3F3F46] text-cyan-500 focus:ring-0"
            />
            <span className="text-[#A1A1AA]">Injetar cabeçalho <code className="text-cyan-300">X-Aegis-Scan-Authorization</code> para bypass legítimo</span>
          </label>

          <label className="flex items-center space-x-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoThrottle}
              onChange={(e) => setAutoThrottle(e.target.checked)}
              className="rounded bg-[#1C1C1F] border-[#3F3F46] text-cyan-500 focus:ring-0"
            />
            <span className="text-[#A1A1AA]">Auto-throttling / Backoff ao receber respostas HTTP 429 ou 503</span>
          </label>
        </div>

        {/* Actions */}
        <div className="flex justify-end space-x-3 pt-4 border-t border-[#262626]">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-[#262626] hover:bg-[#3F3F46] text-[#E4E4E7] text-xs font-semibold rounded-xl transition"
          >
            Cancelar
          </button>
          <button
            onClick={handleLaunch}
            className="px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs sm:text-sm rounded-xl transition shadow-lg shadow-cyan-500/20 flex items-center space-x-2"
          >
            <Flame className="w-4 h-4" />
            <span>Iniciar Varredura Agora</span>
          </button>
        </div>
      </div>
    </div>
  );
};
