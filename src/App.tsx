import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Header } from './components/Header';
import { DashboardOverview } from './components/DashboardOverview';
import { DomainVerificationView } from './components/DomainVerificationView';
import { PipelineOrchestratorView } from './components/PipelineOrchestratorView';
import { FalsePositiveAiView } from './components/FalsePositiveAiView';
import { WafBypassConfigView } from './components/WafBypassConfigView';
import { SecurityReportView } from './components/SecurityReportView';
import { ArchitectureDocView } from './components/ArchitectureDocView';
import { ScanConfigModal } from './components/ScanConfigModal';
import { NewTargetModal } from './components/NewTargetModal';
import { INITIAL_VULNERABILITIES } from './data/mockSecurityData';
import {
  TargetDomain,
  ScanJob,
  ScanProfile,
  ScanConfiguration,
  VerificationMethod
} from './types';

const POLL_INTERVAL_MS = 1500;
const RUNNING_STATUSES: ScanJob['status'][] = ['QUEUED', 'RECON', 'ACTIVE_SCAN', 'TRIAGE'];

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [targets, setTargets] = useState<TargetDomain[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<TargetDomain | null>(null);
  const [activeScan, setActiveScan] = useState<ScanJob | null>(null);
  const [isScanConfigOpen, setIsScanConfigOpen] = useState(false);
  const [isNewTargetOpen, setIsNewTargetOpen] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isLoadingTargets, setIsLoadingTargets] = useState(true);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const fetchTargets = useCallback(async (preferId?: string) => {
    try {
      const res = await fetch('/api/targets');
      const data = await res.json();
      const list: TargetDomain[] = data.targets || [];
      setTargets(list);
      setSelectedTarget(prev => {
        const wantedId = preferId || prev?.id;
        return list.find(t => t.id === wantedId) || list[0] || null;
      });
    } catch (err) {
      console.error('[App] Falha ao carregar alvos:', err);
    } finally {
      setIsLoadingTargets(false);
    }
  }, []);

  useEffect(() => {
    fetchTargets();
    return () => stopPolling();
  }, [fetchTargets, stopPolling]);

  // Chamado pela tela de verificação depois que o backend confirma (real ou sandbox).
  // O servidor é a fonte da verdade agora, então re-buscamos o alvo em vez de
  // apenas remendar o estado local.
  const handleVerifySuccess = (targetId: string, _method: VerificationMethod) => {
    fetchTargets(targetId);
  };

  const handleAddTarget = async (draft: { domain: string; organizationName: string; verificationMethod: VerificationMethod }) => {
    try {
      const res = await fetch('/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft)
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Falha ao cadastrar alvo.');
        return;
      }
      const { target } = await res.json();
      await fetchTargets(target.id);
      setActiveTab('verification');
    } catch (err) {
      console.error('[App] Falha ao criar alvo:', err);
      alert('Falha de comunicação com o servidor ao cadastrar o alvo.');
    }
  };

  const pollScan = useCallback((scanId: string) => {
    stopPolling();
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        if (!res.ok) return;
        const { scan } = await res.json();
        setActiveScan(scan);
        if (!RUNNING_STATUSES.includes(scan.status)) {
          stopPolling();
          setIsScanning(false);
          fetchTargets(scan.targetId);
        }
      } catch (err) {
        console.error('[App] Falha ao consultar status do scan:', err);
      }
    }, POLL_INTERVAL_MS);
  }, [stopPolling, fetchTargets]);

  const handleStartScan = async (target: TargetDomain, profile: ScanProfile, config: ScanConfiguration) => {
    if (target.verificationStatus !== 'VERIFIED') {
      alert('Atenção: A validação de posse do domínio é obrigatória antes de iniciar o escaneamento.');
      return;
    }

    setIsScanning(true);
    setActiveTab('pipeline');

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetId: target.id, profile, config })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        alert(err.error || 'Falha ao iniciar a varredura.');
        setIsScanning(false);
        return;
      }
      const { scan } = await res.json();
      setActiveScan(scan);
      if (RUNNING_STATUSES.includes(scan.status)) {
        // Hoje /api/scans é síncrona e sempre devolve um status terminal (ver
        // server/scanOrchestrator.ts) — este ramo é só uma rede de segurança
        // caso isso mude no futuro para um modelo assíncrono de verdade.
        pollScan(scan.id);
      } else {
        setIsScanning(false);
        fetchTargets(scan.targetId);
      }
    } catch (err) {
      console.error('[App] Falha ao iniciar varredura:', err);
      alert('Falha de comunicação com o servidor ao iniciar a varredura.');
      setIsScanning(false);
    }
  };

  const handleStopScan = async () => {
    if (!activeScan) return;
    try {
      await fetch(`/api/scans/${activeScan.id}/stop`, { method: 'POST' });
    } catch (err) {
      console.error('[App] Falha ao solicitar cancelamento:', err);
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-[#E4E4E7] flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      {/* Header / Nav */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        targets={targets}
        selectedTarget={selectedTarget}
        onSelectTarget={(t) => setSelectedTarget(t)}
        onOpenNewTarget={() => setIsNewTargetOpen(true)}
        onOpenScanConfig={() => setIsScanConfigOpen(true)}
        isScanning={isScanning}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {isLoadingTargets ? (
          <div className="text-center text-sm text-[#71717A] py-20">Carregando alvos...</div>
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardOverview
                targets={targets}
                selectedTarget={selectedTarget}
                onSelectTarget={(t) => setSelectedTarget(t)}
                onOpenNewTarget={() => setIsNewTargetOpen(true)}
                onOpenScanConfig={() => setIsScanConfigOpen(true)}
                onNavigateTab={(tabId) => setActiveTab(tabId)}
              />
            )}

            {activeTab === 'verification' && (
              <DomainVerificationView
                target={selectedTarget}
                onVerifySuccess={handleVerifySuccess}
                onSelectTab={(tabId) => setActiveTab(tabId)}
              />
            )}

            {activeTab === 'pipeline' && (
              <PipelineOrchestratorView
                target={selectedTarget}
                activeScan={activeScan}
                isScanning={isScanning}
                onStartScan={handleStartScan}
                onStopScan={handleStopScan}
                onViewReport={() => setActiveTab('reports')}
                onOpenScanConfig={() => setIsScanConfigOpen(true)}
                onSelectTab={(tabId) => setActiveTab(tabId)}
              />
            )}

            {activeTab === 'waf-ai' && (
              <div className="space-y-12">
                <FalsePositiveAiView
                  vulnerabilities={activeScan?.vulnerabilities || INITIAL_VULNERABILITIES}
                  targetDomain={selectedTarget?.domain || 'app.fintech-pay.com.br'}
                />
                <div className="pt-6 border-t border-[#262626]">
                  <WafBypassConfigView target={selectedTarget} />
                </div>
              </div>
            )}

            {activeTab === 'reports' && (
              <SecurityReportView scan={activeScan || undefined} />
            )}

            {activeTab === 'architecture' && (
              <ArchitectureDocView />
            )}
          </>
        )}
      </main>

      {/* Modals */}
      <ScanConfigModal
        isOpen={isScanConfigOpen}
        onClose={() => setIsScanConfigOpen(false)}
        target={selectedTarget}
        onStartScan={handleStartScan}
      />

      <NewTargetModal
        isOpen={isNewTargetOpen}
        onClose={() => setIsNewTargetOpen(false)}
        onAddTarget={handleAddTarget}
      />

      {/* Footer */}
      <footer className="border-t border-[#262626] bg-[#0E0E10] py-6 text-xs text-[#71717A] text-center no-print">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            AegisDAST Enterprise Security Platform &bull; Architecture & Code Implementation
          </div>
          <div className="font-mono text-[#A1A1AA]">
            Offensive Security & Cloud Architecture Standard
          </div>
        </div>
      </footer>
    </div>
  );
}
