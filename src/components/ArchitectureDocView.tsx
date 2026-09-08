import React, { useState } from 'react';
import { 
  Layers, 
  Database, 
  Cpu, 
  Server, 
  ShieldCheck, 
  Terminal, 
  Copy, 
  Check, 
  FileCode2, 
  ArrowRight,
  Boxes,
  Lock,
  GitBranch,
  Network
} from 'lucide-react';
import { POSTGRESQL_SCHEMA_DDL, CELERY_PYTHON_WORKER_CODE } from '../data/mockSecurityData';

export const ArchitectureDocView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'FLOW' | 'STACK' | 'SCHEMA' | 'WORKER_CODE'>('FLOW');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const techStack = [
    {
      category: '1. Frontend & Client UI',
      tools: 'React 19, TypeScript, Tailwind CSS, Vite, Lucide Icons',
      purpose: 'Interface web de alta performance para clientes e analistas com visualização de métricas em tempo real, painel de validação de posse, console de logs streaming e relatórios executivos.'
    },
    {
      category: '2. Backend API & Gatekeeper',
      tools: 'Node.js / Express ou Python FastAPI / Go',
      purpose: 'API REST / GraphQL multi-tenant com autenticação JWT/MFA, controle de acesso RBAC, validação criptográfica de DNS TXT/HTTP (Anti-Abuso) e disparo de tarefas assíncronas.'
    },
    {
      category: '3. Fila de Mensageria & Task Broker',
      tools: 'Redis + Celery ou AWS SQS + Temporal.io',
      purpose: 'Distribuição assíncrona de jobs de varredura com controle de concorrência, retentativas automáticas (retry backoff), dead-letter queues e priorização de planos pagos.'
    },
    {
      category: '4. Workers de Escaneamento (Contêineres Efêmeros)',
      tools: 'Docker, Kubernetes Jobs / AWS ECS Fargate, Alpine/Debian Linux',
      purpose: 'Contêineres isolados sem privilégios root (drop capabilities) que executam as ferramentas de segurança por tarefa e são destruídos ao término, prevenindo contaminação cruzada.'
    },
    {
      category: '5. Ferramentas Open-Source Integradas',
      tools: 'Nuclei v3, OWASP ZAP (API daemon), Subfinder, Naabu, Nmap NSE, Wappalyzer',
      purpose: 'Motor offensive security de alta velocidade para reconhecimento passivo/ativo e varredura de vulnerabilidades conhecidas (CVEs) e lógicas.'
    },
    {
      category: '6. Camada de Pós-Processamento & AI Triage',
      tools: 'Gemini 3.8 Flash SDK + Heuristic Correlation Engine',
      purpose: 'Descarte automatizado de falsos positivos através de análise diferencial de payloads, códigos de status e teste de consistência estatística de tempo de resposta.'
    },
    {
      category: '7. Banco de Dados Primário',
      tools: 'PostgreSQL 16+ com Row-Level Security (RLS) e pgvector',
      purpose: 'Armazenamento seguro de organizações, alvos auditados, tokens assinados, histórico de varreduras, relatórios gerados e telemetria de logs.'
    }
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 relative overflow-hidden shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 rounded-xl text-white shadow-lg shadow-cyan-500/20">
              <Layers className="w-7 h-7" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                Especificação de Arquitetura & Stack Técnica
              </h2>
              <p className="text-xs sm:text-sm text-[#A1A1AA] mt-1 max-w-3xl">
                Documentação técnica da infraestrutura distribuída do SaaS, modelo relacional PostgreSQL (DDL), pipeline de contêineres Celery e salvaguardas de cibersegurança.
              </p>
            </div>
          </div>

          {/* Sub Navigation */}
          <div className="flex flex-wrap bg-[#0E0E10] p-1 rounded-xl border border-[#262626] text-xs">
            {[
              { id: 'FLOW', label: '1. Diagrama de Fluxo' },
              { id: 'STACK', label: '2. Stack Ideal' },
              { id: 'SCHEMA', label: '3. Schema PostgreSQL (DDL)' },
              { id: 'WORKER_CODE', label: '4. Worker Celery/Docker' }
            ].map((sub) => (
              <button
                key={sub.id}
                onClick={() => setActiveSubTab(sub.id as any)}
                className={`px-3 py-1.5 rounded-lg font-medium transition ${
                  activeSubTab === sub.id
                    ? 'bg-[#1C1C1F] text-cyan-400 shadow-sm'
                    : 'text-[#A1A1AA] hover:text-white'
                }`}
              >
                {sub.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 1. ARCHITECTURE FLOW DIAGRAM */}
      {activeSubTab === 'FLOW' && (
        <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 sm:p-8 space-y-6 shadow-sm">
          <div className="border-b border-[#262626] pb-4">
            <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <Network className="w-5 h-5 text-cyan-400" />
              <span>Fluxo Arquitetural Completo (End-to-End)</span>
            </h3>
            <p className="text-xs text-[#A1A1AA] mt-1">
              Como o tráfego transita da solicitação do cliente até a geração do relatório técnico auditado.
            </p>
          </div>

          {/* Flow Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Step 1 */}
            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 space-y-3 relative">
              <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800 text-cyan-400 font-bold flex items-center justify-center text-sm">
                01
              </div>
              <h4 className="font-bold text-sm text-white">Cadastro & Anti-Abuse</h4>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                O cliente cadastra o domínio alvo e gera o token de verificação. O backend consulta os resolvedores DNS autoritativos para comprovação do registro TXT.
              </p>
              <div className="text-[10px] font-mono text-cyan-400 bg-[#161618] p-2 rounded border border-[#262626]">
                Gatekeeper: Validação de Posse Obrigatória
              </div>
            </div>

            {/* Step 2 */}
            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 space-y-3 relative">
              <div className="w-8 h-8 rounded-lg bg-blue-950/80 border border-blue-800 text-blue-400 font-bold flex items-center justify-center text-sm">
                02
              </div>
              <h4 className="font-bold text-sm text-white">Disparo & Fila Assíncrona</h4>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                A API enfileira o job no Redis/Celery com perfil de scan (Passivo/Normal/Agressivo), rate limits, headers de autorização WAF e IPs estáticos de saída.
              </p>
              <div className="text-[10px] font-mono text-blue-400 bg-[#161618] p-2 rounded border border-[#262626]">
                Task Queue: Redis / AWS SQS
              </div>
            </div>

            {/* Step 3 */}
            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 space-y-3 relative">
              <div className="w-8 h-8 rounded-lg bg-indigo-950/80 border border-indigo-800 text-indigo-400 font-bold flex items-center justify-center text-sm">
                03
              </div>
              <h4 className="font-bold text-sm text-white">Execução em Contêiner</h4>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                Um contêiner Docker efêmero sobe isolado e orquestra sequencialmente: 1) Subfinder/Naabu (Recon), 2) Nuclei/ZAP (DAST), aplicando limites de taxa.
              </p>
              <div className="text-[10px] font-mono text-indigo-400 bg-[#161618] p-2 rounded border border-[#262626]">
                Docker / K8s Worker Pods
              </div>
            </div>

            {/* Step 4 */}
            <div className="bg-[#0E0E10] border border-[#262626] rounded-2xl p-5 space-y-3 relative">
              <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-400 font-bold flex items-center justify-center text-sm">
                04
              </div>
              <h4 className="font-bold text-sm text-white">Pós-Processamento & IA</h4>
              <p className="text-xs text-[#A1A1AA] leading-relaxed">
                O motor correlaciona as saídas brutas, descarta falsos positivos com Gemini AI, grava o resultado no PostgreSQL e gera o relatório Executivo e Técnico em PDF.
              </p>
              <div className="text-[10px] font-mono text-emerald-400 bg-[#161618] p-2 rounded border border-[#262626]">
                AI Triage + PDF Generator
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. TECH STACK SPECIFICATION */}
      {activeSubTab === 'STACK' && (
        <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 sm:p-8 space-y-6 shadow-sm">
          <div className="border-b border-[#262626] pb-4">
            <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <Boxes className="w-5 h-5 text-cyan-400" />
              <span>Stack de Tecnologias Recomendada para Produção</span>
            </h3>
            <p className="text-xs text-[#A1A1AA] mt-1">
              Arquitetura corporativa desenhada para escalabilidade, isolamento de contêineres e alta disponibilidade.
            </p>
          </div>

          <div className="space-y-3">
            {techStack.map((item, idx) => (
              <div key={idx} className="p-4 bg-[#0E0E10] border border-[#262626] rounded-xl space-y-1">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <span className="font-bold text-sm text-cyan-400">{item.category}</span>
                  <span className="font-mono text-xs text-[#E4E4E7] bg-[#161618] px-2 py-0.5 rounded border border-[#262626]">
                    {item.tools}
                  </span>
                </div>
                <p className="text-xs text-[#A1A1AA] leading-relaxed pt-1">{item.purpose}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 3. POSTGRESQL SCHEMA DDL */}
      {activeSubTab === 'SCHEMA' && (
        <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 sm:p-8 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#262626] pb-4">
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <Database className="w-5 h-5 text-cyan-400" />
                <span>Modelo de Dados PostgreSQL 16+ (DDL Completo)</span>
              </h3>
              <p className="text-xs text-[#A1A1AA] mt-1">
                Tabelas para Usuários, Organizações, Domínios Alvo, Auditoria de DNS, Scan Jobs, Vulnerabilidades e Logs.
              </p>
            </div>

            <button
              onClick={() => copyToClipboard(POSTGRESQL_SCHEMA_DDL, 'schema')}
              className="px-4 py-2 bg-[#262626] hover:bg-[#3F3F46] text-[#E4E4E7] text-xs font-semibold rounded-xl border border-[#3F3F46] transition flex items-center space-x-1.5 whitespace-nowrap"
            >
              {copiedKey === 'schema' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              <span>{copiedKey === 'schema' ? 'Copiado para Clipboard' : 'Copiar DDL SQL'}</span>
            </button>
          </div>

          <pre className="p-4 bg-[#0A0A0B] border border-[#262626] rounded-xl text-xs font-mono text-emerald-300 overflow-x-auto max-h-[500px] leading-relaxed scrollbar-thin scrollbar-thumb-[#262626]">
            {POSTGRESQL_SCHEMA_DDL}
          </pre>
        </div>
      )}

      {/* 4. CELERY / PYTHON WORKER CODE */}
      {activeSubTab === 'WORKER_CODE' && (
        <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 sm:p-8 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#262626] pb-4">
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                <span>Código do Worker Celery & Docker (Python 3.12)</span>
              </h3>
              <p className="text-xs text-[#A1A1AA] mt-1">
                Encadeamento assíncrono (chain) das etapas: DNS Gatekeeper → Subfinder/Naabu → Nuclei/ZAP → AI Triage.
              </p>
            </div>

            <button
              onClick={() => copyToClipboard(CELERY_PYTHON_WORKER_CODE, 'worker')}
              className="px-4 py-2 bg-[#262626] hover:bg-[#3F3F46] text-[#E4E4E7] text-xs font-semibold rounded-xl border border-[#3F3F46] transition flex items-center space-x-1.5 whitespace-nowrap"
            >
              {copiedKey === 'worker' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              <span>{copiedKey === 'worker' ? 'Copiado para Clipboard' : 'Copiar Código Python'}</span>
            </button>
          </div>

          <pre className="p-4 bg-[#0A0A0B] border border-[#262626] rounded-xl text-xs font-mono text-cyan-300 overflow-x-auto max-h-[500px] leading-relaxed scrollbar-thin scrollbar-thumb-[#262626]">
            {CELERY_PYTHON_WORKER_CODE}
          </pre>
        </div>
      )}
    </div>
  );
};
