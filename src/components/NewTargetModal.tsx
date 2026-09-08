import React, { useState } from 'react';
import { X, Globe, Plus, ShieldCheck, Lock } from 'lucide-react';
import { VerificationMethod } from '../types';

export interface NewTargetDraft {
  domain: string;
  organizationName: string;
  verificationMethod: VerificationMethod;
}

interface NewTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddTarget: (draft: NewTargetDraft) => void;
}

export const NewTargetModal: React.FC<NewTargetModalProps> = ({
  isOpen,
  onClose,
  onAddTarget
}) => {
  const [domain, setDomain] = useState('');
  const [orgName, setOrgName] = useState('');
  const [method, setMethod] = useState<VerificationMethod>('DNS_TXT');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    // O backend limpa o domínio, gera o token de verificação e persiste o
    // registro (GET /api/targets/:id volta a ser a fonte da verdade) — este
    // modal só coleta a intenção do usuário.
    onAddTarget({
      domain: domain.trim(),
      organizationName: orgName.trim() || 'Minha Organização',
      verificationMethod: method
    });
    onClose();
    setDomain('');
    setOrgName('');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#161618] border border-[#262626] rounded-3xl max-w-lg w-full overflow-hidden shadow-2xl p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-[#262626] pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 bg-cyan-950/80 text-cyan-400 rounded-xl border border-cyan-800/60">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Cadastrar Novo Domínio Alvo</h3>
              <p className="text-xs text-[#A1A1AA]">Adicione uma aplicação web para validação de posse e DAST</p>
            </div>
          </div>

          <button onClick={onClose} className="p-1.5 text-[#A1A1AA] hover:text-white hover:bg-[#262626] rounded-lg transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[#E4E4E7] mb-1.5">
              Organização / Empresa:
            </label>
            <input
              type="text"
              placeholder="Ex: Minha Empresa S.A."
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="w-full bg-[#0E0E10] border border-[#262626] rounded-xl px-3.5 py-2.5 text-sm text-[#E4E4E7] placeholder-[#71717A] focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#E4E4E7] mb-1.5">
              Domínio ou URL da Aplicação:
            </label>
            <input
              type="text"
              required
              placeholder="Ex: app.minhaempresa.com.br"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-[#0E0E10] border border-[#262626] rounded-xl px-3.5 py-2.5 text-sm font-mono text-[#E4E4E7] placeholder-[#71717A] focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[#E4E4E7] mb-1.5">
              Método Preferencial de Validação:
            </label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as VerificationMethod)}
              className="w-full bg-[#0E0E10] border border-[#262626] rounded-xl px-3.5 py-2.5 text-sm text-[#E4E4E7] focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition"
            >
              <option value="DNS_TXT">Registro DNS TXT (Recomendado)</option>
              <option value="HTTP_FILE">Arquivo HTTP /.well-known/aegis-verify.txt</option>
              <option value="HTML_META">Tag HTML Meta no &lt;head&gt;</option>
            </select>
          </div>

          <div className="p-3 bg-[#0E0E10] rounded-xl border border-[#262626] text-xs text-[#A1A1AA] flex items-start space-x-2.5">
            <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p>
              Ao cadastrar, você receberá um token criptográfico único. A varredura só será liberada após a confirmação de propriedade do domínio.
            </p>
          </div>

          <div className="flex justify-end space-x-3 pt-3 border-t border-[#262626]">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-[#262626] hover:bg-[#3F3F46] text-[#E4E4E7] text-xs font-semibold rounded-xl transition"
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="px-5 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs sm:text-sm rounded-xl transition flex items-center space-x-1.5 shadow-lg shadow-cyan-500/20"
            >
              <Plus className="w-4 h-4" />
              <span>Criar Alvo & Gerar Token</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
