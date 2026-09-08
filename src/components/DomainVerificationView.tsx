import React, { useState } from 'react';
import { 
  ShieldAlert, 
  CheckCircle2, 
  Copy, 
  Check, 
  RefreshCw, 
  ExternalLink, 
  FileCode2, 
  Globe, 
  Terminal, 
  AlertTriangle,
  Lock,
  ArrowRight,
  ShieldCheck
} from 'lucide-react';
import { TargetDomain, VerificationMethod } from '../types';

interface DomainVerificationViewProps {
  target: TargetDomain | null;
  onVerifySuccess: (targetId: string, method: VerificationMethod) => void;
  onSelectTab: (tab: string) => void;
}

export const DomainVerificationView: React.FC<DomainVerificationViewProps> = ({
  target,
  onVerifySuccess,
  onSelectTab
}) => {
  const [selectedMethod, setSelectedMethod] = useState<VerificationMethod>('DNS_TXT');
  const [isChecking, setIsChecking] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [checkResult, setCheckResult] = useState<{
    success?: boolean;
    message?: string;
    details?: any;
    error?: string;
  } | null>(null);

  if (!target) {
    return (
      <div className="p-8 text-center bg-[#161618] border border-[#262626] rounded-2xl max-w-xl mx-auto my-12">
        <Globe className="w-12 h-12 text-[#71717A] mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">Nenhum Alvo Selecionado</h3>
        <p className="text-sm text-[#A1A1AA] mb-4">Selecione ou cadastre um domínio para validar a propriedade.</p>
      </div>
    );
  }

  const token = target.verificationToken || 'aegis-sec-9a4f21b7d83c9901e';
  const cleanDomain = target.domain.replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  const dnsHost = `_aegis-challenge.${cleanDomain}`;
  const httpFileUrl = `https://${cleanDomain}/.well-known/aegis-verify.txt`;
  const metaTag = `<meta name="aegis-site-verification" content="${token}" />`;
  const digCommand = `dig +short TXT ${dnsHost}`;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleVerifyCheck = async (sandboxMode: boolean = false) => {
    setIsChecking(true);
    setCheckResult(null);

    const endpoint = sandboxMode ? '/api/verify-domain/sandbox' : '/api/verify-domain';
    const body = sandboxMode
      ? { targetId: target.id, domain: cleanDomain }
      : { targetId: target.id, domain: cleanDomain, method: selectedMethod, token };

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      const data = await res.json();
      setIsChecking(false);

      if (res.ok && data.verified) {
        setCheckResult({
          success: true,
          message: data.message || 'Validação confirmada!',
          details: data.details
        });
        onVerifySuccess(target.id, data.method || selectedMethod);
      } else {
        setCheckResult({
          success: false,
          message: data.message || data.error || 'Não foi possível encontrar a chave de validação.',
          error: data.error
        });
      }
    } catch (err: any) {
      setIsChecking(false);
      setCheckResult({
        success: false,
        message: 'Falha na comunicação com o verificador de DNS/HTTP.',
        error: err.message
      });
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Banner Alert / Anti-Abuse Directive */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 relative overflow-hidden shadow-sm">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-4">
            <div className={`p-3 rounded-xl border ${
              target.verificationStatus === 'VERIFIED' 
                ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400' 
                : 'bg-amber-950/60 border-amber-500/40 text-amber-400'
            }`}>
              {target.verificationStatus === 'VERIFIED' ? (
                <ShieldCheck className="w-7 h-7" />
              ) : (
                <Lock className="w-7 h-7" />
              )}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-xl font-bold text-white tracking-tight">
                  Validação de Propriedade do Domínio (Anti-Abuse Core)
                </h2>
                <span className={`px-2.5 py-0.5 text-xs font-semibold rounded-full border ${
                  target.verificationStatus === 'VERIFIED'
                    ? 'bg-emerald-900/60 text-emerald-300 border-emerald-700'
                    : 'bg-amber-900/60 text-amber-300 border-amber-700'
                }`}>
                  {target.verificationStatus === 'VERIFIED' ? '✓ Domínio Verificado' : '⚠ Verificação Obrigatória'}
                </span>
                {target.verificationStatus === 'VERIFIED' && target.verificationMethod === 'SANDBOX_DEMO' && (
                  <span
                    className="px-2.5 py-0.5 text-xs font-semibold rounded-full border bg-rose-950/60 text-rose-300 border-rose-800"
                    title="Este alvo foi marcado como verificado pelo atalho de demonstração — nenhuma checagem criptográfica real foi feita."
                  >
                    ⚡ Sandbox (não criptográfico)
                  </span>
                )}
              </div>
              <p className="text-sm text-[#A1A1AA] mt-1 max-w-2xl leading-relaxed">
                Para prevenir abusos e ataques não autorizados contra terceiros (em conformidade com a LGPD e termos dos provedores de nuvem), o botão de <strong className="text-white">"Iniciar Varredura"</strong> permanece bloqueado até a comprovação criptográfica de controle do domínio.
              </p>
            </div>
          </div>

          {target.verificationStatus === 'VERIFIED' ? (
            <button
              id="btn-go-to-scanner"
              onClick={() => onSelectTab('pipeline')}
              className="px-5 py-2.5 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-black font-extrabold text-sm rounded-xl transition shadow-lg shadow-emerald-500/20 flex items-center justify-center space-x-2 whitespace-nowrap"
            >
              <span>Avançar para Scanner</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          ) : (
            <div className="text-right flex flex-col items-end">
              <span className="text-xs text-amber-400 font-mono flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5" /> Bloqueio Anti-Abuso Ativo
              </span>
              <span className="text-[11px] text-[#71717A] mt-0.5">Scans desabilitados para este alvo</span>
            </div>
          )}
        </div>
      </div>

      {/* Target Details Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Method Selector & Instructions */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 shadow-sm">
            <h3 className="text-base font-bold text-white mb-4 flex items-center space-x-2">
              <span>Escolha o Método de Validação</span>
            </h3>

            {/* Methods Tabs */}
            <div className="grid grid-cols-3 gap-3 mb-6">
              {[
                { id: 'DNS_TXT' as VerificationMethod, label: 'Registro DNS TXT', sub: 'Recomendado (Produção)', icon: Globe },
                { id: 'HTTP_FILE' as VerificationMethod, label: 'Arquivo .well-known', sub: 'Upload no Servidor Web', icon: FileCode2 },
                { id: 'HTML_META' as VerificationMethod, label: 'Tag HTML Meta', sub: 'Inserção na tag <head>', icon: Terminal }
              ].map(m => {
                const Icon = m.icon;
                const isSel = selectedMethod === m.id;
                return (
                  <button
                    key={m.id}
                    onClick={() => {
                      setSelectedMethod(m.id);
                      setCheckResult(null);
                    }}
                    className={`p-3.5 rounded-xl text-left border transition ${
                      isSel 
                        ? 'bg-[#1C1C1F] border-cyan-500 ring-1 ring-cyan-500/40 text-white' 
                        : 'bg-[#0E0E10] border-[#262626] text-[#A1A1AA] hover:border-[#3F3F46] hover:text-[#E4E4E7]'
                    }`}
                  >
                    <Icon className={`w-5 h-5 mb-2 ${isSel ? 'text-cyan-400' : 'text-[#71717A]'}`} />
                    <div className="font-semibold text-xs sm:text-sm text-[#E4E4E7]">{m.label}</div>
                    <div className="text-[11px] text-[#71717A] mt-0.5">{m.sub}</div>
                  </button>
                );
              })}
            </div>

            {/* Specific Instructions based on method */}
            {selectedMethod === 'DNS_TXT' && (
              <div className="space-y-4 bg-[#0E0E10] border border-[#262626] rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Passo a Passo DNS TXT</span>
                  <span className="text-xs text-[#71717A] font-mono">TTL sugerido: 300s (5min)</span>
                </div>
                <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed">
                  Acesse o painel do seu provedor de DNS (Cloudflare, Route 53, Registro.br, GoDaddy) e crie o seguinte registro TXT:
                </p>

                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                      <span>Nome / Host do Registro:</span>
                      <button 
                        onClick={() => copyToClipboard(dnsHost, 'host')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedKey === 'host' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'host' ? 'Copiado' : 'Copiar'}</span>
                      </button>
                    </div>
                    <div className="bg-[#161618] border border-[#262626] rounded-lg p-2.5 font-mono text-xs sm:text-sm text-cyan-300 break-all select-all">
                      {dnsHost}
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                      <span>Tipo:</span>
                    </div>
                    <div className="bg-[#161618] border border-[#262626] rounded-lg p-2.5 font-mono text-xs sm:text-sm text-[#E4E4E7]">
                      TXT
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                      <span>Valor do Registro (Token de Verificação):</span>
                      <button 
                        onClick={() => copyToClipboard(token, 'token')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedKey === 'token' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'token' ? 'Copiado' : 'Copiar'}</span>
                      </button>
                    </div>
                    <div className="bg-[#161618] border border-[#262626] rounded-lg p-2.5 font-mono text-xs sm:text-sm text-amber-300 break-all select-all">
                      {token}
                    </div>
                  </div>
                </div>

                {/* CLI Dig preview */}
                <div className="mt-3 pt-3 border-t border-[#262626]">
                  <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                    <span className="flex items-center gap-1 font-mono text-[#A1A1AA]">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Teste local via Terminal:
                    </span>
                    <button 
                      onClick={() => copyToClipboard(digCommand, 'dig')}
                      className="text-[#A1A1AA] hover:text-white"
                    >
                      {copiedKey === 'dig' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                  <pre className="bg-[#161618] text-[#E4E4E7] text-xs p-2.5 rounded font-mono overflow-x-auto border border-[#262626]">
                    {digCommand}
                  </pre>
                </div>
              </div>
            )}

            {selectedMethod === 'HTTP_FILE' && (
              <div className="space-y-4 bg-[#0E0E10] border border-[#262626] rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Passo a Passo Arquivo HTTP</span>
                  <span className="text-xs text-[#71717A] font-mono">Status HTTP 200 OK</span>
                </div>
                <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed">
                  Crie um arquivo de texto no diretório público do seu servidor web no caminho <code className="text-cyan-300">/.well-known/aegis-verify.txt</code> contendo exclusivamente o token.
                </p>

                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                      <span>URL Pública Esperada:</span>
                      <button 
                        onClick={() => copyToClipboard(httpFileUrl, 'url')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedKey === 'url' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'url' ? 'Copiado' : 'Copiar'}</span>
                      </button>
                    </div>
                    <div className="bg-[#161618] border border-[#262626] rounded-lg p-2.5 font-mono text-xs sm:text-sm text-cyan-300 break-all select-all">
                      {httpFileUrl}
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                      <span>Conteúdo do Arquivo:</span>
                      <button 
                        onClick={() => copyToClipboard(token, 'token-file')}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                      >
                        {copiedKey === 'token-file' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedKey === 'token-file' ? 'Copiado' : 'Copiar'}</span>
                      </button>
                    </div>
                    <div className="bg-[#161618] border border-[#262626] rounded-lg p-2.5 font-mono text-xs sm:text-sm text-amber-300">
                      {token}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {selectedMethod === 'HTML_META' && (
              <div className="space-y-4 bg-[#0E0E10] border border-[#262626] rounded-xl p-5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Passo a Passo HTML Meta Tag</span>
                </div>
                <p className="text-xs sm:text-sm text-[#A1A1AA] leading-relaxed">
                  Adicione a seguinte meta tag dentro da seção <code className="text-cyan-300">&lt;head&gt;</code> da página inicial do seu site ({target.url}):
                </p>

                <div>
                  <div className="flex justify-between items-center text-xs text-[#A1A1AA] mb-1">
                    <span>Meta Tag:</span>
                    <button 
                      onClick={() => copyToClipboard(metaTag, 'meta')}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                    >
                      {copiedKey === 'meta' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey === 'meta' ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                  <div className="bg-[#161618] border border-[#262626] rounded-lg p-2.5 font-mono text-xs text-cyan-300 break-all select-all">
                    {metaTag}
                  </div>
                </div>
              </div>
            )}

            {/* Check Buttons */}
            <div className="mt-6 flex flex-wrap gap-3">
              <button
                id="btn-verify-domain-live"
                onClick={() => handleVerifyCheck(false)}
                disabled={isChecking}
                className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-black font-extrabold text-sm rounded-xl transition flex items-center space-x-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
              >
                {isChecking ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Consultando Servidores DNS...</span>
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    <span>Verificar Registro Agora</span>
                  </>
                )}
              </button>

              <button
                id="btn-simulate-verify"
                onClick={() => handleVerifyCheck(true)}
                disabled={isChecking}
                className="px-4 py-2.5 bg-[#1C1C1F] hover:bg-[#27272A] text-[#E4E4E7] text-sm font-medium rounded-xl border border-[#27272A] transition flex items-center space-x-2 shadow-sm"
                title="Chama o backend com o atalho de demonstração — só funciona se ALLOW_DEMO_VERIFICATION=true estiver configurado no servidor. Grava o método como SANDBOX_DEMO, nunca como uma validação criptográfica real."
              >
                <span>⚡ Simular Sucesso (Modo Sandbox — requer ALLOW_DEMO_VERIFICATION=true)</span>
              </button>
            </div>

            {/* Result Box */}
            {checkResult && (
              <div className={`mt-5 p-4 rounded-xl border text-sm ${
                checkResult.success 
                  ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300' 
                  : 'bg-rose-950/60 border-rose-500/40 text-rose-300'
              }`}>
                <div className="flex items-start space-x-3">
                  {checkResult.success ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <div className="space-y-1">
                    <div className="font-semibold">{checkResult.message}</div>
                    {checkResult.details && (
                      <pre className="text-[11px] bg-[#0A0A0B] p-2 rounded text-[#E4E4E7] font-mono mt-2 overflow-x-auto border border-[#262626]">
                        {JSON.stringify(checkResult.details, null, 2)}
                      </pre>
                    )}
                    {checkResult.error && (
                      <div className="text-xs text-rose-400/80 font-mono mt-1">
                        Código de Erro: {checkResult.error}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Security & Anti-Abuse Specifications */}
        <div className="space-y-6">
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span>Por que a verificação é mandatória?</span>
            </h3>

            <div className="space-y-3 text-xs text-[#E4E4E7] leading-relaxed">
              <div className="p-3.5 bg-[#0E0E10] rounded-xl border border-[#262626]">
                <div className="font-semibold text-white mb-1">1. Prevenção de Ataques Cibernéticos Ilegais</div>
                <p className="text-[#A1A1AA]">
                  Ferramentas de DAST ativas injetam payloads reais (SQLi, XSS, SSRF). Sem a validação de posse, um atacante poderia usar o SaaS como vetor de ataque contra sites de concorrentes ou órgãos governamentais.
                </p>
              </div>

              <div className="p-3.5 bg-[#0E0E10] rounded-xl border border-[#262626]">
                <div className="font-semibold text-white mb-1">2. Termos de Uso de Provedores Cloud (AWS / GCP / Cloudflare)</div>
                <p className="text-[#A1A1AA]">
                  Provedores de infraestrutura exigem que qualquer plataforma de segurança automatizada garanta autorização formal por escrito ou técnica antes de emitir tráfego invasivo de teste.
                </p>
              </div>

              <div className="p-3.5 bg-[#0E0E10] rounded-xl border border-[#262626]">
                <div className="font-semibold text-white mb-1">3. Token Criptográfico com Expiração</div>
                <p className="text-[#A1A1AA]">
                  O token gerado (<code className="text-cyan-300">{token.slice(0, 15)}...</code>) é assinado com HMAC-SHA256 e vinculado ao ID da Organização para evitar usurpação de domínios.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
