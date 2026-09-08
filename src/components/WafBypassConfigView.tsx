import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Copy, 
  Check, 
  Lock, 
  Server, 
  Globe, 
  Sliders, 
  Gauge, 
  RefreshCw, 
  Flame, 
  Cloud,
  FileCode2
} from 'lucide-react';
import { STATIC_EGRESS_IPS } from '../data/mockSecurityData';
import { TargetDomain } from '../types';

interface WafBypassConfigViewProps {
  target: TargetDomain | null;
}

export const WafBypassConfigView: React.FC<WafBypassConfigViewProps> = ({ target }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [rateLimit, setRateLimit] = useState(15);
  const [concurrency, setConcurrency] = useState(5);
  const [autoBackoff, setAutoBackoff] = useState(true);

  const domain = target?.domain || 'app.fintech-pay.com.br';
  const headerName = 'X-Aegis-Scan-Authorization';
  const headerValue = `Bearer aegis_sec_auth_${(target?.verificationToken || 'aegis_key_prod_991').slice(0, 24)}`;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const cloudflareRule = `(http.request.headers["${headerName}"][0] eq "${headerValue}") or (ip.src in {${STATIC_EGRESS_IPS.join(' ')}})`;

  const awsWafJson = JSON.stringify({
    Name: 'AllowAegisSecurityScanner',
    Priority: 0,
    Action: { Allow: {} },
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: 'AegisScanAllow'
    },
    Statement: {
      OrStatement: {
        Statements: [
          {
            ByteMatchStatement: {
              SearchString: headerValue,
              FieldToMatch: { SingleHeader: { Name: headerName.toLowerCase() } },
              TextTransformations: [{ Priority: 0, Type: 'NONE' }],
              PositionalConstraint: 'EXACTLY'
            }
          },
          {
            IPSetReferenceStatement: {
              ARN: 'arn:aws:wafv2:us-east-1:123456789012:regional/ipset/AegisScannerIPs'
            }
          }
        ]
      }
    }
  }, null, 2);

  const nginxSnippet = `# /etc/nginx/conf.d/aegis-allowlist.conf
geo $is_aegis_scanner {
    default 0;
    ${STATIC_EGRESS_IPS.map(ip => `${ip}/32 1;`).join('\n    ')}
}

# Bypass rate limiting and block rules if authorized
if ($http_x_aegis_scan_authorization = "${headerValue}") {
    set $is_aegis_scanner 1;
}

# Example limit_req bypass
limit_req_whitelist $is_aegis_scanner;`;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner */}
      <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 relative overflow-hidden shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-3 bg-gradient-to-tr from-cyan-600 to-teal-600 rounded-xl text-white shadow-lg shadow-cyan-500/20">
              <Cloud className="w-7 h-7" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                Controles de WAF/CDN & Salvaguardas de Produção
              </h2>
              <p className="text-xs sm:text-sm text-[#A1A1AA] mt-1 max-w-3xl leading-relaxed">
                Configure a passagem legítima para o scanner através de <strong className="text-[#E4E4E7]">Cabeçalhos de Autorização Criptográficos</strong> e <strong className="text-[#E4E4E7]">IPs Estáticos de Egress</strong>, evitando falsos bloqueios e garantindo estabilidade via Rate Limiting.
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Column: WAF / Allowlist Rules Generator */}
        <div className="space-y-6">
          {/* Header & Egress IPs Card */}
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center justify-between">
              <span>1. Credenciais de Egress & Cabeçalho Seguro</span>
              <Lock className="w-4 h-4 text-cyan-400" />
            </h3>

            {/* Custom Header */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-[#A1A1AA]">
                <span>Cabeçalho HTTP de Autorização:</span>
                <button
                  onClick={() => copyToClipboard(`${headerName}: ${headerValue}`, 'header')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
                >
                  {copiedKey === 'header' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'header' ? 'Copiado' : 'Copiar Par'}</span>
                </button>
              </div>
              <div className="bg-[#0A0A0B] border border-[#262626] rounded-lg p-3 font-mono text-xs text-cyan-300 break-all select-all">
                <span className="text-[#71717A]">{headerName}:</span> {headerValue}
              </div>
            </div>

            {/* Static Egress IPs */}
            <div className="space-y-1.5 pt-2 border-t border-[#262626]">
              <div className="flex items-center justify-between text-xs text-[#A1A1AA]">
                <span>IPs Estáticos de Egress (Nossos Scanners):</span>
                <button
                  onClick={() => copyToClipboard(STATIC_EGRESS_IPS.join('\n'), 'ips')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
                >
                  {copiedKey === 'ips' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey === 'ips' ? 'Copiado' : 'Copiar Todos'}</span>
                </button>
              </div>
              <div className="grid grid-cols-2 gap-2">
                {STATIC_EGRESS_IPS.map((ip) => (
                  <div key={ip} className="bg-[#0E0E10] border border-[#262626] rounded-lg p-2 font-mono text-xs text-[#E4E4E7] flex items-center justify-between">
                    <span>{ip}</span>
                    <span className="text-[10px] text-emerald-400 font-semibold">/32</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Cloudflare & AWS WAF Configuration Presets */}
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 space-y-4 shadow-sm">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <FileCode2 className="w-4 h-4 text-cyan-400" />
              <span>Regras Prontas para Cloudflare / AWS / Nginx</span>
            </h3>

            {/* Cloudflare Rule */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs text-[#A1A1AA]">
                <span className="font-semibold text-[#E4E4E7]">Cloudflare Custom Rule (Expression):</span>
                <button
                  onClick={() => copyToClipboard(cloudflareRule, 'cf')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
                >
                  {copiedKey === 'cf' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar</span>
                </button>
              </div>
              <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-lg text-xs font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap">
                {cloudflareRule}
              </pre>
            </div>

            {/* Nginx snippet */}
            <div className="space-y-1.5 pt-2 border-t border-[#262626]">
              <div className="flex items-center justify-between text-xs text-[#A1A1AA]">
                <span className="font-semibold text-[#E4E4E7]">Nginx Allowlist Snippet:</span>
                <button
                  onClick={() => copyToClipboard(nginxSnippet, 'nginx')}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
                >
                  {copiedKey === 'nginx' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>Copiar</span>
                </button>
              </div>
              <pre className="p-3 bg-[#0A0A0B] border border-[#262626] rounded-lg text-[11px] font-mono text-[#E4E4E7] overflow-x-auto">
                {nginxSnippet}
              </pre>
            </div>
          </div>
        </div>

        {/* Right Column: Rate Limiting & Production Impact Controls */}
        <div className="space-y-6">
          <div className="bg-[#161618] border border-[#262626] rounded-2xl p-6 space-y-5 shadow-sm">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center justify-between">
              <span>2. Proteção Anti-DoS & Limites de Taxa</span>
              <Gauge className="w-4 h-4 text-cyan-400" />
            </h3>

            {/* Rate Limiting Slider */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold text-white">Taxa Máxima de Requisições (RPS)</span>
                  <p className="text-[11px] text-[#A1A1AA]">Controla o throughput de envio do Nuclei e OWASP ZAP</p>
                </div>
                <span className="px-3 py-1 bg-cyan-950/80 border border-cyan-800 text-cyan-300 font-mono font-bold text-sm rounded-lg">
                  {rateLimit} req/s
                </span>
              </div>

              <input
                type="range"
                min="1"
                max="100"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                className="w-full h-2 bg-[#0E0E10] rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />

              <div className="flex justify-between text-[10px] text-[#71717A] font-mono">
                <span>1 req/s (Ultra Seguro)</span>
                <span>15 req/s (Recomendado)</span>
                <span>100 req/s (Ambiente Dev/Staging)</span>
              </div>
            </div>

            {/* Concurrency Threads */}
            <div className="space-y-3 pt-3 border-t border-[#262626]">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-semibold text-white">Concorrência de Threads</span>
                  <p className="text-[11px] text-[#A1A1AA]">Número de conexões TCP paralelas simultâneas</p>
                </div>
                <span className="px-3 py-1 bg-[#0E0E10] border border-[#262626] text-[#E4E4E7] font-mono font-bold text-sm rounded-lg">
                  {concurrency} threads
                </span>
              </div>

              <input
                type="range"
                min="1"
                max="20"
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                className="w-full h-2 bg-[#0E0E10] rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>

            {/* Auto Adaptive Backoff Toggle */}
            <div className="pt-3 border-t border-[#262626]">
              <label className="flex items-start space-x-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoBackoff}
                  onChange={(e) => setAutoBackoff(e.target.checked)}
                  className="mt-1 rounded bg-[#0E0E10] border-[#27272A] text-cyan-500 focus:ring-0"
                />
                <div className="space-y-0.5">
                  <span className="text-xs font-semibold text-white">Adaptive Exponential Backoff Ativo</span>
                  <p className="text-[11px] text-[#A1A1AA] leading-relaxed">
                    Caso a aplicação alvo responda com código <strong className="text-amber-300">429</strong> ou tempo de resposta &gt; 3000ms, o worker reduz automaticamente a velocidade pela metade para não degradar a experiência de usuários reais em produção.
                  </p>
                </div>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
