// Camada de triagem por IA (Gemini). Extraído de server.ts para ser reutilizável
// tanto pela rota HTTP /api/ai/triage (chamada manual pela UI) quanto pelo
// scanOrchestrator (Etapa 3 do pipeline, automática ao fim de cada scan).
import { GoogleGenAI } from '@google/genai';
import type { Vulnerability } from '../src/types';

let aiClient: GoogleGenAI | null = null;
function getAiClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: { headers: { 'User-Agent': 'aistudio-build' } }
    });
  }
  return aiClient;
}

export function isAiConfigured(): boolean {
  return !!process.env.GEMINI_API_KEY;
}

export interface TriageResult {
  isFalsePositive: boolean;
  confidenceScore: number;
  reasoning: string;
  executiveSummaryText: string;
  recommendedMitigation: string;
  usedRealModel: boolean;
}

function heuristicFallback(vuln: Partial<Vulnerability>): TriageResult {
  return {
    isFalsePositive: false,
    confidenceScore: vuln.aiConfidenceScore ?? 90,
    reasoning: vuln.aiTriageReasoning || 'Modelo de IA indisponível no momento; mantendo a classificação heurística do motor de correlação.',
    executiveSummaryText: `A vulnerabilidade "${vuln.title || 'identificada'}" foi mantida com a classificação original do motor de correlação (IA indisponível para nova triagem).`,
    recommendedMitigation: vuln.remediation?.recommendation || 'Consulte a documentação OWASP para o tipo de falha identificado.',
    usedRealModel: false
  };
}

export async function triageVulnerability(
  vulnerability: Partial<Vulnerability>,
  targetDomain: string,
  rawHttpTrace?: string
): Promise<TriageResult> {
  const ai = getAiClient();
  if (!ai) return heuristicFallback(vulnerability);

  const prompt = `Você é um Engenheiro de Cibersegurança Sênior especialista em Offensive Security e DAST.
Analise a seguinte vulnerabilidade detectada por scanner automatizado e determine se é um FALSO POSITIVO ou uma VULNERABILIDADE CONFIRMADA.

Alvo: ${targetDomain}
Vulnerabilidade: ${JSON.stringify(vulnerability, null, 2)}
Trace HTTP: ${rawHttpTrace || 'Não fornecido'}

Responda ESTRITAMENTE em formato JSON com o seguinte schema:
{
  "isFalsePositive": boolean,
  "confidenceScore": number (0 a 100),
  "reasoning": string (explicação técnica detalhada em português com análise do vetor de ataque),
  "executiveSummaryText": string (resumo executivo claro sem jargões para diretores/C-Level),
  "recommendedMitigation": string (passo a passo para desenvolvedores corrigirem)
}`;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: { responseMimeType: 'application/json', temperature: 0.2 }
    });
    const parsed = JSON.parse(response.text || '{}');
    return { ...parsed, usedRealModel: true };
  } catch (err) {
    console.error('[AI Triage] Falha na chamada ao Gemini:', err);
    return heuristicFallback(vulnerability);
  }
}
