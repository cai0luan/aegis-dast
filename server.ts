// O pacote "dotenv" já era uma dependência declarada, mas nunca era importado —
// fora do runtime da AI Studio (que injeta as env vars diretamente), o .env local
// era silenciosamente ignorado e GEMINI_API_KEY/ALLOW_DEMO_VERIFICATION nunca chegavam.
import 'dotenv/config';
import express, { Request, Response } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { registerRoutes } from './server/routes.js';
import { isAiConfigured } from './server/aiTriage.js';
import { isSandboxDemoAllowed } from './server/domainVerification.js';

const PORT = Number(process.env.PORT) || 3000;

// Entrypoint de DEV LOCAL / self-host fora da Vercel. Todas as rotas vêm de
// server/routes.ts — este arquivo só monta o transporte (Vite em dev, estático
// em produção self-hospedada) em volta delas. O entrypoint da Vercel
// (api/index.ts) chama exatamente a mesma registerRoutes(app); nenhuma rota deve
// ser adicionada aqui que não exista lá, nem vice-versa.
async function startServer() {
  const app = express();
  registerRoutes(app);

  // Vite middleware setup
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AegisDAST] Server running on http://localhost:${PORT}`);
    console.log(`[AegisDAST] AI Triage: ${isAiConfigured() ? 'Gemini real (chave configurada)' : 'fallback heurístico (GEMINI_API_KEY ausente)'}`);
    console.log(`[AegisDAST] Verificação sandbox: ${isSandboxDemoAllowed() ? 'HABILITADA (ALLOW_DEMO_VERIFICATION=true)' : 'desabilitada'}`);
  });
}

startServer();
