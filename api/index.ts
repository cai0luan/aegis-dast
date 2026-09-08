// Entrypoint da Vercel Serverless Function. Nenhuma rota vive aqui — apenas
// registra o mesmo registerRoutes(app) que server.ts usa em dev local (ver o
// comentário lá para o porquê disso ser inegociável). Sem Vite, sem app.listen:
// a Vercel invoca o app Express exportado diretamente como handler HTTP (um app
// Express já é uma função (req, res) => void, então não precisa de nenhum
// adaptador extra nem da dependência @vercel/node só para isto).
//
// vercel.json reescreve todo /api/* para cá — é por isso que req.path continua
// batendo com as rotas de routes.ts (ex: /api/targets) mesmo só existindo este
// arquivo em api/: uma rewrite muda QUAL função a Vercel invoca, não a URL que a
// função enxerga.
import 'dotenv/config';
import express from 'express';
import { registerRoutes } from '../server/routes';

const app = express();
registerRoutes(app);

export default app;
