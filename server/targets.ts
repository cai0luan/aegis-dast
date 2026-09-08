// Fachada de targets — o ÚNICO módulo que routes.ts e scanOrchestrator.ts devem
// importar para ler/escrever targets. Decide o backend por isRedisConfigured(),
// exatamente como server/routes.ts já faz para scans:
//
//   Redis configurado    -> server/targetsStore.ts (Upstash, sem tocar disco)
//   Redis NÃO configurado -> server/db.ts (arquivo local em dev, /tmp na Vercel)
//
// Sem esta fachada, dev local (sem Redis) e produção (com Redis) usariam dois
// pares de função com nomes iguais vindos de módulos diferentes espalhados
// pelas rotas — exatamente o tipo de duplicação que gera um caminho testado e
// outro não. Todas as funções são async mesmo quando o backend local é
// síncrono por baixo, para que o chamador nunca precise saber qual dos dois
// está ativo.
import { isRedisConfigured } from './redisClient.js';
import * as localDb from './db.js';
import * as redisStore from './targetsStore.js';
import type { TargetDomain } from '../src/types';

export async function listTargets(): Promise<TargetDomain[]> {
  return isRedisConfigured() ? redisStore.listTargetsRedis() : localDb.listTargets();
}

export async function getTarget(id: string): Promise<TargetDomain | undefined> {
  return isRedisConfigured() ? redisStore.getTargetRedis(id) : localDb.getTarget(id);
}

export async function createTarget(target: TargetDomain): Promise<TargetDomain> {
  return isRedisConfigured() ? redisStore.createTargetRedis(target) : localDb.createTarget(target);
}

export async function updateTarget(id: string, patch: Partial<TargetDomain>): Promise<TargetDomain | undefined> {
  return isRedisConfigured() ? redisStore.updateTargetRedis(id, patch) : localDb.updateTarget(id, patch);
}
