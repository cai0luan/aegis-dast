// Persistência de targets no Upstash — usado por server/targets.ts (a fachada
// que routes.ts e scanOrchestrator.ts realmente importam) quando
// isRedisConfigured() é true. Nunca toca o sistema de arquivos: só HTTP para o
// Upstash, então nada aqui pode disparar EROFS no diretório somente-leitura da
// função da Vercel.
//
//   SADD aegis_targets <id>      -- índice de todos os ids existentes
//   HSET target:<id> data=<json> -- o TargetDomain inteiro, serializado
import { getRedisClient } from './redisClient';
import type { TargetDomain } from '../src/types';

const TARGETS_SET_KEY = 'aegis_targets';

function targetKey(id: string): string {
  return `target:${id}`;
}

async function readTarget(id: string): Promise<TargetDomain | null> {
  const redis = getRedisClient();
  const fields = await redis.hgetall<{ data?: string }>(targetKey(id));
  if (!fields || !fields.data) return null;
  return typeof fields.data === 'string' ? JSON.parse(fields.data) : (fields.data as unknown as TargetDomain);
}

async function writeTarget(target: TargetDomain): Promise<void> {
  const redis = getRedisClient();
  await Promise.all([
    redis.sadd(TARGETS_SET_KEY, target.id),
    redis.hset(targetKey(target.id), { data: JSON.stringify(target) })
  ]);
}

export async function listTargetsRedis(): Promise<TargetDomain[]> {
  const redis = getRedisClient();
  const ids = await redis.smembers(TARGETS_SET_KEY);
  if (!ids || ids.length === 0) return [];
  const targets = await Promise.all(ids.map(id => readTarget(id)));
  return targets.filter((t): t is TargetDomain => t !== null);
}

export async function getTargetRedis(id: string): Promise<TargetDomain | undefined> {
  const target = await readTarget(id);
  return target ?? undefined;
}

export async function createTargetRedis(target: TargetDomain): Promise<TargetDomain> {
  await writeTarget(target);
  return target;
}

export async function updateTargetRedis(id: string, patch: Partial<TargetDomain>): Promise<TargetDomain | undefined> {
  const existing = await readTarget(id);
  if (!existing) return undefined;
  const updated = { ...existing, ...patch };
  await writeTarget(updated);
  return updated;
}
