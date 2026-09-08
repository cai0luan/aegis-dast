// Fila assíncrona sobre o Redis do Upstash — o mecanismo que resolve de vez o
// problema descrito em routes.ts (job em segundo plano + polling não sobrevive a
// uma função serverless congelada após a resposta, porque não havia estado
// compartilhado entre invocações). Agora existe: o Upstash é externo às duas
// pontas, então tanto uma invocação da Vercel quanto o worker Python local em
// worker/worker.py enxergam exatamente o mesmo estado.
//
//   POST /api/scans   -> LPUSH aegis_jobs <ScanJob inicial em JSON>
//                         HSET  scan:<id>  status=QUEUED  job=<mesmo JSON>
//   worker/worker.py  -> RPOP  aegis_jobs, processa, HSET scan:<id> a cada etapa
//   GET  /api/scans/:id -> HGETALL scan:<id>, devolve o campo `job` parseado
//
// Este módulo é o ÚNICO lugar no lado Node que fala com o Upstash — mesmo
// desenho de "uma camada, um dono" já usado para IA (server/ai*) e persistência
// local (server/db.ts). Sem Redis configurado, isRedisConfigured() volta false e
// routes.ts cai para o pipeline síncrono em processo (ver scanOrchestrator.ts) —
// rodar sem fila real é um estado suportado, não um erro, para dev local sem
// depender de credenciais do Upstash nem do worker Python estar de pé.
import { getRedisClient, isRedisConfigured } from './redisClient';
import type { ScanJob } from '../src/types';

export { isRedisConfigured };

const QUEUE_KEY = 'aegis_jobs';
const SCAN_HASH_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 dias — evita crescer o Upstash sem limite

function scanKey(jobId: string): string {
  return `scan:${jobId}`;
}

// Enfileira o job para o worker E já grava o hash inicial, para que um GET
// imediatamente após o POST (antes de qualquer worker pegar o job) encontre o
// registro com status QUEUED em vez de 404.
export async function enqueueScanJob(job: ScanJob): Promise<void> {
  const redis = getRedisClient();
  const payload = JSON.stringify(job);
  await Promise.all([
    redis.lpush(QUEUE_KEY, payload),
    redis.hset(scanKey(job.id), { status: job.status, job: payload }),
    redis.expire(scanKey(job.id), SCAN_HASH_TTL_SECONDS)
  ]);
}

export async function getScanFromRedis(jobId: string): Promise<ScanJob | null> {
  const redis = getRedisClient();
  const fields = await redis.hgetall<{ status?: string; job?: string }>(scanKey(jobId));
  if (!fields || !fields.job) return null;
  // O cliente do Upstash já desserializa valores que parecem JSON automaticamente
  // em alguns casos — cobre os dois formatos (string crua ou já objeto) sem
  // assumir qual delas virá.
  return typeof fields.job === 'string' ? JSON.parse(fields.job) : (fields.job as unknown as ScanJob);
}
