// Único dono do cliente Upstash no lado Node — mesmo desenho de "uma camada,
// um dono" já usado para IA (server/ai*) e persistência local (server/db.ts).
// server/queue.ts (fila de scans) e server/targetsStore.ts (targets) importam
// daqui em vez de cada um instanciar seu próprio cliente Redis.
import { Redis } from '@upstash/redis';

export function isRedisConfigured(): boolean {
  return !!(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);
}

let client: Redis | null = null;
export function getRedisClient(): Redis {
  if (!client) {
    client = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL!,
      token: process.env.UPSTASH_REDIS_REST_TOKEN!
    });
  }
  return client;
}
