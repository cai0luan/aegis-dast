// Camada de persistência do AegisDAST.
//
// Este projeto roda num ambiente sandbox sem Postgres/Docker provisionados, então
// a persistência real usa um arquivo JSON local em vez do schema PostgreSQL
// descrito em ArchitectureDocView/mockSecurityData — aquele DDL continua sendo o
// alvo de produção documentado, este arquivo é o que roda hoje. Isso substitui os
// arrays em memória que o frontend usava antes (INITIAL_TARGETS etc. eram
// perdidos a cada reload); agora targets/scans sobrevivem a restarts do processo.
//
// A ONDE esse arquivo mora depende do ambiente, e isso é o ponto central deste
// módulo:
//   - Dev local / self-host: ./data/aegis-db.json, ao lado do código — sobrevive
//     a restarts do processo indefinidamente, como qualquer arquivo em disco.
//   - Vercel: o diretório do projeto é somente-leitura em runtime (gravar ali
//     lançaria EROFS), então usamos /tmp, que a Vercel garante gravável. Mas
//     /tmp É EFÊMERO DE VERDADE ali — pode sumir a qualquer cold start, e duas
//     invocações concorrentes podem cair em instâncias diferentes com /tmp's
//     diferentes. Isto não é "quase tão bom quanto um banco": é estado que dura,
//     na prática, "enquanto a mesma instância ficar quente" — nada mais.
//     Não existe hoje um caminho para persistência de verdade (cross-instância)
//     na Vercel sem introduzir um serviço externo (Postgres/KV/Redis), o que é
//     uma decisão de infraestrutura própria, não algo que este arquivo decide
//     sozinho. Rodar com esse grau de efemeridade é o estado suportado hoje.
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { TargetDomain, ScanJob } from '../src/types';
import { INITIAL_TARGETS } from '../src/data/mockSecurityData.js';

const IS_VERCEL = !!process.env.VERCEL;
// os.tmpdir() em vez de um literal '/tmp': na Vercel (Linux) resolve para /tmp,
// que é o diretório gravável documentado da função — mas usar a API do Node em
// vez do caminho Unix cravado também deixa isto testável neste Windows local
// (onde '/tmp' não existe e não é gravável na raiz de C:\), sem mudar o
// comportamento real em produção.
const DATA_DIR = IS_VERCEL ? path.join(os.tmpdir(), 'aegis-dast-data') : path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'aegis-db.json');

interface DbShape {
  targets: TargetDomain[];
  scans: ScanJob[];
}

function seedDb(): DbShape {
  // Os 3 alvos de demonstração do mockSecurityData continuam aqui só para a UI
  // não abrir vazia na primeira execução — são dados de exemplo, não alvos reais.
  return {
    targets: INITIAL_TARGETS.map(t => ({ ...t })),
    scans: []
  };
}

function loadDb(): DbShape {
  if (!fs.existsSync(DB_FILE)) {
    const seeded = seedDb();
    persist(seeded);
    return seeded;
  }
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<DbShape>;
    return {
      targets: Array.isArray(parsed.targets) ? parsed.targets : [],
      scans: Array.isArray(parsed.scans) ? parsed.scans : []
    };
  } catch (err) {
    console.error('[db] Falha ao ler aegis-db.json, reiniciando com seed padrão:', err);
    const seeded = seedDb();
    persist(seeded);
    return seeded;
  }
}

function persist(db: DbShape) {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
}

// Estado em memória + escrita síncrona em disco a cada mutação. Suficiente para o
// volume de um piloto/demo; uma carga real de produção trocaria isto por Postgres
// (o schema já documentado em POSTGRESQL_SCHEMA_DDL) sem mudar a API deste módulo.
let db: DbShape = loadDb();

export function listTargets(): TargetDomain[] {
  return db.targets;
}

export function getTarget(id: string): TargetDomain | undefined {
  return db.targets.find(t => t.id === id);
}

export function createTarget(target: TargetDomain): TargetDomain {
  db.targets.unshift(target);
  persist(db);
  return target;
}

export function updateTarget(id: string, patch: Partial<TargetDomain>): TargetDomain | undefined {
  const idx = db.targets.findIndex(t => t.id === id);
  if (idx === -1) return undefined;
  db.targets[idx] = { ...db.targets[idx], ...patch };
  persist(db);
  return db.targets[idx];
}

export function listScans(targetId?: string): ScanJob[] {
  const all = [...db.scans].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return targetId ? all.filter(s => s.targetId === targetId) : all;
}

export function getScan(id: string): ScanJob | undefined {
  return db.scans.find(s => s.id === id);
}

export function createScan(scan: ScanJob): ScanJob {
  db.scans.unshift(scan);
  persist(db);
  return scan;
}

export function updateScan(id: string, patch: Partial<ScanJob>): ScanJob | undefined {
  const idx = db.scans.findIndex(s => s.id === id);
  if (idx === -1) return undefined;
  db.scans[idx] = { ...db.scans[idx], ...patch };
  persist(db);
  return db.scans[idx];
}
