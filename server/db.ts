// Camada de persistência do AegisDAST.
//
// Este projeto roda num ambiente sandbox sem Postgres/Docker provisionados, então
// a persistência real usa um arquivo JSON local (data/aegis-db.json) em vez do
// schema PostgreSQL descrito em ArchitectureDocView/mockSecurityData — aquele DDL
// continua sendo o alvo de produção documentado, este arquivo é o que roda hoje.
// Isso substitui os arrays em memória que o frontend usava antes (INITIAL_TARGETS
// etc. eram perdidos a cada reload); agora targets/scans sobrevivem a restarts do
// servidor.
import fs from 'fs';
import path from 'path';
import type { TargetDomain, ScanJob } from '../src/types';
import { INITIAL_TARGETS } from '../src/data/mockSecurityData';

const DATA_DIR = path.join(process.cwd(), 'data');
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
