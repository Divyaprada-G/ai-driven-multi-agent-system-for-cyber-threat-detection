import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema.ts';

declare global {
  var _postgresPool: Pool | undefined;
}

export const isDbConfigured = (): boolean => {
  return Boolean(
    process.env.SQL_HOST &&
    process.env.SQL_DB_NAME &&
    process.env.SQL_USER &&
    process.env.SQL_PASSWORD
  );
};

export const createPool = (): Pool | null => {
  if (!isDbConfigured()) {
    return null;
  }
  if (!global._postgresPool) {
    global._postgresPool = new Pool({
      host: process.env.SQL_HOST,
      user: process.env.SQL_USER,
      password: process.env.SQL_PASSWORD,
      database: process.env.SQL_DB_NAME,
      max: 10,
      connectionTimeoutMillis: 5000,
    });

    global._postgresPool.on('error', (err) => {
      console.warn('PostgreSQL pool client notice:', err.message);
    });
  }
  return global._postgresPool;
};

const pool = createPool();

let dbInstance: any;
if (pool) {
  try {
    dbInstance = drizzle(pool, { schema });
  } catch (err) {
    console.warn('[AI Studio] Drizzle connection error — using mock proxy:', err);
  }
}

if (!dbInstance) {
  const noOp = {
    findMany: async () => [],
    findFirst: async () => null,
    findUnique: async () => null,
    create: async (d: any) => d?.data ?? {},
    update: async (d: any) => d?.data ?? {},
    delete: async () => ({}),
  };
  dbInstance = new Proxy({}, {
    get: (_, prop) => {
      if (prop === 'query') return new Proxy({}, { get: () => noOp });
      if (prop === 'execute') return async () => ({ rows: [] });
      if (prop === 'select' || prop === 'insert' || prop === 'update' || prop === 'delete') {
        const chain: any = () => chain;
        chain.from = () => chain;
        chain.where = () => chain;
        chain.values = () => chain;
        chain.set = () => chain;
        chain.orderBy = () => chain;
        chain.limit = () => chain;
        chain.offset = () => chain;
        chain.returning = async () => [];
        chain.onConflictDoNothing = () => chain;
        chain.onConflictDoUpdate = () => chain;
        chain.then = (resolve: any) => Promise.resolve([]).then(resolve);
        return chain;
      }
      return async () => [];
    },
  });
}

export const db = dbInstance;
export { schema, pool };
