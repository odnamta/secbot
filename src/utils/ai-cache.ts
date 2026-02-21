import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export interface AICacheOptions {
  cacheDir?: string;
  ttlMs?: number;
}

interface CacheEntry {
  createdAt: string;
  ttlMs: number;
  value: string;
}

const DEFAULT_TTL_MS = 86_400_000; // 24 hours

export class AICache {
  readonly cacheDir: string;
  readonly ttlMs: number;

  constructor(options: AICacheOptions = {}) {
    this.cacheDir = options.cacheDir ?? join(homedir(), '.secbot', 'cache');
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  }

  /**
   * Generate a deterministic SHA-256 hash key from arbitrary inputs.
   */
  generateKey(inputs: Record<string, unknown>): string {
    const serialized = JSON.stringify(inputs, Object.keys(inputs).sort());
    return createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Read a cached response if it exists and hasn't expired.
   * Expired entries are lazily deleted on read.
   */
  async get(key: string): Promise<string | null> {
    const filePath = join(this.cacheDir, `${key}.json`);

    if (!existsSync(filePath)) {
      return null;
    }

    try {
      const raw = readFileSync(filePath, 'utf-8');
      const entry: CacheEntry = JSON.parse(raw);

      const age = Date.now() - new Date(entry.createdAt).getTime();
      if (age > entry.ttlMs) {
        // Expired — lazy cleanup
        try {
          unlinkSync(filePath);
        } catch {
          // Ignore cleanup errors
        }
        return null;
      }

      return entry.value;
    } catch {
      // Corrupt file — treat as miss
      return null;
    }
  }

  /**
   * Write a response to the cache.
   * Auto-creates the cache directory if it doesn't exist.
   */
  async set(key: string, value: string): Promise<void> {
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true });
    }

    const entry: CacheEntry = {
      createdAt: new Date().toISOString(),
      ttlMs: this.ttlMs,
      value,
    };

    const filePath = join(this.cacheDir, `${key}.json`);
    writeFileSync(filePath, JSON.stringify(entry, null, 2), 'utf-8');
  }
}
