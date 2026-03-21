import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { log } from '../utils/logger.js';

/**
 * Config file shape — all fields optional.
 * CLI args override config file values.
 */
export interface SecbotConfig {
  target?: string;
  profile?: 'quick' | 'standard' | 'deep';
  auth?: string;
  format?: string;
  output?: string;
  scope?: string;
  excludeChecks?: string[];
  maxPages?: number;
  timeout?: number;
  ignoreRobots?: boolean;
  logRequests?: boolean;
  noAi?: boolean;
  callbackUrl?: string;
  rateLimit?: number;
  baseline?: string;
  proxy?: string;
  /** Per-domain rate limits. Keys are domain patterns (e.g. "*.hackerone.com"), values are RPS. Use "default" for fallback. */
  rateLimits?: Record<string, number>;
  /** Custom plugin directory. Default: ~/.secbot/plugins/ */
  pluginDir?: string;
}

const CONFIG_FILE_NAMES = ['.secbotrc.json', 'secbot.config.json'] as const;

/**
 * Loads a SecBot config file from the current working directory.
 *
 * Search order:
 *   1. .secbotrc.json
 *   2. secbot.config.json
 *   3. package.json → "secbot" key
 *
 * Returns the parsed config object, or null if no config file is found.
 */
export function loadConfigFile(cwd?: string): SecbotConfig | null {
  const dir = cwd ?? process.cwd();

  // Try dedicated config files first
  for (const name of CONFIG_FILE_NAMES) {
    const filePath = resolve(dir, name);
    if (existsSync(filePath)) {
      try {
        const raw = readFileSync(filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        log.info(`Loaded config from ${name}`);
        return parsed as SecbotConfig;
      } catch (err) {
        console.error(`Error: Config file ${name} is invalid JSON: ${(err as Error).message}`);
        console.error('Fix the config file or delete it to use defaults.');
        process.exit(2);
      }
    }
  }

  // Try package.json "secbot" key
  const pkgPath = resolve(dir, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const raw = readFileSync(pkgPath, 'utf-8');
      const pkg = JSON.parse(raw);
      if (pkg.secbot && typeof pkg.secbot === 'object') {
        log.info('Loaded config from package.json "secbot" key');
        return pkg.secbot as SecbotConfig;
      }
    } catch (err) {
      console.error(`Error: package.json is invalid JSON: ${(err as Error).message}`);
      console.error('Fix the package.json or remove the "secbot" key to use defaults.');
      process.exit(2);
    }
  }

  return null;
}
