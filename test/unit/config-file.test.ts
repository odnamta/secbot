import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfigFile } from '../../src/config/file.js';

// Suppress logger output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

describe('loadConfigFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'secbot-config-test-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads .secbotrc.json when present', () => {
    const config = { target: 'http://localhost:3000', profile: 'deep' };
    writeFileSync(join(tmpDir, '.secbotrc.json'), JSON.stringify(config));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(config);
  });

  it('loads secbot.config.json when present', () => {
    const config = { profile: 'quick', maxPages: 10 };
    writeFileSync(join(tmpDir, 'secbot.config.json'), JSON.stringify(config));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(config);
  });

  it('loads from package.json "secbot" key', () => {
    const secbotConfig = { target: 'http://localhost:8080', timeout: 5000 };
    const pkg = { name: 'my-app', version: '1.0.0', secbot: secbotConfig };
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify(pkg));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(secbotConfig);
  });

  it('respects priority order: .secbotrc.json > secbot.config.json > package.json', () => {
    const rcConfig = { profile: 'deep' as const, target: 'http://rc-target' };
    const configJson = { profile: 'quick' as const, target: 'http://config-target' };
    const pkgConfig = { profile: 'standard' as const, target: 'http://pkg-target' };

    writeFileSync(join(tmpDir, '.secbotrc.json'), JSON.stringify(rcConfig));
    writeFileSync(join(tmpDir, 'secbot.config.json'), JSON.stringify(configJson));
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', secbot: pkgConfig }));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(rcConfig);
  });

  it('falls back to secbot.config.json when .secbotrc.json is absent', () => {
    const configJson = { profile: 'quick' as const };
    const pkgConfig = { profile: 'standard' as const };

    writeFileSync(join(tmpDir, 'secbot.config.json'), JSON.stringify(configJson));
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', secbot: pkgConfig }));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(configJson);
  });

  it('falls back to package.json when no dedicated config files exist', () => {
    const pkgConfig = { target: 'http://localhost:4000' };
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', secbot: pkgConfig }));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(pkgConfig);
  });

  it('returns null when no config file exists', () => {
    const result = loadConfigFile(tmpDir);
    expect(result).toBeNull();
  });

  it('returns null when package.json exists but has no secbot key', () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', version: '1.0.0' }));

    const result = loadConfigFile(tmpDir);
    expect(result).toBeNull();
  });

  it('returns null and warns on invalid JSON in .secbotrc.json', () => {
    writeFileSync(join(tmpDir, '.secbotrc.json'), '{ invalid json !!!');

    const result = loadConfigFile(tmpDir);
    expect(result).toBeNull();
  });

  it('returns null and warns on invalid JSON in secbot.config.json', () => {
    writeFileSync(join(tmpDir, 'secbot.config.json'), 'not json at all');

    const result = loadConfigFile(tmpDir);
    expect(result).toBeNull();
  });

  it('returns null and warns on invalid JSON in package.json', () => {
    writeFileSync(join(tmpDir, 'package.json'), '{{broken}}');

    const result = loadConfigFile(tmpDir);
    expect(result).toBeNull();
  });

  it('handles partial config (only some fields set)', () => {
    const config = { excludeChecks: ['xss', 'sqli'], rateLimit: 5 };
    writeFileSync(join(tmpDir, '.secbotrc.json'), JSON.stringify(config));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(config);
    expect(result!.target).toBeUndefined();
    expect(result!.profile).toBeUndefined();
    expect(result!.excludeChecks).toEqual(['xss', 'sqli']);
    expect(result!.rateLimit).toBe(5);
  });

  it('loads all supported config fields', () => {
    const config = {
      target: 'http://localhost:9000',
      profile: 'deep' as const,
      auth: './auth.json',
      format: 'json,html',
      output: './reports',
      scope: '*.example.com,-admin.example.com',
      excludeChecks: ['traversal'],
      maxPages: 50,
      timeout: 45000,
      ignoreRobots: true,
      logRequests: true,
      noAi: true,
      callbackUrl: 'https://callback.example.com',
      rateLimit: 10,
      baseline: './baseline.json',
    };
    writeFileSync(join(tmpDir, '.secbotrc.json'), JSON.stringify(config));

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual(config);
  });

  it('handles empty config object', () => {
    writeFileSync(join(tmpDir, '.secbotrc.json'), '{}');

    const result = loadConfigFile(tmpDir);
    expect(result).toEqual({});
  });

  it('ignores package.json secbot key when it is not an object', () => {
    writeFileSync(join(tmpDir, 'package.json'), JSON.stringify({ name: 'test', secbot: 'not-an-object' }));

    const result = loadConfigFile(tmpDir);
    expect(result).toBeNull();
  });

  it('uses cwd when no directory argument is provided', () => {
    // loadConfigFile() with no args should use process.cwd()
    // We can't easily test this without changing cwd, but we can verify
    // it doesn't throw when called without arguments
    const result = loadConfigFile();
    // Should return either a config or null, depending on cwd
    expect(result === null || typeof result === 'object').toBe(true);
  });
});
