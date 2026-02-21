import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Suppress logger output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Import after mocking
import { loadPlugins, isValidPlugin, scanDirectory, discoverNpmPlugins } from '../../src/plugins/loader.js';
import { log } from '../../src/utils/logger.js';

describe('Plugin Loader', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'secbot-plugin-test-'));
    vi.clearAllMocks();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('isValidPlugin', () => {
    it('returns true for object with name string and run function', () => {
      expect(isValidPlugin({ name: 'test', run: async () => [] })).toBe(true);
    });

    it('returns true when object has extra properties (category, meta)', () => {
      expect(isValidPlugin({
        name: 'test',
        category: 'xss',
        run: async () => [],
        meta: { version: '1.0.0' },
      })).toBe(true);
    });

    it('returns false for null', () => {
      expect(isValidPlugin(null)).toBe(false);
    });

    it('returns false for undefined', () => {
      expect(isValidPlugin(undefined)).toBe(false);
    });

    it('returns false for non-object', () => {
      expect(isValidPlugin('string')).toBe(false);
      expect(isValidPlugin(42)).toBe(false);
    });

    it('returns false when name is missing', () => {
      expect(isValidPlugin({ run: async () => [] })).toBe(false);
    });

    it('returns false when name is not a string', () => {
      expect(isValidPlugin({ name: 123, run: async () => [] })).toBe(false);
    });

    it('returns false when run is missing', () => {
      expect(isValidPlugin({ name: 'test' })).toBe(false);
    });

    it('returns false when run is not a function', () => {
      expect(isValidPlugin({ name: 'test', run: 'not-a-fn' })).toBe(false);
    });
  });

  describe('scanDirectory', () => {
    it('returns empty array for non-existent directory', () => {
      expect(scanDirectory('/nonexistent/path/12345')).toEqual([]);
    });

    it('returns empty array for a file instead of directory', () => {
      const filePath = join(tmpDir, 'file.txt');
      writeFileSync(filePath, 'hello');
      expect(scanDirectory(filePath)).toEqual([]);
    });

    it('finds .js files in directory', () => {
      writeFileSync(join(tmpDir, 'check-a.js'), '');
      writeFileSync(join(tmpDir, 'check-b.js'), '');
      writeFileSync(join(tmpDir, 'readme.md'), '');

      const files = scanDirectory(tmpDir);
      expect(files).toHaveLength(2);
      expect(files.every((f) => f.endsWith('.js'))).toBe(true);
    });

    it('finds .mjs, .ts, .mts files', () => {
      writeFileSync(join(tmpDir, 'a.mjs'), '');
      writeFileSync(join(tmpDir, 'b.ts'), '');
      writeFileSync(join(tmpDir, 'c.mts'), '');
      writeFileSync(join(tmpDir, 'd.json'), '');

      const files = scanDirectory(tmpDir);
      expect(files).toHaveLength(3);
    });

    it('returns empty array for empty directory', () => {
      const emptyDir = join(tmpDir, 'empty');
      mkdirSync(emptyDir);
      expect(scanDirectory(emptyDir)).toEqual([]);
    });
  });

  describe('discoverNpmPlugins', () => {
    it('returns empty array when node_modules does not exist', () => {
      expect(discoverNpmPlugins(tmpDir)).toEqual([]);
    });

    it('finds packages matching secbot-plugin-* pattern', () => {
      const nodeModules = join(tmpDir, 'node_modules');
      mkdirSync(nodeModules);
      mkdirSync(join(nodeModules, 'secbot-plugin-custom'));
      mkdirSync(join(nodeModules, 'secbot-plugin-auth'));
      mkdirSync(join(nodeModules, 'other-package'));
      mkdirSync(join(nodeModules, 'secbot-not-a-plugin'));

      const found = discoverNpmPlugins(tmpDir);
      expect(found).toHaveLength(2);
      expect(found).toContain('secbot-plugin-custom');
      expect(found).toContain('secbot-plugin-auth');
    });

    it('ignores files that are not directories', () => {
      const nodeModules = join(tmpDir, 'node_modules');
      mkdirSync(nodeModules);
      writeFileSync(join(nodeModules, 'secbot-plugin-file'), 'not a dir');

      const found = discoverNpmPlugins(tmpDir);
      expect(found).toEqual([]);
    });
  });

  describe('loadPlugins', () => {
    it('returns empty array for non-existent plugin directory', async () => {
      const plugins = await loadPlugins(join(tmpDir, 'nonexistent'));
      expect(plugins).toEqual([]);
    });

    it('loads a valid plugin from .js file', async () => {
      const pluginContent = `
        export default {
          name: 'test-check',
          category: 'xss',
          run: async (context, targets, config) => {
            return [];
          }
        };
      `;
      writeFileSync(join(tmpDir, 'test-check.mjs'), pluginContent);

      const plugins = await loadPlugins(tmpDir);
      expect(plugins).toHaveLength(1);
      expect(plugins[0].name).toBe('test-check');
      expect(typeof plugins[0].run).toBe('function');
    });

    it('skips files that do not export a valid plugin', async () => {
      // A file that exports an object without 'name' or 'run'
      const badPlugin = `export default { foo: 'bar' };`;
      writeFileSync(join(tmpDir, 'bad.mjs'), badPlugin);

      const plugins = await loadPlugins(tmpDir);
      expect(plugins).toEqual([]);
      expect(log.warn).toHaveBeenCalled();
    });

    it('skips duplicate plugin names', async () => {
      const plugin1 = `export default { name: 'dupe', category: 'xss', run: async () => [] };`;
      const plugin2 = `export default { name: 'dupe', category: 'sqli', run: async () => [] };`;
      writeFileSync(join(tmpDir, 'plugin-a.mjs'), plugin1);
      writeFileSync(join(tmpDir, 'plugin-b.mjs'), plugin2);

      const plugins = await loadPlugins(tmpDir);
      expect(plugins).toHaveLength(1);
      expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('Duplicate plugin name'));
    });

    it('loads multiple valid plugins', async () => {
      const p1 = `export default { name: 'check-alpha', category: 'xss', run: async () => [] };`;
      const p2 = `export default { name: 'check-beta', category: 'sqli', run: async () => [] };`;
      writeFileSync(join(tmpDir, 'alpha.mjs'), p1);
      writeFileSync(join(tmpDir, 'beta.mjs'), p2);

      const plugins = await loadPlugins(tmpDir);
      expect(plugins).toHaveLength(2);
      const names = plugins.map((p) => p.name).sort();
      expect(names).toEqual(['check-alpha', 'check-beta']);
    });

    it('handles plugin that throws on import', async () => {
      const badPlugin = `throw new Error('deliberate import error');`;
      writeFileSync(join(tmpDir, 'crasher.mjs'), badPlugin);

      const plugins = await loadPlugins(tmpDir);
      expect(plugins).toEqual([]);
      expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('Failed to load plugin'));
    });

    it('logs the number of loaded plugins', async () => {
      const p1 = `export default { name: 'logged-check', category: 'xss', run: async () => [] };`;
      writeFileSync(join(tmpDir, 'logged.mjs'), p1);

      await loadPlugins(tmpDir);
      expect(log.info).toHaveBeenCalledWith(expect.stringContaining('Total plugins loaded: 1'));
    });
  });
});
