import { readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';
import { homedir } from 'node:os';
import { pathToFileURL } from 'node:url';
import type { ActiveCheck } from '../scanner/active/index.js';
import type { SecbotPlugin } from './types.js';
import { log } from '../utils/logger.js';

const DEFAULT_PLUGIN_DIR = join(homedir(), '.secbot', 'plugins');
const PLUGIN_FILE_EXTENSIONS = new Set(['.js', '.mjs', '.ts', '.mts']);
const NPM_PLUGIN_PREFIX = 'secbot-plugin-';

/**
 * Validates that an object conforms to the ActiveCheck interface:
 * must have a string `name` and a function `run`.
 */
function isValidPlugin(obj: unknown): obj is SecbotPlugin {
  if (obj == null || typeof obj !== 'object') return false;
  const candidate = obj as Record<string, unknown>;
  return typeof candidate.name === 'string' && typeof candidate.run === 'function';
}

/**
 * Load a single plugin from a file path.
 * Returns the plugin if valid, null otherwise.
 */
async function loadPluginFile(filePath: string): Promise<SecbotPlugin | null> {
  try {
    const fileUrl = pathToFileURL(filePath).href;
    const mod = await import(fileUrl);
    const plugin = mod.default ?? mod;

    if (!isValidPlugin(plugin)) {
      log.warn(`Plugin "${filePath}" does not export a valid ActiveCheck (needs name + run). Skipping.`);
      return null;
    }

    return plugin;
  } catch (err) {
    log.warn(`Failed to load plugin "${filePath}": ${(err as Error).message}`);
    return null;
  }
}

/**
 * Scan a directory for plugin files (.js, .mjs, .ts, .mts).
 * Returns an array of absolute file paths.
 */
function scanDirectory(dir: string): string[] {
  if (!existsSync(dir)) return [];

  try {
    const stat = statSync(dir);
    if (!stat.isDirectory()) return [];
  } catch {
    return [];
  }

  const files: string[] = [];
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const ext = extname(entry);
      if (PLUGIN_FILE_EXTENSIONS.has(ext)) {
        files.push(resolve(dir, entry));
      }
    }
  } catch (err) {
    log.warn(`Failed to scan plugin directory "${dir}": ${(err as Error).message}`);
  }

  return files;
}

/**
 * Discover npm packages matching the `secbot-plugin-*` pattern.
 * Looks in node_modules of the current working directory.
 * Returns an array of package names that can be imported.
 */
function discoverNpmPlugins(cwd?: string): string[] {
  const nodeModulesDir = resolve(cwd ?? process.cwd(), 'node_modules');
  if (!existsSync(nodeModulesDir)) return [];

  const packages: string[] = [];
  try {
    const entries = readdirSync(nodeModulesDir);
    for (const entry of entries) {
      if (entry.startsWith(NPM_PLUGIN_PREFIX)) {
        const pkgDir = join(nodeModulesDir, entry);
        try {
          const stat = statSync(pkgDir);
          if (stat.isDirectory()) {
            packages.push(entry);
          }
        } catch {
          // Skip entries we can't stat
        }
      }
    }
  } catch (err) {
    log.debug(`Could not scan node_modules for plugins: ${(err as Error).message}`);
  }

  return packages;
}

/**
 * Load an npm plugin package by name.
 * Returns the plugin if valid, null otherwise.
 */
async function loadNpmPlugin(packageName: string, cwd?: string): Promise<SecbotPlugin | null> {
  try {
    const pkgPath = resolve(cwd ?? process.cwd(), 'node_modules', packageName);
    const fileUrl = pathToFileURL(pkgPath).href;
    const mod = await import(fileUrl);
    const plugin = mod.default ?? mod;

    if (!isValidPlugin(plugin)) {
      log.warn(`npm plugin "${packageName}" does not export a valid ActiveCheck. Skipping.`);
      return null;
    }

    return plugin;
  } catch (err) {
    log.warn(`Failed to load npm plugin "${packageName}": ${(err as Error).message}`);
    return null;
  }
}

/**
 * Load all plugins from:
 *   1. A plugin directory (default: ~/.secbot/plugins/)
 *   2. npm packages matching `secbot-plugin-*` in node_modules
 *
 * Returns an array of valid ActiveCheck objects.
 * Invalid plugins are skipped with a warning.
 */
export async function loadPlugins(pluginDir?: string): Promise<ActiveCheck[]> {
  const dir = pluginDir ?? DEFAULT_PLUGIN_DIR;
  const plugins: ActiveCheck[] = [];
  const seenNames = new Set<string>();

  // 1. Load from plugin directory
  const files = scanDirectory(dir);
  if (files.length > 0) {
    log.info(`Found ${files.length} plugin file(s) in ${dir}`);
  }

  for (const file of files) {
    const plugin = await loadPluginFile(file);
    if (plugin) {
      if (seenNames.has(plugin.name)) {
        log.warn(`Duplicate plugin name "${plugin.name}" from ${file}. Skipping.`);
        continue;
      }
      seenNames.add(plugin.name);
      plugins.push(plugin);
      log.info(`Loaded plugin: ${plugin.name}${plugin.meta?.version ? ` v${plugin.meta.version}` : ''}`);
    }
  }

  // 2. Load npm plugin packages
  const npmPackages = discoverNpmPlugins();
  if (npmPackages.length > 0) {
    log.info(`Found ${npmPackages.length} npm plugin package(s): ${npmPackages.join(', ')}`);
  }

  for (const pkg of npmPackages) {
    const plugin = await loadNpmPlugin(pkg);
    if (plugin) {
      if (seenNames.has(plugin.name)) {
        log.warn(`Duplicate plugin name "${plugin.name}" from npm package ${pkg}. Skipping.`);
        continue;
      }
      seenNames.add(plugin.name);
      plugins.push(plugin);
      log.info(`Loaded npm plugin: ${plugin.name}`);
    }
  }

  if (plugins.length > 0) {
    log.info(`Total plugins loaded: ${plugins.length}`);
  }

  return plugins;
}

// Re-export for testing
export { isValidPlugin, scanDirectory, discoverNpmPlugins, DEFAULT_PLUGIN_DIR };
