import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { log } from './logger.js';

const WORDLIST_SOURCES = [
  { name: 'paths-common.txt', url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt' },
  { name: 'paths-large.txt', url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt' },
  { name: 'api-endpoints.txt', url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt' },
  { name: 'subdomains-5000.txt', url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt' },
  { name: 'params-large.txt', url: 'https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/large.txt' },
  { name: 'params-burp.txt', url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt' },
];

/**
 * Download/update wordlists from known sources into ~/.secbot/wordlists/.
 * Falls back to project-local config/wordlists/ if HOME is unavailable.
 */
export async function updateWordlists(): Promise<void> {
  const dir = join(homedir(), '.secbot', 'wordlists');
  await mkdir(dir, { recursive: true });

  log.info(`Updating wordlists into ${dir}...`);
  let succeeded = 0;

  for (const source of WORDLIST_SOURCES) {
    try {
      const resp = await fetch(source.url, { signal: AbortSignal.timeout(30_000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const content = await resp.text();
      await writeFile(join(dir, source.name), content);
      const lines = content.split('\n').filter(l => l.trim()).length;
      log.info(`  Updated ${source.name}: ${lines} entries`);
      succeeded++;
    } catch (err) {
      log.warn(`  Failed to update ${source.name}: ${(err as Error).message}`);
    }
  }

  log.info(`Wordlist update complete: ${succeeded}/${WORDLIST_SOURCES.length} updated`);
}

/**
 * Update vulnerability templates from external sources.
 * Currently a placeholder — uses built-in templates.
 */
export async function updateTemplates(): Promise<void> {
  log.info('Template updates: using built-in templates (external template loading coming soon)');
  // Future: download Nuclei community templates from a template repository
}
