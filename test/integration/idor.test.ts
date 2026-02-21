import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { startTestServer, stopTestServer } from '../setup.js';
import { idorCheck } from '../../src/scanner/active/idor.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('IDOR Integration Tests', () => {
  let browser: Browser;
  let context: BrowserContext;
  let baseUrl: string;
  let altAuthFile: string;

  const defaultConfig: ScanConfig = {
    targetUrl: '',
    profile: 'standard',
    maxPages: 10,
    timeout: 15000,
    respectRobots: false,
    outputFormat: ['terminal'],
    concurrency: 1,
    requestDelay: 50,
    logRequests: false,
    useAI: false,
    authStorageState: '', // set in beforeAll
    idorAltAuthState: '', // set in beforeAll
  };

  beforeAll(async () => {
    baseUrl = await startTestServer();
    defaultConfig.targetUrl = baseUrl;

    // Create dummy Playwright storage state files for both sessions
    const dummyState = JSON.stringify({ cookies: [], origins: [] });
    const authFile = join(tmpdir(), 'secbot-test-auth.json');
    altAuthFile = join(tmpdir(), 'secbot-test-alt-auth.json');
    writeFileSync(authFile, dummyState);
    writeFileSync(altAuthFile, dummyState);
    defaultConfig.authStorageState = authFile;
    defaultConfig.idorAltAuthState = altAuthFile;

    browser = await chromium.launch({ headless: true });
    context = await browser.newContext();
  }, 30000);

  afterAll(async () => {
    await context?.close();
    await browser?.close();
    await stopTestServer();
    try { unlinkSync(defaultConfig.authStorageState!); } catch { /* ok */ }
    try { unlinkSync(altAuthFile); } catch { /* ok */ }
  });

  it('detects IDOR on /api/v1/users/:id when dual auth is configured', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/users/1`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/users/1`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await idorCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const idorFinding = findings.find((f) => f.category === 'idor');
    expect(idorFinding).toBeDefined();
    expect(idorFinding!.severity).toBe('high');
    expect(idorFinding!.title).toContain('IDOR');
    expect(idorFinding!.title).toContain('users');
    expect(idorFinding!.evidence).toContain('200');
  }, 60000);

  it('skips IDOR check when no auth is configured', async () => {
    const noAuthConfig: ScanConfig = {
      ...defaultConfig,
      authStorageState: undefined,
      idorAltAuthState: undefined,
    };

    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/users/1`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/users/1`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await idorCheck.run(context, targets, noAuthConfig);
    expect(findings.length).toBe(0);
  }, 30000);

  it('skips IDOR check when no alt-auth is configured', async () => {
    const singleAuthConfig: ScanConfig = {
      ...defaultConfig,
      idorAltAuthState: undefined,
    };

    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/users/1`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/users/1`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await idorCheck.run(context, targets, singleAuthConfig);
    expect(findings.length).toBe(0);
  }, 30000);

  it('findings have required RawFinding fields', async () => {
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/users/1`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/users/1`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await idorCheck.run(context, targets, defaultConfig);

    expect(findings.length).toBeGreaterThanOrEqual(1);

    const finding = findings[0];
    expect(finding.id).toBeDefined();
    expect(finding.category).toBe('idor');
    expect(finding.severity).toBe('high');
    expect(finding.title).toBeDefined();
    expect(finding.description).toBeDefined();
    expect(finding.url).toBeDefined();
    expect(finding.evidence).toBeDefined();
    expect(finding.timestamp).toBeDefined();
    expect(finding.request).toBeDefined();
    expect(finding.response).toBeDefined();
  }, 60000);
});
