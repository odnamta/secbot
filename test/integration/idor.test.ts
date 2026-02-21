import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type BrowserContext } from 'playwright';
import { startTestServer, stopTestServer } from '../setup.js';
import { idorCheck } from '../../src/scanner/active/idor.js';
import type { ScanConfig } from '../../src/scanner/types.js';
import type { ScanTargets } from '../../src/scanner/active/index.js';

describe('IDOR Integration Tests', () => {
  let browser: Browser;
  let context: BrowserContext;
  let baseUrl: string;

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
    authStorageState: '/fake/auth-state.json', // Enables IDOR check
  };

  beforeAll(async () => {
    baseUrl = await startTestServer();
    defaultConfig.targetUrl = baseUrl;
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext();
  }, 30000);

  afterAll(async () => {
    await context?.close();
    await browser?.close();
    await stopTestServer();
  });

  it('detects IDOR on /api/v1/users/:id when auth is configured', async () => {
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

  it('does not flag when adjacent IDs return 404', async () => {
    // Use ID 3 — ID 4 does not exist, returns 404
    // ID 2 exists but we test the logic with a higher ID boundary
    const targets: ScanTargets = {
      pages: [`${baseUrl}/api/v1/users/3`],
      forms: [],
      urlsWithParams: [],
      apiEndpoints: [`${baseUrl}/api/v1/users/3`],
      redirectUrls: [],
      fileParams: [],
    };

    const findings = await idorCheck.run(context, targets, defaultConfig);

    // ID 2 exists (returns 200), so we expect a finding for id-1
    // But ID 4 doesn't exist (returns 404), so only 1 finding max
    // The check breaks after first finding per resource, so exactly 1
    const idorFindings = findings.filter((f) => f.category === 'idor');
    expect(idorFindings.length).toBe(1);
  }, 60000);

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
    expect(finding.affectedUrls).toBeDefined();
    expect(finding.affectedUrls!.length).toBe(2);
  }, 60000);
});
