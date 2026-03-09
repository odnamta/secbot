import { describe, it, expect } from 'vitest';
import { buildPayloadContext, summarizePayloadContext, type PayloadContext } from '../../src/utils/payload-context.js';
import type { ReconResult } from '../../src/scanner/types.js';

function makeRecon(overrides: Partial<ReconResult> = {}): ReconResult {
  return {
    techStack: { languages: [], detected: [] },
    waf: { detected: false, confidence: 'medium', evidence: [] },
    framework: { confidence: 'low', evidence: [] },
    endpoints: { pages: [], apiRoutes: [], forms: [], staticAssets: [], graphql: [] },
    ...overrides,
  };
}

describe('buildPayloadContext', () => {
  it('detects PHP + MySQL from WordPress', () => {
    const recon = makeRecon({
      techStack: { languages: ['PHP'], detected: ['WordPress'], server: 'Apache' },
      framework: { name: 'WordPress', confidence: 'high', evidence: [] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.databases).toContain('mysql');
    expect(ctx.backendLanguages).toContain('php');
    expect(ctx.osHint).toBe('unix');
  });

  it('detects .NET + MSSQL from IIS', () => {
    const recon = makeRecon({
      techStack: { languages: ['.NET'], detected: [], server: 'Microsoft-IIS/10.0' },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.databases).toContain('mssql');
    expect(ctx.backendLanguages).toContain('dotnet');
    expect(ctx.osHint).toBe('windows');
  });

  it('detects Python + PostgreSQL from Django', () => {
    const recon = makeRecon({
      framework: { name: 'Django', confidence: 'high', evidence: [] },
      techStack: { languages: [], detected: [], poweredBy: 'Django' },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.databases).toContain('postgres');
    expect(ctx.backendLanguages).toContain('python');
    expect(ctx.templateEngines).toContain('jinja2');
  });

  it('detects Java from JSESSIONID', () => {
    const recon = makeRecon({
      techStack: { languages: ['Java'], detected: [] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.backendLanguages).toContain('java');
    expect(ctx.databases).toContain('oracle');
    expect(ctx.templateEngines).toContain('freemarker');
  });

  it('sets preferDomXss for SPA frameworks', () => {
    const recon = makeRecon({
      framework: { name: 'Angular', confidence: 'high', evidence: [] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.preferDomXss).toBe(true);
  });

  it('does not set preferDomXss for server-rendered', () => {
    const recon = makeRecon({
      framework: { name: 'WordPress', confidence: 'high', evidence: [] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.preferDomXss).toBe(false);
  });

  it('detects WAF presence', () => {
    const recon = makeRecon({
      waf: { detected: true, name: 'Cloudflare', confidence: 'high', evidence: [], recommendedTechniques: ['unicode-encoding'] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.wafPresent).toBe(true);
    expect(ctx.wafBypasses).toContain('unicode-encoding');
  });

  it('generates framework hints for Express', () => {
    const recon = makeRecon({
      framework: { name: 'Express', confidence: 'high', evidence: [] },
      techStack: { languages: [], detected: [] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.frameworkHints.some(h => h.includes('prototype pollution'))).toBe(true);
    expect(ctx.templateEngines).toContain('handlebars');
  });

  it('returns unknown defaults for empty recon', () => {
    const recon = makeRecon();
    const ctx = buildPayloadContext(recon);
    expect(ctx.databases).toEqual(['unknown']);
    expect(ctx.templateEngines).toEqual(['unknown']);
    expect(ctx.backendLanguages).toEqual(['unknown']);
    expect(ctx.preferDomXss).toBe(false);
    expect(ctx.wafPresent).toBe(false);
  });

  it('detects Next.js as Node + SPA', () => {
    const recon = makeRecon({
      framework: { name: 'Next.js', confidence: 'high', evidence: [] },
      techStack: { languages: [], detected: ['Next.js'] },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.backendLanguages).toContain('node');
    expect(ctx.preferDomXss).toBe(true);
    expect(ctx.databases).toContain('mongodb');
  });

  it('detects Ruby on Rails', () => {
    const recon = makeRecon({
      framework: { name: 'Rails', confidence: 'high', evidence: [] },
      techStack: { languages: [], detected: [], poweredBy: 'Phusion Passenger' },
    });
    const ctx = buildPayloadContext(recon);
    expect(ctx.backendLanguages).toContain('ruby');
    expect(ctx.databases).toContain('postgres');
    expect(ctx.templateEngines).toContain('erb');
  });
});

describe('summarizePayloadContext', () => {
  it('summarizes detected technologies', () => {
    const ctx: PayloadContext = {
      databases: ['mysql'],
      templateEngines: ['twig'],
      backendLanguages: ['php'],
      preferDomXss: false,
      wafPresent: true,
      wafBypasses: ['unicode'],
      frameworkHints: ['Test wp-admin'],
      osHint: 'unix',
    };
    const summary = summarizePayloadContext(ctx);
    expect(summary).toContain('php');
    expect(summary).toContain('mysql');
    expect(summary).toContain('twig');
    expect(summary).toContain('WAF');
    expect(summary).toContain('unix');
  });

  it('returns no-tech message for empty context', () => {
    const ctx: PayloadContext = {
      databases: ['unknown'],
      templateEngines: ['unknown'],
      backendLanguages: ['unknown'],
      preferDomXss: false,
      wafPresent: false,
      wafBypasses: [],
      frameworkHints: [],
      osHint: 'unknown',
    };
    const summary = summarizePayloadContext(ctx);
    expect(summary).toContain('No specific tech');
  });
});
