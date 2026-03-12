import { describe, it, expect } from 'vitest';
import {
  MUTATION_XSS_PAYLOADS,
  CSP_BYPASS_PAYLOADS,
} from '../../src/config/payloads/xss.js';

// ─── Mutation XSS Payloads ──────────────────────────────────────────────────

describe('MUTATION_XSS_PAYLOADS', () => {
  it('has at least 8 payloads', () => {
    expect(MUTATION_XSS_PAYLOADS.length).toBeGreaterThanOrEqual(8);
  });

  it('all markers are unique', () => {
    const markers = MUTATION_XSS_PAYLOADS.map(p => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it('markers follow secbot-mxss-N naming convention', () => {
    for (const p of MUTATION_XSS_PAYLOADS) {
      expect(p.marker).toMatch(/^secbot-mxss-\d+$/);
    }
  });

  it('each payload contains its marker string', () => {
    for (const p of MUTATION_XSS_PAYLOADS) {
      expect(p.payload).toContain(p.marker);
    }
  });

  it('each payload has a valid type', () => {
    const validTypes = ['reflected', 'dom', 'event-handler', 'template'];
    for (const p of MUTATION_XSS_PAYLOADS) {
      expect(validTypes).toContain(p.type);
    }
  });

  it('includes noscript breakout pattern (browser parser quirk)', () => {
    const hasNoscript = MUTATION_XSS_PAYLOADS.some(p =>
      p.payload.toLowerCase().includes('noscript'),
    );
    expect(hasNoscript).toBe(true);
  });

  it('includes math namespace confusion pattern (mXSS)', () => {
    const hasMath = MUTATION_XSS_PAYLOADS.some(p =>
      p.payload.toLowerCase().includes('<math'),
    );
    expect(hasMath).toBe(true);
  });

  it('includes SVG namespace pattern (mXSS)', () => {
    const hasSvg = MUTATION_XSS_PAYLOADS.some(p =>
      p.payload.toLowerCase().includes('<svg'),
    );
    expect(hasSvg).toBe(true);
  });

  it('has dom-type payloads (namespace-based)', () => {
    const domPayloads = MUTATION_XSS_PAYLOADS.filter(p => p.type === 'dom');
    expect(domPayloads.length).toBeGreaterThan(0);
  });

  it('markers are unique across MUTATION_XSS_PAYLOADS and XSS_PAYLOADS', async () => {
    const { XSS_PAYLOADS } = await import('../../src/config/payloads/xss.js');
    const allMarkers = [
      ...XSS_PAYLOADS.map(p => p.marker),
      ...MUTATION_XSS_PAYLOADS.map(p => p.marker),
    ];
    expect(new Set(allMarkers).size).toBe(allMarkers.length);
  });
});

// ─── CSP Bypass Payloads ────────────────────────────────────────────────────

describe('CSP_BYPASS_PAYLOADS', () => {
  it('has at least 5 payloads', () => {
    expect(CSP_BYPASS_PAYLOADS.length).toBeGreaterThanOrEqual(5);
  });

  it('all markers are unique', () => {
    const markers = CSP_BYPASS_PAYLOADS.map(p => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it('markers follow secbot-csp-N naming convention', () => {
    for (const p of CSP_BYPASS_PAYLOADS) {
      expect(p.marker).toMatch(/^secbot-csp-\d+$/);
    }
  });

  it('each payload has a valid type', () => {
    const validTypes = ['reflected', 'dom', 'event-handler', 'template'];
    for (const p of CSP_BYPASS_PAYLOADS) {
      expect(validTypes).toContain(p.type);
    }
  });

  it('includes base tag hijacking payload', () => {
    const hasBaseTag = CSP_BYPASS_PAYLOADS.some(p =>
      p.payload.toLowerCase().includes('<base'),
    );
    expect(hasBaseTag).toBe(true);
  });

  it('includes JSONP callback bypass payload', () => {
    const hasJsonp = CSP_BYPASS_PAYLOADS.some(p =>
      p.payload.toLowerCase().includes('callback='),
    );
    expect(hasJsonp).toBe(true);
  });

  it('markers are unique across CSP_BYPASS_PAYLOADS and XSS_PAYLOADS', async () => {
    const { XSS_PAYLOADS } = await import('../../src/config/payloads/xss.js');
    const allMarkers = [
      ...XSS_PAYLOADS.map(p => p.marker),
      ...CSP_BYPASS_PAYLOADS.map(p => p.marker),
    ];
    expect(new Set(allMarkers).size).toBe(allMarkers.length);
  });

  it('markers are unique across CSP_BYPASS_PAYLOADS and MUTATION_XSS_PAYLOADS', () => {
    const allMarkers = [
      ...MUTATION_XSS_PAYLOADS.map(p => p.marker),
      ...CSP_BYPASS_PAYLOADS.map(p => p.marker),
    ];
    expect(new Set(allMarkers).size).toBe(allMarkers.length);
  });
});
