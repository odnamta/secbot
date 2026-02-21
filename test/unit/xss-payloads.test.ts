import { describe, it, expect } from 'vitest';
import { XSS_PAYLOADS, XSS_MARKERS } from '../../src/config/payloads/xss.js';

describe('XSS Payloads', () => {
  it('has at least 30 payloads', () => {
    expect(XSS_PAYLOADS.length).toBeGreaterThanOrEqual(30);
  });

  it('each payload contains its marker', () => {
    for (const p of XSS_PAYLOADS) {
      expect(p.payload).toContain(p.marker);
    }
  });

  it('all markers are unique', () => {
    const markers = XSS_PAYLOADS.map(p => p.marker);
    expect(new Set(markers).size).toBe(markers.length);
  });

  it('has multiple payload types', () => {
    const types = new Set(XSS_PAYLOADS.map(p => p.type));
    expect(types.size).toBeGreaterThanOrEqual(3);
  });

  it('has reflected payloads', () => {
    const reflected = XSS_PAYLOADS.filter(p => p.type === 'reflected');
    expect(reflected.length).toBeGreaterThan(0);
  });

  it('has event-handler payloads', () => {
    const eventHandler = XSS_PAYLOADS.filter(p => p.type === 'event-handler');
    expect(eventHandler.length).toBeGreaterThan(0);
  });

  it('has template payloads', () => {
    const template = XSS_PAYLOADS.filter(p => p.type === 'template');
    expect(template.length).toBeGreaterThan(0);
  });

  it('has dom payloads', () => {
    const dom = XSS_PAYLOADS.filter(p => p.type === 'dom');
    expect(dom.length).toBeGreaterThan(0);
  });

  it('each payload has valid type', () => {
    const validTypes = ['reflected', 'dom', 'event-handler', 'template'];
    for (const p of XSS_PAYLOADS) {
      expect(validTypes).toContain(p.type);
    }
  });

  it('markers follow secbot-xss-N naming convention', () => {
    for (const p of XSS_PAYLOADS) {
      expect(p.marker).toMatch(/^secbot-xss-\d+$/);
    }
  });

  it('deprecated XSS_MARKERS array matches payloads', () => {
    expect(XSS_MARKERS.length).toBe(XSS_PAYLOADS.length);
    for (let i = 0; i < XSS_PAYLOADS.length; i++) {
      expect(XSS_MARKERS[i]).toBe(XSS_PAYLOADS[i].marker);
    }
  });
});
