import { describe, it, expect } from 'vitest';
import { CMDI_PAYLOADS_TIMING, CMDI_PAYLOADS_OUTPUT } from '../../src/config/payloads/cmdi.js';
import { prioritizeCmdiPayloads } from '../../src/scanner/active/cmdi.js';

describe('CMDi Timing Payloads', () => {
  it('has grouped execution variants', () => {
    const grouped = CMDI_PAYLOADS_TIMING.filter((p) => p.payload.includes('{ '));
    expect(grouped.length).toBeGreaterThanOrEqual(1);
    expect(grouped[0].os).toBe('unix');
  });

  it('has shell invocation bypass variants', () => {
    const shVariants = CMDI_PAYLOADS_TIMING.filter((p) => p.payload.includes("sh -c"));
    expect(shVariants.length).toBeGreaterThanOrEqual(1);
    const bashVariants = CMDI_PAYLOADS_TIMING.filter((p) => p.payload.includes("bash -c"));
    expect(bashVariants.length).toBeGreaterThanOrEqual(1);
  });

  it('has Windows cmd invocation bypass', () => {
    const cmdVariants = CMDI_PAYLOADS_TIMING.filter((p) => p.payload.includes('cmd /c'));
    expect(cmdVariants.length).toBeGreaterThanOrEqual(1);
    expect(cmdVariants[0].os).toBe('windows');
  });

  it('all payloads have valid structure', () => {
    for (const p of CMDI_PAYLOADS_TIMING) {
      expect(p.payload.length).toBeGreaterThan(0);
      expect(p.delay).toBe(5);
      expect(['unix', 'windows']).toContain(p.os);
    }
  });

  it('covers both unix and windows', () => {
    const oses = new Set(CMDI_PAYLOADS_TIMING.map((p) => p.os));
    expect(oses.has('unix')).toBe(true);
    expect(oses.has('windows')).toBe(true);
  });
});

describe('CMDi Output Payloads', () => {
  it('has grouped execution output variants', () => {
    const grouped = CMDI_PAYLOADS_OUTPUT.filter((p) => p.payload.includes('{ echo'));
    expect(grouped.length).toBeGreaterThanOrEqual(1);
    expect(grouped[0].os).toBe('unix');
  });

  it('has shell invocation output variants', () => {
    const shVariants = CMDI_PAYLOADS_OUTPUT.filter((p) => p.payload.includes("sh -c"));
    expect(shVariants.length).toBeGreaterThanOrEqual(1);
    const bashVariants = CMDI_PAYLOADS_OUTPUT.filter((p) => p.payload.includes("bash -c"));
    expect(bashVariants.length).toBeGreaterThanOrEqual(1);
  });

  it('has Windows cmd invocation output variant', () => {
    const cmdVariants = CMDI_PAYLOADS_OUTPUT.filter((p) => p.payload.includes('cmd /c echo'));
    expect(cmdVariants.length).toBeGreaterThanOrEqual(1);
    expect(cmdVariants[0].os).toBe('windows');
  });

  it('all payloads use secbot-cmdi-marker', () => {
    for (const p of CMDI_PAYLOADS_OUTPUT) {
      expect(p.marker).toBe('secbot-cmdi-marker');
      expect(p.payload).toContain('secbot-cmdi-marker');
    }
  });

  it('covers both unix and windows', () => {
    const oses = new Set(CMDI_PAYLOADS_OUTPUT.map((p) => p.os));
    expect(oses.has('unix')).toBe(true);
    expect(oses.has('windows')).toBe(true);
  });
});

describe('prioritizeCmdiPayloads', () => {
  it('puts unix payloads first for unix hint', () => {
    const { timing, output } = prioritizeCmdiPayloads('unix');
    const firstNonUnix = timing.findIndex((p) => p.os !== 'unix');
    const lastUnix = timing.findLastIndex((p) => p.os === 'unix');
    if (firstNonUnix !== -1) {
      expect(lastUnix).toBeLessThan(firstNonUnix);
    }
  });

  it('puts windows payloads first for windows hint', () => {
    const { timing, output } = prioritizeCmdiPayloads('windows');
    const firstNonWin = timing.findIndex((p) => p.os !== 'windows');
    const lastWin = timing.findLastIndex((p) => p.os === 'windows');
    if (firstNonWin !== -1) {
      expect(lastWin).toBeLessThan(firstNonWin);
    }
  });

  it('returns all payloads for unknown hint', () => {
    const { timing, output } = prioritizeCmdiPayloads('unknown');
    expect(timing.length).toBe(CMDI_PAYLOADS_TIMING.length);
    expect(output.length).toBe(CMDI_PAYLOADS_OUTPUT.length);
  });
});
