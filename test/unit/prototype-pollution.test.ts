import { describe, it, expect } from 'vitest';
import {
  PP_QUERY_PAYLOADS,
  PP_JSON_PAYLOADS,
  PP_CLIENT_PAYLOADS,
  PP_CANARY,
  PP_RESPONSE_INDICATORS,
  detectServerPollution,
} from '../../src/scanner/active/prototype-pollution.js';

describe('Prototype Pollution Payloads', () => {
  describe('PP_QUERY_PAYLOADS', () => {
    it('has at least 6 query payloads', () => {
      expect(PP_QUERY_PAYLOADS.length).toBeGreaterThanOrEqual(6);
    });

    it('includes __proto__ bracket notation', () => {
      const proto = PP_QUERY_PAYLOADS.filter(p => p.key.includes('__proto__['));
      expect(proto.length).toBeGreaterThanOrEqual(1);
    });

    it('includes __proto__ dot notation', () => {
      const proto = PP_QUERY_PAYLOADS.filter(p => p.key.includes('__proto__.'));
      expect(proto.length).toBeGreaterThanOrEqual(1);
    });

    it('includes constructor.prototype bypass', () => {
      const ctor = PP_QUERY_PAYLOADS.filter(p => p.key.includes('constructor'));
      expect(ctor.length).toBeGreaterThanOrEqual(2);
    });

    it('includes nested __proto__ variant', () => {
      const nested = PP_QUERY_PAYLOADS.filter(p => p.technique.includes('nested'));
      expect(nested.length).toBeGreaterThanOrEqual(1);
    });

    it('all payloads have key, value, and technique', () => {
      for (const p of PP_QUERY_PAYLOADS) {
        expect(p.key).toBeTruthy();
        expect(p.value).toBeTruthy();
        expect(p.technique).toBeTruthy();
      }
    });

    it('most payloads target the canary property', () => {
      const canaryPayloads = PP_QUERY_PAYLOADS.filter(p => p.key.includes(PP_CANARY));
      expect(canaryPayloads.length).toBeGreaterThanOrEqual(5);
    });
  });

  describe('PP_JSON_PAYLOADS', () => {
    it('has at least 2 JSON body payloads', () => {
      expect(PP_JSON_PAYLOADS.length).toBeGreaterThanOrEqual(2);
    });

    it('includes __proto__ JSON payload', () => {
      const proto = PP_JSON_PAYLOADS.filter(p => p.bodyJson.includes('__proto__'));
      expect(proto.length).toBeGreaterThanOrEqual(1);
    });

    it('includes constructor.prototype JSON payload', () => {
      const ctor = PP_JSON_PAYLOADS.filter(p => p.bodyJson.includes('constructor'));
      expect(ctor.length).toBeGreaterThanOrEqual(1);
    });

    it('all JSON payloads are valid JSON', () => {
      for (const p of PP_JSON_PAYLOADS) {
        expect(() => JSON.parse(p.bodyJson)).not.toThrow();
      }
    });

    it('all JSON payloads contain the canary', () => {
      for (const p of PP_JSON_PAYLOADS) {
        expect(p.bodyJson).toContain(PP_CANARY);
      }
    });
  });

  describe('PP_CLIENT_PAYLOADS', () => {
    it('has at least 4 client-side payloads', () => {
      expect(PP_CLIENT_PAYLOADS.length).toBeGreaterThanOrEqual(4);
    });

    it('includes query string variants', () => {
      const qs = PP_CLIENT_PAYLOADS.filter(p => !p.startsWith('#'));
      expect(qs.length).toBeGreaterThanOrEqual(2);
    });

    it('includes URL fragment variants', () => {
      const hash = PP_CLIENT_PAYLOADS.filter(p => p.startsWith('#'));
      expect(hash.length).toBeGreaterThanOrEqual(2);
    });

    it('all contain the canary property', () => {
      for (const p of PP_CLIENT_PAYLOADS) {
        expect(p).toContain(PP_CANARY);
      }
    });
  });

  describe('PP_CANARY', () => {
    it('is a recognizable secbot marker', () => {
      expect(PP_CANARY).toBe('secbot_pp');
    });
  });

  describe('PP_RESPONSE_INDICATORS', () => {
    it('has at least 2 indicators', () => {
      expect(PP_RESPONSE_INDICATORS.length).toBeGreaterThanOrEqual(2);
    });

    it('matches canary in response', () => {
      const body = '{"secbot_pp":"polluted"}';
      expect(PP_RESPONSE_INDICATORS.some(r => r.test(body))).toBe(true);
    });
  });
});

describe('detectServerPollution()', () => {
  it('detects canary value reflected in response body', () => {
    const body = '{"data":{"secbot_pp":"polluted","name":"test"}}';
    const result = detectServerPollution(body, 200, 200);
    expect(result.polluted).toBe(true);
    expect(result.evidence).toContain('Canary value');
  });

  it('detects server crash after pollution', () => {
    const body = 'Internal Server Error';
    const result = detectServerPollution(body, 500, 200);
    expect(result.polluted).toBe(true);
    expect(result.evidence).toContain('Server error 500');
    expect(result.evidence).toContain('baseline was 200');
  });

  it('does not flag 500 when baseline was already 500', () => {
    const body = 'Internal Server Error';
    const result = detectServerPollution(body, 500, 500);
    expect(result.polluted).toBe(false);
  });

  it('does not flag normal 200 response without canary', () => {
    const body = '{"data":{"name":"test"}}';
    const result = detectServerPollution(body, 200, 200);
    expect(result.polluted).toBe(false);
  });

  it('does not flag 404 after 200 baseline (not a crash, just different endpoint)', () => {
    const body = 'Not Found';
    const result = detectServerPollution(body, 404, 200);
    expect(result.polluted).toBe(false);
  });

  it('detects canary even with other content around it', () => {
    const body = 'some prefix secbot_pp = "polluted" some suffix';
    const result = detectServerPollution(body, 200, 200);
    expect(result.polluted).toBe(true);
  });

  it('does not flag partial canary (secbot_pp without polluted)', () => {
    const body = '{"secbot_pp":"not_the_value"}';
    const result = detectServerPollution(body, 200, 200);
    expect(result.polluted).toBe(false);
  });

  it('detects 502 gateway error as server crash', () => {
    const body = 'Bad Gateway';
    const result = detectServerPollution(body, 502, 200);
    expect(result.polluted).toBe(true);
    expect(result.evidence).toContain('Server error 502');
  });
});
