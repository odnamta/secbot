import { describe, it, expect } from 'vitest';
import { SSRF_PAYLOADS, getSSRFPayloads, generateCallbackPayloads, SSRF_OBFUSCATION_PAYLOADS, getObfuscationPayloads, SSRF_JSON_FIELD_NAMES, SSRF_INDICATORS, SSRF_INTERNAL_SERVICE_PROBES, CLOUD_METADATA_PROBES } from '../../src/config/payloads/ssrf.js';

describe('SSRF Callback Payloads', () => {
  describe('getSSRFPayloads() without callback URL', () => {
    it('returns only base payloads when no callback URL is provided', () => {
      const payloads = getSSRFPayloads();
      expect(payloads).toEqual(SSRF_PAYLOADS);
    });

    it('returns only base payloads when callback URL is undefined', () => {
      const payloads = getSSRFPayloads(undefined);
      expect(payloads).toEqual(SSRF_PAYLOADS);
    });

    it('returns a copy, not a reference to SSRF_PAYLOADS', () => {
      const payloads = getSSRFPayloads();
      payloads.push('http://test');
      expect(SSRF_PAYLOADS).not.toContain('http://test');
    });
  });

  describe('getSSRFPayloads() with callback URL', () => {
    const callbackUrl = 'https://callback.example.com';

    it('returns base payloads plus callback payloads', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      expect(payloads.length).toBeGreaterThan(SSRF_PAYLOADS.length);
    });

    it('starts with all base payloads', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      for (let i = 0; i < SSRF_PAYLOADS.length; i++) {
        expect(payloads[i]).toBe(SSRF_PAYLOADS[i]);
      }
    });

    it('callback payloads contain the provided URL', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      const callbackPayloads = payloads.slice(SSRF_PAYLOADS.length);
      expect(callbackPayloads.length).toBeGreaterThan(0);
      for (const payload of callbackPayloads) {
        // URL-encoded variant still contains the base URL (just encoded)
        expect(
          payload.includes('callback.example.com')
        ).toBe(true);
      }
    });

    it('callback payloads contain unique identifiers', () => {
      const payloads = getSSRFPayloads(callbackUrl);
      const callbackPayloads = payloads.slice(SSRF_PAYLOADS.length);
      // Each payload should contain 'ssrf-' followed by a UUID
      for (const payload of callbackPayloads) {
        expect(payload).toMatch(/ssrf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
      }
    });

    it('generates different UUIDs each call', () => {
      const payloads1 = getSSRFPayloads(callbackUrl);
      const payloads2 = getSSRFPayloads(callbackUrl);
      const cb1 = payloads1.slice(SSRF_PAYLOADS.length);
      const cb2 = payloads2.slice(SSRF_PAYLOADS.length);
      // UUIDs should differ between calls
      expect(cb1).not.toEqual(cb2);
    });
  });

  describe('generateCallbackPayloads()', () => {
    it('generates 5 callback payload variants', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      expect(payloads).toHaveLength(5);
    });

    it('strips trailing slashes from callback URL', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com///');
      for (const payload of payloads) {
        expect(payload).not.toMatch(/example\.com\/\/\//);
      }
    });

    it('includes a plain URL variant', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const plain = payloads.filter((p) => p.startsWith('https://callback.example.com/ssrf-') && !p.includes('/probe') && !p.includes(':80') && !p.includes(':443'));
      expect(plain.length).toBeGreaterThanOrEqual(1);
    });

    it('includes a nested path variant', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const nested = payloads.filter((p) => p.includes('/probe'));
      expect(nested.length).toBeGreaterThanOrEqual(1);
    });

    it('includes port variants', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const withPort80 = payloads.filter((p) => p.includes(':80/'));
      const withPort443 = payloads.filter((p) => p.includes(':443/'));
      expect(withPort80.length).toBeGreaterThanOrEqual(1);
      expect(withPort443.length).toBeGreaterThanOrEqual(1);
    });

    it('includes a URL-encoded variant', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      // The encoded variant goes through encodeURI, which for this URL is the same
      // but the structure should still be valid
      expect(payloads.length).toBe(5);
      // All payloads should be valid URLs or URL-like strings
      for (const payload of payloads) {
        expect(payload).toContain('callback.example.com');
      }
    });

    it('all payloads have unique UUIDs', () => {
      const payloads = generateCallbackPayloads('https://callback.example.com');
      const uuids = payloads
        .map((p) => {
          const match = p.match(/ssrf-([0-9a-f-]{36})/);
          return match ? match[1] : null;
        })
        .filter(Boolean);
      expect(new Set(uuids).size).toBe(uuids.length);
    });
  });

  describe('SSRF IP Obfuscation Payloads', () => {
    it('contains numeric IP representations of 127.0.0.1', () => {
      expect(SSRF_OBFUSCATION_PAYLOADS).toContainEqual(expect.stringContaining('2130706433'));  // decimal
      expect(SSRF_OBFUSCATION_PAYLOADS).toContainEqual(expect.stringContaining('0x7f000001'));  // hex
      expect(SSRF_OBFUSCATION_PAYLOADS).toContainEqual(expect.stringContaining('0177.0.0.1'));  // octal
      expect(SSRF_OBFUSCATION_PAYLOADS).toContainEqual(expect.stringContaining('127.1'));       // short form
    });

    it('contains IPv6-mapped IPv4 representations', () => {
      const ipv6 = SSRF_OBFUSCATION_PAYLOADS.filter(p => p.includes('ffff'));
      expect(ipv6.length).toBeGreaterThanOrEqual(2);
    });

    it('contains DNS rebinding payloads', () => {
      const dnsRebind = SSRF_OBFUSCATION_PAYLOADS.filter(p =>
        p.includes('localtest.me') || p.includes('nip.io'),
      );
      expect(dnsRebind.length).toBeGreaterThanOrEqual(2);
    });

    it('contains URL authority bypass payloads', () => {
      const authBypass = SSRF_OBFUSCATION_PAYLOADS.filter(p => p.includes('@'));
      expect(authBypass.length).toBeGreaterThanOrEqual(1);
    });

    it('contains cloud metadata obfuscation payloads', () => {
      const cloudObf = SSRF_OBFUSCATION_PAYLOADS.filter(p =>
        p.includes('meta-data') && !SSRF_PAYLOADS.includes(p),
      );
      expect(cloudObf.length).toBeGreaterThanOrEqual(2);
    });

    it('all payloads start with http:// or https://', () => {
      for (const p of SSRF_OBFUSCATION_PAYLOADS) {
        expect(p).toMatch(/^https?:\/\//);
      }
    });
  });

  describe('getObfuscationPayloads()', () => {
    it('returns full set for deep profile', () => {
      const payloads = getObfuscationPayloads('deep');
      expect(payloads).toEqual(SSRF_OBFUSCATION_PAYLOADS);
    });

    it('returns full set when WAF detected', () => {
      const payloads = getObfuscationPayloads('standard', true);
      expect(payloads).toEqual(SSRF_OBFUSCATION_PAYLOADS);
    });

    it('returns subset for standard profile without WAF', () => {
      const payloads = getObfuscationPayloads('standard', false);
      expect(payloads.length).toBe(6);
      expect(payloads.length).toBeLessThan(SSRF_OBFUSCATION_PAYLOADS.length);
    });

    it('returns subset for quick profile', () => {
      const payloads = getObfuscationPayloads('quick');
      expect(payloads.length).toBe(6);
    });

    it('returns a copy, not a reference', () => {
      const payloads = getObfuscationPayloads('deep');
      payloads.push('http://test');
      expect(SSRF_OBFUSCATION_PAYLOADS).not.toContain('http://test');
    });
  });

  describe('SSRF JSON Field Names', () => {
    it('contains common URL-accepting field names', () => {
      expect(SSRF_JSON_FIELD_NAMES).toContain('url');
      expect(SSRF_JSON_FIELD_NAMES).toContain('callback');
      expect(SSRF_JSON_FIELD_NAMES).toContain('webhook');
      expect(SSRF_JSON_FIELD_NAMES).toContain('webhookUrl');
      expect(SSRF_JSON_FIELD_NAMES).toContain('imageUrl');
      expect(SSRF_JSON_FIELD_NAMES).toContain('redirect');
    });

    it('has at least 20 field names', () => {
      expect(SSRF_JSON_FIELD_NAMES.length).toBeGreaterThanOrEqual(20);
    });

    it('all field names are non-empty strings', () => {
      for (const name of SSRF_JSON_FIELD_NAMES) {
        expect(name).toBeTruthy();
        expect(typeof name).toBe('string');
      }
    });
  });

  describe('SSRF Internal Service Probes', () => {
    it('has at least 15 service probes', () => {
      expect(SSRF_INTERNAL_SERVICE_PROBES.length).toBeGreaterThanOrEqual(15);
    });

    it('includes Kubernetes API probes', () => {
      const k8s = SSRF_INTERNAL_SERVICE_PROBES.filter(p => p.service.includes('Kubernetes') || p.service.includes('Kubelet'));
      expect(k8s.length).toBeGreaterThanOrEqual(2);
    });

    it('includes Docker daemon probes', () => {
      const docker = SSRF_INTERNAL_SERVICE_PROBES.filter(p => p.service.includes('Docker'));
      expect(docker.length).toBeGreaterThanOrEqual(2);
    });

    it('includes Consul probes', () => {
      const consul = SSRF_INTERNAL_SERVICE_PROBES.filter(p => p.service.includes('Consul'));
      expect(consul.length).toBeGreaterThanOrEqual(1);
    });

    it('includes etcd probes', () => {
      const etcd = SSRF_INTERNAL_SERVICE_PROBES.filter(p => p.service.includes('etcd'));
      expect(etcd.length).toBeGreaterThanOrEqual(1);
    });

    it('includes Elasticsearch probes', () => {
      const es = SSRF_INTERNAL_SERVICE_PROBES.filter(p => p.service.includes('Elasticsearch'));
      expect(es.length).toBeGreaterThanOrEqual(1);
    });

    it('includes database probes (Redis, CouchDB)', () => {
      const db = SSRF_INTERNAL_SERVICE_PROBES.filter(p =>
        p.service.includes('Redis') || p.service.includes('CouchDB'),
      );
      expect(db.length).toBeGreaterThanOrEqual(2);
    });

    it('includes monitoring probes (Prometheus, Grafana)', () => {
      const monitoring = SSRF_INTERNAL_SERVICE_PROBES.filter(p =>
        p.service.includes('Prometheus') || p.service.includes('Grafana'),
      );
      expect(monitoring.length).toBeGreaterThanOrEqual(2);
    });

    it('all probes have url, indicator, service, and severity', () => {
      for (const probe of SSRF_INTERNAL_SERVICE_PROBES) {
        expect(probe.url).toBeTruthy();
        expect(probe.indicator).toBeInstanceOf(RegExp);
        expect(probe.service).toBeTruthy();
        expect(['critical', 'high']).toContain(probe.severity);
      }
    });

    it('Kubernetes/Docker/etcd/Consul probes are critical severity', () => {
      const criticalServices = SSRF_INTERNAL_SERVICE_PROBES.filter(p =>
        p.service.includes('Kubernetes') || p.service.includes('Docker') ||
        p.service.includes('etcd') || p.service === 'Consul KV Store',
      );
      for (const probe of criticalServices) {
        expect(probe.severity).toBe('critical');
      }
    });
  });

  describe('Cloud Metadata Probes', () => {
    it('includes AWS, GCP, Azure, DigitalOcean, Alibaba', () => {
      const clouds = CLOUD_METADATA_PROBES.map(p => p.cloud);
      expect(clouds.some(c => c.includes('AWS'))).toBe(true);
      expect(clouds.some(c => c.includes('GCP'))).toBe(true);
      expect(clouds.some(c => c.includes('Azure'))).toBe(true);
      expect(clouds.some(c => c.includes('DigitalOcean'))).toBe(true);
      expect(clouds.some(c => c.includes('Alibaba'))).toBe(true);
    });

    it('all cloud metadata probes are critical severity', () => {
      for (const probe of CLOUD_METADATA_PROBES) {
        expect(probe.severity).toBe('critical');
      }
    });
  });

  describe('SSRF Indicators (extended)', () => {
    it('matches obfuscated IP error messages', () => {
      const hexError = 'Could not fetch 0x7f000001: connection refused';
      const decimalError = 'Could not fetch 2130706433: timeout';
      const nipError = 'Could not fetch 127.0.0.1.nip.io: ECONNREFUSED';
      const localtestError = 'Could not fetch localtest.me: EHOSTUNREACH';

      expect(SSRF_INDICATORS.some(i => i.test(hexError))).toBe(true);
      expect(SSRF_INDICATORS.some(i => i.test(decimalError))).toBe(true);
      expect(SSRF_INDICATORS.some(i => i.test(nipError))).toBe(true);
      expect(SSRF_INDICATORS.some(i => i.test(localtestError))).toBe(true);
    });

    it('still matches original indicators', () => {
      expect(SSRF_INDICATORS.some(i => i.test('root:x:0:0:root:/root'))).toBe(true);
      expect(SSRF_INDICATORS.some(i => i.test('ami-id'))).toBe(true);
      expect(SSRF_INDICATORS.some(i => i.test('Connection refused'))).toBe(true);
    });
  });
});
