import { describe, it, expect } from 'vitest';
import {
  InteractshClient,
  interactionsToCallbackHits,
  type Interaction,
  type InteractshOptions,
} from '../../src/scanner/oob/interactsh-client.js';

describe('InteractshClient', () => {
  describe('constructor defaults', () => {
    it('uses oast.fun as default server URL', () => {
      const client = new InteractshClient();
      const url = client.getUrl();
      expect(url).toContain('oast.fun');
    });

    it('accepts custom server URL', () => {
      const client = new InteractshClient({ serverUrl: 'https://interact.sh' });
      const url = client.getUrl();
      expect(url).toContain('interact.sh');
    });

    it('strips trailing slashes from server URL', () => {
      const client = new InteractshClient({ serverUrl: 'https://interact.sh///' });
      const url = client.getUrl();
      expect(url).toContain('interact.sh');
      expect(url).not.toContain('///');
    });

    it('starts as not registered', () => {
      const client = new InteractshClient();
      expect(client.isRegistered()).toBe(false);
    });
  });

  describe('getUrl()', () => {
    it('returns correlationId.hostname format', () => {
      const client = new InteractshClient();
      const url = client.getUrl();
      const correlationId = client.getCorrelationId();
      expect(url).toBe(`${correlationId}.oast.fun`);
    });

    it('does not include protocol prefix', () => {
      const client = new InteractshClient();
      const url = client.getUrl();
      expect(url).not.toMatch(/^https?:\/\//);
    });

    it('uses custom server hostname', () => {
      const client = new InteractshClient({ serverUrl: 'https://my-oob.example.com' });
      const url = client.getUrl();
      expect(url).toContain('my-oob.example.com');
    });
  });

  describe('getHttpUrl()', () => {
    it('returns http:// prefixed URL', () => {
      const client = new InteractshClient();
      const httpUrl = client.getHttpUrl();
      expect(httpUrl).toMatch(/^http:\/\//);
    });

    it('contains the correlation ID', () => {
      const client = new InteractshClient();
      const httpUrl = client.getHttpUrl();
      const correlationId = client.getCorrelationId();
      expect(httpUrl).toContain(correlationId);
    });

    it('matches http:// + getUrl()', () => {
      const client = new InteractshClient();
      expect(client.getHttpUrl()).toBe(`http://${client.getUrl()}`);
    });
  });

  describe('getTaggedUrl()', () => {
    it('prepends tag as subdomain', () => {
      const client = new InteractshClient();
      const tagged = client.getTaggedUrl('bssrf-01');
      expect(tagged).toBe(`http://bssrf-01.${client.getUrl()}`);
    });

    it('sanitizes non-DNS-safe characters', () => {
      const client = new InteractshClient();
      const tagged = client.getTaggedUrl('My_Payload!@#$');
      // Should only contain lowercase alphanum and hyphens
      const subdomain = tagged.replace('http://', '').split('.')[0];
      expect(subdomain).toMatch(/^[a-z0-9-]+$/);
    });

    it('converts tag to lowercase', () => {
      const client = new InteractshClient();
      const tagged = client.getTaggedUrl('BXSS-TEST');
      expect(tagged).toContain('bxss-test');
    });

    it('truncates tag to 63 chars max (DNS label limit)', () => {
      const client = new InteractshClient();
      const longTag = 'a'.repeat(100);
      const tagged = client.getTaggedUrl(longTag);
      const subdomain = tagged.replace('http://', '').split('.')[0];
      expect(subdomain.length).toBeLessThanOrEqual(63);
    });

    it('strips leading and trailing hyphens from sanitized tag', () => {
      const client = new InteractshClient();
      const tagged = client.getTaggedUrl('---test---');
      const subdomain = tagged.replace('http://', '').split('.')[0];
      expect(subdomain).not.toMatch(/^-/);
      expect(subdomain).not.toMatch(/-$/);
    });
  });

  describe('correlationId uniqueness', () => {
    it('generates unique correlationId per instance', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 20; i++) {
        ids.add(new InteractshClient().getCorrelationId());
      }
      expect(ids.size).toBe(20);
    });

    it('correlationId is 20 hex characters', () => {
      const client = new InteractshClient();
      const id = client.getCorrelationId();
      expect(id).toMatch(/^[0-9a-f]{20}$/);
    });
  });

  describe('poll() when not registered', () => {
    it('returns empty array when not registered', async () => {
      const client = new InteractshClient();
      const result = await client.poll();
      expect(result).toEqual([]);
    });
  });

  describe('deregister() when not registered', () => {
    it('does nothing when not registered (no throw)', async () => {
      const client = new InteractshClient();
      // Should not throw
      await client.deregister();
      expect(client.isRegistered()).toBe(false);
    });
  });

  describe('Interaction type shape', () => {
    it('matches expected interface fields', () => {
      const interaction: Interaction = {
        protocol: 'http',
        fullId: 'bssrf-01.abc123.oast.fun',
        rawRequest: 'GET / HTTP/1.1\r\nHost: abc123.oast.fun',
        timestamp: '2026-03-26T10:00:00Z',
        remoteAddress: '1.2.3.4',
      };

      expect(interaction.protocol).toBe('http');
      expect(interaction.fullId).toBeTruthy();
      expect(interaction.rawRequest).toBeTruthy();
      expect(interaction.timestamp).toBeTruthy();
      expect(interaction.remoteAddress).toBeTruthy();
    });

    it('allows optional fields to be undefined', () => {
      const interaction: Interaction = {
        protocol: 'dns',
        fullId: 'abc123.oast.fun',
        timestamp: '2026-03-26T10:00:00Z',
      };

      expect(interaction.rawRequest).toBeUndefined();
      expect(interaction.remoteAddress).toBeUndefined();
    });
  });

  describe('InteractshOptions type', () => {
    it('accepts empty options', () => {
      const opts: InteractshOptions = {};
      const client = new InteractshClient(opts);
      expect(client.isRegistered()).toBe(false);
    });

    it('accepts all options', () => {
      const opts: InteractshOptions = {
        serverUrl: 'https://custom.oast.example.com',
        pollInterval: 3000,
        token: 'my-secret-token',
      };
      const client = new InteractshClient(opts);
      expect(client.getUrl()).toContain('custom.oast.example.com');
    });
  });
});

describe('interactionsToCallbackHits()', () => {
  it('converts interactions to CallbackHit-compatible format', () => {
    const interactions: Interaction[] = [
      {
        protocol: 'http',
        fullId: 'bssrf-01.abc123.oast.fun',
        rawRequest: 'GET / HTTP/1.1',
        timestamp: '2026-03-26T10:00:00Z',
        remoteAddress: '1.2.3.4',
      },
    ];

    const hits = interactionsToCallbackHits(interactions);
    expect(hits).toHaveLength(1);
    expect(hits[0].payloadId).toBe('bssrf-01');
    expect(hits[0].timestamp).toBe('2026-03-26T10:00:00Z');
    expect(hits[0].sourceIp).toBe('1.2.3.4');
    expect(hits[0].body).toBe('GET / HTTP/1.1');
  });

  it('extracts tag from subdomain prefix of fullId', () => {
    const interactions: Interaction[] = [
      {
        protocol: 'dns',
        fullId: 'bxss-myid.correlationid.oast.fun',
        timestamp: '2026-03-26T10:00:00Z',
      },
    ];

    const hits = interactionsToCallbackHits(interactions);
    expect(hits[0].payloadId).toBe('bxss-myid');
  });

  it('uses fullId as payloadId when no subdomain tag present', () => {
    const interactions: Interaction[] = [
      {
        protocol: 'http',
        fullId: 'ab',
        timestamp: '2026-03-26T10:00:00Z',
      },
    ];

    const hits = interactionsToCallbackHits(interactions);
    // "ab" has no dots, parts.length <= 2 => payloadId = fullId
    expect(hits[0].payloadId).toBe('ab');
  });

  it('uses DNS as method for DNS protocol interactions', () => {
    const interactions: Interaction[] = [
      {
        protocol: 'dns',
        fullId: 'tag.corr.oast.fun',
        timestamp: '2026-03-26T10:00:00Z',
      },
    ];

    const hits = interactionsToCallbackHits(interactions);
    expect(hits[0].method).toBe('DNS');
  });

  it('uses GET as method for HTTP protocol interactions', () => {
    const interactions: Interaction[] = [
      {
        protocol: 'http',
        fullId: 'tag.corr.oast.fun',
        timestamp: '2026-03-26T10:00:00Z',
      },
    ];

    const hits = interactionsToCallbackHits(interactions);
    expect(hits[0].method).toBe('GET');
  });

  it('defaults sourceIp to "unknown" when remoteAddress is missing', () => {
    const interactions: Interaction[] = [
      {
        protocol: 'http',
        fullId: 'tag.corr.oast.fun',
        timestamp: '2026-03-26T10:00:00Z',
      },
    ];

    const hits = interactionsToCallbackHits(interactions);
    expect(hits[0].sourceIp).toBe('unknown');
  });

  it('returns empty array for empty input', () => {
    expect(interactionsToCallbackHits([])).toEqual([]);
  });
});
