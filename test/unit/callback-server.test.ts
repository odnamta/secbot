import { describe, it, expect, afterEach } from 'vitest';
import { CallbackServer } from '../../src/scanner/oob/callback-server.js';

describe('CallbackServer', () => {
  let server: CallbackServer;

  afterEach(async () => {
    if (server?.isRunning()) {
      await server.stop();
    }
  });

  describe('start / stop lifecycle', () => {
    it('starts and stops without error', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0); // port 0 = OS assigns random available port
      expect(server.isRunning()).toBe(true);
      await server.stop();
      expect(server.isRunning()).toBe(false);
    });

    it('throws when starting a server that is already running', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      await expect(server.start(0)).rejects.toThrow('already running');
    });

    it('stop is idempotent when server is not running', async () => {
      server = new CallbackServer('127.0.0.1');
      // Stopping a server that was never started should not throw
      await expect(server.stop()).resolves.toBeUndefined();
    });
  });

  describe('generateCallbackUrl', () => {
    it('generates a URL with the payload ID in the path', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      const url = server.generateCallbackUrl('test-payload-123');
      expect(url).toContain('/cb/test-payload-123');
      expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/cb\/test-payload-123$/);
    });

    it('uses 127.0.0.1 when host is 0.0.0.0', async () => {
      server = new CallbackServer('0.0.0.0');
      await server.start(0);
      const url = server.generateCallbackUrl('xyz');
      expect(url).toContain('http://127.0.0.1:');
    });

    it('preserves custom host', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      const url = server.generateCallbackUrl('abc');
      expect(url).toContain('http://127.0.0.1:');
    });
  });

  describe('hit detection', () => {
    it('starts with zero hits', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      expect(server.getHits()).toEqual([]);
    });

    it('records a hit when a request is received at /cb/<id>', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      const cbUrl = server.generateCallbackUrl('my-payload');

      // Send a request to the callback server
      const response = await fetch(cbUrl);
      expect(response.status).toBe(200);

      // Allow a small delay for the handler to process
      await new Promise((r) => setTimeout(r, 50));

      const hits = server.getHits();
      expect(hits).toHaveLength(1);
      expect(hits[0].payloadId).toBe('my-payload');
      expect(hits[0].method).toBe('GET');
      expect(hits[0].path).toBe('/cb/my-payload');
      expect(hits[0].timestamp).toBeTruthy();
      expect(hits[0].sourceIp).toBeTruthy();
    });

    it('records multiple hits from different payload IDs', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);

      await fetch(server.generateCallbackUrl('payload-a'));
      await fetch(server.generateCallbackUrl('payload-b'));
      await fetch(server.generateCallbackUrl('payload-c'));

      await new Promise((r) => setTimeout(r, 50));

      const hits = server.getHits();
      expect(hits).toHaveLength(3);
      expect(hits.map((h) => h.payloadId)).toEqual(['payload-a', 'payload-b', 'payload-c']);
    });

    it('captures POST body', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      const cbUrl = server.generateCallbackUrl('post-test');

      await fetch(cbUrl, {
        method: 'POST',
        body: 'exfiltrated=data',
        headers: { 'Content-Type': 'text/plain' },
      });

      await new Promise((r) => setTimeout(r, 50));

      const hits = server.getHits();
      expect(hits).toHaveLength(1);
      expect(hits[0].method).toBe('POST');
      expect(hits[0].body).toBe('exfiltrated=data');
    });

    it('captures request headers', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);
      const cbUrl = server.generateCallbackUrl('header-test');

      await fetch(cbUrl, {
        headers: { 'X-Custom-Header': 'test-value' },
      });

      await new Promise((r) => setTimeout(r, 50));

      const hits = server.getHits();
      expect(hits).toHaveLength(1);
      expect(hits[0].headers['x-custom-header']).toBe('test-value');
    });

    it('getHits returns a copy, not a reference', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(0);

      await fetch(server.generateCallbackUrl('copy-test'));
      await new Promise((r) => setTimeout(r, 50));

      const hits1 = server.getHits();
      const hits2 = server.getHits();
      expect(hits1).not.toBe(hits2);
      expect(hits1).toEqual(hits2);
    });
  });

  describe('getPort', () => {
    it('returns the configured port', async () => {
      server = new CallbackServer('127.0.0.1');
      await server.start(9876);
      expect(server.getPort()).toBe(9876);
    });
  });
});
