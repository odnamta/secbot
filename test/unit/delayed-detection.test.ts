import { describe, it, expect, afterEach } from 'vitest';
import { CallbackServer } from '../../src/scanner/oob/callback-server.js';
import { waitForDelayedCallbacks, getDefaultWaitMs } from '../../src/scanner/oob/delayed-detection.js';

describe('waitForDelayedCallbacks', () => {
  let server: CallbackServer;

  afterEach(async () => {
    if (server?.isRunning()) {
      await server.stop();
    }
  });

  it('returns empty array when no callbacks arrive during wait', async () => {
    server = new CallbackServer('127.0.0.1');
    await server.start(0);

    const hits = await waitForDelayedCallbacks(server, 200);
    expect(hits).toEqual([]);
  });

  it('returns hits that arrive during the wait period', async () => {
    server = new CallbackServer('127.0.0.1');
    await server.start(0);

    // Send a hit after a short delay
    setTimeout(async () => {
      try {
        await fetch(server.generateCallbackUrl('delayed-hit'));
      } catch { /* server may be closed */ }
    }, 50);

    const hits = await waitForDelayedCallbacks(server, 500);
    expect(hits).toHaveLength(1);
    expect(hits[0].payloadId).toBe('delayed-hit');
  });

  it('only returns hits received during the wait, not before', async () => {
    server = new CallbackServer('127.0.0.1');
    await server.start(0);

    // Send a hit before calling waitForDelayedCallbacks
    await fetch(server.generateCallbackUrl('pre-existing'));
    await new Promise((r) => setTimeout(r, 50));

    // Now send one during the wait
    setTimeout(async () => {
      try {
        await fetch(server.generateCallbackUrl('during-wait'));
      } catch { /* server may be closed */ }
    }, 50);

    const delayedHits = await waitForDelayedCallbacks(server, 500);
    expect(delayedHits).toHaveLength(1);
    expect(delayedHits[0].payloadId).toBe('during-wait');

    // Total hits should be 2
    expect(server.getHits()).toHaveLength(2);
  });

  it('returns empty array when server is not running', async () => {
    server = new CallbackServer('127.0.0.1');
    // Not started — isRunning() returns false
    const hits = await waitForDelayedCallbacks(server, 100);
    expect(hits).toEqual([]);
  });

  it('collects multiple delayed hits', async () => {
    server = new CallbackServer('127.0.0.1');
    await server.start(0);

    // Send multiple hits at staggered times
    setTimeout(async () => {
      try {
        await fetch(server.generateCallbackUrl('hit-1'));
      } catch { /* ignore */ }
    }, 30);
    setTimeout(async () => {
      try {
        await fetch(server.generateCallbackUrl('hit-2'));
      } catch { /* ignore */ }
    }, 60);
    setTimeout(async () => {
      try {
        await fetch(server.generateCallbackUrl('hit-3'));
      } catch { /* ignore */ }
    }, 90);

    const hits = await waitForDelayedCallbacks(server, 500);
    expect(hits).toHaveLength(3);
  });
});

describe('getDefaultWaitMs', () => {
  it('returns 30000 (30 seconds)', () => {
    expect(getDefaultWaitMs()).toBe(30000);
  });
});
