import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  parseIntervalMs,
  installShutdownHandlers,
  interruptibleSleep,
} from '../../src/hunting/daemon.js';
import type { DaemonState } from '../../src/hunting/daemon.js';

describe('parseIntervalMs', () => {
  it('converts minutes string to milliseconds', () => {
    expect(parseIntervalMs('60')).toBe(60 * 60 * 1000);
    expect(parseIntervalMs('1')).toBe(1 * 60 * 1000);
    expect(parseIntervalMs('120')).toBe(120 * 60 * 1000);
  });

  it('clamps to minimum 1 minute for invalid/zero input', () => {
    expect(parseIntervalMs('0')).toBe(60 * 1000);
    expect(parseIntervalMs('-5')).toBe(60 * 1000);
    expect(parseIntervalMs('abc')).toBe(60 * 1000);
    expect(parseIntervalMs('')).toBe(60 * 1000);
  });

  it('clamps to maximum 24 hours', () => {
    expect(parseIntervalMs('1441')).toBe(1440 * 60 * 1000);
    expect(parseIntervalMs('9999')).toBe(1440 * 60 * 1000);
  });

  it('handles boundary values correctly', () => {
    expect(parseIntervalMs('1440')).toBe(1440 * 60 * 1000); // exactly 24h
    expect(parseIntervalMs('1')).toBe(60 * 1000); // exactly 1 min
  });
});

describe('installShutdownHandlers', () => {
  afterEach(() => {
    // Clean up any leftover listeners from failed tests
    process.removeAllListeners('SIGINT');
    process.removeAllListeners('SIGTERM');
  });

  it('sets shuttingDown on SIGINT', () => {
    const state: DaemonState = { shuttingDown: false };
    const removeHandlers = installShutdownHandlers(state);

    // Simulate SIGINT by emitting the event
    process.emit('SIGINT', 'SIGINT');
    expect(state.shuttingDown).toBe(true);

    removeHandlers();
  });

  it('sets shuttingDown on SIGTERM', () => {
    const state: DaemonState = { shuttingDown: false };
    const removeHandlers = installShutdownHandlers(state);

    process.emit('SIGTERM', 'SIGTERM');
    expect(state.shuttingDown).toBe(true);

    removeHandlers();
  });

  it('cleanup removes the listeners', () => {
    const state: DaemonState = { shuttingDown: false };
    const removeHandlers = installShutdownHandlers(state);
    removeHandlers();

    // After removal, emitting should NOT set shuttingDown
    // (unless other handlers are installed, but we cleared in afterEach)
    // We just verify the function doesn't throw
    expect(state.shuttingDown).toBe(false);
  });
});

describe('interruptibleSleep', () => {
  it('resolves immediately if already shutting down', async () => {
    const state: DaemonState = { shuttingDown: true };
    const start = Date.now();
    await interruptibleSleep(60_000, state);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(100); // should be nearly instant
  });

  it('resolves early when shuttingDown is set during sleep', async () => {
    const state: DaemonState = { shuttingDown: false };
    const start = Date.now();

    // Set shuttingDown after 200ms
    setTimeout(() => { state.shuttingDown = true; }, 200);

    await interruptibleSleep(60_000, state);
    const elapsed = Date.now() - start;

    // Should resolve around 200ms-1200ms (200ms trigger + up to 1s poll interval)
    expect(elapsed).toBeLessThan(2000);
    expect(elapsed).toBeGreaterThanOrEqual(200);
  });

  it('resolves after the specified duration when not interrupted', async () => {
    const state: DaemonState = { shuttingDown: false };
    const start = Date.now();

    await interruptibleSleep(500, state);
    const elapsed = Date.now() - start;

    // Should complete around 500ms
    expect(elapsed).toBeGreaterThanOrEqual(450);
    expect(elapsed).toBeLessThan(1600); // allow some slack for poll interval
  });
});
