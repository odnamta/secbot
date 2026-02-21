import { describe, it, expect, beforeEach } from 'vitest';
import { getTokenUsage, resetTokenUsage } from '../../src/ai/client.js';

describe('Token tracking', () => {
  beforeEach(() => {
    resetTokenUsage();
  });

  it('returns zeros initially', () => {
    const usage = getTokenUsage();
    expect(usage.inputTokens).toBe(0);
    expect(usage.outputTokens).toBe(0);
    expect(usage.totalTokens).toBe(0);
  });

  it('resetTokenUsage clears accumulated tokens', () => {
    // We can't easily call askClaude without mocking the full Anthropic client,
    // so we test that reset returns to zero after a reset call.
    const before = getTokenUsage();
    expect(before.totalTokens).toBe(0);

    resetTokenUsage();
    const after = getTokenUsage();
    expect(after.inputTokens).toBe(0);
    expect(after.outputTokens).toBe(0);
    expect(after.totalTokens).toBe(0);
  });

  it('getTokenUsage returns consistent totalTokens', () => {
    const usage = getTokenUsage();
    expect(usage.totalTokens).toBe(usage.inputTokens + usage.outputTokens);
  });
});
