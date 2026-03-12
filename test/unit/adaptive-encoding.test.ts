import { describe, it, expect } from 'vitest';
import { AdaptiveEncoder } from '../../src/utils/payload-mutator.js';

describe('AdaptiveEncoder', () => {
  it('starts with first strategy', () => {
    const encoder = new AdaptiveEncoder();
    expect(encoder.currentStrategy()).toBe('none');
  });

  it('switches strategy on block', () => {
    const encoder = new AdaptiveEncoder();
    const first = encoder.currentStrategy();
    encoder.recordBlock();
    const second = encoder.currentStrategy();
    expect(second).not.toBe(first);
  });

  it('stays on current strategy on success', () => {
    const encoder = new AdaptiveEncoder();
    const first = encoder.currentStrategy();
    encoder.recordSuccess();
    expect(encoder.currentStrategy()).toBe(first);
  });

  it('cycles through all strategies before repeating', () => {
    const encoder = new AdaptiveEncoder();
    const seen = new Set<string>();
    for (let i = 0; i < 8; i++) {
      seen.add(encoder.currentStrategy());
      encoder.recordBlock();
    }
    expect(seen.size).toBe(8);
  });

  it('skips already-blocked strategies', () => {
    const encoder = new AdaptiveEncoder(['none', 'url', 'unicode']);
    encoder.recordBlock(); // blocks 'none', moves to 'url'
    expect(encoder.currentStrategy()).toBe('url');
    encoder.recordBlock(); // blocks 'url', moves to 'unicode'
    expect(encoder.currentStrategy()).toBe('unicode');
    encoder.recordBlock(); // blocks 'unicode', all blocked
    expect(encoder.allBlocked()).toBe(true);
  });

  it('allBlocked returns false when strategies remain', () => {
    const encoder = new AdaptiveEncoder(['none', 'url']);
    expect(encoder.allBlocked()).toBe(false);
    encoder.recordBlock();
    expect(encoder.allBlocked()).toBe(false);
    encoder.recordBlock();
    expect(encoder.allBlocked()).toBe(true);
  });

  it('encode applies current strategy', () => {
    const encoder = new AdaptiveEncoder(['none', 'url']);
    expect(encoder.encode('<script>')).toBe('<script>');
    encoder.recordBlock();
    const encoded = encoder.encode('<script>');
    expect(encoded).not.toBe('<script>');
    expect(encoded).toContain('%3C');
  });

  it('remaining counts available strategies', () => {
    const encoder = new AdaptiveEncoder(['none', 'url', 'unicode']);
    expect(encoder.remaining()).toBe(3);
    encoder.recordBlock();
    expect(encoder.remaining()).toBe(2);
  });

  it('accepts custom strategy list', () => {
    const encoder = new AdaptiveEncoder(['url', 'double-url']);
    expect(encoder.currentStrategy()).toBe('url');
    encoder.recordBlock();
    expect(encoder.currentStrategy()).toBe('double-url');
  });
});
