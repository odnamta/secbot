import { describe, it, expect } from 'vitest';
import { rateLimitCheck } from '../../src/scanner/active/rate-limit.js';

describe('Rate limit check: metadata', () => {
  it('has correct name and category', () => {
    expect(rateLimitCheck.name).toBe('rate-limit');
    expect(rateLimitCheck.category).toBe('rate-limit');
  });
});
