import { describe, it, expect } from 'vitest';
import { FPMemory } from '../../src/learning/fp-memory.js';

describe('FPMemory', () => {
  it('starts with no patterns', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    expect(fp.getPatterns()).toHaveLength(0);
  });

  it('records a new pattern', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: '<script>alert(1)</script>', techStack: ['react'], count: 1 });
    expect(fp.getPatterns()).toHaveLength(1);
    expect(fp.getPatterns()[0].count).toBe(1);
  });

  it('increments count when same pattern recorded again', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: 'test-pattern', techStack: [], count: 1 });
    fp.record({ category: 'xss', pattern: 'test-pattern', techStack: [], count: 2 });
    const patterns = fp.getPatterns();
    expect(patterns).toHaveLength(1);
    expect(patterns[0].count).toBe(3);
  });

  it('does not merge patterns with different category', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: 'same-pattern', techStack: [], count: 1 });
    fp.record({ category: 'sqli', pattern: 'same-pattern', techStack: [], count: 1 });
    expect(fp.getPatterns()).toHaveLength(2);
  });

  it('does not merge patterns with different pattern string', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: 'pattern-a', techStack: [], count: 1 });
    fp.record({ category: 'xss', pattern: 'pattern-b', techStack: [], count: 1 });
    expect(fp.getPatterns()).toHaveLength(2);
  });

  it('isKnownFP returns true when count >= 1', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: 'known', techStack: [], count: 1 });
    expect(fp.isKnownFP('xss', 'known')).toBe(true);
  });

  it('isKnownFP returns false for unknown pattern', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    expect(fp.isKnownFP('xss', 'unknown')).toBe(false);
  });

  it('confidenceAdjustment returns downgrade when count >= 3', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'sqli', pattern: 'fp-pattern', techStack: [], count: 3 });
    expect(fp.confidenceAdjustment('sqli', 'fp-pattern')).toBe('downgrade');
  });

  it('confidenceAdjustment returns none when count < 3', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'sqli', pattern: 'low-count', techStack: [], count: 2 });
    expect(fp.confidenceAdjustment('sqli', 'low-count')).toBe('none');
  });

  it('confidenceAdjustment returns none for unknown pattern', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    expect(fp.confidenceAdjustment('sqli', 'nope')).toBe('none');
  });

  it('getPatternsForCategory filters correctly', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: 'p1', techStack: [], count: 1 });
    fp.record({ category: 'xss', pattern: 'p2', techStack: [], count: 1 });
    fp.record({ category: 'sqli', pattern: 'p3', techStack: [], count: 1 });
    const xssPatterns = fp.getPatternsForCategory('xss');
    expect(xssPatterns).toHaveLength(2);
    expect(xssPatterns.every(p => p.category === 'xss')).toBe(true);
  });

  it('getPatterns returns a copy', () => {
    const fp = new FPMemory('/tmp/nonexistent-fp.json');
    fp.record({ category: 'xss', pattern: 'x', techStack: [], count: 1 });
    const patterns = fp.getPatterns();
    patterns.pop();
    expect(fp.getPatterns()).toHaveLength(1);
  });
});
