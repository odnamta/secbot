import { describe, it, expect } from 'vitest';
import { TechProfiler } from '../../src/learning/tech-profiles.js';

describe('TechProfiler', () => {
  it('starts empty', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    const rec = tp.recommend(['react']);
    expect(rec.prioritize).toHaveLength(0);
    expect(rec.deprioritize).toHaveLength(0);
  });

  it('returns empty recommendation with fewer than 3 records', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    tp.record(['react'], 'xss', true);
    tp.record(['react'], 'xss', true);
    const rec = tp.recommend(['react']);
    expect(rec.prioritize).toHaveLength(0);
    expect(rec.deprioritize).toHaveLength(0);
  });

  it('prioritizes category with >= 50% effectiveness and >= 3 records', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    tp.record(['react'], 'xss', true);
    tp.record(['react'], 'xss', true);
    tp.record(['react'], 'xss', true);
    const rec = tp.recommend(['react']);
    expect(rec.prioritize).toContain('xss');
    expect(rec.deprioritize).not.toContain('xss');
  });

  it('deprioritizes category with < 20% effectiveness and >= 3 records', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    tp.record(['django'], 'sqli', false);
    tp.record(['django'], 'sqli', false);
    tp.record(['django'], 'sqli', false);
    tp.record(['django'], 'sqli', false);
    tp.record(['django'], 'sqli', false);
    // 0/5 = 0% — below 20%
    const rec = tp.recommend(['django']);
    expect(rec.deprioritize).toContain('sqli');
    expect(rec.prioritize).not.toContain('sqli');
  });

  it('does not classify category with rate between 20% and 50%', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    // 1/4 = 25% — between 20% and 50%, should be in neither list
    tp.record(['vue'], 'cors', true);
    tp.record(['vue'], 'cors', false);
    tp.record(['vue'], 'cors', false);
    tp.record(['vue'], 'cors', false);
    const rec = tp.recommend(['vue']);
    expect(rec.prioritize).not.toContain('cors');
    expect(rec.deprioritize).not.toContain('cors');
  });

  it('matches tech stack order-insensitively', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    tp.record(['node', 'react'], 'xss', true);
    tp.record(['react', 'node'], 'xss', true);
    tp.record(['node', 'react'], 'xss', true);
    // should still match as the same tech stack regardless of input order
    const rec = tp.recommend(['react', 'node']);
    expect(rec.prioritize).toContain('xss');
  });

  it('does not mix records from different tech stacks', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    tp.record(['react'], 'xss', true);
    tp.record(['react'], 'xss', true);
    tp.record(['react'], 'xss', true);
    // vue stack has no records
    const rec = tp.recommend(['vue']);
    expect(rec.prioritize).toHaveLength(0);
  });

  it('handles multiple categories independently', () => {
    const tp = new TechProfiler('/tmp/nonexistent-tech-profiles.json');
    // xss: 3/3 effective → prioritize
    tp.record(['node'], 'xss', true);
    tp.record(['node'], 'xss', true);
    tp.record(['node'], 'xss', true);
    // sqli: 0/3 effective → deprioritize
    tp.record(['node'], 'sqli', false);
    tp.record(['node'], 'sqli', false);
    tp.record(['node'], 'sqli', false);
    const rec = tp.recommend(['node']);
    expect(rec.prioritize).toContain('xss');
    expect(rec.deprioritize).toContain('sqli');
  });
});
