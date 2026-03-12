import { describe, it, expect } from 'vitest';
import { EscalationQueue } from '../../src/hunting/escalation.js';
import type { RawFinding } from '../../src/scanner/types.js';

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: 'finding-001',
    category: 'xss',
    severity: 'medium',
    title: 'Reflected XSS',
    description: 'XSS in search param',
    url: 'https://example.com/search?q=test',
    evidence: '<script>alert(1)</script>',
    timestamp: new Date().toISOString(),
    confidence: 'medium',
    ...overrides,
  };
}

describe('EscalationQueue', () => {
  it('starts with no items', () => {
    const queue = new EscalationQueue();
    expect(queue.getItems()).toHaveLength(0);
  });

  describe('addBlocked', () => {
    it('adds a blocked item with reason', () => {
      const queue = new EscalationQueue();
      queue.addBlocked('https://example.com/login', 'captcha');
      const items = queue.getItems();
      expect(items).toHaveLength(1);
      expect(items[0].url).toBe('https://example.com/login');
      expect(items[0].reason).toBe('captcha');
    });

    it('adds optional type field', () => {
      const queue = new EscalationQueue();
      queue.addBlocked('https://example.com/api', 'rate-limited', 'api-endpoint');
      const items = queue.getItems();
      expect(items[0].type).toBe('api-endpoint');
    });

    it('sets a timestamp', () => {
      const queue = new EscalationQueue();
      const before = new Date().toISOString();
      queue.addBlocked('https://example.com/', '2fa-required');
      const after = new Date().toISOString();
      const ts = queue.getItems()[0].timestamp;
      expect(ts >= before).toBe(true);
      expect(ts <= after).toBe(true);
    });

    it('can add multiple blocked items', () => {
      const queue = new EscalationQueue();
      queue.addBlocked('https://a.com', 'captcha');
      queue.addBlocked('https://b.com', 'auth-required');
      queue.addBlocked('https://c.com', 'rate-limited');
      expect(queue.getItems()).toHaveLength(3);
    });
  });

  describe('addAmbiguousFinding', () => {
    it('adds an ambiguous-finding item', () => {
      const queue = new EscalationQueue();
      const finding = makeFinding();
      queue.addAmbiguousFinding(finding);
      const items = queue.getItems();
      expect(items).toHaveLength(1);
      expect(items[0].reason).toBe('ambiguous-finding');
    });

    it('uses the finding url', () => {
      const queue = new EscalationQueue();
      const finding = makeFinding({ url: 'https://example.com/vuln' });
      queue.addAmbiguousFinding(finding);
      expect(queue.getItems()[0].url).toBe('https://example.com/vuln');
    });

    it('uses finding confidence when present', () => {
      const queue = new EscalationQueue();
      const finding = makeFinding({ confidence: 'low' });
      queue.addAmbiguousFinding(finding);
      expect(queue.getItems()[0].confidence).toBe('low');
    });

    it('defaults confidence to medium when not set', () => {
      const queue = new EscalationQueue();
      const finding = makeFinding({ confidence: undefined });
      queue.addAmbiguousFinding(finding);
      expect(queue.getItems()[0].confidence).toBe('medium');
    });

    it('stores findingId', () => {
      const queue = new EscalationQueue();
      const finding = makeFinding({ id: 'abc-123' });
      queue.addAmbiguousFinding(finding);
      expect(queue.getItems()[0].findingId).toBe('abc-123');
    });
  });

  describe('getItems', () => {
    it('returns a copy of items (not the internal array)', () => {
      const queue = new EscalationQueue();
      queue.addBlocked('https://example.com', 'captcha');
      const items = queue.getItems();
      items.push({ url: 'injected', reason: 'captcha', timestamp: '' });
      expect(queue.getItems()).toHaveLength(1);
    });
  });

  describe('toJSON', () => {
    it('returns correct structure', () => {
      const queue = new EscalationQueue();
      queue.setTarget('https://example.com');
      queue.setCompleted(42);
      queue.addBlocked('https://example.com/login', 'captcha');

      const json = queue.toJSON();
      expect(json.target).toBe('https://example.com');
      expect(json.completed).toBe(42);
      expect(json.needsHuman).toBe(1);
      expect(json.blocked).toHaveLength(1);
      expect(typeof json.scanDate).toBe('string');
    });

    it('needsHuman equals the number of items', () => {
      const queue = new EscalationQueue();
      queue.addBlocked('https://a.com', 'captcha');
      queue.addBlocked('https://b.com', 'rate-limited');
      queue.addAmbiguousFinding(makeFinding());
      expect(queue.toJSON().needsHuman).toBe(3);
    });

    it('starts with empty blocked array', () => {
      const queue = new EscalationQueue();
      expect(queue.toJSON().blocked).toHaveLength(0);
      expect(queue.toJSON().needsHuman).toBe(0);
    });

    it('sets completed from setCompleted', () => {
      const queue = new EscalationQueue();
      queue.setCompleted(100);
      expect(queue.toJSON().completed).toBe(100);
    });
  });
});
