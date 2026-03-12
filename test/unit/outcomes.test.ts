import { describe, it, expect } from 'vitest';
import { OutcomeTracker } from '../../src/learning/outcomes.js';
import type { OutcomeRecord } from '../../src/learning/types.js';

function makeRecord(overrides: Partial<OutcomeRecord> = {}): OutcomeRecord {
  return {
    findingId: 'f1',
    program: 'test-program',
    category: 'xss',
    techStack: ['react', 'node'],
    outcome: 'accepted',
    submittedAt: new Date().toISOString(),
    ...overrides,
  };
}

describe('OutcomeTracker', () => {
  it('starts with empty state', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    const stats = tracker.getStats();
    expect(stats.total).toBe(0);
    expect(stats.accepted).toBe(0);
    expect(stats.totalBounty).toBe(0);
  });

  it('records an entry and reflects in getStats', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ outcome: 'accepted', bounty: 500 }));
    const stats = tracker.getStats();
    expect(stats.total).toBe(1);
    expect(stats.accepted).toBe(1);
    expect(stats.totalBounty).toBe(500);
  });

  it('aggregates bounty across multiple accepted records', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ outcome: 'accepted', bounty: 200 }));
    tracker.record(makeRecord({ findingId: 'f2', outcome: 'accepted', bounty: 300 }));
    tracker.record(makeRecord({ findingId: 'f3', outcome: 'duplicate' }));
    const stats = tracker.getStats();
    expect(stats.total).toBe(3);
    expect(stats.accepted).toBe(2);
    expect(stats.duplicate).toBe(1);
    expect(stats.totalBounty).toBe(500);
  });

  it('counts all outcome types correctly', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ outcome: 'accepted' }));
    tracker.record(makeRecord({ outcome: 'duplicate' }));
    tracker.record(makeRecord({ outcome: 'informative' }));
    tracker.record(makeRecord({ outcome: 'not-applicable' }));
    tracker.record(makeRecord({ outcome: 'out-of-scope' }));
    const stats = tracker.getStats();
    expect(stats.accepted).toBe(1);
    expect(stats.duplicate).toBe(1);
    expect(stats.informative).toBe(1);
    expect(stats.notApplicable).toBe(1);
    expect(stats.outOfScope).toBe(1);
  });

  it('calculates successRateByCategory — accepts', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ category: 'xss', outcome: 'accepted' }));
    tracker.record(makeRecord({ category: 'xss', outcome: 'accepted' }));
    const rates = tracker.successRateByCategory();
    expect(rates['xss']).toBe(1);
  });

  it('calculates successRateByCategory — rejects', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ category: 'sqli', outcome: 'duplicate' }));
    tracker.record(makeRecord({ category: 'sqli', outcome: 'informative' }));
    const rates = tracker.successRateByCategory();
    expect(rates['sqli']).toBe(0);
  });

  it('calculates successRateByCategory — mixed', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ category: 'cors', outcome: 'accepted' }));
    tracker.record(makeRecord({ category: 'cors', outcome: 'duplicate' }));
    const rates = tracker.successRateByCategory();
    expect(rates['cors']).toBeCloseTo(0.5);
  });

  it('getRecords returns a copy', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord());
    const records = tracker.getRecords();
    expect(records).toHaveLength(1);
    records.pop();
    expect(tracker.getRecords()).toHaveLength(1);
  });

  it('handles missing bounty as 0 in totalBounty', () => {
    const tracker = new OutcomeTracker('/tmp/nonexistent-outcomes.json');
    tracker.record(makeRecord({ outcome: 'accepted' })); // no bounty field
    const stats = tracker.getStats();
    expect(stats.totalBounty).toBe(0);
  });
});
