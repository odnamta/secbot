import { describe, it, expect } from 'vitest';
import {
  analyzeBurstResults,
  raceCheck,
  type BurstResponseEntry,
  type BurstResult,
} from '../../src/scanner/active/race.js';
import { CHECK_REGISTRY } from '../../src/scanner/active/index.js';

// ─── Helper: build response arrays quickly ──────────────────────────

function makeResponse(
  status: number,
  body: string = '',
  timeMs: number = 50,
): BurstResponseEntry {
  return { status, body, timeMs };
}

function makeResponses(
  count: number,
  status: number,
  body: string = '{"ok":true}',
): BurstResponseEntry[] {
  return Array.from({ length: count }, () => makeResponse(status, body));
}

// ─── Module registration ────────────────────────────────────────────

describe('Race condition check: module registration', () => {
  it('has correct name and category', () => {
    expect(raceCheck.name).toBe('race');
    expect(raceCheck.category).toBe('race-condition');
  });

  it('is present in CHECK_REGISTRY', () => {
    const check = CHECK_REGISTRY.find((c) => c.name === 'race');
    expect(check).toBeDefined();
    expect(check!.category).toBe('race-condition');
  });

  it('is NOT marked as parallel (state-changing requests)', () => {
    expect(raceCheck.parallel).toBeFalsy();
  });
});

// ─── BurstResult type shape ─────────────────────────────────────────

describe('BurstResult type shape', () => {
  it('analyzeBurstResults returns raceDetected boolean and indicators array', () => {
    const result = analyzeBurstResults([]);
    expect(typeof result.raceDetected).toBe('boolean');
    expect(Array.isArray(result.indicators)).toBe(true);
  });

  it('returns false with empty responses', () => {
    const result = analyzeBurstResults([]);
    expect(result.raceDetected).toBe(false);
    expect(result.indicators).toHaveLength(0);
  });

  it('returns false with a single response', () => {
    const result = analyzeBurstResults([makeResponse(200, '{"ok":true}')]);
    expect(result.raceDetected).toBe(false);
  });
});

// ─── Indicator 1: Multiple successes ────────────────────────────────

describe('analyzeBurstResults: multiple successes', () => {
  it('detects when all 10 requests return 200', () => {
    const responses = makeResponses(10, 200);
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('10/10 requests succeeded'))).toBe(true);
  });

  it('detects when 5 of 10 requests return 200', () => {
    const responses = [
      ...makeResponses(5, 200),
      ...makeResponses(5, 409, '{"error":"conflict"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('5/10 requests succeeded'))).toBe(true);
  });

  it('detects 201 Created as success', () => {
    const responses = makeResponses(10, 201, '{"created":true}');
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('10/10 requests succeeded'))).toBe(true);
  });

  it('does NOT flag when only 1 request succeeds (proper protection)', () => {
    const responses = [
      makeResponse(200, '{"ok":true}'),
      ...makeResponses(9, 409, '{"error":"conflict"}'),
    ];
    const result = analyzeBurstResults(responses);
    // 1 success is expected — no "multiple successes" indicator
    const multipleSuccessIndicator = result.indicators.find((i) => i.includes('requests succeeded'));
    expect(multipleSuccessIndicator).toBeUndefined();
  });

  it('does NOT flag when all requests return 409 (all rejected)', () => {
    const responses = makeResponses(10, 409, '{"error":"conflict"}');
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(false);
  });

  it('does NOT flag when all requests return 429 (rate limited)', () => {
    const responses = makeResponses(10, 429, 'Too Many Requests');
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(false);
  });
});

// ─── Indicator 2: Mixed success/error statuses ─────────────────────

describe('analyzeBurstResults: status code inconsistency', () => {
  it('detects mix of 200 and 500 (fragile concurrency)', () => {
    const responses = [
      ...makeResponses(6, 200),
      ...makeResponses(4, 500, 'Internal Server Error'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('Mixed success/error'))).toBe(true);
    expect(result.indicators.some((i) => i.includes('200x6'))).toBe(true);
    expect(result.indicators.some((i) => i.includes('500x4'))).toBe(true);
  });

  it('detects mix of 201 and 502 (server crash under concurrency)', () => {
    const responses = [
      ...makeResponses(3, 201, '{"id":"abc"}'),
      ...makeResponses(7, 502, 'Bad Gateway'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('Mixed success/error'))).toBe(true);
  });

  it('does NOT flag mix of 200 and 409 (proper rejection, no 5xx)', () => {
    const responses = [
      ...makeResponses(1, 200),
      ...makeResponses(9, 409, '{"error":"conflict"}'),
    ];
    const result = analyzeBurstResults(responses);
    // 409 is not a 5xx, so no "mixed" indicator
    const mixedIndicator = result.indicators.find((i) => i.includes('Mixed success/error'));
    expect(mixedIndicator).toBeUndefined();
  });

  it('does NOT flag all-500 (server just broken, not a race)', () => {
    const responses = makeResponses(10, 500, 'error');
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(false);
  });
});

// ─── Indicator 3: Body variation (inconsistent state) ───────────────

describe('analyzeBurstResults: body variation', () => {
  it('detects 4 different bodies across 10 responses', () => {
    const responses = [
      ...makeResponses(3, 200, '{"balance":100}'),
      ...makeResponses(3, 200, '{"balance":90}'),
      ...makeResponses(2, 200, '{"balance":80}'),
      ...makeResponses(2, 200, '{"balance":70}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(
      result.indicators.some((i) => i.includes('4 different response bodies') && i.includes('inconsistent state')),
    ).toBe(true);
  });

  it('does NOT flag body variation with fewer than 5 responses', () => {
    const responses = [
      makeResponse(200, '{"a":1}'),
      makeResponse(200, '{"a":2}'),
      makeResponse(200, '{"a":3}'),
      makeResponse(200, '{"a":4}'),
    ];
    const result = analyzeBurstResults(responses);
    // Only 4 responses — threshold is >= 5
    const bodyIndicator = result.indicators.find((i) => i.includes('different response bodies'));
    expect(bodyIndicator).toBeUndefined();
  });

  it('does NOT flag when only 2 unique bodies exist (normal binary outcome)', () => {
    const responses = [
      ...makeResponses(5, 200, '{"ok":true}'),
      ...makeResponses(5, 200, '{"ok":false}'),
    ];
    const result = analyzeBurstResults(responses);
    // 2 unique bodies is <= 2, so no "inconsistent state" indicator
    const bodyIndicator = result.indicators.find((i) => i.includes('different response bodies'));
    expect(bodyIndicator).toBeUndefined();
  });

  it('ignores empty bodies in uniqueness count', () => {
    const responses = [
      ...makeResponses(5, 200, ''),
      ...makeResponses(3, 200, '{"ok":true}'),
      ...makeResponses(2, 200, '{"ok":false}'),
    ];
    const result = analyzeBurstResults(responses);
    // Only 2 non-empty unique bodies — shouldn't trigger
    const bodyIndicator = result.indicators.find((i) => i.includes('different response bodies'));
    expect(bodyIndicator).toBeUndefined();
  });
});

// ─── Indicator 4: Duplicate IDs ─────────────────────────────────────

describe('analyzeBurstResults: duplicate IDs', () => {
  it('detects duplicate order_id across responses', () => {
    const responses = [
      makeResponse(200, '{"order_id":"ORD-123","status":"created"}'),
      makeResponse(200, '{"order_id":"ORD-123","status":"created"}'),
      makeResponse(200, '{"order_id":"ORD-124","status":"created"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(true);
    expect(result.indicators.some((i) => i.includes('3 total, 2 unique'))).toBe(true);
  });

  it('detects duplicate transaction_id', () => {
    const responses = [
      makeResponse(200, '{"transaction_id":"TXN-001"}'),
      makeResponse(200, '{"transaction_id":"TXN-001"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(true);
  });

  it('detects duplicate id field', () => {
    const responses = [
      makeResponse(200, '{"id":"abc-def-123"}'),
      makeResponse(200, '{"id":"abc-def-123"}'),
      makeResponse(200, '{"id":"abc-def-456"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(true);
  });

  it('detects duplicate txn_id', () => {
    const responses = [
      makeResponse(200, '{"txn_id":"T100"}'),
      makeResponse(200, '{"txn_id":"T100"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
  });

  it('detects duplicate confirmation_id', () => {
    const responses = [
      makeResponse(200, '{"confirmation_id":"CONF-A"}'),
      makeResponse(200, '{"confirmation_id":"CONF-A"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
  });

  it('detects duplicate booking_id', () => {
    const responses = [
      makeResponse(200, '{"booking_id":"BK-999"}'),
      makeResponse(200, '{"booking_id":"BK-999"}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
  });

  it('does NOT flag when all IDs are unique', () => {
    const responses = [
      makeResponse(200, '{"order_id":"ORD-001"}'),
      makeResponse(200, '{"order_id":"ORD-002"}'),
      makeResponse(200, '{"order_id":"ORD-003"}'),
    ];
    const result = analyzeBurstResults(responses);
    const dupIndicator = result.indicators.find((i) => i.includes('Duplicate IDs'));
    expect(dupIndicator).toBeUndefined();
  });

  it('does NOT flag when only one response has an ID', () => {
    const responses = [
      makeResponse(200, '{"order_id":"ORD-001"}'),
      makeResponse(409, '{"error":"conflict"}'),
    ];
    const result = analyzeBurstResults(responses);
    const dupIndicator = result.indicators.find((i) => i.includes('Duplicate IDs'));
    expect(dupIndicator).toBeUndefined();
  });

  it('handles numeric ID values (without quotes)', () => {
    const responses = [
      makeResponse(200, '{"id": 42}'),
      makeResponse(200, '{"id": 42}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(true);
  });
});

// ─── Combined indicators ────────────────────────────────────────────

describe('analyzeBurstResults: combined indicators', () => {
  it('reports multiple indicators simultaneously', () => {
    // All succeed + duplicate IDs + body variation
    const responses = [
      makeResponse(200, '{"order_id":"ORD-1","balance":100}'),
      makeResponse(200, '{"order_id":"ORD-1","balance":90}'),
      makeResponse(200, '{"order_id":"ORD-2","balance":80}'),
      makeResponse(500, '{"order_id":"ORD-1","balance":70}'),
      makeResponse(200, '{"order_id":"ORD-1","balance":60}'),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    // Should have at least: multiple successes + mixed statuses + duplicate IDs
    expect(result.indicators.length).toBeGreaterThanOrEqual(3);
    expect(result.indicators.some((i) => i.includes('requests succeeded'))).toBe(true);
    expect(result.indicators.some((i) => i.includes('Mixed success/error'))).toBe(true);
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(true);
  });

  it('classic double-spend scenario: all 200, same order ID', () => {
    const body = '{"order_id":"ORD-DOUBLE","amount":50,"status":"completed"}';
    const responses = makeResponses(10, 200, body);
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    // Multiple successes + duplicate IDs
    expect(result.indicators.some((i) => i.includes('10/10 requests succeeded'))).toBe(true);
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(true);
  });
});

// ─── Edge cases ─────────────────────────────────────────────────────

describe('analyzeBurstResults: edge cases', () => {
  it('handles responses with no JSON body', () => {
    const responses = makeResponses(10, 200, 'OK');
    const result = analyzeBurstResults(responses);
    // Should still detect multiple successes
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('10/10 requests succeeded'))).toBe(true);
    // But no duplicate ID indicator
    expect(result.indicators.some((i) => i.includes('Duplicate IDs'))).toBe(false);
  });

  it('handles responses with HTML body', () => {
    const responses = makeResponses(10, 200, '<html><body>Success</body></html>');
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('requests succeeded'))).toBe(true);
  });

  it('handles mixed 2xx codes (200 + 204)', () => {
    const responses = [
      ...makeResponses(5, 200, '{"ok":true}'),
      ...makeResponses(5, 204, ''),
    ];
    const result = analyzeBurstResults(responses);
    expect(result.raceDetected).toBe(true);
    expect(result.indicators.some((i) => i.includes('10/10 requests succeeded'))).toBe(true);
  });

  it('two identical responses do not trigger body variation', () => {
    const responses = makeResponses(10, 200, '{"same":"body"}');
    const result = analyzeBurstResults(responses);
    const bodyIndicator = result.indicators.find((i) => i.includes('different response bodies'));
    expect(bodyIndicator).toBeUndefined();
  });

  it('handles very large response bodies (truncated to 1000 chars in real use)', () => {
    const longBody = '{"data":"' + 'x'.repeat(5000) + '"}';
    const responses = makeResponses(5, 200, longBody);
    const result = analyzeBurstResults(responses);
    // Should still work — analysis does not care about body length
    expect(result.raceDetected).toBe(true);
  });
});
