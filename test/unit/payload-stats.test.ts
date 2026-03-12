import { describe, it, expect } from 'vitest';
import { PayloadStats } from '../../src/learning/payload-stats.js';

describe('PayloadStats', () => {
  it('starts empty', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    expect(ps.bestStrategy('cloudflare')).toBeUndefined();
    expect(ps.worstStrategy('cloudflare')).toBeUndefined();
    expect(ps.getStatsForWaf('cloudflare')).toEqual({});
  });

  it('records entries', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    ps.record('cloudflare', 'base64', true);
    ps.record('cloudflare', 'unicode', false);
    const stats = ps.getStatsForWaf('cloudflare');
    expect(stats['base64']).toBeDefined();
    expect(stats['unicode']).toBeDefined();
  });

  it('bestStrategy returns strategy with highest success rate', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    ps.record('cloudflare', 'base64', true);
    ps.record('cloudflare', 'base64', true);
    ps.record('cloudflare', 'unicode', false);
    ps.record('cloudflare', 'unicode', false);
    expect(ps.bestStrategy('cloudflare')).toBe('base64');
  });

  it('worstStrategy returns strategy with lowest success rate', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    ps.record('akamai', 'base64', true);
    ps.record('akamai', 'base64', true);
    ps.record('akamai', 'unicode', false);
    ps.record('akamai', 'unicode', false);
    expect(ps.worstStrategy('akamai')).toBe('unicode');
  });

  it('getStatsForWaf returns correct success/total/rate', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    ps.record('modsec', 'double-encode', true);
    ps.record('modsec', 'double-encode', true);
    ps.record('modsec', 'double-encode', false);
    const stats = ps.getStatsForWaf('modsec');
    expect(stats['double-encode'].success).toBe(2);
    expect(stats['double-encode'].total).toBe(3);
    expect(stats['double-encode'].rate).toBeCloseTo(2 / 3);
  });

  it('isolates stats per WAF', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    ps.record('waf-a', 'strat-x', true);
    ps.record('waf-b', 'strat-x', false);
    const statsA = ps.getStatsForWaf('waf-a');
    const statsB = ps.getStatsForWaf('waf-b');
    expect(statsA['strat-x'].success).toBe(1);
    expect(statsB['strat-x'].success).toBe(0);
  });

  it('bestStrategy returns undefined for unknown waf', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    ps.record('known-waf', 'strat', true);
    expect(ps.bestStrategy('unknown-waf')).toBeUndefined();
  });

  it('worstStrategy returns undefined for unknown waf', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    expect(ps.worstStrategy('unknown-waf')).toBeUndefined();
  });

  it('bestStrategy handles multiple strategies correctly', () => {
    const ps = new PayloadStats('/tmp/nonexistent-payload-stats.json');
    // strat-a: 1/3 = 33%
    ps.record('cf', 'strat-a', true);
    ps.record('cf', 'strat-a', false);
    ps.record('cf', 'strat-a', false);
    // strat-b: 2/2 = 100%
    ps.record('cf', 'strat-b', true);
    ps.record('cf', 'strat-b', true);
    // strat-c: 0/2 = 0%
    ps.record('cf', 'strat-c', false);
    ps.record('cf', 'strat-c', false);
    expect(ps.bestStrategy('cf')).toBe('strat-b');
    expect(ps.worstStrategy('cf')).toBe('strat-c');
  });
});
