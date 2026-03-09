import { describe, it, expect } from 'vitest';
import { raceCheck } from '../../src/scanner/active/race.js';

describe('Race condition check: metadata', () => {
  it('has correct name and category', () => {
    expect(raceCheck.name).toBe('race');
    expect(raceCheck.category).toBe('race-condition');
  });
});
