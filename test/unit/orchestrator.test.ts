import { describe, it, expect } from 'vitest';
import { getDuePrograms, Orchestrator } from '../../src/hunting/orchestrator.js';
import type { Program } from '../../src/hunting/types.js';

function makeProgram(overrides: Partial<Program> = {}): Program {
  return {
    name: 'Test Corp',
    platform: 'hackerone',
    scopeFile: './scopes/test.scope',
    profile: 'standard',
    schedule: 'daily',
    ...overrides,
  };
}

describe('getDuePrograms', () => {
  it('returns programs due for scanning', () => {
    const programs: Program[] = [
      makeProgram({
        name: 'A',
        schedule: 'daily',
        lastScan: new Date(Date.now() - 2 * 86400000).toISOString(),
      }),
      makeProgram({
        name: 'B',
        schedule: 'weekly',
        lastScan: new Date().toISOString(), // scanned today
      }),
    ];
    const due = getDuePrograms(programs);
    expect(due.map(p => p.name)).toContain('A');
    expect(due.map(p => p.name)).not.toContain('B');
  });

  it('includes programs with no lastScan', () => {
    const programs = [makeProgram({ name: 'New', lastScan: undefined })];
    const due = getDuePrograms(programs);
    expect(due).toHaveLength(1);
  });

  it('excludes disabled programs', () => {
    const programs = [makeProgram({ name: 'Off', enabled: false })];
    const due = getDuePrograms(programs);
    expect(due).toHaveLength(0);
  });

  it('returns empty array when no programs due', () => {
    const programs = [
      makeProgram({ schedule: 'monthly', lastScan: new Date().toISOString() }),
    ];
    const due = getDuePrograms(programs);
    expect(due).toHaveLength(0);
  });
});

describe('Orchestrator', () => {
  it('can be instantiated', () => {
    const orch = new Orchestrator({ registryPath: '/tmp/test-registry.yaml' });
    expect(orch).toBeDefined();
  });
});
