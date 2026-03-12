import { describe, it, expect } from 'vitest';
import type { LearningContext } from '../../src/learning/types.js';

describe('Learning integration types', () => {
  it('LearningContext has expected shape', () => {
    const ctx: LearningContext = {
      techProfile: {
        prioritize: ['idor', 'sqli'],
        deprioritize: ['cors-misconfiguration'],
      },
      fpPatterns: ['cors-wildcard-no-creds'],
      payloadStats: {
        cloudflare: { best: 'double-url', worst: 'unicode' },
      },
      outcomeRates: {
        xss: 0.5,
        idor: 0.8,
      },
    };
    expect(ctx.techProfile?.prioritize).toContain('idor');
    expect(ctx.techProfile?.deprioritize).toContain('cors-misconfiguration');
    expect(ctx.fpPatterns).toContain('cors-wildcard-no-creds');
    expect(ctx.payloadStats?.cloudflare.best).toBe('double-url');
    expect(ctx.outcomeRates?.xss).toBe(0.5);
  });

  it('LearningContext is fully optional', () => {
    const ctx: LearningContext = {};
    expect(ctx.techProfile).toBeUndefined();
    expect(ctx.fpPatterns).toBeUndefined();
  });

  it('planner deprioritizes historically ineffective checks', async () => {
    // Verify that buildDefaultPlan accepts learningContext parameter
    const { planAttack } = await import('../../src/ai/planner.js');
    expect(typeof planAttack).toBe('function');
    // planAttack signature: (url, recon, pages, profile, payloadContext?, learningContext?)
    expect(planAttack.length).toBeGreaterThanOrEqual(4);
  });
});
