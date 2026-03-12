// src/learning/types.ts
export type OutcomeResult = 'accepted' | 'duplicate' | 'informative' | 'not-applicable' | 'out-of-scope';

export interface OutcomeRecord {
  findingId: string;
  program: string;
  category: string;
  techStack: string[];
  outcome: OutcomeResult;
  bounty?: number;
  submittedAt: string;
  notes?: string;
}

export interface OutcomeStats {
  total: number;
  accepted: number;
  duplicate: number;
  informative: number;
  notApplicable: number;
  outOfScope: number;
  totalBounty: number;
}

export interface FPPattern {
  category: string;
  pattern: string;
  techStack: string[];
  count: number;
  firstSeen: string;
  lastSeen: string;
}

export interface TechRecommendation {
  prioritize: string[];
  deprioritize: string[];
}

export interface LearningContext {
  techProfile?: TechRecommendation;
  fpPatterns?: string[];
  payloadStats?: Record<string, { best: string; worst: string }>;
  outcomeRates?: Record<string, number>;
}
