import type { ScanConfig, ScanProfile } from '../scanner/types.js';

const PROFILE_SETTINGS: Record<ScanProfile, Partial<ScanConfig>> = {
  quick: {
    maxPages: 5,
    timeout: 15000,
    concurrency: 3,
    requestDelay: 50,
  },
  standard: {
    maxPages: 25,
    timeout: 30000,
    concurrency: 5,
    requestDelay: 100,
  },
  deep: {
    maxPages: 100,
    timeout: 60000,
    concurrency: 10,
    requestDelay: 100,
  },
  stealth: {
    maxPages: 3,
    timeout: 30000,
    concurrency: 1,
    requestDelay: 500, // base delay; actual delay randomized 200-800ms by stealth module
  },
};

export function buildConfig(
  targetUrl: string,
  overrides: Partial<ScanConfig> = {},
): ScanConfig {
  const profile = overrides.profile ?? 'standard';
  const profileDefaults = PROFILE_SETTINGS[profile];

  return {
    targetUrl,
    profile,
    maxPages: parseInt(process.env.SECBOT_MAX_PAGES ?? '', 10) || profileDefaults.maxPages!,
    timeout: parseInt(process.env.SECBOT_TIMEOUT ?? '', 10) || profileDefaults.timeout!,
    respectRobots: true,
    outputFormat: ['terminal'],
    concurrency: profileDefaults.concurrency!,
    requestDelay: profileDefaults.requestDelay!,
    logRequests: false,
    useAI: true,
    ...overrides,
  };
}
