/**
 * Stealth scan utilities — randomize fingerprints and timing to reduce
 * detection by WAFs, IDS, and rate-limiting systems.
 */

/** Pool of realistic browser User-Agent strings (Chrome, Firefox, Safari, Edge). */
const USER_AGENTS = [
  // Chrome on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  // Chrome on macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  // Firefox on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
  // Firefox on macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0',
  // Safari on macOS
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
  // Edge on Windows
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
] as const;

/**
 * Returns a random realistic browser User-Agent string from the pool.
 */
export function getRandomUserAgent(): string {
  const index = Math.floor(Math.random() * USER_AGENTS.length);
  return USER_AGENTS[index];
}

/**
 * Waits for `baseMs` with +/- 50% random jitter.
 * For example, baseMs=500 will wait between 250ms and 750ms.
 */
export async function jitteredDelay(baseMs: number): Promise<void> {
  const jitter = baseMs * 0.5;
  const actual = baseMs - jitter + Math.random() * jitter * 2;
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, actual)));
}

/** Expose the UA pool size for testing. */
export const USER_AGENT_COUNT = USER_AGENTS.length;

// ─── Behavioral Stealth (v1.0) ──────────────────────────────────────

/**
 * Gaussian-distributed delay using Box-Muller transform.
 * Produces human-like timing (bell curve centered on meanMs).
 */
export function gaussianDelay(meanMs: number, stdDev?: number): number {
  const sigma = stdDev ?? meanMs * 0.3;
  // Box-Muller transform
  const u1 = Math.random() || 0.0001; // avoid log(0)
  const u2 = Math.random();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return Math.max(50, Math.round(meanMs + z * sigma));
}

/**
 * Generates a plausible referrer chain for a target URL.
 * Simulates: search engine → landing page → target.
 */
export function generateRefererChain(targetUrl: string): string[] {
  const url = new URL(targetUrl);
  const searchEngines = [
    `https://www.google.com/search?q=${encodeURIComponent(url.hostname)}`,
    `https://www.bing.com/search?q=${encodeURIComponent(url.hostname)}`,
    `https://duckduckgo.com/?q=${encodeURIComponent(url.hostname)}`,
  ];
  const engine = searchEngines[Math.floor(Math.random() * searchEngines.length)];
  const landing = `${url.origin}/`;
  return [engine, landing, targetUrl];
}

/**
 * Simulates basic human behavior on a Playwright page.
 * Mouse movement, scroll, brief pause — for stealth profile.
 */
export async function simulateHumanBehavior(page: { mouse: { move: (x: number, y: number) => Promise<void> }; evaluate: (fn: () => void) => Promise<void> }): Promise<void> {
  // Random mouse movement
  const x = 100 + Math.floor(Math.random() * 800);
  const y = 100 + Math.floor(Math.random() * 400);
  await page.mouse.move(x, y);

  // Small random scroll
  await page.evaluate(() => {
    window.scrollBy(0, Math.floor(Math.random() * 300) + 50);
  });

  // Brief human-like pause
  const pause = gaussianDelay(800);
  await new Promise(resolve => setTimeout(resolve, pause));
}

/** Browser profile for consistent fingerprinting per scan session. */
export interface BrowserProfile {
  userAgent: string;
  viewport: { width: number; height: number };
  locale: string;
  timezoneId: string;
}

/** Common viewport sizes paired with their typical OS/browser combos. */
const VIEWPORT_PROFILES: Array<{ viewport: { width: number; height: number }; indices: number[] }> = [
  // 1920x1080 — desktop Chrome/Edge on Windows
  { viewport: { width: 1920, height: 1080 }, indices: [0, 1, 2, 5, 6, 10, 11] },
  // 1440x900 — macOS Chrome/Safari
  { viewport: { width: 1440, height: 900 }, indices: [3, 4, 7, 8, 9] },
];

/**
 * Builds a consistent browser profile — matched UA + viewport + timezone.
 * Use once per scan to avoid fingerprint inconsistencies.
 */
export function buildConsistentProfile(): BrowserProfile {
  const profile = VIEWPORT_PROFILES[Math.floor(Math.random() * VIEWPORT_PROFILES.length)];
  const uaIndex = profile.indices[Math.floor(Math.random() * profile.indices.length)];
  const ua = USER_AGENTS[uaIndex];
  const isMac = ua.includes('Macintosh');
  return {
    userAgent: ua,
    viewport: profile.viewport,
    locale: 'en-US',
    timezoneId: isMac ? 'America/Los_Angeles' : 'America/New_York',
  };
}
