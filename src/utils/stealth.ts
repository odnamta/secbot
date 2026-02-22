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
