import { log } from '../../utils/logger.js';
import type { CallbackServer, CallbackHit } from './callback-server.js';

const DEFAULT_WAIT_MS = 30_000;

/**
 * Wait for delayed out-of-band callbacks after the injection phase.
 *
 * Many blind vulnerabilities (stored XSS, async SSRF, cron-triggered SQLi)
 * only fire after a delay. This function keeps the callback server running
 * for the specified duration and collects any hits that arrive.
 *
 * @param server - The running CallbackServer instance
 * @param waitMs - How long to wait in milliseconds (default: 30000)
 * @returns All callback hits received during the wait period
 */
export async function waitForDelayedCallbacks(
  server: CallbackServer,
  waitMs: number = DEFAULT_WAIT_MS,
): Promise<CallbackHit[]> {
  if (!server.isRunning()) {
    log.warn('Callback server is not running — skipping delayed detection');
    return [];
  }

  const hitsBefore = server.getHits().length;
  const waitSeconds = Math.round(waitMs / 1000);

  log.info(`Waiting ${waitSeconds}s for delayed out-of-band callbacks...`);

  // Report progress every 5 seconds
  const intervalMs = 5_000;
  const intervals = Math.ceil(waitMs / intervalMs);

  for (let i = 0; i < intervals; i++) {
    const remaining = waitMs - i * intervalMs;
    const sleepFor = Math.min(intervalMs, remaining);

    await sleep(sleepFor);

    const currentHits = server.getHits().length;
    const newHits = currentHits - hitsBefore;

    if (newHits > 0) {
      log.info(
        `  ${newHits} new callback(s) received (${Math.round((i + 1) * intervalMs / 1000)}s elapsed)`,
      );
    }
  }

  const allHits = server.getHits();
  const delayedHits = allHits.slice(hitsBefore);

  if (delayedHits.length > 0) {
    log.info(`Delayed detection complete: ${delayedHits.length} new callback(s) received`);
  } else {
    log.info('Delayed detection complete: no new callbacks received');
  }

  return delayedHits;
}

/**
 * Get the default wait time in milliseconds.
 */
export function getDefaultWaitMs(): number {
  return DEFAULT_WAIT_MS;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
