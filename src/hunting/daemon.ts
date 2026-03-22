/**
 * Daemon control logic for continuous hunt mode.
 * Handles graceful shutdown, interruptible sleep, and interval parsing.
 */

import { log } from '../utils/logger.js';

export interface DaemonState {
  shuttingDown: boolean;
}

/**
 * Parse interval string (minutes) to milliseconds.
 * Returns the interval clamped to [1 minute, 24 hours].
 */
export function parseIntervalMs(intervalStr: string): number {
  const minutes = parseInt(intervalStr, 10);
  if (isNaN(minutes) || minutes < 1) return 60 * 1000; // minimum 1 minute
  if (minutes > 1440) return 1440 * 60 * 1000; // maximum 24 hours
  return minutes * 60 * 1000;
}

/**
 * Install SIGINT/SIGTERM handlers that set shuttingDown = true
 * instead of immediately exiting. Returns cleanup function.
 */
export function installShutdownHandlers(state: DaemonState): () => void {
  const onSigint = () => {
    log.info('Received SIGINT — finishing current cycle and shutting down...');
    state.shuttingDown = true;
  };
  const onSigterm = () => {
    log.info('Received SIGTERM — shutting down...');
    state.shuttingDown = true;
  };

  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);

  return () => {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
  };
}

/**
 * Interruptible sleep — resolves early if state.shuttingDown becomes true.
 * Checks every second.
 */
export function interruptibleSleep(ms: number, state: DaemonState): Promise<void> {
  return new Promise<void>(resolve => {
    if (state.shuttingDown) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      clearInterval(checkInterval);
      resolve();
    }, ms);
    const checkInterval = setInterval(() => {
      if (state.shuttingDown) {
        clearTimeout(timer);
        clearInterval(checkInterval);
        resolve();
      }
    }, 1000);
  });
}
