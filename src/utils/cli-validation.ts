import { existsSync } from 'node:fs';

export const VALID_PROFILES = ['quick', 'standard', 'deep', 'stealth'] as const;

export interface CliValidationError {
  field: string;
  message: string;
}

export interface CliOptions {
  profile?: string;
  auth?: string;
  urls?: string;
  maxPages?: string;
  timeout?: string;
  rateLimit?: string;
}

/**
 * Validates CLI options and returns an array of errors (empty if all valid).
 * Uses a fileExists function for testability (defaults to fs.existsSync).
 */
export function validateCliOptions(
  options: CliOptions,
  fileExists: (path: string) => boolean = existsSync,
): CliValidationError[] {
  const errors: CliValidationError[] = [];

  // Validate --profile
  if (options.profile !== undefined && !VALID_PROFILES.includes(options.profile as typeof VALID_PROFILES[number])) {
    errors.push({
      field: '--profile',
      message: `Invalid profile "${options.profile}". Must be one of: ${VALID_PROFILES.join(', ')}`,
    });
  }

  // Validate --auth file existence
  if (options.auth !== undefined && !fileExists(options.auth)) {
    errors.push({
      field: '--auth',
      message: `Auth file not found: ${options.auth}`,
    });
  }

  // Validate --urls file existence
  if (options.urls !== undefined && !fileExists(options.urls)) {
    errors.push({
      field: '--urls',
      message: `URLs file not found: ${options.urls}`,
    });
  }

  // Validate --max-pages is a positive integer
  if (options.maxPages !== undefined) {
    const n = Number(options.maxPages);
    if (!Number.isInteger(n) || n <= 0) {
      errors.push({
        field: '--max-pages',
        message: `Invalid value "${options.maxPages}" for --max-pages. Must be a positive integer.`,
      });
    }
  }

  // Validate --timeout is a positive integer
  if (options.timeout !== undefined) {
    const n = Number(options.timeout);
    if (!Number.isInteger(n) || n <= 0) {
      errors.push({
        field: '--timeout',
        message: `Invalid value "${options.timeout}" for --timeout. Must be a positive integer.`,
      });
    }
  }

  // Validate --rate-limit is a positive integer
  if (options.rateLimit !== undefined) {
    const n = Number(options.rateLimit);
    if (!Number.isInteger(n) || n <= 0) {
      errors.push({
        field: '--rate-limit',
        message: `Invalid value "${options.rateLimit}" for --rate-limit. Must be a positive integer.`,
      });
    }
  }

  return errors;
}
