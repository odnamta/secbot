import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import type { Page, BrowserContext } from 'playwright';
import type { RawFinding } from './types.js';
import { log } from '../utils/logger.js';

/**
 * Capture a full-page screenshot and save it as a PNG.
 * Returns the absolute path to the saved file.
 */
export async function captureScreenshot(
  page: Page,
  outputPath: string,
): Promise<string> {
  mkdirSync(dirname(outputPath), { recursive: true });
  await page.screenshot({ path: outputPath, fullPage: true });
  log.info(`Screenshot saved: ${outputPath}`);
  return outputPath;
}

/**
 * Navigate to a finding's URL and capture a screenshot.
 * Returns the path to the screenshot, or null if capture fails.
 */
export async function captureScreenshotOnFinding(
  context: BrowserContext,
  finding: RawFinding,
  outputDir: string,
): Promise<string | null> {
  const page = await context.newPage();
  try {
    const sanitizedId = finding.id.replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `finding-${sanitizedId}.png`;
    const outputPath = join(outputDir, filename);

    await page.goto(finding.url, {
      waitUntil: 'networkidle',
      timeout: 15000,
    });

    return await captureScreenshot(page, outputPath);
  } catch (err) {
    log.warn(`Screenshot capture failed for ${finding.url}: ${(err as Error).message}`);
    return null;
  } finally {
    try {
      await page.close();
    } catch {
      // best effort
    }
  }
}
