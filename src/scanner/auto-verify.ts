import type { BrowserContext } from 'playwright';
import type { RawFinding, Confidence } from './types.js';

export function upgradeConfidence(current: Confidence, verified: boolean): Confidence {
  if (verified) return current === 'low' ? 'medium' : 'high';
  return current === 'high' ? 'medium' : 'low';
}

export async function verifyFinding(finding: RawFinding, context: BrowserContext): Promise<RawFinding> {
  switch (finding.category) {
    case 'xss':
      return { ...finding, confidence: (await verifyXss(finding, context)) ? 'high' : 'low' };
    case 'sqli':
      return { ...finding, confidence: (await verifySqli(finding)) ? 'high' : 'low' };
    case 'subdomain-takeover':
      return { ...finding, confidence: (await verifySubdomainTakeover(finding)) ? 'high' : 'low' };
    default:
      return finding;
  }
}

export async function verifyXss(finding: RawFinding, context: BrowserContext): Promise<boolean> {
  try {
    const page = await context.newPage();
    let dialogFired = false;
    page.on('dialog', async d => { dialogFired = true; await d.dismiss(); });
    await page.goto(finding.url, { timeout: 10000, waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
    await page.close();
    return dialogFired;
  } catch { return false; }
}

export async function verifySqli(finding: RawFinding): Promise<boolean> {
  if (!finding.request?.url) return false;
  try {
    const url = new URL(finding.request.url);
    for (const [key, value] of url.searchParams) {
      if (value.includes("'") || value.includes('OR')) {
        url.searchParams.set(key, "' OR 2=2--");
        const resp = await fetch(url.toString(), { signal: AbortSignal.timeout(10000) });
        const body = await resp.text();
        const errorPatterns = ['SQL', 'mysql', 'syntax error', 'ORA-', 'PostgreSQL', 'sqlite'];
        return errorPatterns.some(p => body.toLowerCase().includes(p.toLowerCase()));
      }
    }
    return false;
  } catch { return false; }
}

export async function verifySubdomainTakeover(finding: RawFinding): Promise<boolean> {
  try {
    const resp = await fetch(finding.url, { signal: AbortSignal.timeout(10000) });
    const body = await resp.text();
    return resp.status === 404 || body.includes("There isn't a GitHub Pages site here") || body.includes('NoSuchBucket');
  } catch { return false; }
}

export async function verifyFindings(findings: RawFinding[], context: BrowserContext): Promise<RawFinding[]> {
  const results: RawFinding[] = [];
  for (const f of findings) {
    if (f.confidence === 'medium') {
      results.push(await verifyFinding(f, context));
    } else {
      results.push(f);
    }
  }
  return results;
}
