import type {
  CrawledPage,
  InterceptedResponse,
  ReconResult,
  TechFingerprint,
  WafDetection,
  FrameworkDetection,
  EndpointMap,
  Confidence,
} from './types.js';
import { fingerprintWaf } from './waf-fingerprint.js';
import { log } from '../utils/logger.js';

/** Map WafFingerprint confidence to a comparable numeric value */
const CONFIDENCE_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

export function runRecon(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
): ReconResult {
  log.info('Running reconnaissance...');

  const techStack = fingerprintTechStack(pages, responses);
  let waf = detectWaf(pages, responses);
  const framework = detectFramework(pages, responses);
  const endpoints = mapEndpoints(pages);

  // Enhanced WAF fingerprinting — augments basic detection with specific
  // WAF product identification and recommended bypass techniques
  const enhanced = fingerprintWaf(responses);
  const enhancedRank = CONFIDENCE_RANK[enhanced.confidence] ?? 0;
  const basicRank = CONFIDENCE_RANK[waf.confidence] ?? 0;

  if (enhanced.wafName !== 'Unknown' && enhancedRank >= basicRank) {
    // Enhanced detection identified a specific WAF with equal or higher confidence
    waf = {
      detected: true,
      name: enhanced.wafName,
      confidence: enhanced.confidence,
      evidence: [...new Set([...waf.evidence, ...enhanced.evidence])],
      recommendedTechniques: enhanced.recommendedTechniques,
    };
    log.info(`Enhanced WAF fingerprint: ${enhanced.wafName} (${enhanced.confidence} confidence)`);
  } else if (waf.detected) {
    // Basic detection found a WAF but enhanced didn't beat it — still store techniques
    waf.recommendedTechniques = enhanced.recommendedTechniques;
  }

  log.info(
    `Recon complete: ${techStack.detected.length} technologies, ` +
    `WAF: ${waf.detected ? waf.name : 'none'}, ` +
    `Framework: ${framework.name ?? 'unknown'}, ` +
    `${endpoints.apiRoutes.length} API routes`,
  );

  return { techStack, waf, framework, endpoints };
}

function fingerprintTechStack(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
): TechFingerprint {
  const detected: string[] = [];
  const languages: string[] = [];
  let server: string | undefined;
  let poweredBy: string | undefined;
  let cdn: string | undefined;

  for (const page of pages) {
    const h = page.headers;

    // Server header
    if (h['server'] && !server) {
      server = h['server'];
      detected.push(`Server: ${server}`);
    }

    // X-Powered-By
    if (h['x-powered-by'] && !poweredBy) {
      poweredBy = h['x-powered-by'];
      detected.push(`Powered-By: ${poweredBy}`);
    }

    // CDN detection
    if (h['cf-ray'] || h['server']?.toLowerCase().includes('cloudflare')) {
      if (!cdn) { cdn = 'Cloudflare'; detected.push('CDN: Cloudflare'); }
    }
    if (h['x-vercel-id']) {
      if (!cdn) { cdn = 'Vercel'; detected.push('CDN: Vercel'); }
    }
    if (h['x-amz-cf-id'] || h['x-amz-cf-pop']) {
      if (!cdn) { cdn = 'CloudFront'; detected.push('CDN: CloudFront'); }
    }
    if (h['x-fastly-request-id']) {
      if (!cdn) { cdn = 'Fastly'; detected.push('CDN: Fastly'); }
    }

    // Cookie-based detection
    for (const cookie of page.cookies) {
      if (cookie.name === 'PHPSESSID' && !languages.includes('PHP')) {
        languages.push('PHP');
        detected.push('Language: PHP');
      }
      if (cookie.name === 'ASP.NET_SessionId' && !languages.includes('.NET')) {
        languages.push('.NET');
        detected.push('Language: .NET');
      }
      if (cookie.name === 'JSESSIONID' && !languages.includes('Java')) {
        languages.push('Java');
        detected.push('Language: Java');
      }
    }

    // Script-based detection
    for (const script of page.scripts) {
      if (script.includes('/_next/') && !detected.includes('Next.js')) {
        detected.push('Next.js');
      }
      if (script.includes('/__nuxt/') && !detected.includes('Nuxt')) {
        detected.push('Nuxt');
      }
      if (script.includes('/wp-content/') && !detected.includes('WordPress')) {
        detected.push('WordPress');
      }
      if (script.includes('/wp-includes/') && !detected.includes('WordPress')) {
        detected.push('WordPress');
      }
    }
  }

  // Check response bodies for meta generators
  for (const resp of responses) {
    if (!resp.body) continue;

    const generatorMatch = resp.body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
    if (generatorMatch) {
      const gen = generatorMatch[1];
      if (!detected.includes(`Generator: ${gen}`)) {
        detected.push(`Generator: ${gen}`);
      }
    }
  }

  return { server, poweredBy, cdn, languages, detected };
}

function detectWaf(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
): WafDetection {
  const evidence: string[] = [];

  for (const page of pages) {
    const h = page.headers;

    // Cloudflare WAF
    if (h['cf-ray'] && h['server']?.toLowerCase() === 'cloudflare') {
      return { detected: true, name: 'Cloudflare', confidence: 'high', evidence: ['cf-ray header present', 'Server: cloudflare'] };
    }

    // AWS WAF
    if (h['x-amzn-waf-action'] || h['x-amzn-requestid']) {
      evidence.push('AWS WAF headers detected');
    }

    // Akamai
    if (h['x-akamai-transformed'] || h['akamai-grn']) {
      return { detected: true, name: 'Akamai', confidence: 'high', evidence: ['Akamai headers detected'] };
    }

    // Sucuri
    if (h['x-sucuri-id'] || h['server']?.toLowerCase().includes('sucuri')) {
      return { detected: true, name: 'Sucuri', confidence: 'high', evidence: ['Sucuri headers detected'] };
    }

    // Imperva / Incapsula
    if (h['x-iinfo'] || h['x-cdn']?.toLowerCase().includes('incapsula')) {
      return { detected: true, name: 'Imperva', confidence: 'medium', evidence: ['Imperva/Incapsula headers detected'] };
    }
  }

  // Check for blocked responses (common WAF behavior)
  const blockedResponses = responses.filter((r) => r.status === 403 || r.status === 406);
  if (blockedResponses.length > 0) {
    for (const resp of blockedResponses) {
      if (resp.body?.includes('blocked') || resp.body?.includes('firewall')) {
        evidence.push(`Blocked response (${resp.status}) with firewall content`);
      }
    }
  }

  if (evidence.length > 0) {
    return { detected: true, name: 'Unknown WAF', confidence: 'low', evidence };
  }

  return { detected: false, confidence: 'medium', evidence: [] };
}

function detectFramework(
  pages: CrawledPage[],
  responses: InterceptedResponse[],
): FrameworkDetection {
  const evidence: string[] = [];

  for (const page of pages) {
    // Script-based detection
    for (const script of page.scripts) {
      if (script.includes('/_next/')) {
        evidence.push('Next.js script bundle detected');
        return { name: 'Next.js', confidence: 'high', evidence };
      }
      if (script.includes('/__nuxt/')) {
        evidence.push('Nuxt script bundle detected');
        return { name: 'Nuxt', confidence: 'high', evidence };
      }
      if (script.includes('/wp-content/') || script.includes('/wp-includes/')) {
        evidence.push('WordPress scripts detected');
        return { name: 'WordPress', confidence: 'high', evidence };
      }
    }

    // Header-based detection
    const h = page.headers;
    if (h['x-powered-by']?.toLowerCase().includes('next.js')) {
      evidence.push('X-Powered-By: Next.js');
      return { name: 'Next.js', confidence: 'high', evidence };
    }
    if (h['x-powered-by']?.toLowerCase().includes('express')) {
      evidence.push('X-Powered-By: Express');
      return { name: 'Express', confidence: 'high', evidence };
    }
    if (h['x-powered-by']?.toLowerCase().includes('laravel')) {
      evidence.push('X-Powered-By: Laravel');
      return { name: 'Laravel', confidence: 'high', evidence };
    }
    if (h['x-powered-by']?.toLowerCase().includes('django')) {
      evidence.push('X-Powered-By: Django');
      return { name: 'Django', confidence: 'high', evidence };
    }
  }

  // Body-based detection
  for (const resp of responses) {
    if (!resp.body) continue;

    if (resp.body.includes('__NEXT_DATA__')) {
      evidence.push('__NEXT_DATA__ found in HTML');
      return { name: 'Next.js', confidence: 'high', evidence };
    }
    if (resp.body.includes('__NUXT__')) {
      evidence.push('__NUXT__ found in HTML');
      return { name: 'Nuxt', confidence: 'high', evidence };
    }
    if (resp.body.includes('ng-version=') || resp.body.includes('ng-app')) {
      evidence.push('Angular markers found');
      return { name: 'Angular', confidence: 'medium', evidence };
    }
    if (resp.body.includes('data-reactroot') || resp.body.includes('__REACT')) {
      evidence.push('React markers found');
      return { name: 'React', confidence: 'medium', evidence };
    }
    if (resp.body.includes('data-v-') || resp.body.includes('Vue.js')) {
      evidence.push('Vue markers found');
      return { name: 'Vue', confidence: 'medium', evidence };
    }

    const generatorMatch = resp.body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
    if (generatorMatch) {
      const gen = generatorMatch[1];
      if (gen.toLowerCase().includes('wordpress')) {
        return { name: 'WordPress', version: gen.split(' ')[1], confidence: 'high', evidence: [`Generator: ${gen}`] };
      }
      if (gen.toLowerCase().includes('drupal')) {
        return { name: 'Drupal', confidence: 'high', evidence: [`Generator: ${gen}`] };
      }
      if (gen.toLowerCase().includes('rails')) {
        return { name: 'Rails', confidence: 'high', evidence: [`Generator: ${gen}`] };
      }
    }
  }

  return { confidence: 'low', evidence: [] };
}

function mapEndpoints(pages: CrawledPage[]): EndpointMap {
  const pagesUrls: string[] = [];
  const apiRoutes: string[] = [];
  const staticAssets: string[] = [];
  const graphql: string[] = [];
  const allForms = pages.flatMap((p) => p.forms);

  for (const page of pages) {
    const path = new URL(page.url).pathname;

    if (/\/api\//i.test(path)) {
      apiRoutes.push(page.url);
    } else if (/\/graphql/i.test(path)) {
      graphql.push(page.url);
    } else if (/\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)$/i.test(path)) {
      staticAssets.push(page.url);
    } else {
      pagesUrls.push(page.url);
    }

    // Also check links for API/GraphQL endpoints
    for (const link of page.links) {
      try {
        const linkPath = new URL(link).pathname;
        if (/\/api\//i.test(linkPath) && !apiRoutes.includes(link)) {
          apiRoutes.push(link);
        }
        if (/\/graphql/i.test(linkPath) && !graphql.includes(link)) {
          graphql.push(link);
        }
      } catch {
        // Invalid URL
      }
    }
  }

  return {
    pages: pagesUrls,
    apiRoutes,
    forms: allForms,
    staticAssets,
    graphql,
  };
}
