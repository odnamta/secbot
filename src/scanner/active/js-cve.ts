import { randomUUID } from 'node:crypto';
import type { RawFinding, Severity } from '../types.js';
import { log } from '../../utils/logger.js';
import type { ActiveCheck } from './index.js';

// ─── Vulnerability Database ────────────────────────────────────────

interface VulnEntry {
  below: string;
  cves: string[];
  severity: Severity;
  description: string;
}

export const KNOWN_VULNS: Record<string, VulnEntry[]> = {
  jquery: [
    { below: '3.5.0', cves: ['CVE-2020-11022', 'CVE-2020-11023'], severity: 'medium', description: 'XSS via HTML passed to DOM manipulation methods' },
    { below: '3.0.0', cves: ['CVE-2015-9251'], severity: 'medium', description: 'XSS in cross-domain ajax requests' },
    { below: '1.12.0', cves: ['CVE-2015-9251'], severity: 'medium', description: 'XSS via cross-site scripting' },
  ],
  angularjs: [
    { below: '1.8.0', cves: ['CVE-2022-25844'], severity: 'high', description: 'Prototype pollution' },
    { below: '1.6.0', cves: ['CVE-2019-10768'], severity: 'high', description: 'Prototype pollution via merge function' },
  ],
  lodash: [
    { below: '4.17.21', cves: ['CVE-2021-23337'], severity: 'high', description: 'Command injection via template function' },
    { below: '4.17.12', cves: ['CVE-2019-10744'], severity: 'critical', description: 'Prototype pollution' },
  ],
  bootstrap: [
    { below: '4.3.1', cves: ['CVE-2019-8331'], severity: 'medium', description: 'XSS in tooltip/popover data-template' },
    { below: '3.4.0', cves: ['CVE-2018-14042'], severity: 'medium', description: 'XSS in collapse data-parent attribute' },
  ],
  vue: [
    { below: '2.5.0', cves: ['CVE-2018-11235'], severity: 'medium', description: 'XSS via template injection' },
  ],
  react: [
    { below: '16.0.0', cves: ['CVE-2018-6341'], severity: 'medium', description: 'XSS via attribute name in SSR' },
  ],
  moment: [
    { below: '2.29.4', cves: ['CVE-2022-31129'], severity: 'high', description: 'ReDoS in string parsing' },
    { below: '2.19.3', cves: ['CVE-2017-18214'], severity: 'high', description: 'ReDoS vulnerability' },
  ],
  handlebars: [
    { below: '4.7.7', cves: ['CVE-2021-23369'], severity: 'critical', description: 'Prototype pollution leading to RCE' },
  ],
  dompurify: [
    { below: '2.3.6', cves: ['CVE-2022-24713'], severity: 'high', description: 'Mutation XSS bypass' },
  ],
};

// ─── Semver Comparison ─────────────────────────────────────────────

/**
 * Parse a version string into numeric parts [major, minor, patch].
 * Handles versions like "3.5.0", "1.8", "4" by filling missing parts with 0.
 * Strips leading 'v' and any pre-release/build suffixes (e.g. "-beta.1", "+build").
 */
export function parseVersion(version: string): number[] {
  // Strip leading 'v' or 'V'
  let cleaned = version.replace(/^[vV]/, '');
  // Strip pre-release and build metadata (-beta.1, +build, etc.)
  cleaned = cleaned.replace(/[-+].*$/, '');

  const parts = cleaned.split('.').map((p) => {
    const n = parseInt(p, 10);
    return isNaN(n) ? 0 : n;
  });

  // Pad to at least 3 parts
  while (parts.length < 3) parts.push(0);
  return parts;
}

/**
 * Compare two semver strings.
 * Returns negative if a < b, 0 if equal, positive if a > b.
 */
export function compareSemver(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/**
 * Check if version is below the threshold.
 */
export function isVersionBelow(version: string, below: string): boolean {
  return compareSemver(version, below) < 0;
}

// ─── Version Detection from Script URLs ────────────────────────────

interface DetectedLib {
  name: string;
  version: string;
}

/**
 * Patterns to extract library name and version from script URLs/filenames.
 * Matches patterns like: jquery-3.6.0.min.js, angular-1.8.3.js, lodash-4.17.21.js
 */
const URL_PATTERNS: { pattern: RegExp; name: string }[] = [
  { pattern: /jquery[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'jquery' },
  { pattern: /angular(?:js)?[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'angularjs' },
  { pattern: /vue[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'vue' },
  { pattern: /react-dom[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'react' },
  { pattern: /react[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'react' },
  { pattern: /bootstrap[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'bootstrap' },
  { pattern: /lodash[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'lodash' },
  { pattern: /underscore[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'lodash' }, // underscore shares lodash vulns
  { pattern: /moment[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'moment' },
  { pattern: /handlebars[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'handlebars' },
  { pattern: /dompurify[.@/\-](\d+\.\d+(?:\.\d+)?)/i, name: 'dompurify' },
];

/**
 * Extract library name and version from a script URL.
 * Returns null if no known library pattern is matched.
 */
export function detectLibFromUrl(url: string): DetectedLib | null {
  for (const { pattern, name } of URL_PATTERNS) {
    const match = url.match(pattern);
    if (match) {
      return { name, version: match[1] };
    }
  }
  return null;
}

// ─── Vulnerability Matching ────────────────────────────────────────

export interface VulnMatch {
  library: string;
  version: string;
  cves: string[];
  severity: Severity;
  description: string;
}

/**
 * Check a detected library+version against the known vulnerability database.
 * Returns all matching vulnerabilities (a library can match multiple entries).
 */
export function findVulnerabilities(lib: DetectedLib): VulnMatch[] {
  const entries = KNOWN_VULNS[lib.name];
  if (!entries) return [];

  const matches: VulnMatch[] = [];
  for (const entry of entries) {
    if (isVersionBelow(lib.version, entry.below)) {
      matches.push({
        library: lib.name,
        version: lib.version,
        cves: entry.cves,
        severity: entry.severity,
        description: entry.description,
      });
    }
  }

  return matches;
}

// ─── Active Check Implementation ──────────────────────────────────

/**
 * JS Library CVE check.
 *
 * Detects loaded JavaScript libraries and their versions via:
 * 1. Runtime globals (window.jQuery, window.angular, etc.) using page.evaluate
 * 2. Script URL patterns (jquery-3.6.0.min.js, etc.) from crawled page data
 *
 * Detected versions are cross-referenced against a built-in vulnerability
 * database covering common CVEs for jQuery, AngularJS, React, Vue, Lodash,
 * Bootstrap, Moment, Handlebars, and DOMPurify.
 */
export const jsCveCheck: ActiveCheck = {
  parallel: true,
  name: 'js-cve',
  category: 'js-cve',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];
    const checkedLibs = new Set<string>(); // Dedup: "library@version@url" combos

    log.info(`JS CVE check: scanning ${targets.pages.length} page(s) for vulnerable JS libraries...`);

    for (const pageUrl of targets.pages) {
      let page;
      try {
        page = await context.newPage();
        await page.goto(pageUrl, {
          waitUntil: 'domcontentloaded',
          timeout: config.timeout,
        });

        // 1. Detect libraries via runtime globals
        const runtimeLibs = await page.evaluate(() => {
          const detected: Array<{ name: string; version: string }> = [];

          // jQuery
          const jq = (window as any).jQuery || (window as any).$;
          if (jq && typeof jq === 'function' && jq.fn && jq.fn.jquery) {
            detected.push({ name: 'jquery', version: jq.fn.jquery });
          }

          // AngularJS (1.x)
          const ng = (window as any).angular;
          if (ng && ng.version && ng.version.full) {
            detected.push({ name: 'angularjs', version: ng.version.full });
          }

          // React
          const react = (window as any).React;
          if (react && react.version) {
            detected.push({ name: 'react', version: react.version });
          }

          // Vue
          const vue = (window as any).Vue;
          if (vue && vue.version) {
            detected.push({ name: 'vue', version: vue.version });
          }

          // Lodash / Underscore
          const lo = (window as any)._;
          if (lo && lo.VERSION) {
            detected.push({ name: 'lodash', version: lo.VERSION });
          }

          // Moment.js
          const mom = (window as any).moment;
          if (mom && mom.version) {
            detected.push({ name: 'moment', version: mom.version });
          }

          // Handlebars
          const hbs = (window as any).Handlebars;
          if (hbs && hbs.VERSION) {
            detected.push({ name: 'handlebars', version: hbs.VERSION });
          }

          // DOMPurify
          const dp = (window as any).DOMPurify;
          if (dp && dp.version) {
            detected.push({ name: 'dompurify', version: dp.version });
          }

          // Bootstrap (check via jQuery plugin or standalone)
          const bs = (window as any).bootstrap;
          if (bs && bs.Tooltip && bs.Tooltip.VERSION) {
            detected.push({ name: 'bootstrap', version: bs.Tooltip.VERSION });
          } else if (jq && typeof jq === 'function' && jq.fn && jq.fn.tooltip && jq.fn.tooltip.Constructor && jq.fn.tooltip.Constructor.VERSION) {
            detected.push({ name: 'bootstrap', version: jq.fn.tooltip.Constructor.VERSION });
          }

          return detected;
        });

        // 2. Detect libraries from script src URLs
        const scriptUrls = await page.evaluate(() => {
          const urls: string[] = [];
          const scripts = document.querySelectorAll('script[src]');
          for (const el of scripts) {
            const src = el.getAttribute('src');
            if (src) urls.push(src);
          }
          return urls;
        });

        const urlLibs: DetectedLib[] = [];
        for (const scriptUrl of scriptUrls) {
          const detected = detectLibFromUrl(scriptUrl);
          if (detected) urlLibs.push(detected);
        }

        // Combine runtime + URL detections (runtime takes priority for version)
        const allDetected = new Map<string, DetectedLib>();
        // URL detections first (lower priority)
        for (const lib of urlLibs) {
          allDetected.set(lib.name, lib);
        }
        // Runtime detections overwrite (higher priority — more accurate version)
        for (const lib of runtimeLibs) {
          allDetected.set(lib.name, lib);
        }

        // 3. Check each detected library against vuln database
        for (const lib of allDetected.values()) {
          const vulns = findVulnerabilities(lib);
          for (const vuln of vulns) {
            const dedupKey = `${vuln.library}@${vuln.version}@${vuln.cves.join(',')}`;
            if (checkedLibs.has(dedupKey)) continue;
            checkedLibs.add(dedupKey);

            findings.push({
              id: randomUUID(),
              category: 'js-cve',
              severity: vuln.severity,
              title: `Vulnerable JS Library: ${vuln.library} ${vuln.version}`,
              description:
                `${vuln.library} ${vuln.version} is loaded on this page and is affected by known vulnerabilities. ` +
                `${vuln.description}. Affected CVE(s): ${vuln.cves.join(', ')}.`,
              url: pageUrl,
              evidence: `Detected ${vuln.library} v${vuln.version} (vulnerable below ${KNOWN_VULNS[vuln.library]?.find(e => e.cves.join(',') === vuln.cves.join(','))?.below ?? 'unknown'}). CVEs: ${vuln.cves.join(', ')}`,
              timestamp: new Date().toISOString(),
              confidence: 'high',
            });
          }
        }
      } catch (err) {
        log.debug(`JS CVE check: failed on ${pageUrl}: ${(err as Error).message}`);
      } finally {
        if (page) {
          try { await page.close(); } catch { /* ignore */ }
        }
      }
    }

    log.info(`JS CVE check: ${findings.length} finding(s)`);
    return findings;
  },
};
