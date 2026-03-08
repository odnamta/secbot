import { describe, it, expect } from 'vitest';
import {
  parseVersion,
  compareSemver,
  isVersionBelow,
  detectLibFromUrl,
  findVulnerabilities,
  KNOWN_VULNS,
} from '../../src/scanner/active/js-cve.js';

// ─── parseVersion ──────────────────────────────────────────────────

describe('parseVersion', () => {
  it('parses standard semver (3.5.0)', () => {
    expect(parseVersion('3.5.0')).toEqual([3, 5, 0]);
  });

  it('parses two-part version (1.8)', () => {
    expect(parseVersion('1.8')).toEqual([1, 8, 0]);
  });

  it('parses single-part version (4)', () => {
    expect(parseVersion('4')).toEqual([4, 0, 0]);
  });

  it('strips leading v prefix', () => {
    expect(parseVersion('v2.5.1')).toEqual([2, 5, 1]);
  });

  it('strips pre-release suffix', () => {
    expect(parseVersion('4.17.21-beta.1')).toEqual([4, 17, 21]);
  });

  it('strips build metadata', () => {
    expect(parseVersion('1.2.3+build.456')).toEqual([1, 2, 3]);
  });

  it('handles non-numeric parts gracefully', () => {
    expect(parseVersion('abc.def.ghi')).toEqual([0, 0, 0]);
  });
});

// ─── compareSemver ─────────────────────────────────────────────────

describe('compareSemver', () => {
  it('returns 0 for equal versions', () => {
    expect(compareSemver('3.5.0', '3.5.0')).toBe(0);
  });

  it('returns negative when a < b (major)', () => {
    expect(compareSemver('2.0.0', '3.0.0')).toBeLessThan(0);
  });

  it('returns positive when a > b (major)', () => {
    expect(compareSemver('4.0.0', '3.0.0')).toBeGreaterThan(0);
  });

  it('compares minor versions correctly', () => {
    expect(compareSemver('3.4.0', '3.5.0')).toBeLessThan(0);
    expect(compareSemver('3.6.0', '3.5.0')).toBeGreaterThan(0);
  });

  it('compares patch versions correctly', () => {
    expect(compareSemver('3.5.1', '3.5.2')).toBeLessThan(0);
    expect(compareSemver('3.5.3', '3.5.2')).toBeGreaterThan(0);
  });

  it('handles two-part vs three-part versions', () => {
    expect(compareSemver('3.5', '3.5.0')).toBe(0);
    expect(compareSemver('3.5', '3.5.1')).toBeLessThan(0);
  });

  it('handles v prefix in comparison', () => {
    expect(compareSemver('v1.2.3', '1.2.3')).toBe(0);
  });
});

// ─── isVersionBelow ────────────────────────────────────────────────

describe('isVersionBelow', () => {
  it('returns true when version is below threshold', () => {
    expect(isVersionBelow('3.4.0', '3.5.0')).toBe(true);
  });

  it('returns false when version equals threshold', () => {
    expect(isVersionBelow('3.5.0', '3.5.0')).toBe(false);
  });

  it('returns false when version is above threshold', () => {
    expect(isVersionBelow('3.6.0', '3.5.0')).toBe(false);
  });

  it('works with real jQuery CVE threshold', () => {
    // jQuery < 3.5.0 is vulnerable to CVE-2020-11022
    expect(isVersionBelow('3.4.1', '3.5.0')).toBe(true);
    expect(isVersionBelow('3.5.0', '3.5.0')).toBe(false);
    expect(isVersionBelow('3.6.0', '3.5.0')).toBe(false);
  });

  it('works with real Lodash CVE threshold', () => {
    // Lodash < 4.17.21 is vulnerable to CVE-2021-23337
    expect(isVersionBelow('4.17.20', '4.17.21')).toBe(true);
    expect(isVersionBelow('4.17.21', '4.17.21')).toBe(false);
  });
});

// ─── detectLibFromUrl ──────────────────────────────────────────────

describe('detectLibFromUrl', () => {
  it('detects jQuery from CDN URL', () => {
    const result = detectLibFromUrl('https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js');
    expect(result).toEqual({ name: 'jquery', version: '3.6.0' });
  });

  it('detects jQuery from filename with dash', () => {
    const result = detectLibFromUrl('/assets/js/jquery-3.4.1.min.js');
    expect(result).toEqual({ name: 'jquery', version: '3.4.1' });
  });

  it('detects AngularJS from URL', () => {
    const result = detectLibFromUrl('https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js');
    expect(result).toEqual({ name: 'angularjs', version: '1.8.2' });
  });

  it('detects Vue from URL', () => {
    const result = detectLibFromUrl('https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js');
    expect(result).toEqual({ name: 'vue', version: '2.6.14' });
  });

  it('detects Bootstrap from URL', () => {
    const result = detectLibFromUrl('/static/bootstrap-3.3.7.min.js');
    expect(result).toEqual({ name: 'bootstrap', version: '3.3.7' });
  });

  it('detects Moment.js from URL', () => {
    const result = detectLibFromUrl('/vendor/moment-2.24.0.min.js');
    expect(result).toEqual({ name: 'moment', version: '2.24.0' });
  });

  it('detects Lodash from URL', () => {
    const result = detectLibFromUrl('https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js');
    expect(result).toEqual({ name: 'lodash', version: '4.17.11' });
  });

  it('detects react-dom as react', () => {
    const result = detectLibFromUrl('/static/react-dom-16.14.0.min.js');
    expect(result).toEqual({ name: 'react', version: '16.14.0' });
  });

  it('returns null for unrecognized URLs', () => {
    expect(detectLibFromUrl('/assets/js/main.js')).toBeNull();
    expect(detectLibFromUrl('/bundle.js')).toBeNull();
    expect(detectLibFromUrl('https://example.com/app.min.js')).toBeNull();
  });

  it('detects version with two-part semver', () => {
    const result = detectLibFromUrl('/js/jquery-3.6.min.js');
    expect(result).toEqual({ name: 'jquery', version: '3.6' });
  });

  it('detects Handlebars from URL', () => {
    const result = detectLibFromUrl('/vendor/handlebars-4.5.3.min.js');
    expect(result).toEqual({ name: 'handlebars', version: '4.5.3' });
  });

  it('detects DOMPurify from URL', () => {
    const result = detectLibFromUrl('/vendor/dompurify-2.3.0.min.js');
    expect(result).toEqual({ name: 'dompurify', version: '2.3.0' });
  });
});

// ─── findVulnerabilities ───────────────────────────────────────────

describe('findVulnerabilities', () => {
  it('finds jQuery XSS vulnerability for 3.4.1', () => {
    const vulns = findVulnerabilities({ name: 'jquery', version: '3.4.1' });
    expect(vulns.length).toBeGreaterThanOrEqual(1);
    expect(vulns[0].cves).toContain('CVE-2020-11022');
    expect(vulns[0].severity).toBe('medium');
  });

  it('finds multiple jQuery vulnerabilities for 1.11.3', () => {
    const vulns = findVulnerabilities({ name: 'jquery', version: '1.11.3' });
    // Should match all three entries (below 3.5.0, below 3.0.0, below 1.12.0)
    expect(vulns.length).toBe(3);
  });

  it('finds no vulnerabilities for latest jQuery', () => {
    const vulns = findVulnerabilities({ name: 'jquery', version: '3.7.1' });
    expect(vulns).toHaveLength(0);
  });

  it('finds Lodash critical prototype pollution for 4.17.10', () => {
    const vulns = findVulnerabilities({ name: 'lodash', version: '4.17.10' });
    expect(vulns.length).toBe(2);
    const critical = vulns.find((v) => v.severity === 'critical');
    expect(critical).toBeDefined();
    expect(critical!.cves).toContain('CVE-2019-10744');
  });

  it('finds Lodash command injection for 4.17.20 but not prototype pollution', () => {
    const vulns = findVulnerabilities({ name: 'lodash', version: '4.17.20' });
    expect(vulns.length).toBe(1);
    expect(vulns[0].cves).toContain('CVE-2021-23337');
    expect(vulns[0].severity).toBe('high');
  });

  it('finds AngularJS prototype pollution for 1.5.0', () => {
    const vulns = findVulnerabilities({ name: 'angularjs', version: '1.5.0' });
    expect(vulns.length).toBe(2);
  });

  it('finds Bootstrap XSS for 3.3.7', () => {
    const vulns = findVulnerabilities({ name: 'bootstrap', version: '3.3.7' });
    expect(vulns.length).toBe(2);
    expect(vulns.some((v) => v.cves.includes('CVE-2019-8331'))).toBe(true);
    expect(vulns.some((v) => v.cves.includes('CVE-2018-14042'))).toBe(true);
  });

  it('finds Moment ReDoS for 2.24.0', () => {
    const vulns = findVulnerabilities({ name: 'moment', version: '2.24.0' });
    expect(vulns.length).toBe(1);
    expect(vulns[0].cves).toContain('CVE-2022-31129');
  });

  it('finds Handlebars RCE for 4.5.3', () => {
    const vulns = findVulnerabilities({ name: 'handlebars', version: '4.5.3' });
    expect(vulns.length).toBe(1);
    expect(vulns[0].severity).toBe('critical');
  });

  it('returns empty for unknown library', () => {
    const vulns = findVulnerabilities({ name: 'unknown-lib', version: '1.0.0' });
    expect(vulns).toHaveLength(0);
  });

  it('finds React SSR XSS for 15.6.2', () => {
    const vulns = findVulnerabilities({ name: 'react', version: '15.6.2' });
    expect(vulns.length).toBe(1);
    expect(vulns[0].cves).toContain('CVE-2018-6341');
  });

  it('finds DOMPurify mutation XSS for 2.3.0', () => {
    const vulns = findVulnerabilities({ name: 'dompurify', version: '2.3.0' });
    expect(vulns.length).toBe(1);
    expect(vulns[0].cves).toContain('CVE-2022-24713');
  });

  it('finds Vue XSS for 2.4.0', () => {
    const vulns = findVulnerabilities({ name: 'vue', version: '2.4.0' });
    expect(vulns.length).toBe(1);
    expect(vulns[0].cves).toContain('CVE-2018-11235');
  });
});

// ─── KNOWN_VULNS database integrity ───────────────────────────────

describe('KNOWN_VULNS database', () => {
  it('has entries for all documented libraries', () => {
    const expectedLibs = ['jquery', 'angularjs', 'lodash', 'bootstrap', 'vue', 'react', 'moment', 'handlebars', 'dompurify'];
    for (const lib of expectedLibs) {
      expect(KNOWN_VULNS[lib]).toBeDefined();
      expect(KNOWN_VULNS[lib].length).toBeGreaterThan(0);
    }
  });

  it('every entry has valid fields', () => {
    for (const [lib, entries] of Object.entries(KNOWN_VULNS)) {
      for (const entry of entries) {
        expect(entry.below).toBeTruthy();
        expect(entry.cves.length).toBeGreaterThan(0);
        expect(['critical', 'high', 'medium', 'low', 'info']).toContain(entry.severity);
        expect(entry.description).toBeTruthy();
        // Verify "below" is a valid semver
        const parts = parseVersion(entry.below);
        expect(parts.length).toBeGreaterThanOrEqual(3);
      }
    }
  });

  it('entries are ordered from highest to lowest "below" version per library', () => {
    for (const [lib, entries] of Object.entries(KNOWN_VULNS)) {
      for (let i = 0; i < entries.length - 1; i++) {
        const cmp = compareSemver(entries[i].below, entries[i + 1].below);
        expect(cmp).toBeGreaterThanOrEqual(0);
      }
    }
  });
});
