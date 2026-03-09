/**
 * Contextual Payload Generation
 *
 * Analyzes recon results to generate intelligent payload recommendations.
 * Active checks consult this to prioritize relevant payloads and skip
 * those unlikely to work against the detected tech stack.
 */

import type { ReconResult, TechFingerprint, FrameworkDetection, WafDetection } from '../scanner/types.js';

export type DatabaseType = 'mysql' | 'mssql' | 'postgres' | 'oracle' | 'sqlite' | 'mongodb' | 'unknown';
export type TemplateEngine = 'jinja2' | 'twig' | 'handlebars' | 'pug' | 'ejs' | 'erb' | 'freemarker' | 'velocity' | 'unknown';
export type BackendLang = 'php' | 'java' | 'dotnet' | 'python' | 'ruby' | 'node' | 'go' | 'unknown';

export interface PayloadContext {
  /** Most likely database(s) based on tech stack */
  databases: DatabaseType[];
  /** Most likely template engine(s) */
  templateEngines: TemplateEngine[];
  /** Backend language(s) detected */
  backendLanguages: BackendLang[];
  /** Whether to prioritize DOM XSS over reflected (SPA detected) */
  preferDomXss: boolean;
  /** Whether WAF is present (affects payload encoding strategy) */
  wafPresent: boolean;
  /** WAF-specific bypass techniques to try */
  wafBypasses: string[];
  /** Specific framework recommendations */
  frameworkHints: string[];
  /** OS hint for command injection payloads */
  osHint: 'unix' | 'windows' | 'unknown';
}

/**
 * Infer database types from detected technologies.
 */
function inferDatabases(tech: TechFingerprint, framework: FrameworkDetection): DatabaseType[] {
  const dbs: DatabaseType[] = [];
  const all = [...tech.detected, ...tech.languages, framework.name ?? '', tech.poweredBy ?? ''].join(' ').toLowerCase();

  // PHP typically uses MySQL
  if (all.includes('php') || all.includes('wordpress') || all.includes('laravel') || all.includes('drupal')) {
    dbs.push('mysql');
  }
  // .NET typically uses MSSQL
  if (all.includes('.net') || all.includes('asp') || all.includes('iis')) {
    dbs.push('mssql');
  }
  // Java often uses Oracle or PostgreSQL
  if (all.includes('java') || all.includes('spring') || all.includes('tomcat')) {
    dbs.push('oracle', 'postgres');
  }
  // Python frameworks often use PostgreSQL or SQLite
  if (all.includes('python') || all.includes('django') || all.includes('flask') || all.includes('fastapi')) {
    dbs.push('postgres', 'sqlite');
  }
  // Ruby on Rails typically uses PostgreSQL
  if (all.includes('ruby') || all.includes('rails')) {
    dbs.push('postgres');
  }
  // Node.js uses MongoDB often, but also PostgreSQL
  if (all.includes('express') || all.includes('next.js') || all.includes('nuxt') || all.includes('node')) {
    dbs.push('mongodb', 'postgres');
  }

  return dbs.length > 0 ? [...new Set(dbs)] : ['unknown'];
}

/**
 * Infer template engines from detected technologies.
 */
function inferTemplateEngines(tech: TechFingerprint, framework: FrameworkDetection): TemplateEngine[] {
  const engines: TemplateEngine[] = [];
  const all = [...tech.detected, ...tech.languages, framework.name ?? '', tech.poweredBy ?? ''].join(' ').toLowerCase();

  if (all.includes('django') || all.includes('flask')) engines.push('jinja2');
  if (all.includes('php') || all.includes('laravel') || all.includes('symfony')) engines.push('twig');
  if (all.includes('express') || all.includes('node')) engines.push('handlebars', 'pug', 'ejs');
  if (all.includes('ruby') || all.includes('rails')) engines.push('erb');
  if (all.includes('java') || all.includes('spring')) engines.push('freemarker', 'velocity');

  return engines.length > 0 ? [...new Set(engines)] : ['unknown'];
}

/**
 * Infer backend languages from detected technologies.
 */
function inferBackendLanguages(tech: TechFingerprint, framework: FrameworkDetection): BackendLang[] {
  const langs: BackendLang[] = [];
  const all = [...tech.detected, ...tech.languages, framework.name ?? '', tech.poweredBy ?? '', tech.server ?? ''].join(' ').toLowerCase();

  if (all.includes('php') || all.includes('wordpress') || all.includes('laravel') || all.includes('drupal')) langs.push('php');
  if (all.includes('java') || all.includes('spring') || all.includes('tomcat') || all.includes('jsessionid')) langs.push('java');
  if (all.includes('.net') || all.includes('asp') || all.includes('iis')) langs.push('dotnet');
  if (all.includes('python') || all.includes('django') || all.includes('flask') || all.includes('fastapi') || all.includes('gunicorn') || all.includes('uvicorn')) langs.push('python');
  if (all.includes('ruby') || all.includes('rails') || all.includes('puma') || all.includes('unicorn')) langs.push('ruby');
  if (all.includes('express') || all.includes('next.js') || all.includes('nuxt') || all.includes('node') || all.includes('koa')) langs.push('node');
  if (all.includes('go') || all.includes('gin') || all.includes('fiber')) langs.push('go');

  return langs.length > 0 ? [...new Set(langs)] : ['unknown'];
}

/**
 * Generate framework-specific hints for payload selection.
 */
function generateFrameworkHints(framework: FrameworkDetection, tech: TechFingerprint): string[] {
  const hints: string[] = [];
  const name = (framework.name ?? '').toLowerCase();

  if (name.includes('next') || name.includes('nuxt') || name.includes('react') || name.includes('angular') || name.includes('vue')) {
    hints.push('SPA framework — prioritize DOM-based attacks');
    hints.push('API endpoints likely return JSON — test JSON parameter injection');
  }
  if (name.includes('wordpress')) {
    hints.push('Test wp-admin, wp-login.php, xmlrpc.php, wp-json/wp/v2/');
    hints.push('Check for plugin/theme vulnerabilities in /wp-content/');
  }
  if (name.includes('django')) {
    hints.push('Django ORM typically prevents SQLi — focus on raw query endpoints');
    hints.push('Test for DEBUG=True information disclosure at /');
  }
  if (name.includes('rails')) {
    hints.push('Rails uses strong parameters — focus on mass assignment');
    hints.push('Test /rails/info for debug info disclosure');
  }
  if (name.includes('express')) {
    hints.push('Express apps may have prototype pollution via __proto__');
    hints.push('Test for NoSQL injection if MongoDB detected');
  }
  if (name.includes('laravel')) {
    hints.push('Test /_ignition for debug mode disclosure');
    hints.push('Laravel uses Eloquent ORM — focus on raw query endpoints');
  }

  // Server-specific hints
  const server = (tech.server ?? '').toLowerCase();
  if (server.includes('apache')) {
    hints.push('Apache — test .htaccess disclosure, mod_status (/server-status)');
  }
  if (server.includes('nginx')) {
    hints.push('Nginx — test for alias traversal, stub_status endpoint');
  }
  if (server.includes('iis')) {
    hints.push('IIS — test short filename disclosure (~1), web.config exposure');
  }

  return hints;
}

/**
 * Infer OS from server and technology stack.
 */
function inferOS(tech: TechFingerprint): 'unix' | 'windows' | 'unknown' {
  const server = (tech.server ?? '').toLowerCase();
  const all = tech.detected.join(' ').toLowerCase();

  if (server.includes('iis') || all.includes('.net') || all.includes('asp')) return 'windows';
  if (server.includes('apache') || server.includes('nginx') || all.includes('linux') || all.includes('unix')) return 'unix';

  // Most web servers are unix-based
  return 'unix';
}

/**
 * Build a PayloadContext from recon results.
 *
 * This drives intelligent payload selection across all active checks:
 * - SQLi checks prioritize database-specific payloads
 * - SSTI checks try framework-matched template engines first
 * - XSS checks prioritize DOM vs reflected based on SPA detection
 * - CMDi checks use OS-appropriate payloads
 * - All checks apply WAF bypass encodings when WAF is detected
 */
export function buildPayloadContext(recon: ReconResult): PayloadContext {
  const databases = inferDatabases(recon.techStack, recon.framework);
  const templateEngines = inferTemplateEngines(recon.techStack, recon.framework);
  const backendLanguages = inferBackendLanguages(recon.techStack, recon.framework);

  const spaFrameworks = ['next.js', 'nuxt', 'angular', 'react', 'vue', 'svelte'];
  const preferDomXss = spaFrameworks.some(
    (f) => recon.framework.name?.toLowerCase().includes(f),
  );

  return {
    databases,
    templateEngines,
    backendLanguages,
    preferDomXss,
    wafPresent: recon.waf.detected,
    wafBypasses: recon.waf.recommendedTechniques ?? [],
    frameworkHints: generateFrameworkHints(recon.framework, recon.techStack),
    osHint: inferOS(recon.techStack),
  };
}

/**
 * Get a human-readable summary of the payload context for logging.
 */
export function summarizePayloadContext(ctx: PayloadContext): string {
  const parts: string[] = [];

  if (ctx.backendLanguages[0] !== 'unknown') {
    parts.push(`Backend: ${ctx.backendLanguages.join(', ')}`);
  }
  if (ctx.databases[0] !== 'unknown') {
    parts.push(`DB: ${ctx.databases.join(', ')}`);
  }
  if (ctx.templateEngines[0] !== 'unknown') {
    parts.push(`Template: ${ctx.templateEngines.join(', ')}`);
  }
  if (ctx.preferDomXss) {
    parts.push('SPA → DOM XSS priority');
  }
  if (ctx.wafPresent) {
    parts.push(`WAF detected (${ctx.wafBypasses.length} bypass techniques)`);
  }
  if (ctx.osHint !== 'unknown') {
    parts.push(`OS: ${ctx.osHint}`);
  }
  if (ctx.frameworkHints.length > 0) {
    parts.push(`${ctx.frameworkHints.length} framework hint(s)`);
  }

  return parts.length > 0 ? parts.join(' | ') : 'No specific tech detected';
}
