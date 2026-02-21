import chalk from 'chalk';
import { readFileSync } from 'node:fs';

const loggerPkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf-8'));

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let currentLevel: LogLevel = 'info';

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[currentLevel];
}

function timestamp(): string {
  return new Date().toISOString().slice(11, 19);
}

export const log = {
  debug(msg: string, ...args: unknown[]): void {
    if (shouldLog('debug')) {
      console.log(chalk.gray(`[${timestamp()}] DBG ${msg}`), ...args);
    }
  },
  info(msg: string, ...args: unknown[]): void {
    if (shouldLog('info')) {
      console.log(chalk.blue(`[${timestamp()}]`) + ` ${msg}`, ...args);
    }
  },
  warn(msg: string, ...args: unknown[]): void {
    if (shouldLog('warn')) {
      console.log(chalk.yellow(`[${timestamp()}] WARN ${msg}`), ...args);
    }
  },
  error(msg: string, ...args: unknown[]): void {
    if (shouldLog('error')) {
      console.error(chalk.red(`[${timestamp()}] ERR ${msg}`), ...args);
    }
  },
  finding(severity: string, title: string): void {
    const colorFn =
      severity === 'critical' ? chalk.bgRed.white :
      severity === 'high' ? chalk.red :
      severity === 'medium' ? chalk.yellow :
      severity === 'low' ? chalk.cyan :
      chalk.gray;
    console.log(colorFn(`  [${severity.toUpperCase()}]`) + ` ${title}`);
  },
  banner(): void {
    console.log(chalk.bold.cyan(`
  ╔═══════════════════════════════════════╗
  ║         SecBot v${loggerPkg.version.padEnd(22)}║
  ║   AI-Powered Security Scanner        ║
  ╚═══════════════════════════════════════╝
`));
  },
  progress(current: number, total: number, label: string): void {
    const pct = Math.round((current / total) * 100);
    const bar = '█'.repeat(Math.round(pct / 5)) + '░'.repeat(20 - Math.round(pct / 5));
    process.stdout.write(`\r  ${bar} ${pct}% ${label}`);
    if (current === total) console.log();
  },
};
