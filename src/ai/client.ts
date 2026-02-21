import Anthropic from '@anthropic-ai/sdk';
import { log } from '../utils/logger.js';

const MODEL = process.env.SECBOT_MODEL || 'claude-sonnet-4-5-20250929';
let cachedClient: Anthropic | null = null;

// ─── Token Tracking ───────────────────────────────────────────────
let totalInputTokens = 0;
let totalOutputTokens = 0;

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export function getTokenUsage(): TokenUsage {
  return {
    inputTokens: totalInputTokens,
    outputTokens: totalOutputTokens,
    totalTokens: totalInputTokens + totalOutputTokens,
  };
}

export function resetTokenUsage(): void {
  totalInputTokens = 0;
  totalOutputTokens = 0;
}

function getTokenBudget(): number {
  const env = process.env.SECBOT_TOKEN_BUDGET;
  if (!env) return Infinity;
  const parsed = parseInt(env, 10);
  return isNaN(parsed) ? Infinity : parsed;
}

export function getClient(): Anthropic | null {
  if (cachedClient) return cachedClient;
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    log.debug('ANTHROPIC_API_KEY not set — AI features unavailable');
    return null;
  }
  cachedClient = new Anthropic({ apiKey });
  return cachedClient;
}

export interface AskClaudeOptions {
  maxTokens?: number;
  temperature?: number;
  /** Timeout in ms — defaults to 30s */
  timeout?: number;
}

/**
 * Send a prompt to Claude and return the text response.
 * Returns null if client unavailable, API call fails, budget exceeded, or timeout.
 */
export async function askClaude(
  systemPrompt: string,
  userPrompt: string,
  options: AskClaudeOptions = {},
): Promise<string | null> {
  // Budget check before making the call
  const budget = getTokenBudget();
  const currentTotal = totalInputTokens + totalOutputTokens;
  if (currentTotal >= budget) {
    log.warn(`Token budget exceeded (${currentTotal}/${budget}) — skipping AI call`);
    return null;
  }

  const client = getClient();
  if (!client) return null;

  const { maxTokens = 4096, temperature = 0.1, timeout = 30000 } = options;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const message = await client.messages.create(
      {
        model: MODEL,
        max_tokens: maxTokens,
        temperature,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      },
      { signal: controller.signal },
    );

    clearTimeout(timer);

    // Track token usage from the response
    if (message.usage) {
      totalInputTokens += message.usage.input_tokens;
      totalOutputTokens += message.usage.output_tokens;
    }

    const textBlock = message.content.find((b) => b.type === 'text');
    if (!textBlock || textBlock.type !== 'text') {
      log.warn('Claude returned no text content');
      return null;
    }

    return textBlock.text;
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes('abort') || msg.includes('cancel')) {
      log.warn(`Claude API timed out after ${timeout}ms`);
    } else {
      log.error(`Claude API error: ${msg}`);
    }
    return null;
  }
}

/**
 * Parse a JSON response from Claude, handling markdown code blocks and truncated JSON.
 */
export function parseJsonResponse<T>(text: string): T | null {
  let jsonStr = text.trim();

  // Handle markdown code blocks
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1].trim();
  }

  // Try to find JSON object if there's text before/after
  if (!jsonStr.startsWith('{') && !jsonStr.startsWith('[')) {
    const startObj = jsonStr.indexOf('{');
    const startArr = jsonStr.indexOf('[');
    const start = startObj === -1 ? startArr : startArr === -1 ? startObj : Math.min(startObj, startArr);
    const endObj = jsonStr.lastIndexOf('}');
    const endArr = jsonStr.lastIndexOf(']');
    const end = Math.max(endObj, endArr);

    if (start !== -1 && end !== -1 && end > start) {
      jsonStr = jsonStr.slice(start, end + 1);
    }
  }

  try {
    return JSON.parse(jsonStr) as T;
  } catch {
    // Try to recover truncated JSON
    const recovered = tryRecoverTruncatedJson(jsonStr);
    if (recovered) {
      try {
        return JSON.parse(recovered) as T;
      } catch (err2) {
        log.debug(`JSON recovery failed: ${(err2 as Error).message}`);
      }
    }
    log.debug('JSON parse failed and recovery unsuccessful');
    return null;
  }
}

/**
 * Attempt to fix truncated/malformed JSON from Claude responses.
 * Handles: unclosed brackets, dangling strings, trailing commas.
 */
function tryRecoverTruncatedJson(input: string): string | null {
  let str = input.trim();

  // Remove trailing comma before we close brackets
  str = str.replace(/,\s*$/, '');

  // Track open brackets
  const stack: string[] = [];
  let inString = false;
  let escape = false;

  for (let i = 0; i < str.length; i++) {
    const ch = str[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === '\\' && inString) {
      escape = true;
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === '{' || ch === '[') {
      stack.push(ch);
    } else if (ch === '}') {
      if (stack.length > 0 && stack[stack.length - 1] === '{') stack.pop();
    } else if (ch === ']') {
      if (stack.length > 0 && stack[stack.length - 1] === '[') stack.pop();
    }
  }

  // If nothing is unclosed, no recovery needed (or possible)
  if (stack.length === 0 && !inString) return null;

  // Close dangling string
  if (inString) {
    str += '"';
  }

  // Remove any trailing comma after closing the string
  str = str.replace(/,\s*$/, '');

  // Close unclosed brackets in reverse order
  while (stack.length > 0) {
    const open = stack.pop();
    // Remove trailing comma before closing
    str = str.replace(/,\s*$/, '');
    str += open === '{' ? '}' : ']';
  }

  log.debug('Recovered truncated JSON');
  return str;
}
