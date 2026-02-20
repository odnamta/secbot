import Anthropic from '@anthropic-ai/sdk';
import { log } from '../utils/logger.js';

const MODEL = 'claude-sonnet-4-5-20250929';
let cachedClient: Anthropic | null = null;

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
 * Returns null if client unavailable, API call fails, or timeout.
 */
export async function askClaude(
  systemPrompt: string,
  userPrompt: string,
  options: AskClaudeOptions = {},
): Promise<string | null> {
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
  } catch (err) {
    log.debug(`JSON parse failed: ${(err as Error).message}`);
    return null;
  }
}
