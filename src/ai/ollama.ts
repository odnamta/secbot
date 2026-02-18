import { log } from '../utils/logger.js';

const OLLAMA_BASE_URL = process.env.OLLAMA_URL ?? 'http://localhost:11434';

interface OllamaChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface OllamaChatResponse {
  message: { role: string; content: string };
  done: boolean;
}

/** Check if Ollama is running and the model is available */
export async function isOllamaAvailable(model: string): Promise<boolean> {
  try {
    const res = await fetch(`${OLLAMA_BASE_URL}/api/tags`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return false;
    const data = (await res.json()) as { models?: { name: string }[] };
    const models = data.models ?? [];
    return models.some((m) => m.name === model || m.name.startsWith(model.split(':')[0]));
  } catch {
    return false;
  }
}

/** List available Ollama models */
export async function listOllamaModels(): Promise<string[]> {
  try {
    const res = await fetch(`${OLLAMA_BASE_URL}/api/tags`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return [];
    const data = (await res.json()) as { models?: { name: string }[] };
    return (data.models ?? []).map((m) => m.name);
  } catch {
    return [];
  }
}

/** Send a chat completion request to Ollama */
export async function ollamaChat(
  model: string,
  systemPrompt: string,
  userMessage: string,
): Promise<string> {
  const messages: OllamaChatMessage[] = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userMessage },
  ];

  log.debug(`Ollama request to ${model} (${userMessage.length} chars)`);

  const res = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages,
      stream: false,
      format: 'json', // Force JSON output mode
      options: {
        temperature: 0.1,
        num_predict: 4096,
      },
    }),
    signal: AbortSignal.timeout(180000), // 3 min timeout for local models
  });

  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`Ollama error (${res.status}): ${errorText}`);
  }

  const data = (await res.json()) as OllamaChatResponse;
  return data.message.content;
}
