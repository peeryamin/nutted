import { config } from '../config.js';
import { makeCompletion, type LLMCompletion, type LLMCompletionRequest, type LLMProvider } from './provider.js';

/**
 * Claude (Anthropic Messages API) implementation.
 * The API key is read ONLY from the ANTHROPIC_API_KEY env var — never
 * hardcoded, never logged. config.ts throws at boot if the key is missing
 * while LLM_PROVIDER=claude.
 */
export class ClaudeProvider implements LLMProvider {
  readonly name = 'claude';
  private readonly apiKey: string;
  private readonly model: string;

  constructor(apiKey?: string, model?: string) {
    const key = apiKey ?? config.anthropicApiKey;
    if (!key) {
      throw new Error('ANTHROPIC_API_KEY is required for the Claude provider');
    }
    this.apiKey = key;
    this.model = model ?? config.anthropicModel;
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const system = req.messages
      .filter((m) => m.role === 'system')
      .map((m) => m.content)
      .join('\n\n');
    const messages = req.messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({ role: m.role, content: m.content }));

    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: req.maxTokens ?? 2000,
        temperature: req.temperature ?? 0.2,
        system: system || undefined,
        messages,
      }),
    });

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Anthropic API error ${res.status}: ${body.slice(0, 300)}`);
    }
    const data = (await res.json()) as {
      content: Array<{ type: string; text?: string }>;
      usage: { input_tokens: number; output_tokens: number };
    };
    const text = data.content
      .filter((b) => b.type === 'text' && b.text)
      .map((b) => b.text as string)
      .join('');
    return makeCompletion(text, {
      inputTokens: data.usage.input_tokens,
      outputTokens: data.usage.output_tokens,
    });
  }
}
