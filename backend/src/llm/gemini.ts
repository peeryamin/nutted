import { config } from '../config.js';
import { makeCompletion, type LLMCompletion, type LLMCompletionRequest, type LLMProvider } from './provider.js';

/**
 * Google Gemini (AI Studio Developer API) implementation — the DEFAULT provider.
 *
 * REST endpoint: https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
 * Auth: `x-goog-api-key` header (never a query param — keeps the key out of logs/URLs).
 * The API key is read ONLY from the GEMINI_API_KEY env var — never hardcoded,
 * never logged.
 *
 * Tiered routing (cost control — the user is a cost-sensitive student):
 * - tier 'routine'   → GEMINI_ROUTINE_MODEL   (default gemini-3.8-flash: cheap, fast)
 * - tier 'reasoning' → GEMINI_REASONING_MODEL (default gemini-3.1-pro-preview:  strong reasoning)
 * Model IDs are configurable via env; defaults are pinned stable GA versions.
 */
export class GeminiProvider implements LLMProvider {
  readonly name = 'gemini';
  private readonly apiKey: string;
  private readonly routineModel: string;
  private readonly reasoningModel: string;

  constructor(apiKey?: string, routineModel?: string, reasoningModel?: string) {
    const key = apiKey ?? config.geminiApiKey;
    if (!key) {
      throw new Error('GEMINI_API_KEY is required for the Gemini provider');
    }
    this.apiKey = key;
    this.routineModel = routineModel ?? config.geminiRoutineModel;
    this.reasoningModel = reasoningModel ?? config.geminiReasoningModel;
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const model = req.tier === 'reasoning' ? this.reasoningModel : this.routineModel;

    const system = req.messages
      .filter((m) => m.role === 'system')
      .map((m) => m.content)
      .join('\n\n');
    const contents = req.messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

    const body: Record<string, unknown> = {
      contents,
      generationConfig: {
        maxOutputTokens: req.maxTokens ?? 2000,
        temperature: req.temperature ?? 0.2,
      },
    };
    if (system) {
      body['systemInstruction'] = { parts: [{ text: system }] };
    }

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;
    const data = await this.postWithRetry(url, body);

    const blockReason = data?.promptFeedback?.blockReason;
    if (blockReason) {
      throw new Error(`Gemini request blocked (safety): ${blockReason}`);
    }
    const candidate = data?.candidates?.[0];
    if (!candidate) {
      throw new Error(
        `Gemini returned no candidates (finishReason: ${data?.candidates?.[0]?.finishReason ?? 'unknown'})`
      );
    }
    const parts: Array<{ text?: string; thought?: boolean }> = candidate.content?.parts ?? [];
    const text = parts
      .filter((p) => typeof p.text === 'string' && !p.thought)
      .map((p) => p.text as string)
      .join('');
    if (!text) {
      throw new Error(
        `Gemini returned an empty response (finishReason: ${candidate.finishReason ?? 'unknown'})`
      );
    }
    return makeCompletion(text, {
      inputTokens: data?.usageMetadata?.promptTokenCount ?? 0,
      outputTokens: data?.usageMetadata?.candidatesTokenCount ?? 0,
    });
  }

  /**
   * POST with one retry on transient statuses (429 / 5xx), exponential backoff.
   * Keeps paid calls minimal: at most 2 attempts per completion.
   */
  private async postWithRetry(url: string, body: Record<string, unknown>): Promise<any> {
    let lastError: Error | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt - 1)));
      }
      let res: Response;
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-goog-api-key': this.apiKey,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(60_000),
        });
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        continue;
      }
      if (res.ok) {
        return (await res.json()) as any;
      }
      const payload = await res.text().catch(() => '');
      lastError = new Error(`Gemini API error ${res.status}: ${payload.slice(0, 300)}`);
      if (res.status !== 429 && res.status < 500) break; // non-transient — don't retry
    }
    throw lastError ?? new Error('Gemini request failed');
  }
}
