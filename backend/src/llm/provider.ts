/**
 * Provider-agnostic LLM interface.
 *
 * Agent decisions go through this interface so the underlying model is
 * swappable (Claude today; OpenAI or a fine-tuned model tomorrow — plan §4.3).
 * The API key for any provider comes ONLY from environment variables, never
 * hardcoded (see .env.example).
 */

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LLMCompletionRequest {
  messages: LLMMessage[];
  maxTokens?: number;
  temperature?: number;
  /**
   * Routing hint for tiered model strategy (cost control):
   * - 'routine': high-volume, low-complexity calls (test planning, simple
   *   classification) → Flash-class model.
   * - 'reasoning': complex analysis (reflection, severity judgment,
   *   honeypot adjudication, chaining) → Pro-class model.
   * Providers without tiering support may ignore this field.
   */
  tier?: 'routine' | 'reasoning';
}

export interface LLMUsage {
  inputTokens: number;
  outputTokens: number;
}

export interface LLMCompletion {
  text: string;
  usage: LLMUsage;
  /** Parse the completion as JSON; throws a descriptive error on failure. */
  parseJson<T>(): T;
}

export interface LLMProvider {
  readonly name: string;
  complete(req: LLMCompletionRequest): Promise<LLMCompletion>;
}

export function makeCompletion(text: string, usage: LLMUsage): LLMCompletion {
  return {
    text,
    usage,
    parseJson<T>(): T {
      // Tolerate code fences around the JSON payload.
      const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
      try {
        return JSON.parse(cleaned) as T;
      } catch (err) {
        throw new Error(
          `LLM returned invalid JSON: ${(err as Error).message}. Raw output (truncated): ${cleaned.slice(0, 300)}`
        );
      }
    },
  };
}
