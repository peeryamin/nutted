import { config } from '../config.js';
import type { LLMProvider } from './provider.js';
import { ClaudeProvider } from './claude.js';
import { GeminiProvider } from './gemini.js';
import { MockProvider } from './mock.js';

/**
 * Select the LLM provider from config (env LLM_PROVIDER).
 *
 * Default is `gemini` (Google AI). If LLM_PROVIDER=gemini but GEMINI_API_KEY
 * is not set, we fall back to the mock provider with a warning so `npm run
 * dev` keeps working with zero infrastructure and zero cost. Set the key to
 * use live models.
 */
export function createLLMProvider(): LLMProvider {
  switch (config.llmProvider) {
    case 'gemini':
      if (!config.geminiApiKey) {
        // SECURITY: never serve deterministic fake findings as real ones in
        // production. In dev/test the mock keeps zero-cost local runs working.
        if (process.env['NODE_ENV'] === 'production') {
          throw new Error(
            'LLM_PROVIDER=gemini but GEMINI_API_KEY is not set (refusing to fall back to the mock provider in production)'
          );
        }
        console.warn(
          '[llm] LLM_PROVIDER=gemini but GEMINI_API_KEY is not set — falling back to the mock provider (no network, no cost)'
        );
        return new MockProvider();
      }
      return new GeminiProvider();
    case 'claude':
      return new ClaudeProvider();
    case 'mock':
    default:
      return new MockProvider();
  }
}
