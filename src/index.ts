/**
 * @HANDLE/llm-bouncer
 * Detect and block LLM security vulnerabilities in chatbot input and output.
 *
 * @example
 * ```ts
 * import { createGuard } from '@HANDLE/llm-bouncer';
 *
 * const guard = createGuard({ detectors: ['prompt-injection', 'pii-input'], threshold: 0.7 });
 * const verdict = await guard.scan(userMessage);
 * if (verdict.action === 'block') throw new Error('Blocked');
 * ```
 */

// Core API
export { createGuard } from "./guard.js";
export type { Guard } from "./guard.js";

// Middleware
export { withGuard } from "./middleware/nextjs.js";
export { bouncerMiddleware } from "./middleware/node.js";
export type { NodeMiddleware, IncomingMessage, ServerResponse, NextFunction } from "./middleware/node.js";

// Registry helpers (for plugin authors)
export { BUILTIN_DETECTORS, ALL_BUILTIN_IDS } from "./registry.js";

// All public types
export type {
  Action,
  BuiltinDetectorId,
  Detector,
  DetectorContext,
  DetectorResult,
  GuardOptions,
  LogEvent,
  MiddlewareOptions,
  Mode,
  OwaspCategory,
  Verdict,
} from "./types.js";
