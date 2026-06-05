/**
 * Core guard engine.
 * Orchestrates detector execution and applies the enforcement mode.
 */

import type {
  Action,
  Detector,
  DetectorResult,
  GuardOptions,
  LogEvent,
  Mode,
  Verdict,
} from "./types.js";
import { BUILTIN_DETECTORS, ALL_BUILTIN_IDS } from "./registry.js";

const DEFAULT_THRESHOLD = 0.7;
const DEFAULT_MODE: Mode = "flag";

function resolveDetectors(
  ids: GuardOptions["detectors"],
): Detector[] {
  if (!ids || ids.length === 0) {
    return ALL_BUILTIN_IDS.map((id) => BUILTIN_DETECTORS[id]);
  }
  return ids.map((entry) => {
    if (typeof entry === "string") {
      const d = BUILTIN_DETECTORS[entry];
      if (!d) throw new Error(`Unknown built-in detector: "${entry}"`);
      return d;
    }
    return entry;
  });
}

function pickSanitized(results: DetectorResult[]): string | undefined {
  // Prefer the sanitized text from the highest-scoring detector.
  const sorted = [...results]
    .filter((r) => r.sanitized !== undefined)
    .sort((a, b) => b.score - a.score);
  return sorted[0]?.sanitized;
}

function deriveAction(
  flagged: boolean,
  mode: Mode,
  hasSanitized: boolean,
): Action {
  if (!flagged) return "allow";
  switch (mode) {
    case "block": return "block";
    case "sanitize": return hasSanitized ? "sanitize" : "flag";
    case "observe": return "allow";
    case "flag":
    default: return "flag";
  }
}

export interface Guard {
  /**
   * Scan a piece of text through all configured detectors.
   * @param text  The text to analyse (user input or model output).
   * @param direction  Whether this is user → model ("input") or model → user ("output").
   *                   Defaults to "input".
   */
  scan(text: string, direction?: "input" | "output"): Promise<Verdict>;
}

/**
 * Create a guard instance with the given configuration.
 *
 * @example
 * ```ts
 * const guard = createGuard({ detectors: ['prompt-injection', 'pii-input'], threshold: 0.7 });
 * const verdict = await guard.scan(userMessage);
 * if (verdict.action === 'block') return new Response('Blocked', { status: 400 });
 * ```
 */
export function createGuard(options: GuardOptions = {}): Guard {
  const detectors = resolveDetectors(options.detectors);
  const mode: Mode = options.mode ?? DEFAULT_MODE;
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const logger = options.logger;

  return {
    async scan(text: string, direction: "input" | "output" = "input"): Promise<Verdict> {
      const ctx = { text, direction };

      const results: DetectorResult[] = await Promise.all(
        detectors.map((d) => Promise.resolve(d.detect(ctx))),
      );

      const topScore = results.reduce((max, r) => Math.max(max, r.score), 0);
      const flagged = topScore >= threshold;
      const sanitized = flagged ? pickSanitized(results) : undefined;
      const action = deriveAction(flagged, mode, sanitized !== undefined);

      const verdict: Verdict = {
        action,
        score: topScore,
        flagged,
        detectors: results,
        ...(sanitized !== undefined ? { sanitized } : {}),
      };

      if (logger) {
        const event: LogEvent = {
          level: flagged ? "warn" : "info",
          message: flagged ? "llm-bouncer: flagged" : "llm-bouncer: clean",
          verdict,
          text,
        };
        logger(event);
      }

      return verdict;
    },
  };
}
