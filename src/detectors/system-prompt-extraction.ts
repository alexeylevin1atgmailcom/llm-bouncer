/**
 * Detector: system-prompt-extraction
 * OWASP: LLM01 — Prompt Injection
 * Maturity: Moderate
 *
 * Detects attempts to make the model reveal its system prompt or internal
 * instructions. Rule-based; more creative phrasings will evade detection.
 */

import type { Detector, DetectorContext, DetectorResult } from "../types.js";

const EXTRACTION_PATTERNS: RegExp[] = [
  /what\s+(are|is)\s+(your|the)\s+(system\s+)?(prompt|instructions?|context|guidelines?)/i,
  /repeat\s+(your|the)\s+(system\s+)?(prompt|instructions?|context)/i,
  /print\s+(your|the)\s+(system\s+)?(prompt|instructions?|context)/i,
  /show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?|context)/i,
  /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?|context)/i,
  /output\s+(your|the)\s+(system\s+)?(prompt|instructions?|context)/i,
  /tell\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions?)/i,
  /what\s+instructions?\s+(were|was|have\s+you\s+been)\s+given/i,
  /how\s+(were|was)\s+you\s+(prompted|instructed|configured)/i,
  /start\s+(your\s+)?response\s+with\s+["']?\[?SYSTEM/i,
  /verbatim\s+(copy|repeat|output)\s+(of\s+)?(your|the)\s+(system\s+)?prompt/i,
  /translate\s+(your|the)\s+(system\s+)?prompt/i,
  /summarize\s+(your|the)\s+(system\s+)?instructions?/i,
];

export const systemPromptExtractionDetector: Detector = {
  id: "system-prompt-extraction",
  name: "System Prompt Extraction",
  owasp: "LLM01",
  maturity: "Moderate",

  detect(ctx: DetectorContext): DetectorResult {
    const { text } = ctx;
    const hits = EXTRACTION_PATTERNS.filter((p) => p.test(text));
    // Each pattern is quite specific — a single hit is meaningful.
    const score = hits.length > 0 ? Math.min(0.5 + hits.length * 0.2, 1) : 0;

    return {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score,
      flagged: score > 0,
      detail: hits.length > 0 ? `${hits.length} extraction pattern(s) matched` : "",
    };
  },
};
