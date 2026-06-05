/**
 * Detector: prompt-injection
 * OWASP: LLM01 — Prompt Injection
 * Maturity: Strong (rule-based pattern matching)
 *
 * Detects attempts to override, escape, or hijack the system prompt,
 * fake role/delimiter markers, and common obfuscation techniques
 * (base64, hex encoding, zero-width characters).
 *
 * Honest limitations: adversarial inputs crafted to avoid these patterns
 * will slip through. This is a first line of defence, not a guarantee.
 */

import type { Detector, DetectorContext, DetectorResult } from "../types.js";

// ---------------------------------------------------------------------------
// Pattern groups — each group contributes to the final score independently
// so a hit in any one group is meaningful.
// ---------------------------------------------------------------------------

/** Direct override imperatives */
const OVERRIDE_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /disregard\s+(all\s+)?previous\s+instructions?/i,
  /forget\s+(all\s+)?previous\s+instructions?/i,
  /ignore\s+(all\s+)?prior\s+instructions?/i,
  /override\s+(all\s+|your\s+)?(previous\s+|prior\s+)?instructions?/i,
  /you\s+are\s+now\s+(a|an)\s+/i,
  /act\s+as\s+if\s+you\s+(have\s+no|are\s+not)/i,
  /your\s+new\s+(role|task|purpose|instructions?)\s+(is|are)/i,
  /do\s+not\s+follow\s+(your\s+)?(previous\s+|prior\s+)?instructions?/i,
  /pretend\s+(you\s+are|to\s+be)\s+/i,
  /simulate\s+(being\s+)?a\s+/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /developer\s+mode\s+(enabled|activated|on)/i,
  /prompt\s+injection/i,
];

/** Fake delimiter / role injection markers */
const DELIMITER_PATTERNS: RegExp[] = [
  /\[SYSTEM\]/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /<\|im_start\|>/i,
  /<\|im_end\|>/i,
  /\[\/INST\]/i,
  /\[ASSISTANT\]/i,
  /\[USER\]/i,
  /###\s*(System|Instruction|Context|Prompt)/i,
  /---+\s*(system|instruction)/i,
  /system\s+prompt\s*:/i,
  /\bHuman\s*:\s*$/im,
  /\bAssistant\s*:\s*$/im,
];

/** Escape sequences — trying to break out of a wrapper */
const ESCAPE_PATTERNS: RegExp[] = [
  /\\n\\n(system|assistant|human):/i,
  /<\/?(system|instructions?|context|prompt)>/i,
  /\}\s*,?\s*\{\s*"role"\s*:\s*"system"/i, // JSON role injection
  /\]\s*,?\s*\[\s*"system"/i,
];

/** Obfuscation — base64-encoded common injection triggers */
const BASE64_INJECTION_PAYLOADS = [
  "aWdub3Jl", // ignore
  "aW5zdHJ1Y3Rpb25z", // instructions
  "c3lzdGVt", // system
  "am9pbmJyZWFr", // jailbreak
];

const ZERO_WIDTH_RE = /[​-‍﻿⁠᠎]/;

const HEX_ENCODED_RE = /(?:0x[0-9a-f]{2}\s*){4,}/i;

// ---------------------------------------------------------------------------

function scorePatterns(text: string, patterns: RegExp[]): number {
  // Any single pattern hit is meaningful (each is a specific signal).
  // Additional hits push the score up slightly.
  const hits = patterns.filter((p) => p.test(text)).length;
  if (hits === 0) return 0;
  return Math.min(0.75 + (hits - 1) * 0.05, 1);
}

function detectObfuscation(text: string): { score: number; detail: string } {
  const details: string[] = [];
  let score = 0;

  if (ZERO_WIDTH_RE.test(text)) {
    score = Math.max(score, 0.85);
    details.push("zero-width characters detected");
  }

  if (HEX_ENCODED_RE.test(text)) {
    score = Math.max(score, 0.7);
    details.push("hex-encoded sequences detected");
  }

  for (const fragment of BASE64_INJECTION_PAYLOADS) {
    if (text.includes(fragment)) {
      score = Math.max(score, 0.8);
      details.push("base64-encoded injection keyword detected");
      break;
    }
  }

  return { score, detail: details.join("; ") };
}

// ---------------------------------------------------------------------------

export const promptInjectionDetector: Detector = {
  id: "prompt-injection",
  name: "Prompt Injection",
  owasp: "LLM01",
  maturity: "Strong",

  detect(ctx: DetectorContext): DetectorResult {
    const { text } = ctx;
    const details: string[] = [];

    const overrideScore = scorePatterns(text, OVERRIDE_PATTERNS);
    if (overrideScore > 0) details.push(`override patterns (${(overrideScore * 100).toFixed(0)}%)`);

    const delimiterScore = scorePatterns(text, DELIMITER_PATTERNS);
    if (delimiterScore > 0) details.push(`delimiter injection (${(delimiterScore * 100).toFixed(0)}%)`);

    const escapeScore = scorePatterns(text, ESCAPE_PATTERNS);
    if (escapeScore > 0) details.push(`escape sequences (${(escapeScore * 100).toFixed(0)}%)`);

    const obfuscation = detectObfuscation(text);
    if (obfuscation.score > 0) details.push(obfuscation.detail);

    // Weight: overrides count most, then delimiters, then escapes, then obfuscation.
    const score = Math.min(
      overrideScore * 0.9 +
        delimiterScore * 0.6 +
        escapeScore * 0.6 +
        obfuscation.score * 0.7,
      1,
    );

    return {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score,
      flagged: score > 0,
      detail: details.join("; ") || "",
    };
  },
};
