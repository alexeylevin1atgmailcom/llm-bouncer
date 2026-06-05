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

/**
 * High-confidence override imperatives — unambiguously target the model's own
 * system instructions. A single match scores ≥ 0.92 and flags alone.
 *
 * Pattern strategy: unified verb alternation covers all canonical phrasings
 * without requiring a separate regex per verb × (previous|prior) combination.
 */
const STRONG_OVERRIDE_PATTERNS: RegExp[] = [
  // Core imperative: action verb + prior/previous/above/your + instructions/prompt/rules/context
  /(ignore|disregard|forget|override|dismiss|discard)\s+(all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|prompt|context|rules?|guidelines?|directives?)/i,
  // "do not follow/obey your instructions"
  /do\s+not\s+(?:follow|obey|respect|adhere\s+to)\s+(?:your\s+)?(?:previous\s+|prior\s+|any\s+)?(?:instructions?|prompt|context|rules?|guidelines?)/i,
  // "forget everything / what you were told" (no explicit "instructions" keyword)
  /forget\s+(?:all\s+)?(?:everything|what)\s+(?:you\s+)?(?:were\s+told|know|have\s+been\s+told|learned)/i,
  // "you have no rules/restrictions now"
  /you\s+(?:now\s+)?have\s+no\s+(?:rules?|restrictions?|instructions?|guidelines?|constraints?)/i,
];

/**
 * ML-framework injection tokens — zero legitimate use in user messages.
 * A single hit here is high-confidence and carries full weight.
 */
const STRONG_DELIMITER_PATTERNS: RegExp[] = [
  /<\|im_start\|>/i,   // ChatML (OpenAI, many open models)
  /<\|im_end\|>/i,     // ChatML
  /<<SYS>>/i,          // LLaMA / Alpaca instruction format
  /\[INST\]/i,         // LLaMA / Mistral instruction marker
  /\[\/INST\]/i,       // LLaMA / Mistral instruction close
];

/**
 * Weaker override signals — meaningful when stacked with other indicators but
 * too ambiguous to flag in isolation (e.g. appear in creative/roleplay text).
 */
const WEAK_OVERRIDE_PATTERNS: RegExp[] = [
  /you\s+are\s+now\s+(a|an)\s+/i,
  /act\s+as\s+if\s+you\s+(have\s+no|are\s+not)/i,
  /your\s+new\s+(role|task|purpose|instructions?)\s+(is|are)/i,
  /pretend\s+(you\s+are|to\s+be)\s+/i,
  /simulate\s+(being\s+)?a\s+/i,
  /jailbreak/i,
  /DAN\s+mode/i,
  /developer\s+mode\s+(enabled|activated|on)/i,
  /prompt\s+injection/i,
];

/** Ambiguous role/delimiter markers — meaningful in combination, not alone */
const DELIMITER_PATTERNS: RegExp[] = [
  /\[SYSTEM\]/i,
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

function scorePatterns(text: string, patterns: RegExp[], baseScore = 0.75): number {
  const hits = patterns.filter((p) => p.test(text)).length;
  if (hits === 0) return 0;
  return Math.min(baseScore + (hits - 1) * 0.05, 1);
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

    // Strong override imperatives score 0.92 on their own — high-confidence standalone.
    const strongOverrideScore = scorePatterns(text, STRONG_OVERRIDE_PATTERNS, 0.92);
    if (strongOverrideScore > 0)
      details.push(`strong override imperative (${(strongOverrideScore * 100).toFixed(0)}%)`);

    // Weak overrides need to stack with other signals to reach threshold.
    const weakOverrideScore = scorePatterns(text, WEAK_OVERRIDE_PATTERNS);
    if (weakOverrideScore > 0)
      details.push(`override patterns (${(weakOverrideScore * 100).toFixed(0)}%)`);

    // ML-specific tokens (<|im_start|>, <<SYS>>, [INST]) — zero legitimate use in user input.
    const strongDelimScore = scorePatterns(text, STRONG_DELIMITER_PATTERNS, 0.92);
    if (strongDelimScore > 0)
      details.push(`ML injection token (${(strongDelimScore * 100).toFixed(0)}%)`);

    const delimiterScore = scorePatterns(text, DELIMITER_PATTERNS);
    if (delimiterScore > 0) details.push(`delimiter injection (${(delimiterScore * 100).toFixed(0)}%)`);

    const escapeScore = scorePatterns(text, ESCAPE_PATTERNS);
    if (escapeScore > 0) details.push(`escape sequences (${(escapeScore * 100).toFixed(0)}%)`);

    const obfuscation = detectObfuscation(text);
    if (obfuscation.score > 0) details.push(obfuscation.detail);

    // Strong signals (override imperatives, ML injection tokens) carry full weight.
    // Ambiguous signals stack at reduced weight and need corroboration.
    const score = Math.min(
      strongOverrideScore * 1.0 +
        strongDelimScore * 1.0 +
        weakOverrideScore * 0.9 +
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
