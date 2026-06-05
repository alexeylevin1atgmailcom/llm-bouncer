/**
 * Detector: unsafe-output
 * OWASP: LLM05 — Improper Output Handling
 * Maturity: Basic
 *
 * Detects model output that contains markup, script, or HTML that an
 * application might wrongly trust and render without sanitisation —
 * enabling XSS, CSS injection, or similar client-side attacks.
 *
 * Honest limitations: this is a pattern scanner, not a DOM parser.
 * Obfuscated payloads (e.g. split across multiple lines, entity-encoded,
 * or delivered in a PDF/markdown code block) will likely evade detection.
 * Always sanitise output with a dedicated HTML sanitiser in production.
 */

import type { Detector, DetectorContext, DetectorResult } from "../types.js";

const SCRIPT_PATTERNS: RegExp[] = [
  /<script[\s>]/i,
  /<\/script>/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /data\s*:\s*text\/html/i,
  /on(?:load|click|mouse\w+|key\w+|focus|blur|error|submit|change|input)\s*=/i,
];

const HTML_INJECTION_PATTERNS: RegExp[] = [
  /<(?:iframe|object|embed|applet|form|input|button|select|textarea|frame|frameset|meta|link|base)\b/i,
  /<img[^>]+src\s*=/i,
  /expression\s*\(/i, // CSS expression
  /url\s*\(\s*["']?\s*javascript/i,
];

const TEMPLATE_INJECTION_PATTERNS: RegExp[] = [
  /\{\{.*\}\}/, // Handlebars / Vue / Jinja
  /\$\{.*\}/, // JS template literals
  /#\{.*\}/, // Ruby ERB
  /<\?php/i,
  /<%[=\-]?.*%>/,
];

const MARKDOWN_LINK_JS: RegExp = /\[.*?\]\s*\(\s*javascript\s*:/i;

function sanitizeOutput(text: string): string {
  return text
    .replace(/<script[\s\S]*?<\/script>/gi, "[REMOVED-SCRIPT]")
    .replace(/<[^>]+>/g, "[REMOVED-TAG]")
    .replace(/javascript\s*:/gi, "[REMOVED-JS]");
}

export const unsafeOutputDetector: Detector = {
  id: "unsafe-output",
  name: "Unsafe Output (XSS / Injection)",
  owasp: "LLM05",
  maturity: "Basic",

  detect(ctx: DetectorContext): DetectorResult {
    const { text } = ctx;
    const details: string[] = [];
    let score = 0;

    const scriptHits = SCRIPT_PATTERNS.filter((p) => p.test(text));
    if (scriptHits.length > 0) {
      score = Math.max(score, 0.85);
      details.push(`script/event patterns (${scriptHits.length})`);
    }

    const htmlHits = HTML_INJECTION_PATTERNS.filter((p) => p.test(text));
    if (htmlHits.length > 0) {
      score = Math.max(score, 0.65);
      details.push(`risky HTML elements (${htmlHits.length})`);
    }

    const templateHits = TEMPLATE_INJECTION_PATTERNS.filter((p) => p.test(text));
    if (templateHits.length > 0) {
      score = Math.max(score, 0.6);
      details.push(`template injection patterns (${templateHits.length})`);
    }

    if (MARKDOWN_LINK_JS.test(text)) {
      score = Math.max(score, 0.8);
      details.push("markdown javascript: link");
    }

    const base = {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score,
      flagged: score > 0,
      detail: details.join("; ") || "",
    };
    if (score > 0) return { ...base, sanitized: sanitizeOutput(text) };
    return base;
  },
};
