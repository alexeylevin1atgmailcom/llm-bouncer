/**
 * Detector: pii-input / pii-output
 * OWASP: LLM02 — Sensitive Information Disclosure
 * Maturity: Moderate
 *
 * Detects common PII patterns: email addresses, phone numbers, credit/debit
 * card numbers (Luhn-validated), US SSNs, and dates of birth.
 * Sanitized text replaces detected values with [REDACTED-<TYPE>] tokens.
 *
 * Honest limitations: international ID numbers, non-US phone formats, and
 * contextual PII (e.g. "my name is John at 5th Avenue") are not detected.
 */

import type { Detector, DetectorContext, DetectorResult, OwaspCategory } from "../types.js";

// ---------------------------------------------------------------------------
// Patterns and validators
// ---------------------------------------------------------------------------

const EMAIL_RE = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;

// Loose international phone pattern: 7–15 digits, optional + prefix and separators.
const PHONE_RE = /(?<!\d)(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.\-]?)?\d{3}[\s.\-]?\d{4}(?!\d)/g;

// Credit card: 13–19 digits, optionally space/dash separated.
const CARD_RE = /\b(?:\d[ \-]?){13,19}\b/g;

// US SSN: 3-2-4 digit groups with separators.
const SSN_RE = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/g;

// Simple DOB: MM/DD/YYYY or YYYY-MM-DD.
const DOB_RE = /\b(?:0?[1-9]|1[0-2])\/(?:0?[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b|\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g;

/** Luhn algorithm — eliminates most false-positive card numbers. */
function luhn(digits: string): boolean {
  let sum = 0;
  let odd = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i]!, 10);
    if (odd) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    odd = !odd;
  }
  return sum % 10 === 0;
}

interface PiiHit {
  type: string;
  value: string;
}

function findPii(text: string): PiiHit[] {
  const hits: PiiHit[] = [];

  for (const m of text.matchAll(EMAIL_RE)) {
    hits.push({ type: "EMAIL", value: m[0] });
  }

  for (const m of text.matchAll(PHONE_RE)) {
    const digits = m[0].replace(/\D/g, "");
    // Require at least 10 digits for US numbers (or 7 for short local numbers but that
    // would be too noisy — require 10+).
    if (digits.length >= 10) {
      hits.push({ type: "PHONE", value: m[0] });
    }
  }

  for (const m of text.matchAll(CARD_RE)) {
    const digits = m[0].replace(/[\s\-]/g, "");
    if (digits.length >= 13 && luhn(digits)) {
      hits.push({ type: "CARD", value: m[0] });
    }
  }

  for (const m of text.matchAll(SSN_RE)) {
    hits.push({ type: "SSN", value: m[0] });
  }

  for (const m of text.matchAll(DOB_RE)) {
    hits.push({ type: "DOB", value: m[0] });
  }

  return hits;
}

function sanitize(text: string, hits: PiiHit[]): string {
  let result = text;
  // Deduplicate by value to avoid double-replacing.
  const seen = new Set<string>();
  for (const hit of hits) {
    if (seen.has(hit.value)) continue;
    seen.add(hit.value);
    result = result.replaceAll(hit.value, `[REDACTED-${hit.type}]`);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Factory so we can reuse for both pii-input and pii-output directions.
// ---------------------------------------------------------------------------

function makePiiDetector(id: "pii-input" | "pii-output", owasp: OwaspCategory): Detector {
  return {
    id,
    name: id === "pii-input" ? "PII in User Input" : "PII in Model Output",
    owasp,
    maturity: "Moderate",

    detect(ctx: DetectorContext): DetectorResult {
      const hits = findPii(ctx.text);

      const typeCount = new Set(hits.map((h) => h.type)).size;
      // Score: one confirmed PII type = 0.8 (above default 0.7 threshold).
      // Each additional type adds 0.05, capped at 1.0.
      const score = hits.length === 0 ? 0 : Math.min(0.8 + (typeCount - 1) * 0.05, 1);

      const typeSummary = [...new Set(hits.map((h) => h.type))].join(", ");

      const result = {
        id: this.id,
        name: this.name,
        owasp: this.owasp,
        maturity: this.maturity,
        score,
        flagged: hits.length > 0,
        detail: hits.length > 0 ? `${hits.length} PII value(s) found: ${typeSummary}` : "",
      };
      if (hits.length > 0) {
        return { ...result, sanitized: sanitize(ctx.text, hits) };
      }
      return result;
    },
  };
}

export const piiInputDetector = makePiiDetector("pii-input", "LLM02");
export const piiOutputDetector = makePiiDetector("pii-output", "LLM02");
