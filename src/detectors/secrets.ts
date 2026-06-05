/**
 * Detector: secrets
 * OWASP: LLM06 — Sensitive Information Disclosure
 * Maturity: Strong
 *
 * Detects API keys, tokens, passwords, and connection strings in text.
 * Patterns are modelled on common real-world credential formats.
 *
 * Honest limitations: short or context-free secrets (e.g. a random 16-char
 * alphanumeric string) cannot be detected without additional context.
 */

import type { Detector, DetectorContext, DetectorResult } from "../types.js";

interface SecretPattern {
  name: string;
  pattern: RegExp;
  /** Base score contribution when matched. */
  weight: number;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // Cloud providers
  { name: "AWS Access Key",    pattern: /\bAKIA[0-9A-Z]{16}\b/, weight: 0.95 },
  { name: "AWS Secret Key",    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/, weight: 0.4 },
  { name: "GCP API Key",       pattern: /AIza[0-9A-Za-z\-_]{35}/, weight: 0.95 },
  { name: "Azure SAS Token",   pattern: /sig=[A-Za-z0-9%]{20,}/, weight: 0.85 },

  // Auth tokens
  { name: "GitHub Token",      pattern: /gh[pousr]_[A-Za-z0-9]{36,}/, weight: 0.95 },
  { name: "GitLab Token",      pattern: /glpat-[A-Za-z0-9\-]{20,}/, weight: 0.95 },
  { name: "Slack Token",       pattern: /xox[baprs]-[0-9A-Za-z\-]{10,}/, weight: 0.95 },
  { name: "Stripe Key",        pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/, weight: 0.95 },
  { name: "Stripe Publishable",pattern: /pk_(live|test)_[0-9a-zA-Z]{24,}/, weight: 0.7 },
  { name: "OpenAI API Key",    pattern: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/, weight: 0.95 },
  { name: "OpenAI Proj Key",   pattern: /sk-proj-[A-Za-z0-9\-_]{40,}/, weight: 0.95 },
  { name: "Anthropic Key",     pattern: /sk-ant-[A-Za-z0-9\-_]{40,}/, weight: 0.95 },
  { name: "JWT",               pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]{10,}/, weight: 0.75 },
  { name: "Bearer Token",      pattern: /bearer\s+[A-Za-z0-9\-_.+/=]{20,}/i, weight: 0.75 },

  // Connection strings
  { name: "Database URL",      pattern: /(?:postgres(?:ql)?|mysql|mongodb|redis|mssql):\/\/[^@\s]+:[^@\s]+@/, weight: 0.9 },
  { name: "Heroku API Key",    pattern: /[hH]eroku[^=\s]*[=:\s]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, weight: 0.9 },

  // Generic high-entropy secret-looking assignments
  { name: "Generic Secret",    pattern: /(?:api[_-]?key|secret|password|passwd|token|auth)\s*[=:]\s*["']?[A-Za-z0-9\-_.+/=]{16,}["']?/i, weight: 0.65 },
  { name: "PEM Private Key",   pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY-----/, weight: 0.99 },
  { name: "PEM Certificate",   pattern: /-----BEGIN\s+CERTIFICATE-----/, weight: 0.5 },
];

function sanitizeSecrets(text: string, hits: Array<{ value: string; name: string }>): string {
  let result = text;
  const seen = new Set<string>();
  for (const h of hits) {
    if (seen.has(h.value)) continue;
    seen.add(h.value);
    result = result.replaceAll(h.value, `[REDACTED-SECRET]`);
  }
  return result;
}

export const secretsDetector: Detector = {
  id: "secrets",
  name: "Secrets & Credentials",
  owasp: "LLM06",
  maturity: "Strong",

  detect(ctx: DetectorContext): DetectorResult {
    const { text } = ctx;
    const hits: Array<{ name: string; value: string; weight: number }> = [];

    for (const sp of SECRET_PATTERNS) {
      const match = sp.pattern.exec(text);
      if (match) {
        hits.push({ name: sp.name, value: match[0], weight: sp.weight });
      }
    }

    if (hits.length === 0) {
      return {
        id: this.id,
        name: this.name,
        owasp: this.owasp,
        maturity: this.maturity,
        score: 0,
        flagged: false,
        detail: "",
      };
    }

    // Max weight drives the score; multiple hits nudge it up slightly.
    const maxWeight = Math.max(...hits.map((h) => h.weight));
    const score = Math.min(maxWeight + (hits.length - 1) * 0.02, 1);

    const names = [...new Set(hits.map((h) => h.name))].join(", ");

    return {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score,
      flagged: true,
      detail: `Secret(s) detected: ${names}`,
      sanitized: sanitizeSecrets(text, hits),
    };
  },
};
