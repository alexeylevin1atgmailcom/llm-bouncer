/**
 * Detector: excessive-agency
 * OWASP: LLM08 — Excessive Agency
 * Maturity: Basic — first-pass heuristic only.
 *
 * Detects requests that appear to ask the model to take autonomous, broad,
 * or irreversible system actions — signs that the user may be attempting to
 * abuse tool-calling capabilities or get the model to act beyond its scope.
 *
 * Honest limitations: this is a keyword heuristic. Legitimate agentic
 * applications will generate false positives. Use the threshold to tune
 * sensitivity. A proper solution requires analysing the tool schema and
 * call graph in context — planned for v2.
 */

import type { Detector, DetectorContext, DetectorResult } from "../types.js";

/**
 * High-confidence patterns: clearly request dangerous, irreversible system
 * actions. Uses bounded wildcards (.{0,30}) to allow filler words between
 * the action verb and its object without over-matching.
 * A single hit here scores 0.80 — above the default 0.7 threshold.
 */
const HIGH_RISK_PATTERNS: RegExp[] = [
  // Destructive data operations (allows "the entire production" filler)
  /\b(?:delete|drop|truncate|wipe|erase|purge)\b.{0,40}\b(?:all\s+)?(?:database|tables?|collection|all\s+data|all\s+records?|all\s+files?|everything|all\s+users?)/i,
  /\b(?:delete|remove|erase)\b.{0,30}\b(?:user|customer|production|critical)\b.{0,20}\b(?:data|records?|files?|database)/i,
  /\bdrop\b.{0,20}\b(?:every|all)?\s*\btables?\b/i,
  /rm\s+-rf/i,
  /\bwipe\b.{0,20}\b(?:disk|drive|database|storage|all)\b/i,

  // Auth / privilege escalation (allows "me" or other pronouns as filler)
  /\bgrant\b.{0,20}\b(?:admin|root|superuser)\b.{0,20}\b(?:access|permissions?|privileges?)/i,
  /\bdisable\b.{0,20}\b(?:all\s+)?(?:authentication|auth|2fa|mfa|firewall|security|logging)/i,
  /\badd\b.{0,15}\b(?:admin|root|superuser)\s+(?:user|account|role)\b/i,

  // Data exfiltration (flexible: "send ... data ... to", "transfer ... to server")
  /\b(?:send|exfiltrate|transfer|upload|leak|forward)\b.{0,40}\b(?:user|customer|all|production|private)\b.{0,30}\bdata\b.{0,30}\b(?:to|server|endpoint|url|http)/i,
  /exfiltrat/i,

  // Broad autonomy
  /run\s+(?:arbitrary|any)\s+(?:code|commands?|scripts?)/i,
  /execute\s+(?:arbitrary|any)\s+(?:code|commands?|scripts?)/i,
  /bypass\s+(?:security|auth|authorization|rate\s+limit|firewall)/i,
  /act\s+autonomously\s+without\s+(?:asking|checking|confirmation)/i,
];

/**
 * Medium-confidence patterns — meaningful signals but need context.
 * These still rely on exact phrasing; a single hit scores 0.55 (below threshold).
 */
const MEDIUM_RISK_PATTERNS: RegExp[] = [
  /\bdelete\s+(?:all\s+)?(?:files?|directories?|folders?|records?)\b/i,
  /\bwipe\s+(?:the\s+)?(?:disk|drive|table|storage)\b/i,
  /format\s+(?:the\s+)?(?:disk|drive|partition)/i,
  /\bsend\s+(?:an?\s+)?email\s+to\s+(?:all|every|everyone)\b/i,
  /POST\s+to\s+https?:\/\//i,
  /make\s+(?:an?\s+)?outbound\s+(?:request|call|connection)/i,
  /change\s+(?:my\s+)?(?:password|credentials?|API\s+key)/i,
  /do\s+whatever\s+(?:you\s+)?(?:want|need)\s+to\s+(?:complete|finish|achieve)/i,
  /use\s+all\s+(?:available\s+)?tools/i,
];

export const excessiveAgencyDetector: Detector = {
  id: "excessive-agency",
  name: "Excessive Agency",
  owasp: "LLM08",
  maturity: "Basic",

  detect(ctx: DetectorContext): DetectorResult {
    const { text } = ctx;

    const highHits  = HIGH_RISK_PATTERNS.filter((p) => p.test(text)).length;
    const medHits   = MEDIUM_RISK_PATTERNS.filter((p) => p.test(text)).length;
    const totalHits = highHits + medHits;

    if (totalHits === 0) {
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

    // High-risk: first hit = 0.80; each extra adds 0.05, capped at 0.95.
    // Medium-risk: first hit = 0.55; each extra adds 0.05, treated as a
    // corroborating signal that can raise the score toward threshold.
    const highScore = highHits > 0 ? Math.min(0.80 + (highHits - 1) * 0.05, 0.95) : 0;
    const medScore  = medHits  > 0 ? Math.min(0.55 + (medHits  - 1) * 0.05, 0.75) : 0;
    const score     = Math.min(Math.max(highScore, medScore) + (highHits > 0 && medHits > 0 ? 0.05 : 0), 0.95);

    return {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score,
      flagged: true,
      detail: `${totalHits} risky agency pattern(s) matched (${highHits} high, ${medHits} medium risk)`,
    };
  },
};
