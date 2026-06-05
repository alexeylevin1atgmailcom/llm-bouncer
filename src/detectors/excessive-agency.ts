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

const RISKY_ACTIONS: RegExp[] = [
  // File system
  /delete\s+(all\s+)?(files?|directories?|folders?|data|records?|database)/i,
  /rm\s+-rf/i,
  /wipe\s+(the\s+)?(disk|drive|database|table|storage)/i,
  /format\s+(the\s+)?(disk|drive|partition)/i,

  // Network / outbound
  /send\s+(an?\s+)?email\s+to\s+(all|every|everyone)/i,
  /POST\s+to\s+https?:\/\//i,
  /make\s+(an?\s+)?outbound\s+(request|call|connection)/i,
  /exfiltrat/i,

  // Credentials / auth
  /change\s+(my\s+)?(password|credentials?|API\s+key)/i,
  /grant\s+(admin|root|superuser)\s+(access|permissions?|privileges?)/i,
  /add\s+(a\s+)?new\s+(admin|root|superuser)\s+user/i,
  /disable\s+(authentication|auth|2fa|mfa|firewall|logging)/i,

  // Broad / self-directed autonomy
  /act\s+autonomously\s+without\s+(asking|checking|confirmation)/i,
  /do\s+whatever\s+(you\s+)?(want|need)\s+to\s+(complete|finish|achieve)/i,
  /use\s+all\s+(available\s+)?tools/i,
  /run\s+(arbitrary|any)\s+(code|commands?|scripts?)/i,
  /execute\s+(arbitrary|any)\s+(code|commands?|scripts?)/i,
  /bypass\s+(security|auth|authorization|rate\s+limit|firewall)/i,
];

export const excessiveAgencyDetector: Detector = {
  id: "excessive-agency",
  name: "Excessive Agency",
  owasp: "LLM08",
  maturity: "Basic",

  detect(ctx: DetectorContext): DetectorResult {
    const { text } = ctx;
    const hits = RISKY_ACTIONS.filter((p) => p.test(text));

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

    // First hit gets 0.55; each additional hit adds 0.1, capped at 0.95.
    const score = Math.min(0.55 + (hits.length - 1) * 0.1, 0.95);

    return {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score,
      flagged: true,
      detail: `${hits.length} risky agency pattern(s) matched`,
    };
  },
};
