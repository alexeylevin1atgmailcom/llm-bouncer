// ---------------------------------------------------------------------------
// Public types — the contract for the entire library.
// ---------------------------------------------------------------------------

/** OWASP LLM Top 10 categories addressed by each detector. */
export type OwaspCategory =
  | "LLM01" // Prompt Injection
  | "LLM02" // Sensitive Information Disclosure
  | "LLM05" // Improper Output Handling
  | "LLM06" // Excessive Agency
  | "LLM08"; // Excessive Agency (tool-call abuse)

/** What the guard tells the host app to do. */
export type Action = "allow" | "block" | "sanitize" | "flag";

/**
 * How the guard enforces findings.
 *
 * - block     — returns a blocked verdict; caller should stop the request.
 * - sanitize  — scrubs detected content and passes it through.
 * - flag      — lets everything through but attaches the verdict.
 * - observe   — silent logging only; verdict is always "allow".
 */
export type Mode = "block" | "sanitize" | "flag" | "observe";

/** Result from a single detector. */
export interface DetectorResult {
  /** Detector identifier, e.g. "prompt-injection". */
  id: string;
  /** Human-readable detector name. */
  name: string;
  /** OWASP LLM Top 10 tag. */
  owasp: OwaspCategory;
  /**
   * Confidence that a vulnerability was found, 0–1.
   * 0 = definitely clean, 1 = definitely vulnerable.
   */
  score: number;
  /** Whether this detector considers the input/output flagged. */
  flagged: boolean;
  /** Human-readable explanation of what was found (may be empty). */
  detail: string;
  /** Sanitized version of the text, if the detector supports it. */
  sanitized?: string;
  /** Maturity label — be honest about what rule-based detection can catch. */
  maturity: "Strong" | "Moderate" | "Basic";
}

/** The overall verdict returned by guard.scan(). */
export interface Verdict {
  /** Recommended action for the host app. */
  action: Action;
  /**
   * Highest score across all detectors, 0–1.
   * Above threshold → potential block/flag.
   */
  score: number;
  /** Whether any detector fired. */
  flagged: boolean;
  /** Per-detector breakdown. */
  detectors: DetectorResult[];
  /**
   * Sanitized version of the scanned text.
   * Only populated when action === "sanitize".
   */
  sanitized?: string;
}

// ---------------------------------------------------------------------------
// Detector plugin interface
// ---------------------------------------------------------------------------

/** Context passed to each detector. */
export interface DetectorContext {
  /** The raw text to scan. */
  text: string;
  /** "input" = user → model, "output" = model → user. */
  direction: "input" | "output";
}

/** A detector plugin. Implement this interface to add a new detector. */
export interface Detector {
  readonly id: string;
  readonly name: string;
  readonly owasp: OwaspCategory;
  readonly maturity: "Strong" | "Moderate" | "Basic";
  detect(ctx: DetectorContext): DetectorResult | Promise<DetectorResult>;
}

// ---------------------------------------------------------------------------
// Guard configuration
// ---------------------------------------------------------------------------

export type BuiltinDetectorId =
  | "prompt-injection"
  | "system-prompt-extraction"
  | "pii-input"
  | "secrets"
  | "pii-output"
  | "unsafe-output"
  | "excessive-agency";

export interface GuardOptions {
  /**
   * Which detectors to run.
   * Pass built-in IDs, custom Detector instances, or mix both.
   * Defaults to all built-in detectors.
   */
  detectors?: Array<BuiltinDetectorId | Detector>;
  /**
   * Enforcement mode. Default: "flag".
   */
  mode?: Mode;
  /**
   * Score threshold (0–1) above which the guard considers text flagged.
   * Default: 0.7
   */
  threshold?: number;
  /**
   * Optional logger — called with structured log events.
   * Use this to pipe to your own observability stack.
   */
  logger?: (event: LogEvent) => void;
}

export interface LogEvent {
  level: "info" | "warn";
  message: string;
  verdict: Verdict;
  text: string;
}

// ---------------------------------------------------------------------------
// Middleware / wrapper helpers
// ---------------------------------------------------------------------------

/** Options for the Next.js route wrapper and Express/Fastify middleware. */
export interface MiddlewareOptions extends GuardOptions {
  /**
   * Custom extractor — pull the text to scan from the request body.
   * If omitted, auto-detects common chat fields:
   * message, prompt, input, and messages[-1].content
   */
  extract?: (body: unknown) => string | undefined;
  /**
   * Called when a request is blocked (mode === "block").
   * Return a Response/void to override the default 400 response.
   */
  onBlock?: (verdict: Verdict) => Response | void;
}
