/**
 * Built-in detector registry.
 * Adding a new built-in = add to this map. Zero changes to the public API.
 */

import { promptInjectionDetector } from "./detectors/prompt-injection.js";
import { systemPromptExtractionDetector } from "./detectors/system-prompt-extraction.js";
import { piiInputDetector, piiOutputDetector } from "./detectors/pii.js";
import { secretsDetector } from "./detectors/secrets.js";
import { unsafeOutputDetector } from "./detectors/unsafe-output.js";
import { excessiveAgencyDetector } from "./detectors/excessive-agency.js";
import type { BuiltinDetectorId, Detector } from "./types.js";

export const BUILTIN_DETECTORS: Record<BuiltinDetectorId, Detector> = {
  "prompt-injection": promptInjectionDetector,
  "system-prompt-extraction": systemPromptExtractionDetector,
  "pii-input": piiInputDetector,
  "secrets": secretsDetector,
  "pii-output": piiOutputDetector,
  "unsafe-output": unsafeOutputDetector,
  "excessive-agency": excessiveAgencyDetector,
};

export const ALL_BUILTIN_IDS: BuiltinDetectorId[] = Object.keys(
  BUILTIN_DETECTORS,
) as BuiltinDetectorId[];
