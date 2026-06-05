# llm-bouncer — Detect and block LLM security threats before they reach your model

[![npm version](https://img.shields.io/npm/v/llm-bouncer)](https://www.npmjs.com/package/llm-bouncer)
[![weekly downloads](https://img.shields.io/npm/dw/llm-bouncer)](https://www.npmjs.com/package/llm-bouncer)
[![license](https://img.shields.io/npm/l/llm-bouncer)](https://github.com/alexeylevin1atgmailcom/llm-bouncer/blob/main/LICENSE)
[![CI](https://github.com/alexeylevin1atgmailcom/llm-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/alexeylevin1atgmailcom/llm-bouncer/actions/workflows/ci.yml)

```
npm install llm-bouncer
```

---

## 30-second quick start

```ts
import { createGuard } from 'llm-bouncer';

// All 7 detectors, threshold 0.7, mode 'flag' — change nothing to get started
const guard = createGuard();

const verdict = await guard.scan(userMessage);

if (verdict.action === 'block') {
  return new Response('Request blocked', { status: 400 });
}
```

The verdict tells you what happened and which detectors fired — you decide what to do with it.

**One-line Next.js App Router integration:**

```ts
// app/api/chat/route.ts
import { withGuard } from 'llm-bouncer';

export const POST = withGuard(
  async (req) => {
    const body = await req.json();
    const reply = await callYourLLM(body.message);
    return Response.json({ reply });
  },
  { mode: 'block', detectors: ['prompt-injection', 'pii-input', 'secrets'] }
);
```

---

## What it catches

| Detector | ID | OWASP LLM Top 10 | Maturity |
|---|---|---|---|
| Prompt Injection | `prompt-injection` | LLM01 | **Strong** |
| System Prompt Extraction | `system-prompt-extraction` | LLM01 | **Moderate** |
| PII in User Input | `pii-input` | LLM02 | **Moderate** |
| PII in Model Output | `pii-output` | LLM02 | **Moderate** |
| Secrets & Credentials | `secrets` | LLM06 | **Strong** |
| Unsafe Output (XSS / SSTI) | `unsafe-output` | LLM05 | **Basic** |
| Excessive Agency | `excessive-agency` | LLM08 | **Basic** |

**Maturity definitions:**
- **Strong** — high recall on known attack patterns; low false-positive rate on typical chat traffic.
- **Moderate** — catches the common cases; determined adversaries or edge formats will slip through.
- **Basic** — first-pass heuristic; useful for raising awareness, not for sole reliance. Tune `threshold` or layer with other controls.

---

## How it works / limitations

llm-bouncer applies **heuristic pattern matching** — regular expressions, format validators (Luhn for card numbers), and keyword signatures. This is a fast, zero-dependency first layer of defence, not a guarantee. A determined adversary who knows your patterns can craft inputs that slip through.

A **model-based detection** tier (semantic analysis via an optional API call) is planned for v2. v1 heuristics and v2 ML detectors will be composable.

Use this library as one layer in a defence-in-depth strategy, alongside system prompt hardening, output encoding, and rate limiting.

---

## Table of contents

- [Installation](#installation)
- [Core API](#core-api)
- [Enforcement modes](#enforcement-modes)
- [Next.js App Router wrapper](#nextjs-app-router-wrapper)
- [Express / Fastify middleware](#express--fastify-middleware)
- [Detector details](#detector-details)
- [Writing a custom detector](#writing-a-custom-detector)
- [Scanning model output](#scanning-model-output)
- [Verdict shape](#verdict-shape)
- [Future / out of scope for v1](#future--out-of-scope-for-v1)
- [License](#license)

---

## Installation

```bash
npm install llm-bouncer
# or
yarn add llm-bouncer
# or
pnpm add llm-bouncer
```

Ships dual ESM + CJS, so both `import` and `require` work out of the box. Zero runtime dependencies.

---

## Core API

### `createGuard(options?)`

Returns a `Guard` instance.

```ts
import { createGuard } from 'llm-bouncer';

const guard = createGuard({
  detectors: ['prompt-injection', 'pii-input', 'secrets'], // subset, or omit for all 7
  mode: 'block',      // block | sanitize | flag (default) | observe
  threshold: 0.7,     // 0–1, default 0.7
  logger: (event) => console.log(event), // optional structured logging
});
```

### `guard.scan(text, direction?)`

```ts
const verdict = await guard.scan(userMessage, 'input'); // 'input' is the default
```

`direction` is `'input'` (user → model) or `'output'` (model → user). Some detectors are direction-aware.

---

## Enforcement modes

| Mode | What it does |
|---|---|
| `block` | Returns `action: 'block'`; host app should stop the request. |
| `sanitize` | Returns `action: 'sanitize'` + a cleaned `verdict.sanitized`. |
| `flag` | Returns `action: 'flag'`; host app decides. **(default)** |
| `observe` | Always returns `action: 'allow'`; logs only. Good for roll-out. |

---

## Next.js App Router wrapper

Wrap your route handler and the guard runs automatically on every POST, with zero config.

```ts
// app/api/chat/route.ts
import { withGuard } from 'llm-bouncer';

export const POST = withGuard(
  async (req) => {
    const body = await req.json();
    const reply = await callYourLLM(body.message);
    return Response.json({ reply });
  },
  {
    mode: 'block',
    threshold: 0.7,
    detectors: ['prompt-injection', 'pii-input', 'secrets'],
  }
);
```

**Auto-extraction** — no config needed. The wrapper scans the first matching field it finds in the request body:

| Priority | Field name(s) |
|---|---|
| 1st | `message`, `prompt`, `input`, `content`, `text`, `query` |
| 2nd | `messages[last].content` (OpenAI-style array) |

**Custom extraction:**

```ts
export const POST = withGuard(handler, {
  extract: (body) => (body as any).data?.userText,
});
```

**Custom block response:**

```ts
export const POST = withGuard(handler, {
  mode: 'block',
  onBlock: (verdict) =>
    Response.json({ message: 'Not allowed', score: verdict.score }, { status: 422 }),
});
```

**Accessing the verdict in your handler:**

The verdict is attached to the request as `req.bouncerVerdict` (non-enumerable, won't appear in `Object.keys`).

```ts
export const POST = withGuard(async (req) => {
  const verdict = (req as any).bouncerVerdict;
  if (verdict?.flagged) console.warn('Suspicious but allowed:', verdict.score);
  // ...
});
```

---

## Express / Fastify middleware

```ts
import express from 'express';
import { bouncerMiddleware } from 'llm-bouncer';

const app = express();
app.use(express.json());

app.use('/api/chat', bouncerMiddleware({
  mode: 'block',
  threshold: 0.7,
  detectors: ['prompt-injection', 'pii-input', 'secrets'],
}));

app.post('/api/chat', (req, res) => {
  const verdict = req.bouncerVerdict;
  res.json({ reply: '...' });
});
```

TypeScript augmentation:

```ts
declare global {
  namespace Express {
    interface Request {
      bouncerVerdict?: import('llm-bouncer').Verdict;
    }
  }
}
```

---

## Detector details

### `prompt-injection` — LLM01

Override imperatives ("ignore previous instructions"), fake role/delimiter markers (`[SYSTEM]`, `<<SYS>>`, `<|im_start|>`), escape sequences, and common obfuscation (base64-encoded keywords, zero-width characters, hex sequences).

**Maturity: Strong** — comprehensive pattern coverage. Adversarial inputs crafted to avoid these specific patterns will still slip through. Pairs well with model-level system prompt hardening.

---

### `system-prompt-extraction` — LLM01

Attempts to make the model reveal its system prompt: "what are your instructions?", "repeat your system prompt verbatim", etc.

**Maturity: Moderate** — covers common phrasings. Creative social-engineering will partially evade this.

---

### `pii-input` — LLM02

PII in user messages — email addresses, US phone numbers (≥10 digits), credit/debit card numbers (Luhn-validated), US Social Security Numbers, and dates of birth. Sanitized output replaces values with `[REDACTED-EMAIL]`, `[REDACTED-CARD]`, etc.

```ts
const guard = createGuard({ mode: 'sanitize', threshold: 0.5 });
const verdict = await guard.scan('My email is alice@example.com and my SSN is 123-45-6789.');
// verdict.action === 'sanitize'
// verdict.sanitized === 'My email is [REDACTED-EMAIL] and my SSN is [REDACTED-SSN].'
```

**Maturity: Moderate** — catches standard formats. International IDs, non-US phone formats, and contextual PII ("my name is Alice Smith") are not detected.

---

### `pii-output` — LLM02

Same detection logic as `pii-input`, applied to model responses. Use when scanning the LLM's reply before sending it to the client.

**Maturity: Moderate** — same caveats as `pii-input`.

---

### `secrets` — LLM06

API keys, access tokens, and credentials — AWS Access Keys, Google Cloud API Keys, GitHub/GitLab PATs, Slack tokens, Stripe keys, OpenAI and Anthropic API keys, JWTs, Bearer tokens, database connection strings with credentials, PEM private keys, and generic `api_key=` / `secret=` / `password=` assignments.

**Maturity: Strong** — format-based detection is highly reliable for well-known key formats. Short, context-free secrets without a recognisable prefix cannot be detected.

---

### `unsafe-output` — LLM05

Model output containing markup that an app might wrongly render — `<script>` tags, inline event handlers (`onclick=`, `onerror=`), `javascript:` URLs, risky HTML elements (`<iframe>`, `<form>`, `<meta>`), and server-side template injection markers (`{{...}}`, `${...}`, `<%...%>`).

**Maturity: Basic** — pattern scanning, not a DOM parser. Use a dedicated HTML sanitiser (e.g. DOMPurify) in production as a second layer.

---

### `excessive-agency` — LLM08

Requests that appear to ask the model to take broad, autonomous, or irreversible actions — deleting files/databases, granting admin access, disabling authentication, exfiltrating data, making outbound HTTP calls to arbitrary URLs.

**Maturity: Basic** — first-pass heuristic only. Legitimate agentic applications will generate false positives. Tune `threshold` to your use case.

---

## Writing a custom detector

Implement the `Detector` interface and pass the instance directly:

```ts
import { createGuard, Detector, DetectorContext, DetectorResult } from 'llm-bouncer';

const profanityDetector: Detector = {
  id: 'custom-profanity',
  name: 'Profanity Filter',
  owasp: 'LLM05',
  maturity: 'Basic',

  detect(ctx: DetectorContext): DetectorResult {
    const flagged = /badword/i.test(ctx.text);
    return {
      id: this.id,
      name: this.name,
      owasp: this.owasp,
      maturity: this.maturity,
      score: flagged ? 0.9 : 0,
      flagged,
      detail: flagged ? 'profanity detected' : '',
    };
  },
};

const guard = createGuard({
  detectors: ['prompt-injection', profanityDetector], // mix built-ins and custom
});
```

Custom detectors can also be `async` — return `Promise<DetectorResult>`.

---

## Scanning model output

```ts
const llmReply = await callYourLLM(userMessage);
const outputVerdict = await guard.scan(llmReply, 'output');

if (outputVerdict.action === 'block') {
  return Response.json({ error: 'Model produced unsafe output' }, { status: 502 });
}

return Response.json({ reply: outputVerdict.sanitized ?? llmReply });
```

Recommended detector subset for output scanning: `pii-output`, `unsafe-output`.

---

## Verdict shape

```ts
interface Verdict {
  action: 'allow' | 'block' | 'sanitize' | 'flag';
  score: number;               // highest per-detector score, 0–1
  flagged: boolean;            // score >= threshold
  detectors: DetectorResult[]; // one entry per detector
  sanitized?: string;          // present when action === 'sanitize'
}

interface DetectorResult {
  id: string;
  name: string;
  owasp: 'LLM01' | 'LLM02' | 'LLM05' | 'LLM06' | 'LLM08';
  score: number;
  flagged: boolean;
  detail: string;       // human-readable explanation
  sanitized?: string;   // cleaned text, if the detector supports it
  maturity: 'Strong' | 'Moderate' | 'Basic';
}
```

---

## Future / out of scope for v1

| Feature | Notes |
|---|---|
| ML/model-based detection | v2 roadmap — optional cloud API call for semantic detection. Composable with v1 heuristics. |
| WebSocket / SSE / streaming | v1 handles normal HTTP POST only. |
| Hosted API / SaaS | Runs entirely in your process. No account, no key, no cost. |
| LLM03 — Training Data Poisoning | Requires offline corpus analysis; not applicable at request time. |
| LLM04 — Model Denial of Service | Infrastructure-level; outside library scope. |
| LLM07 — Insecure Plugin Design | Requires tool schema analysis; planned for v2 excessive-agency upgrade. |
| LLM09 — Overreliance | UX/product concern; not detectable at the HTTP layer. |
| LLM10 — Model Theft | Infrastructure-level concern. |

---

## License

Apache-2.0

---

Built and maintained by [Alexey Levin](https://github.com/alexeylevin1atgmailcom).
