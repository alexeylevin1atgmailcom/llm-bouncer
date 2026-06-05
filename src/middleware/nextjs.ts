/**
 * Next.js App Router route wrapper.
 *
 * Wraps a Next.js route handler so that incoming POST bodies are scanned
 * before your handler runs. Works with the App Router (next >=13).
 *
 * @example
 * ```ts
 * // app/api/chat/route.ts
 * import { withGuard } from '@HANDLE/llm-bouncer/next';
 *
 * export const POST = withGuard(async (req) => {
 *   const body = await req.json();
 *   // body is safe to use — bouncer already ran
 *   return Response.json({ reply: '...' });
 * });
 * ```
 */

import { createGuard } from "../guard.js";
import type { MiddlewareOptions, Verdict } from "../types.js";
import { autoExtract } from "./extract.js";

type NextRouteHandler = (req: Request, ctx?: unknown) => Promise<Response> | Response;

function defaultBlockResponse(verdict: Verdict): Response {
  return Response.json(
    {
      error: "Request blocked by llm-bouncer",
      score: verdict.score,
      detectors: verdict.detectors
        .filter((d) => d.flagged)
        .map((d) => ({ id: d.id, detail: d.detail })),
    },
    { status: 400 },
  );
}

/**
 * Wrap a Next.js App Router handler with LLM security scanning.
 * Only POST requests are scanned; other methods pass through immediately.
 */
export function withGuard(
  handler: NextRouteHandler,
  options: MiddlewareOptions = {},
): NextRouteHandler {
  const guard = createGuard(options);
  const extract = options.extract ?? autoExtract;
  const onBlock = options.onBlock ?? defaultBlockResponse;
  const mode = options.mode ?? "flag";

  return async (req: Request, ctx?: unknown): Promise<Response> => {
    if (req.method !== "POST") {
      return handler(req, ctx);
    }

    let body: unknown;
    let rawText: string;

    try {
      rawText = await req.text();
      try {
        body = JSON.parse(rawText);
      } catch {
        body = rawText;
      }
    } catch {
      return handler(req, ctx);
    }

    const text = extract(body);

    if (!text) {
      // Reconstruct a new request so the handler can read the body.
      const newReq = new Request(req, { body: rawText });
      return handler(newReq, ctx);
    }

    const verdict = await guard.scan(text, "input");

    if (verdict.action === "block" && mode === "block") {
      const blocked = onBlock(verdict);
      if (blocked) return blocked;
      return defaultBlockResponse(verdict);
    }

    // For sanitize mode, replace the text in the body before passing through.
    let finalBody = rawText;
    if (verdict.action === "sanitize" && verdict.sanitized !== undefined && typeof body === "object" && body !== null) {
      // Attempt a best-effort replacement in the serialised JSON.
      finalBody = rawText.replace(text, verdict.sanitized);
    }

    // Reconstruct the request with the (possibly sanitized) body and attach the verdict.
    const newReq = new Request(req, { body: finalBody });
    // Attach verdict as a header so the handler can inspect it without re-parsing.
    (newReq.headers as unknown as Map<string, string>).set?.(
      "x-llm-bouncer-score",
      String(verdict.score),
    );

    // Attach verdict to the request via a custom property for handlers that want it.
    Object.defineProperty(newReq, "bouncerVerdict", {
      value: verdict,
      writable: false,
      enumerable: false,
    });

    return handler(newReq, ctx);
  };
}
