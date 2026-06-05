/**
 * Generic Node.js middleware — compatible with Express, Fastify (as a plugin),
 * Koa, Hono, and any framework that exposes a (req, res, next) interface.
 *
 * @example Express
 * ```ts
 * import express from 'express';
 * import { bouncerMiddleware } from '@HANDLE/llm-bouncer/middleware';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(bouncerMiddleware({ mode: 'block', threshold: 0.7 }));
 * ```
 */

import { createGuard } from "../guard.js";
import type { MiddlewareOptions, Verdict } from "../types.js";
import { autoExtract } from "./extract.js";

// Minimal typings so we don't depend on @types/express.
export interface IncomingMessage {
  body?: unknown;
  method?: string;
  bouncerVerdict?: Verdict;
}

export interface ServerResponse {
  statusCode: number;
  setHeader(name: string, value: string): void;
  end(body?: string): void;
}

export type NextFunction = (err?: unknown) => void;

export type NodeMiddleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next: NextFunction,
) => Promise<void>;

function defaultBlockResponse(res: ServerResponse, verdict: Verdict): void {
  const body = JSON.stringify({
    error: "Request blocked by llm-bouncer",
    score: verdict.score,
    detectors: verdict.detectors
      .filter((d) => d.flagged)
      .map((d) => ({ id: d.id, detail: d.detail })),
  });
  res.statusCode = 400;
  res.setHeader("Content-Type", "application/json");
  res.end(body);
}

/**
 * Create an Express/Fastify/Koa-compatible middleware.
 */
export function bouncerMiddleware(options: MiddlewareOptions = {}): NodeMiddleware {
  const guard = createGuard(options);
  const extract = options.extract ?? autoExtract;
  const mode = options.mode ?? "flag";

  return async (req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD") {
      return next();
    }

    const text = extract(req.body);

    if (!text) {
      return next();
    }

    const verdict = await guard.scan(text, "input");

    // Attach the verdict so downstream handlers can inspect it.
    req.bouncerVerdict = verdict;

    if (verdict.action === "block" && mode === "block") {
      if (options.onBlock) {
        const r = options.onBlock(verdict);
        // onBlock returns a Web API Response — convert if possible; otherwise fall through.
        if (r) {
          res.statusCode = 400;
          r.text().then((body) => {
            res.setHeader("Content-Type", "application/json");
            res.end(body);
          }).catch(() => defaultBlockResponse(res, verdict));
          return;
        }
      }
      return defaultBlockResponse(res, verdict);
    }

    if (verdict.action === "sanitize" && verdict.sanitized !== undefined) {
      // Mutate the parsed body in-place so downstream handlers use clean text.
      const body = req.body;
      if (body != null && typeof body === "object") {
        for (const key of ["message", "prompt", "input", "content", "text", "query"]) {
          if (typeof (body as Record<string, unknown>)[key] === "string") {
            (body as Record<string, unknown>)[key] = verdict.sanitized;
            break;
          }
        }
      }
    }

    return next();
  };
}
