import type { Context } from "hono";
import type { ApiError } from "../types/index.js";
import { redactSecretText } from "../utils/redact.js";

/** Global error handler for Hono — returns structured ApiError JSON. */
export function errorHandler(err: Error, c: Context): Response {
  const status = err instanceof HttpError ? err.status : 500;
  const code = err instanceof HttpError ? err.code : "INTERNAL_ERROR";
  const message =
    err instanceof HttpError
      ? redactSecretText(err.message)
      : "Security service request failed";

  // Log only the error message and code — never the full error object,
  // which may contain request bodies, tokens, or other secrets.
  console.error(
    `[ERROR] ${c.req.method} ${c.req.path} [${code}] ${err instanceof HttpError ? message : err.name}`,
  );

  const body: ApiError = {
    success: false,
    error: {
      code: String(code),
      message,
    },
  };

  return c.json(body, status as 400);
}

/** Throw an HTTP error with a code. */
export class HttpError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
