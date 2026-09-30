import type { Context } from "hono";

/**
 * core's error envelope: RFC 9457 problem+json with cafaye's extensions
 * (core/docs/openapi-conventions.md, "Error envelope"). No service invents its
 * own error body, and this is the one every rejection in guard goes through.
 *
 * Only the codes guard can actually produce. The reserved list is longer — a
 * routed packet adds `not_found`, `rate_limited` and `internal` — and the codes
 * here are not a closed set for the platform, only for this repository.
 *
 * `invalid_json`, `account_locked` and `payload_too_large` are not on core's
 * reserved list. They are the slugs identity already answers with
 * (identity/internal/httpapi/problem.go), and one vocabulary across the platform
 * beats a guard-private synonym for the same failure. Recorded as a DECISION
 * NEEDED in cafaye.yml.
 */
export type ProblemCode =
  | "unauthorized"
  | "forbidden"
  | "unavailable"
  | "invalid_json"
  | "conflict"
  | "validation_failed"
  | "account_locked"
  | "payload_too_large"
  | "rate_limited";

/** `title` is fixed per code: it is a summary, not per-occurrence detail. */
const TITLES: Record<ProblemCode, string> = {
  unauthorized: "Unauthorized",
  forbidden: "Forbidden",
  unavailable: "Service unavailable",
  invalid_json: "Invalid request",
  conflict: "Conflict",
  validation_failed: "Validation failed",
  account_locked: "Account locked",
  payload_too_large: "Payload too large",
  rate_limited: "Too many requests",
};

/** One per-field failure. core scopes `errors[]` to 422. */
export type FieldError = { field: string; code: string };

export type Problem = {
  /** The status this code answers with. 401 for a caller that failed to
   *  authenticate, 403 for one that may not, 409/422/423 for one whose request
   *  was understood and refused, 429 for one that sent too many requests, 503
   *  for a dependency that will not answer. */
  status: 400 | 401 | 403 | 409 | 413 | 422 | 423 | 429 | 503;
  code: ProblemCode;
  /** What happened, in terms the caller can act on. Never an internal reason:
   *  a host, a port, a query, or a parser's opinion goes to the log instead. */
  detail: string;
  /**
   * Per-field failures, for a 422 and nothing else. Optional because a client
   * that renders a form needs them and a client that logs a 401 does not; the
   * renderer below drops them from any other status, so a caller cannot widen
   * core's rule by passing them.
   */
  errors?: FieldError[];
};

/**
 * Renders a problem response: the envelope, the status, and an `X-Trace-Id`
 * header that matches the `trace_id` in the body.
 *
 * `detail` is written by the caller and is the only place a human-readable
 * reason is chosen, which is why every caller is a fixed string rather than an
 * interpolated error — see the 401s and 503s in `middleware/jwt.ts`.
 */
export function problem(c: Context, { status, code, detail, errors }: Problem): Response {
  const traceId = newTraceId();

  return c.json(
    {
      type: `https://errors.cafaye.com/${code}`,
      title: TITLES[code],
      status,
      detail,
      // The path, never the query: a caller who put a credential in one should
      // not find it echoed back in an error body.
      instance: new URL(c.req.url).pathname,
      code,
      trace_id: traceId,
      // Spread last and only for a 422, so a key that is absent rather than
      // undefined: a client rendering `errors` must be able to tell "no fields
      // failed" from "this response is not about fields".
      ...(status === 422 && errors?.length ? { errors } : {}),
    },
    status,
    { "Content-Type": "application/problem+json", "X-Trace-Id": traceId },
  );
}

/**
 * 32 hex characters, the shape core's conventions show.
 *
 * This is a correlation id for a single failed response, not a distributed
 * trace: guard has no tracing yet, and a request that never reached a handler
 * still has to leave something a caller can quote in a bug report.
 */
function newTraceId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
