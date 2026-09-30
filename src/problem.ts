import type { Context } from "hono";

/**
 * core's error envelope: RFC 9457 problem+json with cafaye's extensions
 * (core/docs/openapi-conventions.md, "Error envelope"). No service invents its
 * own error body, and this is the one every rejection in guard goes through.
 *
 * Only the codes guard can actually produce. The reserved list is longer — a
 * routed packet adds `not_found`, `conflict`, `validation_failed`,
 * `rate_limited` and `internal` — and the codes here are not a closed set for
 * the platform, only for this packet.
 */
export type ProblemCode = "unauthorized" | "forbidden" | "unavailable";

/** `title` is fixed per code: it is a summary, not per-occurrence detail. */
const TITLES: Record<ProblemCode, string> = {
  unauthorized: "Unauthorized",
  forbidden: "Forbidden",
  unavailable: "Service unavailable",
};

export type Problem = {
  /** 401 for a caller that failed to authenticate, 403 for one that may not,
   *  503 for a dependency that will not answer. */
  status: 401 | 403 | 503;
  code: ProblemCode;
  /** What happened, in terms the caller can act on. Never an internal reason:
   *  a host, a port, a query, or a parser's opinion goes to the log instead. */
  detail: string;
};

/**
 * Renders a problem response: the envelope, the status, and an `X-Trace-Id`
 * header that matches the `trace_id` in the body.
 *
 * `detail` is written by the caller and is the only place a human-readable
 * reason is chosen, which is why every caller is a fixed string rather than an
 * interpolated error — see the 401s and 503s in `middleware/jwt.ts`.
 */
export function problem(c: Context, { status, code, detail }: Problem): Response {
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
