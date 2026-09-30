// Configuration checks, in one place.
//
// Every module that reads configuration validates it at construction and throws
// a `RangeError`, because `RATE_LIMIT_REQUESTS=0` has to be a refusal to boot
// rather than a surprise on the first request of the week. The message names the
// field and the value it was given, and never anything the operator did not type.

export function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(`${field} must be an integer >= 1, got ${String(value)}`);
  }
}

export function assertNonNegativeInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`${field} must be an integer >= 0, got ${String(value)}`);
  }
}

/**
 * A structured-field key, per RFC 9651 §3.1.1.3: `lcalpha / DIGIT / "_" / "-"
 * / "." / "*"`, opening on a letter or `*`, at most 64 characters.
 *
 * Used for rate-limit policy names, which go into `RateLimit-Policy` and
 * `RateLimit` header values as quoted strings. A name that fails this is not
 * escaped and truncated — it is rejected, because a policy name is guard's own
 * configuration and a wrong one is a mistake to surface rather than a string to
 * sanitise.
 */
const SF_KEY = /^[a-z*][a-z0-9_.*-]{0,63}$/;

export function assertStructuredKey(value: string, field: string): string {
  if (typeof value !== "string" || !SF_KEY.test(value)) {
    throw new RangeError(`${field} must be a structured-field key, got ${JSON.stringify(value)}`);
  }
  return value;
}
