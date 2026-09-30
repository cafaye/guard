// A limit table for tests that want one number everywhere.
//
// The shipped table is per-route, which is the point of the packet; a test that
// only wants "every request after the first is refused" should not have to
// enumerate the routes to say so. `routes` is empty on purpose: the default
// applies to everything, and the probe endpoints are exempt by wiring rather
// than by a table entry.
import type { LimitTable } from "../src/middleware/limits";

export function strictTable(limit: number, windowMs = 60_000): LimitTable {
  return { default: { limit, windowMs, policy: "test" }, routes: {} };
}
