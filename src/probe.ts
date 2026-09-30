/** What a readiness probe reports for one dependency. */
export type ProbeStatus = "ok" | "unavailable";

/**
 * One dependency's health. A probe that throws, rejects or hangs is
 * `unavailable` — the caller of `/readyz` sees the name, and the reason is
 * logged by whoever runs it. Keeping the type here rather than in `index.ts` is
 * what lets a module like `bff/auth` offer a probe without importing the app
 * factory that consumes it.
 */
export type Probe = () => ProbeStatus | Promise<ProbeStatus>;
