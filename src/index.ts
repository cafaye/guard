import { Hono } from "hono";
import type { Context } from "hono";
import { rateLimit } from "./middleware/rateLimit";

/** What a readiness probe reports for one dependency. */
export type ProbeStatus = "ok" | "unavailable";
export type Probe = () => ProbeStatus | Promise<ProbeStatus>;

export type AppOptions = {
  /**
   * Readiness probes by dependency name. v0 registers none, so `/readyz` is
   * unconditionally ready; the first packet that gives guard a dependency
   * registers it here and nowhere else.
   */
  probes?: Record<string, Probe>;
  /** Omit to run with no rate limiting at all. */
  rateLimit?: { limit: number; windowMs: number };
};

/**
 * Liveness and readiness answer even when the limiter is exhausted: a throttled
 * probe is an orchestrator that cannot see a healthy process, and the restart
 * that follows is worse than the traffic it was protecting against.
 */
const PROBE_PATHS = new Set(["/healthz", "/readyz"]);

/**
 * Builds the app. Exported, and the only entrypoint the tests use — importing
 * this module must never open a socket.
 */
export function createApp(options: AppOptions = {}): Hono {
  const app = new Hono();

  const limiter = options.rateLimit
    ? rateLimit({ ...options.rateLimit, keyGenerator: clientKey })
    : null;

  app.use("*", async (c, next) => {
    if (!limiter || PROBE_PATHS.has(new URL(c.req.url).pathname)) return next();
    return limiter(c, next);
  });

  // Liveness is unconditional and touches nothing. A dependency outage must not
  // get the process restarted out from under in-flight requests; that is
  // /readyz's job. Keep the split.
  app.get("/healthz", (c) => c.json({ status: "ok" }));

  app.get("/readyz", async (c) => {
    const deps: Record<string, ProbeStatus> = {};
    let ready = true;

    for (const [name, probe] of Object.entries(options.probes ?? {})) {
      const status = await runProbe(probe);
      deps[name] = status;
      if (status !== "ok") ready = false;
    }

    return c.json({ deps }, ready ? 200 : 503);
  });

  app.notFound((c) => c.json({ error: "not_found", message: "no such route" }, 404));

  app.onError((error, c) => {
    // The message can carry a dependency host, a query, or a token; the caller
    // gets a flat 500 and the detail goes to the log.
    console.error("guard: unhandled error", error);
    return c.json({ error: "internal_error", message: "unexpected server error" }, 500);
  });

  return app;
}

/**
 * A dependency that throws, rejects, hangs or answers with anything but "ok" is
 * one unavailable dependency. None of those may take the process down:
 * reporting 503 is the entire contract of /readyz.
 */
async function runProbe(probe: Probe): Promise<ProbeStatus> {
  try {
    return (await probe()) === "ok" ? "ok" : "unavailable";
  } catch {
    return "unavailable";
  }
}

/**
 * v0 client identity: the first hop of the forwarding chain.
 *
 * TODO(guard-02): key on the socket peer address instead. This header is
 * chosen by the caller, so until the edge proxy sits in front of guard and
 * overwrites it, a client can mint a fresh allowance per request. It is
 * recorded here as a known hole rather than hidden behind a default nobody
 * reads.
 */
function clientKey(c: Context): string {
  return c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "anonymous";
}

if (import.meta.main) {
  const port = Number(Bun.env.PORT ?? 8080);
  Bun.serve({ port, fetch: createApp().fetch });
  console.log(`guard listening on :${port}`);
}
