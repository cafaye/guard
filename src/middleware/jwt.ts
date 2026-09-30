import type { MiddlewareHandler } from "hono";

/**
 * STUB. Rejects requests with no `Authorization` header and passes everything
 * else straight through.
 *
 * TODO(guard-02): real verification. Fetch identity's JWKS, check `iss`,
 * `aud`, `exp` and `nbf`, verify the signature, and put the claims on the
 * context for downstream handlers. The stub deliberately does *not* parse the
 * token or check the `Bearer` scheme, because a half-check that reads like a
 * check is worse than an obvious stub: it would let a caller believe a token
 * was verified when nothing was. Nothing downstream may treat a request that
 * reached a handler as authenticated until this is real.
 */
export function requireJwt(): MiddlewareHandler {
  return async function requireJwtStub(c, next) {
    const authorization = c.req.header("Authorization");

    // Absent and whitespace-only are the same failure: there is no credential.
    if (!authorization || authorization.trim() === "") {
      return c.json({ error: "unauthorized", message: "missing Authorization header" }, 401);
    }

    await next();
  };
}
