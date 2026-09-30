/**
 * A stand-in for identity's JWKS endpoint, for tests only.
 *
 * It lives in `test/` rather than `src/` so the runtime image never carries a
 * test double (the Dockerfile copies `src` into the runtime stage and `test`
 * only into the test stage). It exists because the honest way to test
 * verification is end to end: real RSA keys, a real HTTP fetch, a real key
 * rotation. Mocking `jose` would test the mock.
 */
import { SignJWT, exportJWK, generateKeyPair, type JWK, type JWTPayload } from "jose";

/** An RSA signing key pair plus the public JWK identity would publish for it. */
export type TestKey = {
  kid: string;
  /** Signs tokens in a test; never leaves the process. */
  privateKey: CryptoKey;
  /** The public half, in the form a JWKS document carries. */
  jwk: JWK;
};

/** Mints an RS256 key pair named `kid`, ready to sign and to publish. */
export async function testKey(kid: string): Promise<TestKey> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(publicKey);

  // `alg` and `use` are what a real JWKS carries; a key set that omits them is
  // legal but says less, and publishing them keeps the double honest.
  return { kid, privateKey, jwk: { ...jwk, kid, alg: "RS256", use: "sig" } };
}

/** Signs `claims` with `key`, RS256, with the key id in the protected header. */
export function signToken(key: TestKey, claims: JWTPayload, header: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: key.kid, ...header })
    .sign(key.privateKey);
}

/**
 * Rewrites a token's payload without re-signing it — a caller editing their own
 * `sub` or `scope`. The signature must stop matching.
 */
export function tamperPayload(token: string, claims: JWTPayload): string {
  const [header, _payload, signature] = token.split(".");
  if (!header || !signature) throw new Error("tamperPayload: not a compact JWS");
  return `${header}.${base64url(claims)}.${signature}`;
}

/** A compact JWS with no signature at all: what `alg: none` looks like. */
export function unsignedToken(claims: JWTPayload, header: Record<string, unknown>): string {
  return `${base64url(header)}.${base64url(claims)}.`;
}

export type JwksServer = {
  /** Issuer-only base URL — the value `IDENTITY_ISSUER` would hold in dev. */
  readonly issuer: string;
  /** Where the keys actually live: `${issuer}/.well-known/jwks.json`. */
  readonly jwksUrl: string;
  /** Every path served, in order. The cache and refresh tests read this. */
  readonly requests: string[];
  /** Publishes exactly these keys; the next fetch sees them. */
  publish(...keys: TestKey[]): void;
  /** Answers `status` with a non-JWKS body: identity down, or misconfigured. */
  failWith(status: number): void;
  /** Answers 200 with something that is not a key set. */
  serveGarbage(): void;
  /** Never answers. Exercises the fetch timeout. */
  hang(): void;
  /** Answers normally again. */
  serveKeys(): void;
  stop(): void;
};

/** Starts a JWKS endpoint on an ephemeral port, publishing `keys`. */
export async function startJwksServer(...keys: TestKey[]): Promise<JwksServer> {
  const requests: string[] = [];
  let published: JWK[] = keys.map((key) => key.jwk);
  let mode: "keys" | "status" | "garbage" | "hang" = "keys";
  let status = 500;

  const server = Bun.serve<unknown>({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const { pathname } = new URL(request.url);
      requests.push(pathname);

      if (mode === "hang") return new Promise<Response>(() => {});
      if (mode === "status") return new Response("upstream is unwell", { status });
      if (mode === "garbage") {
        return new Response("<html>login required</html>", {
          status: 200,
          headers: { "content-type": "text/html" },
        });
      }
      if (pathname !== "/.well-known/jwks.json") {
        return new Response("not found", { status: 404 });
      }
      return Response.json({ keys: published });
    },
  });

  const issuer = `http://127.0.0.1:${server.port}`;

  return {
    issuer,
    jwksUrl: `${issuer}/.well-known/jwks.json`,
    requests,
    publish(...next: TestKey[]) {
      published = next.map((key) => key.jwk);
    },
    failWith(next: number) {
      mode = "status";
      status = next;
    },
    serveGarbage() {
      mode = "garbage";
    },
    hang() {
      mode = "hang";
    },
    serveKeys() {
      mode = "keys";
    },
    stop() {
      // Forced: a hung request keeps its socket open, and the suite must not
      // wait for it.
      server.stop(true);
    },
  };
}

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}
