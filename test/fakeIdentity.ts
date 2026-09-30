/**
 * A stand-in for identity's auth API, for tests only.
 *
 * It lives in `test/` rather than `src/` so the runtime image never carries a
 * test double (the Dockerfile copies `src` into the runtime stage and `test`
 * only into the test stage). It is a `fetch` implementation rather than a
 * listening socket because the BFF's identity calls are injected: a test that
 * opened a port would be testing the network as much as the code, and a test
 * that reached the real identity would be testing nothing at all.
 *
 * Every call is recorded, including the Authorization header, because the claims
 * this suite makes about guard — "the browser's cookie is never identity's
 * token", "logout revokes the token the store is holding" — are only true if
 * something checks what actually went out on the wire.
 */
import type { FetchFn } from "../src/bff/auth";

/** What identity was asked, in the form the assertions need. */
export type RecordedCall = {
  method: string;
  path: string;
  /** The bearer token presented, or null. The subject of most assertions. */
  token: string | null;
  /** The request body exactly as guard forwarded it, or null. */
  body: string | null;
  /** The full URL, so a test can assert guard builds it from IDENTITY_URL. */
  url: string;
};

export type Reply = {
  status: number;
  /** JSON body. Mutually exclusive with `text`. */
  json?: unknown;
  /** A raw body, for a dependency answering something that is not JSON. */
  text?: string;
  headers?: Record<string, string>;
  /** Reject, the way a dependency that is not there does. */
  fail?: Error;
  /** Never answer, the way a hung dependency does. */
  hang?: boolean;
};

export type FakeIdentity = {
  /** Hand this to `createBffAuth` as its `fetch`. */
  readonly fetch: FetchFn;
  /** Every call, in order. */
  readonly calls: RecordedCall[];
  /** Registers the answer to one method and path. */
  route(method: string, path: string, reply: Reply): void;
  /** The calls to one method and path. */
  callsTo(method: string, path: string): RecordedCall[];
  /** Forgets the recorded calls; routes stay registered. */
  clear(): void;
};

/**
 * An identity that 404s every path until a test says otherwise.
 *
 * There is no base URL to configure: guard decides where identity lives, and a
 * double that pretended to have an opinion about it could disagree with the
 * options a test is actually asserting.
 */
export function fakeIdentity(): FakeIdentity {
  const routes = new Map<string, Reply>();
  const calls: RecordedCall[] = [];

  const fetch: FetchFn = async (input, init) => {
    const request = toRequest(input, init);
    const { pathname } = new URL(request.url);

    calls.push({
      method: request.method,
      path: pathname,
      token: bearerOf(request.headers.get("authorization")),
      body: request.body ? await readBody(request) : null,
      url: request.url,
    });

    const reply = routes.get(`${request.method} ${pathname}`);
    if (reply === undefined) {
      // Loud on purpose: a call the test did not expect has to be visible as a
      // 404 rather than quietly answered with something plausible.
      return Response.json({ code: "not_found", detail: `no fake route for ${request.method} ${pathname}` }, 404);
    }
    if (reply.fail) throw reply.fail;
    if (reply.hang) return new Promise<Response>(() => {});

    if (reply.text !== undefined) {
      return new Response(reply.text, {
        status: reply.status,
        headers: { "content-type": "text/html", ...reply.headers },
      });
    }

    return new Response(reply.json === undefined ? "" : JSON.stringify(reply.json), {
      status: reply.status,
      headers: { "content-type": "application/json", ...reply.headers },
    });
  };

  return {
    fetch,
    calls,
    route(method, path, reply) {
      routes.set(`${method} ${path}`, reply);
    },
    callsTo(method, path) {
      return calls.filter((call) => call.method === method && call.path === path);
    },
    clear() {
      calls.length = 0;
    },
  };
}

/** The paths identity publishes, as the guard-03 contract fixes them. */
export const IDENTITY_PATHS = {
  register: "/v1/users",
  session: "/v1/session",
  me: "/v1/me",
  healthz: "/healthz",
} as const;

function toRequest(input: string | URL | Request, init?: RequestInit): Request {
  if (input instanceof Request) return init === undefined ? input : new Request(input, init);
  return new Request(typeof input === "string" ? input : input.href, init);
}

async function readBody(request: Request): Promise<string | null> {
  try {
    return await request.clone().text();
  } catch {
    return null;
  }
}

function bearerOf(authorization: string | null): string | null {
  if (authorization === null) return null;
  return /^bearer +(\S+)$/i.exec(authorization.trim())?.[1] ?? null;
}
