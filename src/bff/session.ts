// Where a browser session lives between requests.
//
// The browser holds a session id and nothing else; the identity token that id
// stands for stays in guard's process. That is the whole BFF claim, and this
// file is the only place that claim is kept or broken.

/**
 * One live session. `expiresAt` is epoch milliseconds, taken from the token's
 * own expiry rather than from a guard-side TTL: identity decides how long a
 * session is good for, and a second clock here would be a second answer.
 */
export type SessionRecord = { token: string; expiresAt: number };

/**
 * The contract every session backend implements.
 *
 * Three methods and nothing else, deliberately. A `size`, a `list` and a
 * `count` are all things a caller could want and none of them anything guard
 * needs, and every one of them added here is a method the Redis implementation
 * has to grow. Expiry is the store's business because an expired record is not
 * a record: a backend that returned one would be handing out a session it knows
 * is dead.
 */
export interface SessionStore {
  /** The live session, or null — absent and expired are the same answer. */
  get(sessionId: string): Promise<SessionRecord | null>;
  put(sessionId: string, session: SessionRecord): Promise<void>;
  delete(sessionId: string): Promise<void>;
}

export type MemorySessionStoreOptions = {
  /** Clock, injected so a test can age a session without sleeping. */
  now?: () => number;
  /**
   * Sessions held before expired ones are swept. A bound on retained memory,
   * not a cap: a live session is never evicted, so a burst of logins makes the
   * map briefly larger and never signs anybody out.
   */
  maxSessions?: number;
};

export type MemorySessionStore = SessionStore & {
  /**
   * Records held right now. v0 introspection — the deploy packet's memory
   * metrics read it. Deliberately not on `SessionStore`: the interface is what
   * every backend owes guard, and this is what this one can cheaply answer.
   */
  size(): number;
};

const DEFAULT_MAX_SESSIONS = 10_000;

/**
 * In-memory sessions for v0.
 *
 * Per process, and lost on restart, exactly as the rate limiter is. A browser
 * whose session lived on the replica it logged in to is signed out when that
 * replica goes away — which is a real, visible failure and the reason the
 * deploy packet replaces this with Redis.
 *
 * TODO(guard-07): Redis-backed sessions, so a session survives a restart and is
 * shared by every replica. The interface above is the seam; nothing outside this
 * file knows what is behind it. The same packet carries the shared API-key store
 * (`./apiKey`) — one deploy story, "guard's per-process state moves to Redis", and
 * the counter store in `./rateLimitRedis` is the pattern to copy.
 */
export function memorySessionStore(options: MemorySessionStoreOptions = {}): MemorySessionStore {
  const { now = Date.now, maxSessions = DEFAULT_MAX_SESSIONS } = options;
  assertPositiveInteger(maxSessions, "maxSessions");

  /** session id -> the identity token it stands for. */
  const sessions = new Map<string, SessionRecord>();

  return {
    async get(sessionId) {
      const session = sessions.get(sessionId);
      if (session === undefined) return null;

      // Dropped on the way out rather than in a background sweep: a record read
      // once is never read again, so this is the only read that has to notice.
      if (session.expiresAt <= now()) {
        sessions.delete(sessionId);
        return null;
      }

      return session;
    },

    async put(sessionId, session) {
      // Over the bound, not at it: a login that is exactly at the bound is not
      // yet a reason to walk the map. A live session is never the thing swept.
      if (sessions.size > maxSessions) sweepExpired(sessions, now());
      sessions.set(sessionId, session);
    },

    async delete(sessionId) {
      sessions.delete(sessionId);
    },

    size() {
      return sessions.size;
    },
  };
}

function sweepExpired(sessions: Map<string, SessionRecord>, at: number): void {
  for (const [sessionId, session] of sessions) {
    if (session.expiresAt <= at) sessions.delete(sessionId);
  }
}

function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(`memorySessionStore: ${field} must be an integer >= 1, got ${String(value)}`);
  }
}
