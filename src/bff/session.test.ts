import { describe, expect, test } from "bun:test";
import { memorySessionStore } from "./session";

const TOKEN = "identity-issued-token";
const live = () => ({ token: TOKEN, expiresAt: Date.now() + 60_000 });
const dead = () => ({ token: TOKEN, expiresAt: Date.now() - 1 });

describe("memorySessionStore", () => {
  test("a session written is a session read", async () => {
    const store = memorySessionStore();
    const record = live();

    await store.put("session-1", record);

    expect(await store.get("session-1")).toEqual(record);
  });

  test("an unknown session is null, not a throw", async () => {
    expect(await memorySessionStore().get("never-existed")).toBeNull();
  });

  test("an expired session reads as absent and is dropped on the way out", async () => {
    const store = memorySessionStore();
    await store.put("session-1", dead());

    expect(await store.get("session-1")).toBeNull();
    // Dropped rather than left for the next sweep: a record read once is never
    // read again, so this is the only read that has to notice it is dead.
    expect(store.size()).toBe(0);
  });

  test("delete removes it", async () => {
    const store = memorySessionStore();
    await store.put("session-1", live());

    await store.delete("session-1");

    expect(await store.get("session-1")).toBeNull();
  });

  test("writing over the bound sweeps what has expired and keeps what has not", async () => {
    const store = memorySessionStore({ maxSessions: 2 });

    await store.put("stale-1", dead());
    await store.put("stale-2", dead());
    await store.put("live-1", live());
    expect(store.size()).toBe(3);

    await store.put("live-2", live());

    // The two abandoned sessions are gone and both live ones are still here.
    // A live session is never the thing a sweep takes: a burst of logins makes
    // the map briefly larger, it does not sign anybody out.
    expect(store.size()).toBe(2);
    expect(await store.get("live-1")).not.toBeNull();
    expect(await store.get("live-2")).not.toBeNull();
  });

  test("a bound of zero is a configuration error, not 'hold nothing'", async () => {
    for (const maxSessions of [0, -1, 1.5]) {
      expect(() => memorySessionStore({ maxSessions })).toThrow(RangeError);
    }
  });
});
