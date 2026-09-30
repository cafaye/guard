// No test in this repository may skip itself.
//
// ## The finding this exists to prevent
//
// `bun test` exits **0** on a run where every test was skipped. That is not a
// quirk of this runner's summary formatting — it is what "no tests matched" means
// to every JavaScript test runner, and it is the property that lets an
// environment-gated tier be added and then quietly never run again.
//
// This repository has that tier already: `rateLimitRedisLive.test.ts` needs a
// real `redis-server` and skips without `GUARD_REDIS_URL`. It carries two
// mechanisms — `GUARD_REDIS_REQUIRED=true` turns the skip into a module-load
// throw, and the `redis` CI job fails on `0 pass` — precisely because the skip
// is otherwise invisible.
//
// Two mechanisms protect **one** file. A second gated tier added tomorrow, or a
// `test.skip` left behind after a flaky run, arrives with neither. This is the
// tripwire: it reads the suite's own source and fails the moment a skip appears
// anywhere it is not declared and justified.
//
// ## What counts as a skip
//
//   * `describe.skip`, `test.skip`, `it.skip` — an explicit skip.
//   * `describe.skipIf(...)`, `test.skipIf(...)` — a conditional skip, the shape
//     the Redis tier uses.
//   * `test.todo` / `it.todo` — never runs, and `bun test` counts it as neither
//     a pass nor a fail.
//
// `describe.each`/`test.each` and `if (cond) test(...)` are deliberately not
// matched: a table-driven test contains no skip call at all, and an `if` that
// guards a `test.skip` still contains the `test.skip`.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { findFiles, findTestFiles } from "./dockerStage";

/** The repository root: one level up from `test/`. */
const root = fileURLToPath(new URL("..", import.meta.url));

const sources = findTestFiles(root).map((file) => ({
  file,
  text: readFileSync(join(root, file), "utf8"),
}));

/**
 * The one declared skip in this repository, and why it is allowed to exist.
 *
 * `file` is matched exactly rather than by pattern so that a *second* skip
 * anywhere — including a second one in this same file — fails this test. That is
 * the whole mechanism: the allowlist is a list of one, so the tripwire cannot be
 * widened by accident, only by editing this file, which is a reviewable act.
 */
const DECLARED_SKIPS: Array<{ file: string; why: string }> = [
  {
    file: "src/middleware/rateLimitRedisLive.test.ts",
    why:
      "needs a real redis-server; forced to run by GUARD_REDIS_REQUIRED=true in the " +
      "`redis` CI job, and by any gate run that sets both variables",
  },
];

/**
 * Matches a skip call, capturing what it is on.
 *
 * Assembled from two arrays at runtime rather than written as one literal, and
 * that is not a style choice: a detector written as a literal
 * `\.\s*(skip|skipIf)` matches its own source text, so the tripwire would
 * always report one violation and always fail for the wrong reason — or, worse,
 * get its allowlist widened to include itself.
 */
const CALLEES = ["describe", "test", "it"];
const KINDS = ["skip", "skipIf", "todo", "only"];

const SKIP = new RegExp(`\\b(${CALLEES.join("|")})\\s*\\.\\s*(${KINDS.join("|")})\\b`, "g");

/** Strips comments and string literals, so prose about skipping is not a skip. */
function code(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''");
}

describe("the suite cannot skip itself", () => {
  test("at least one test file was found to check", () => {
    // A detector that found nothing reads as a pass, which is the exact failure
    // mode it exists to catch. `dockerStage.test.ts` already reads `find`; this
    // asserts the reader still reads.
    expect(sources.length).toBeGreaterThan(10);
  });

  test("the only skip in the suite is the declared one", () => {
    const declared = new Map(DECLARED_SKIPS.map((entry) => [entry.file, entry]));
    const found: string[] = [];

    for (const { file, text } of sources) {
      for (const match of code(text).matchAll(SKIP)) {
        found.push(`${file} uses ${match[1]}.${match[2]}`);
      }
    }

    // Every hit is named here, so the failure message lists the offender rather
    // than asserting an opaque sorted array.
    const undeclared = found.filter((hit) => !declared.has(hit.split(" uses ")[0]!));

    expect(undeclared).toEqual([]);
    // And nothing is allowed to skip by `todo` or by `.only`, in any file —
    // including the one declared. A `.only` narrows a run to one test and a
    // `todo` counts as neither a pass nor a fail, so both are ways for the
    // summary to stop meaning what it says.
    expect(found.filter((hit) => !hit.endsWith("skipIf"))).toEqual([]);
    // The declared skip is present, not merely permitted: an allowlist entry for
    // a skip that was removed would otherwise let the next one through.
    expect(found.some((hit) => hit.startsWith("src/middleware/rateLimitRedisLive.test.ts "))).toBe(true);
  });

  test("the declared skip is still the one the Redis tier actually uses", () => {
    // The allowlist above is a claim about a file. If the Redis tier were ever
    // rewritten to gate on something else, or the file were deleted, this fails
    // rather than the tripwire quietly allowing a stale entry.
    for (const entry of DECLARED_SKIPS) {
      const source = sources.find((candidate) => candidate.file === entry.file);
      expect(source === undefined ? `${entry.file} is missing` : source.text).toContain(entry.file);
    }
  });

  test("the Redis tier still carries the guard that makes its skip a failure", () => {
    // The strongest of the two mechanisms, asserted in the suite rather than
    // trusted to the CI job. If this test file is ever the thing to break, this
    // is the one that matters: without it, `GUARD_REDIS_REQUIRED=true` with no
    // URL would be a skip again and the `redis` job would be the only thing
    // standing between a green run and a tier that verified nothing.
    const live = sources.find((candidate) => candidate.file === "src/middleware/rateLimitRedisLive.test.ts");
    expect(live).toBeDefined();

    const body = code(live!.text);
    expect(body).toContain("GUARD_REDIS_REQUIRED");
    expect(body).toMatch(/REQUIRED\s*&&\s*REDIS_URL\s*===\s*undefined/);
    // Thrown at module load, before a test is registered: a run that could not
    // do the work says so in its first line rather than in a summary of zeroes.
    expect(body).toMatch(/throw new Error\(/);
  });

  test("no source file outside the suite declares a gated environment", () => {
    // A guard reading `process.env` to decide whether to test something is how a
    // second gated tier arrives. There is one such file and it is the Redis tier,
    // which the tests above pin; this says so about the whole tree rather than
    // leaving it to a reader who has to know to look.
    const gated: string[] = [];

    for (const file of findFiles(root, (name) => name.endsWith(".ts"))) {
      if (file.endsWith(".test.ts")) continue;
      if (file.startsWith("test/")) continue;

      const text = code(readFileSync(join(root, file), "utf8"));
      if (/\bprocess\.env\b|\bBun\.env\b/.test(text) && /SKIP|skipIf/.test(text)) {
        gated.push(file);
      }
    }

    expect(gated).toEqual([]);
  });
});