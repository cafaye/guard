// The image's test stage, held to the repository it is supposed to be testing.
//
// ## The finding
//
// `docker build --target test` ran 392 tests across 15 files. The host ran 399
// across 16. The seven missing were `pins.test.ts` — the tripwire asserting that
// the toolchain pin in `package.json`, `mise.toml`, the Dockerfile and compose
// all say the same number. The test stage copied `src`, `test` and `openapi`, and
// a file at the repository root is in none of those, so the image never ran the
// one test whose entire job is to notice the image and the repository
// disagreeing. The build was green.
//
// That is the shape this file makes red. A test file the image does not copy does
// not fail, it disappears — and a green build is then a claim with nothing behind
// it, which is worse than no build at all, because it gets believed.
//
// ## Where the check runs
//
// In the suite, not in a script: `bin/prime` runs the suite, kit's reusable
// workflow runs the suite, and so does the image. A check kept outside the suite
// is a check somebody has to remember to run.
//
// ## The two holes, and which half closes each
//
//   * **A test file the Dockerfile never names.** Silent, and this file is it.
//   * **A path the Dockerfile names that `.dockerignore` then partly drops.** A
//     `COPY src ./src` with one subdirectory excluded copies the rest and stays
//     green — verified against buildkit rather than assumed. Not modelled here
//     and not guessed at: the suite emits the test files it discovered, and CI
//     diffs that set against the repository's. The built image is the authority;
//     this file is the fast one that runs before anyone builds anything.
//
// Neither half sees the other, so together there is no way for a test file to go
// missing quietly.
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  copiesInto,
  copySources,
  covers,
  findFiles,
  findTestFiles,
  parseStages,
  stageChain,
} from "./dockerStage";

/** The repository root: one level up from `test/`. */
const root = fileURLToPath(new URL("..", import.meta.url));
const read = (path: string): string => readFileSync(join(root, path), "utf8");

/** This file, by the path it is walked under. */
const SELF = "test/dockerStage.test.ts";

const dockerfile = read("Dockerfile");

/**
 * Files the suite reads that live outside `src/` and `test/`, so the test stage
 * has to copy them for the image to run the same tests the host runs.
 *
 * This is the one list in the check written down rather than derived, because a
 * test can read a file without its name appearing anywhere a reader could see —
 * and a derived list would be a second, worse inventory of the suite.
 *
 * It is checked in one direction only. Every name here is read by a file in the
 * suite, so the list cannot name something nothing reads and quietly demand a
 * `COPY` forever. The other direction is deliberately not checked: a fixture
 * nobody declared fails loudly on its own — the test that wants it cannot open
 * it — so it needs no tripwire. Only a missing *test* is silent, and that is
 * what the assertions below are for.
 */
const SUITE_INPUTS = [
  "package.json",
  "bun.lock",
  "openapi",
  "mise.toml",
  "Dockerfile",
  "docker-compose.yml",
  ".gitignore",
  // `bin/prime` is executed by `pins.test.ts`, which drives it against a stand-in
  // bun to prove the gate obeys the pin rather than merely needing a bun. It is
  // the fifth file the suite reads and does not otherwise need at test time, and
  // it is listed here for the same reason the other four are: a check that runs
  // in the image and not on the host is a check whose absence nobody notices,
  // because the host is where the defect was found.
  "bin/prime",
] as const;

/** CI greps this prefix out of the suite's own output and diffs it against `find`. */
const REPORT_PREFIX = "GUARD_IMAGE_TEST";

describe("the test stage", () => {
  test("copies every test file in the repository", () => {
    const copied = copiesInto(dockerfile, "test");
    const missing = findTestFiles(root).filter((file) => !covers(copied, file));

    if (missing.length > 0) {
      throw new Error(
        `${missing.length} test file(s) are in the repository and not in what the test stage ` +
          `copies:\n${missing.map((file) => `  ${file}`).join("\n")}\n` +
          `The test stage copies ${copied.join(", ")}.\n` +
          `A test file the image does not have does not fail — it is not run, and the build is ` +
          `green having never executed it. That is how \`pins.test.ts\`, the check that the image ` +
          `and the repository agree on the toolchain pin, went missing from ` +
          `\`docker build --target test\` while the build stayed green.`,
      );
    }
  });

  test("copies every file the suite reads by name", () => {
    const copied = copiesInto(dockerfile, "test");
    const missing = SUITE_INPUTS.filter((input) => !covers(copied, input));

    if (missing.length > 0) {
      throw new Error(
        `the test stage does not copy ${missing.join(", ")}, which the suite reads.\n` +
          `A missing fixture is loud — the test that opens it fails — but a suite that was ` +
          `never meant to run in the image should not be discovering that for the first time ` +
          `inside a build.`,
      );
    }
  });

  test("copies a named list rather than the whole context", () => {
    const copied = copiesInto(dockerfile, "test");

    // Not a preference about tidiness. `COPY . .` makes every assertion above
    // pass without saying anything: a whole-context copy is always a superset, so
    // the check would be a tautology. It also drags README, cafaye.yml and the
    // docs into a stage that only needs to run a suite, and — the reason the
    // runtime-stage assertion below exists at all — it is how a test double ends
    // up in a shipped image.
    expect(copied).not.toContain(".");
  });

  test("runs the suite over the tree rather than over a list of paths", () => {
    const instructions = parseStages(dockerfile)["test"]?.instructions ?? [];
    const run = instructions.find((line) => /^RUN\s/i.test(line) && /\bbun\s+test\b/.test(line));

    expect(run).toBeDefined();

    // `--timeout 30` is a flag and stays; `src/` is a hand-maintained subset and
    // is the exact thing this file exists to end.
    const named = (run ?? "")
      .trim()
      .split(/\s+/)
      .slice(3)
      .filter((word) => !word.startsWith("-"));

    if (named.length > 0) {
      throw new Error(
        `the test stage runs \`${run}\`, which names ${named.join(", ")}.\n` +
          `A path list is a subset somebody maintains by hand, and the file set is the one thing ` +
          `in this repository that must not be maintained by hand. Run \`bun test\`.`,
      );
    }
  });
});

describe("the runtime stage", () => {
  test("copies no test tree and no whole context", () => {
    // What this asserts, precisely: the runtime stage names neither `test/` nor
    // the whole build context. It does NOT assert that no test file reaches the
    // image — 13 `src/**/*.test.ts` do, because `COPY src ./src` takes the
    // directory as it is. They are dead weight in a shipped image, not a
    // reachable path: nothing imports them, and `bun:test` is a runtime builtin
    // rather than a dependency the production tree installs. Fixing it means
    // filtering the copy, which changes what the image produces, so it is a
    // packet of its own and recorded as one in the README rather than done here.
    const copied = copySources(parseStages(dockerfile)["runtime"]?.instructions ?? []);
    const leaks = copied.filter((source) => {
      const from = source.replace(/\/+$/, "").replace(/^\.\//, "");
      return from === "." || from === "test" || from.endsWith(".test.ts");
    });

    if (leaks.length > 0) {
      throw new Error(
        `the runtime stage copies ${leaks.join(", ")}.\n` +
          `\`test/\` holds stand-ins for identity's auth API and its JWKS — doubles that exist so ` +
          `the suite has something to talk to, and that must not reach a running gateway.`,
      );
    }
  });
});

describe("what the image discovered", () => {
  test("emits the test files this image holds, so CI can diff them against the repository", () => {
    // The same run, in the image and on a host, prints the same lines, and CI
    // compares the two lists. This is the half of the check that reads the built
    // image rather than the Dockerfile: it is the only authority on what a build
    // actually put in there, and it catches the `.dockerignore` hole the other
    // half deliberately does not model.
    const found = findTestFiles(root);

    for (const file of found) console.log(`${REPORT_PREFIX} ${file}`);

    // A walk that found nothing would make CI's diff pass by reporting every
    // file as removed, and it would pass *quietly*, which is the failure this
    // packet is about.
    expect(found.length).toBeGreaterThan(0);
  });
});

describe("this reader's own contract", () => {
  test("a stage it cannot find raises rather than reporting an empty image", () => {
    expect(() => stageChain(parseStages(dockerfile), "nope")).toThrow(/no stage named/);
  });

  test("a stage is built from its parents, outermost first", () => {
    const chain = stageChain(
      parseStages("FROM alpine AS base\nFROM base AS mid\nFROM mid AS leaf\n"),
      "leaf",
    );

    expect(chain).toEqual(["base", "mid", "leaf"]);
  });

  test("a chain stops at a base that is an image rather than a stage in the file", () => {
    const chain = stageChain(parseStages("FROM alpine:1 AS only\n"), "only");

    expect(chain).toEqual(["only"]);
  });

  test("a stage that is its own ancestor raises rather than walking forever", () => {
    const cyclic = "FROM b AS a\nFROM a AS b\n";

    expect(() => stageChain(parseStages(cyclic), "a")).toThrow(/its own ancestor/);
  });

  test("a line continuation raises rather than reading half an instruction", () => {
    expect(() => parseStages("FROM alpine AS a\nCOPY a \\\n  b\n")).toThrow(/continuation/);
  });

  test("the JSON-array form of COPY raises rather than inventing sources", () => {
    expect(() => copySources(['COPY ["a", "b"] .'])).toThrow(/JSON-array/);
  });

  test("a flag's value is not read as a path", () => {
    // `--chown bun:bun src ./src` must yield `src`, not `bun:bun`.
    expect(copySources(["COPY --chown bun:bun src ./src"])).toEqual(["src"]);
    expect(copySources(["COPY --chown=bun:bun src ./src"])).toEqual(["src"]);
  });

  test("the destination is not read as a source", () => {
    expect(copySources(["COPY package.json bun.lock ./"])).toEqual(["package.json", "bun.lock"]);
  });

  test("a COPY --from is not a build-context path", () => {
    // Its sources are in another stage's filesystem. Counting them would assert
    // that a path the build context never had is present in the image.
    expect(copySources(["COPY --from=deps --chown=bun:bun /app/node_modules ./node_modules"])).toEqual([]);
  });

  test("an instruction before the first FROM is kept, not dropped", () => {
    // `ARG BUN_VERSION=…` is a build argument, and a reader that dropped it
    // would be silently wrong about a real Dockerfile: the pin lives there, and
    // `pins.test.ts` is the test that reads it.
    expect(parseStages("ARG X=1\nFROM alpine AS a\n")[""]?.instructions).toEqual(["ARG X=1"]);
  });

  test("a source covers a file beneath it and nothing above it", () => {
    expect(covers(["src"], "src/index.test.ts")).toBe(true);
    expect(covers(["src"], "src")).toBe(true);
    expect(covers(["src"], "srcery/index.test.ts")).toBe(false);
    expect(covers(["src"], "test/index.test.ts")).toBe(false);
    expect(covers(["."], "anywhere/at/all.test.ts")).toBe(true);
  });
});

describe("the declared suite inputs", () => {
  test("names nothing the suite does not read", () => {
    // Excluding this file: it names every entry in the list, so counting its own
    // text would let the list justify itself.
    const suite = findFiles(root, (name) => name.endsWith(".ts") && name !== SELF)
      .map((file) => read(file))
      .join("\n");
    const unread = SUITE_INPUTS.filter((input) => !suite.includes(input));

    if (unread.length > 0) {
      throw new Error(
        `${unread.join(", ")} is in SUITE_INPUTS but no file in the suite reads it.\n` +
          `Remove it, or the list is a second inventory of the suite — the thing this check ` +
          `exists to avoid.`,
      );
    }
  });
});
