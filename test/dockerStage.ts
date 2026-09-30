// Reading a Dockerfile well enough to ask whether it copies what the suite needs.
//
// The check built on this is `dockerStage.test.ts`; this module is the part of it
// that has to be right for that check to mean anything. It lives in guard's own
// `test/` rather than in a shared helper, so the next service with a test stage
// copies one file and reads it.
//
// ## It is a reader, not a parser
//
// It answers one question — "which build-context paths does this stage put in the
// image" — and it answers it for the stage *chain*, not the stage alone, because
// a test stage that inherits from a base which already copied `package.json` has
// that file whether or not it says so again.
//
// ## Every reader refuses rather than under-reads
//
// A reader that comes back with an empty set agrees with a reader that came back
// with an empty set, and a check built on "the stage copies nothing" passes. So
// every way this could read less than it should — no stage by that name, an
// instruction before any `FROM`, a line continuation, the JSON-array form of
// `COPY`, a stage that is its own ancestor — raises, naming the line. The shapes
// it deliberately does not understand are listed where they are skipped.
//
// ## What it does not read, and who covers that
//
// `.dockerignore`. A named *file* the ignore file excludes is a hard build error
// — buildkit computes a checksum against a path the context does not hold and
// stops — so a file cannot go missing quietly. A *directory* can: `COPY src ./src`
// with an excluded subdirectory copies everything else and stays green, and both
// halves of that were verified against buildkit rather than assumed. Modelling
// Docker's glob dialect to catch it here would be a second, permissive
// implementation of a rule Docker already has, and a permissive one under-reads
// silently — which is the failure this module exists to refuse.
//
// So it is not modelled here. The suite emits the test files it actually
// discovered and the `image` CI job diffs that set against the repository's: the
// built image is the authority on what a build put in it. This reader is the fast
// half, and it runs before anyone builds anything.
//
// ## For kit, not just guard
//
// The reader is language-agnostic — it knows stages, `COPY` and `.`, and nothing
// about Bun — so the same two files drop into any of kit's Dockerfile templates.
// Two caveats a porter has to decide rather than inherit. The stage names differ
// (`test` here; kit's templates have no test stage at all, which is the larger
// version of this bug and is kit's to close), and a template that wants the check
// to say anything has to stop copying the whole context in its runtime stage: all
// seven currently end in `COPY . .`, which is the pattern this packet argues
// against.

import { readdirSync } from "node:fs";
import { join } from "node:path";

/** One `FROM … AS name` block. */
export type Stage = {
  /** The token after `FROM`: an image reference, or the name of another stage. */
  readonly base: string;
  /** Instruction lines only — comments and blank lines are dropped. */
  readonly instructions: readonly string[];
};

const FROM = /^FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$/i;
const COPY = /^COPY\s+(.*)$/i;

/**
 * Directory names that are never part of the repository's own tree. `node_modules`
 * because a dependency's tests are not ours; the rest because a build artefact
 * in the tree is not source and must not be counted as a test that could be
 * silently skipped.
 */
const NOT_TREE = new Set([".git", "node_modules", "coverage", "dist", "vendor"]);

/**
 * Key for the instructions that precede the first `FROM` — an `ARG`, in every
 * Dockerfile in the fleet. Key for an unnamed stage is `"(unnamed)"`. Neither can
 * be a `FROM … AS` name, so `stageChain` never walks into either by accident.
 */
const PRE_STAGE = "";
const UNNAMED = "(unnamed)";

/**
 * The Dockerfile's stages, keyed by name. Instructions before the first `FROM`
 * are keyed `PRE_STAGE`; an unnamed stage is keyed `UNNAMED`.
 */
export function parseStages(dockerfile: string): Record<string, Stage> {
  const stages: Record<string, Stage> = {};
  let base = "";
  let instructions: string[] = [];
  let name: string | null = null;

  const close = (): void => {
    // Reaching the first `FROM` with instructions already collected is the
    // pre-stage: an `ARG` that sets the base image or a build argument, and in
    // guard's Dockerfile it is where the Bun pin lives.
    if (name === null) {
      if (instructions.length > 0) stages[PRE_STAGE] = { base: "", instructions };
    } else {
      stages[name] = { base, instructions };
    }
  };

  dockerfile.split("\n").forEach((raw, index) => {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) return;

    if (line.endsWith("\\")) {
      throw new Error(
        `Dockerfile line ${index + 1} is continued onto the next one, and this reader does ` +
          `not follow continuations: it would read one instruction as two, and the one that ` +
          `decided what the image holds would be the wrong half.\n  ${line}`,
      );
    }

    const from = FROM.exec(line);
    if (from === null) {
      // `ARG BUN_VERSION=…` before the first `FROM` is a build argument, not a
      // stage, and it is the only instruction that legitimately lands here.
      instructions.push(line);
      return;
    }

    close();
    name = from[2] ?? UNNAMED;
    base = from[1] ?? "";
    instructions = [];
  });
  close();

  return stages;
}

/**
 * The stages `name` is built from, outermost first, so `[deps, test]` for a test
 * stage that inherits from a dependency stage. Stops at a base that is an image
 * rather than a stage in this file.
 */
export function stageChain(stages: Record<string, Stage>, name: string): string[] {
  const chain: string[] = [];
  const seen = new Set<string>();
  let current: string | undefined = name;

  while (current !== undefined) {
    const stage: Stage | undefined = stages[current];
    if (stage === undefined) {
      // Only the stage that was asked for by name is an error; a base that is an
      // image is the normal end of the chain.
      if (chain.length === 0) throw new Error(`this Dockerfile has no stage named \`${name}\``);
      return chain.reverse();
    }
    if (seen.has(current)) {
      throw new Error(`stage \`${current}\` is its own ancestor: ${[...chain, current].join(" -> ")}`);
    }
    seen.add(current);
    chain.push(current);
    current = stages[stage.base] === undefined ? undefined : stage.base;
  }

  return chain.reverse();
}

/**
 * The build-context paths one `COPY` line puts in the image, in the order written.
 *
 * `COPY --from=…` is skipped: its sources live in another stage's filesystem and
 * are not paths in the build context, so counting them would assert that a path
 * the context never had is present in the image.
 */
export function copySources(instructions: readonly string[]): string[] {
  const sources: string[] = [];

  for (const instruction of instructions) {
    const args = COPY.exec(instruction)?.[1];
    if (args === undefined) continue;

    const words = args.split(/\s+/).filter((word) => word !== "");
    if (words[0]?.startsWith("[")) {
      throw new Error(
        `COPY in its JSON-array form is not read by this reader, and reading it as a ` +
          `shell-form list would name sources it does not contain: ${instruction}`,
      );
    }
    if (words.some((word) => word.startsWith("--from="))) continue;

    const paths: string[] = [];
    for (let i = 0; i < words.length; i += 1) {
      const word = words[i];
      if (word === undefined) continue;
      if (!word.startsWith("--")) {
        paths.push(word);
      } else if (!word.includes("=")) {
        // `--chown bun:bun` takes the next word as its value, and that word is a
        // user, not a path. Reading it as a source would invent a directory.
        i += 1;
      }
    }

    // The last path is the destination; every one before it is copied in.
    for (const source of paths.slice(0, -1)) sources.push(source);
  }

  return sources;
}

/** Every build-context path the named stage's chain puts in the image. */
export function copiesInto(dockerfile: string, stage: string): string[] {
  const stages = parseStages(dockerfile);
  return stageChain(stages, stage).flatMap((name) => copySources(stages[name]?.instructions ?? []));
}

/** `COPY src ./src` covers `src/index.test.ts`; a source is a file or a prefix. */
export function covers(sources: readonly string[], path: string): boolean {
  return sources.some((source) => {
    const from = source.replace(/\/+$/, "").replace(/^\.\//, "");
    return from === "." || from === path || path.startsWith(`${from}/`);
  });
}

/** Every file under `root` whose name satisfies `keep`, as sorted `/`-joined paths. */
export function findFiles(root: string, keep: (name: string) => boolean): string[] {
  const found: string[] = [];

  const walk = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (NOT_TREE.has(entry.name)) continue;
      const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) walk(join(dir, entry.name), path);
      else if (keep(entry.name)) found.push(path);
    }
  };
  walk(root, "");

  return found.sort();
}

/** Every test in the tree, wherever it lives — `bun test` discovers the root too. */
export function findTestFiles(root: string): string[] {
  return findFiles(root, (name) => name.endsWith(".test.ts"));
}
