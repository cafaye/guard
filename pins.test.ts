// The runtime pin, in every place the repository states it.
//
// A version number written down in five files and checked by none of them is a
// version number that will disagree with itself. `mise.toml` claims "three
// places, one number" in a comment; this file is what makes that true or red.
//
// The failure this prevents is specific. CI installs Bun, the Dockerfile builds
// on Bun, and a developer's `mise install` installs Bun — three different ways
// to get a runtime, from three different copies of a number. When the copies
// drift, the suite that passed on the contributor's machine does not pass in the
// image that ships, and the only evidence is a failure somewhere else entirely.
//
// So the pin is asserted, not documented. It lives in `package.json` as
// `packageManager` as well as in `mise.toml`, because those answer to different
// readers: `packageManager` is what any tool sees, and `mise.toml` is what a
// contributor with mise sees. A pin in only one of them is a pin half the
// contributors lose.
import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The repository root, one level up from this file — and this file sits at the
// root, deliberately, rather than in `src/`. It reads `Dockerfile`, `mise.toml`,
// `.gitignore` and `docker-compose.yml`, and the Dockerfile's test stage copies
// `src` and `test` only: a repository-consistency check that cannot run in the
// image is a check that makes `docker build --target test` red for having been
// thorough. `bun test` discovers the root, so it still runs everywhere the gate
// does.
//
// One level up, not two. `new URL("../..")` resolves against a *file*, and a
// directory URL drops the last segment, so `../..` lands in the parent of the
// repository — which is how this test first found itself reading a neighbouring
// service's `package.json`.
const root = new URL(".", import.meta.url);
const read = (name: string): string => readFileSync(fileURLToPath(new URL(name, root)), "utf8");

/** The one number every other place has to agree with. */
const PIN = "1.3.12";

describe("the bun pin", () => {
  test("package.json pins the runtime with packageManager", () => {
    const manifest = JSON.parse(read("package.json")) as { packageManager?: string };

    // `packageManager` is the field every tool reads and the only one bun
    // itself honours as an exact version. `engines.bun` is a *floor*: `>=1.3.0`
    // is satisfied by 1.3.12 and by 1.9.0, so it cannot be the pin. Both are
    // kept — the floor says who may run this, the pin says which one CI ran.
    expect(manifest.packageManager).toBe(`bun@${PIN}`);
  });

  test("the engines floor admits the pin rather than excluding it", () => {
    const manifest = JSON.parse(read("package.json")) as { engines?: { bun?: string } };
    const floor = manifest.engines?.bun;

    expect(floor).toBeDefined();
    // A floor that excludes the pinned version refuses to install the runtime the
    // repository chose, which fails at the least useful moment: a fresh clone.
    expect(floor).toContain("1.3");
    expect(PIN.startsWith("1.3")).toBe(true);
  });

  test("mise.toml pins the same number", () => {
    // mise is optional, so this is not the only pin — but a developer who has it
    // must get the same runtime CI does, or their green suite means nothing.
    const mise = read("mise.toml");
    expect(mise).toMatch(/^bun\s*=\s*"(\d+\.\d+\.\d+)"$/m);

    const pinned = /^bun\s*=\s*"(\d+\.\d+\.\d+)"$/m.exec(mise)?.[1];
    expect(pinned).toBe(PIN);
  });

  test("the Dockerfile builds on the same number", () => {
    // The image is what ships. A Dockerfile on a different Bun than CI tests is a
    // suite that passed against a runtime nothing will ever run.
    const dockerfile = read("Dockerfile");

    expect(dockerfile).toMatch(/^ARG BUN_VERSION=(\d+\.\d+\.\d+)$/m);
    expect(/^ARG BUN_VERSION=(\d+\.\d+\.\d+)$/m.exec(dockerfile)?.[1]).toBe(PIN);

    // And the stages that matter name the image through that one argument, so
    // raising the pin cannot leave one stage behind.
    const froms = [...dockerfile.matchAll(/^FROM oven\/bun:(\$\{BUN_VERSION\})?-?\S*/gm)];
    expect(froms.length).toBeGreaterThan(0);
    for (const [, arg] of froms) expect(arg).toBe("${BUN_VERSION}");
  });

  test("compose passes the pin through rather than repeating it", () => {
    // compose is a dev loop, and a dev loop on a different runtime than the image
    // is a bug report that reads as "it works locally". It is a build arg, so it
    // has to be the same number the Dockerfile defaults to.
    const compose = read("docker-compose.yml");
    expect(compose).toMatch(/BUN_VERSION:\s*"(\d+\.\d+\.\d+)"/);
    expect(/BUN_VERSION:\s*"(\d+\.\d+\.\d+)"/.exec(compose)?.[1]).toBe(PIN);
  });
});

// ## The half above says the pin is one number. This says the gate obeys it.
//
// The four files agreeing is a claim about text. Whether `bin/prime` *reads* that
// number or merely has a bun on PATH is a different claim, and it was false: the
// gate's only precondition was `command -v bun`, so a bun that is present and
// wrong — a system install ahead of mise's shims, a global upgrade, a stale CI
// image — ran the whole gate and failed somewhere else entirely.
//
// The failure it produced is the reason this is here. It is not a toolchain
// error; it is `cannot find module 'hono'`, which names a package, sends the
// reader to `package.json` and `bun.lock`, and says nothing at all about the
// runtime that produced it. cafaye-rb's gate failed that way — a Ruby on PATH
// that was not the one mise had installed — and the lesson is not "add a
// version check" in the abstract. It is that a gate which cannot name its own
// preconditions cannot be debugged from its own output.
//
// So the check is run here against a fake bun rather than asserted as text: a
// shell script standing in for the runtime, first on PATH, answering exactly one
// question. Both directions are checked, because a check that only ever refuses
// is indistinguishable from a script that is simply broken.
describe("the gate obeys the pin rather than only needing a bun", () => {
  /** A `bun` that answers `--version` and is otherwise a no-op. */
  const fakeBun = (version: string): string => {
    const dir = mkdtempSync(join(tmpdir(), "guard-fake-bun-"));
    const path = join(dir, "bun");
    writeFileSync(path, `#!/bin/sh\n[ "$1" = "--version" ] && echo ${version}\nexit 0\n`, { mode: 0o755 });
    return dir;
  };

  /** Run `bin/prime` against a bun reporting `version`, and keep the output. */
  const primeAgainst = (version: string): { code: number; stdout: string; stderr: string } => {
    const dir = fakeBun(version);
    try {
      // `PATH` first, so this bun wins over whatever mise has shimmed. The rest
      // of PATH stays: dropping it would make the run fail for want of `bun`
      // rather than for the version, which is the defect this file is about.
      const proc = Bun.spawnSync(["./bin/prime"], {
        cwd: fileURLToPath(root),
        env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` },
      });
      return {
        code: proc.exitCode,
        stdout: proc.stdout.toString(),
        stderr: proc.stderr.toString(),
      };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  test("a wrong bun fails on the pin, naming both numbers", () => {
    const run = primeAgainst("1.2.9");

    // 127, the code this script already used for an absent toolchain: the
    // runtime is the problem, and a wrong one is not a different kind of problem
    // from a missing one.
    expect(run.code).toBe(127);
    // The pin and what was found instead. A message that said only "wrong bun"
    // would leave the reader to go looking for which wrong.
    expect(run.stderr).toContain(PIN);
    expect(run.stderr).toContain("1.2.9");
    // And it must NOT be the red herring. This is the assertion that matters:
    // without it, a gate that printed the pin and then a module error would pass.
    expect(run.stderr).not.toContain("cannot find module");
    // It refused before doing any work, so no step banner was printed — a gate
    // that ran the install against the wrong runtime has already wasted the run.
    expect(run.stdout).not.toContain("bun install");
  });

  test("the pinned bun is admitted, so the check compares rather than refuses", () => {
    const run = primeAgainst(PIN);

    expect(run.code).toBe(0);
    expect(run.stderr).not.toContain("wrong Bun on PATH");
    // The closing banner names the version, and it is the one the check
    // admitted — a second reading at the end of the run could disagree with the
    // check that let the run start.
    expect(run.stdout).toContain(`prime ok (bun ${PIN})`);
  });
});

describe("the lockfile", () => {
  test("bun.lock is committed and named after the package, not after a worktree", () => {
    // `bun.lock` records the workspace name it was generated under, and a
    // worktree name is what a lockfile written inside one looks like:
    // `guard-worker-guard-01` was in this file, so the committed lockfile named a
    // checkout rather than the package. It reaches master because nothing reads
    // the name and a lockfile is not something anyone opens.
    //
    // Read as text, not parsed: `bun.lock` is JSONC — bun writes trailing commas —
    // so `JSON.parse` throws on a perfectly good lockfile, and a check that
    // cannot read the file it is checking is worse than no check.
    const lock = read("bun.lock");
    const manifest = JSON.parse(read("package.json")) as { name?: string };

    expect(manifest.name).toBe("guard");
    expect(lock).toMatch(/"name":\s*"guard"/);
    // The worktree pattern is the general form, so this keeps holding when the
    // next packet runs from a worktree and forgets again.
    expect(lock).not.toMatch(/"name":\s*"[a-z-]+-worker-[a-z]+-\d+"/);
  });

  test("bun.lock is tracked by git rather than ignored", () => {
    // A lockfile CI installs from, that is not committed, is CI resolving a
    // different tree than the one that was reviewed — which is the entire reason
    // `bun install --frozen-lockfile` exists.
    const ignored = read(".gitignore");

    expect(ignored).not.toMatch(/^\s*bun\.lock\s*$/m);
    expect(ignored).not.toMatch(/^\s*\*\.lock\s*$/m);
  });
});
