# Claude Code Project Rules

## Git workflow

- **Never commit changes.** Do not run `git commit` (or `git push`) under any
  circumstances, even if asked to "finish up" or "ship it". All commits are made
  by the user after they review the changes.
- **Always provide a commit message.** After completing any change to the
  repository, end your final summary with a ready-to-use commit message in a
  code block so the user can review and commit without asking for one.

## Worker / reviewer model split

- **Fable 5.1 does small fixes directly.** The main session (Fable 5.1)
  implements a task itself when it is small and well understood: a bug fix or
  change touching roughly one to three files with a clear cause, a test
  addition, a doc or config edit, a lint/type fix, or a follow-up correction to
  a worker's output. Read the code, make the edit, run the targeted tests, and
  report. Do not spin up a worker for work that takes a few minutes by hand;
  the dispatch-and-review round trip costs more than it saves.
- **Opus 5.5 does the large work.** Delegate to a subagent via the `Agent`
  tool with `model: "opus"` when a task is big enough to justify the overhead:
  a new feature, a multi-file refactor, a broad audit or research sweep, or
  anything where the exploration itself is the bulk of the work. Use a
  non-fork agent type (`general-purpose` or a task-specific type) — `fork`
  ignores the `model` override and must not be used for worker tasks. Give
  the worker a complete, self-contained prompt: the goal, relevant file
  paths, constraints from this file, and the expected deliverable. Keep each
  worker's scope narrow and tell it which test files to run; do not ask a
  worker to run the whole suite.
- **Fable 5.1 reviews worker output.** For every delegated task, read the
  changed files, run the relevant tests/build, and check correctness, style
  consistency, and scope creep. Fix issues directly when they are small, or
  send the worker a follow-up with precise instructions for larger ones. Do
  not hand work back to the user until the review is clean.
- **Independent tasks run in parallel.** When a request splits into unrelated
  large pieces, launch one Opus worker per piece in a single turn, then review
  each result as it arrives. Do not serialize phases that can overlap.
- **Keep verification proportionate.** Run the test files that cover the
  change, not the full suite, unless the change is cross-cutting (the database
  facade, migrations, conftest). Run a full suite at most once per task, and
  never twice in one command.

## CI compliance

- **Read the workflow before you change code.** `.github/workflows/ci.yml`
  is the contract every change must pass. Before starting a task, read the
  jobs that cover the files in scope (secret-scan, build-test, frontend) and
  note the exact commands and flags they run: the `pytest` console script
  (not `python -m pytest`), `ruff check`, `mypy netcontrol templates`,
  `pip-audit`, `bandit`, the coverage gates, `npm audit`, `npm run lint`,
  `npm run typecheck`, `npm test`, `npm run build`.
- **Verify the way CI verifies.** Run the CI commands that cover the change
  with the same flags and invocation CI uses, not a local variant that
  happens to pass. A change is not done until those steps pass locally.
  When a job cannot be reproduced (no Postgres, no gh auth), say so and use
  the unauthenticated GitHub REST API for run, job, step, and annotation data.
- **New features update CI.** When a change adds a dependency, a test
  requirement (service, env var, system package, cloud SDK), a new package or
  directory that lint/type/coverage steps should cover, or a new tool, update
  `ci.yml` (and `requirements*.txt`, `tools/coverage_gate.py`, lock files)
  in the same change. Tests that need something CI does not install must
  `importorskip` it or the dependency must be added to CI; never leave a
  test that can only pass on the dev box.
- **Fix CI failures at the root.** On a reported Actions failure, identify
  the exact failing step first (jobs API or annotations), reproduce it
  locally, and assume several steps may be broken at once since the job
  stops at the first failure. Do not loosen a gate, ignore a rule, or skip a
  check to make a job green unless the user asks for that.
- **Workers inherit this rule.** Every delegated worker prompt names the CI
  steps that cover its scope and the exact commands to run before reporting.

## Code reuse

- **Search before you write.** Before adding a helper, parser, validator,
  formatter, or client wrapper, grep the codebase for an existing one that
  does the same job (`netcontrol/`, `routes/`, `templates/`, and the
  frontend `src/`). If one exists, import and reuse it, or extend it with a
  parameter; do not write a second copy. Prefer reusing an existing helper
  over duplication, even when the new copy would be shorter.
- **Share, don't copy.** When the same logic is needed in two or more
  modules, put it in one shared place (an existing utility module, a common
  base class, or a new small module under the nearest shared package) and
  import it from both. The same applies to the frontend: shared hooks,
  components, and utilities live in one place and are imported, not pasted.
- **Fix duplication you touch.** When a change lands in code that already
  duplicates logic found elsewhere, consolidate the copies as part of the
  change if it is small and safe. If consolidation is too large for the
  task, leave the code as is and call out the duplication in the summary.
- **Workers inherit this rule.** Every delegated worker prompt must include
  the reuse rule and name the shared modules relevant to its scope, and the
  reviewer checks worker output for duplicated code before accepting it.
