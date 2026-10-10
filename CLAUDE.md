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
