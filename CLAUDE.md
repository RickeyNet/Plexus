# Claude Code Project Rules

## Git workflow

- **Never commit changes.** Do not run `git commit` (or `git push`) under any
  circumstances, even if asked to "finish up" or "ship it". All commits are made
  by the user after they review the changes.
- **Always provide a commit message.** After completing any change to the
  repository, end your final summary with a ready-to-use commit message in a
  code block so the user can review and commit without asking for one.

## Worker / reviewer model split

- **Opus 5.5 does the work.** Every implementation task (code changes, new
  features, bug fixes, refactors, research, test writing) is delegated to a
  subagent via the `Agent` tool with `model: "opus"`. Use a non-fork agent type
  (`general-purpose` or a task-specific type) — `fork` ignores the `model`
  override and must not be used for worker tasks. Give the worker a complete,
  self-contained prompt: the goal, relevant file paths, constraints from this
  file, and the expected deliverable.
- **Fable 5.1 reviews and corrects.** The main session (Fable 5.1) does not
  implement tasks directly. Its job is to plan, dispatch workers, then review
  each worker's output: read the changed files, run the relevant tests/build,
  check for correctness, style consistency, and scope creep. Fix any issues
  found — either directly for small corrections, or by sending the worker a
  follow-up with precise instructions for larger ones. Do not hand work back to
  the user until the review is clean.
- **Independent tasks run in parallel.** When a request splits into unrelated
  pieces, launch one Opus worker per piece in a single turn, then review each
  result as it arrives.
- **Exceptions.** Trivial one-line edits, answering questions from context
  already in the conversation, and reading files to plan do not require a
  worker. Everything else does.
