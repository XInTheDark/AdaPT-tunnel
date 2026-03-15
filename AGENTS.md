# AdaPT Tunnel Repo Rules

## Architecture

- No god files. Any source file that mixes multiple responsibilities or grows beyond roughly 500 logical lines must be split by responsibility before the change is considered complete.
- Hard stop thresholds:
  - Rust library/runtime modules: 500 lines
  - CLI entrypoints such as `main.rs`: 300 lines
- Exceptions require explicit user approval in the same task.
- New behavior must be added in focused modules, not by extending an existing oversized file.
- If a touched file is already over the limit, the same change must reduce it materially instead of making it larger.


## Planning

- `PLAN.md` is the canonical living implementation plan for non-trivial work.
- When scope, assumptions, status, or expected performance impact changes, update `PLAN.md` in the same task.
- Keep `PLAN.md` forward-looking: current milestone, active/pending work, next tasks, assumptions, and expected performance notes only.

## Refactoring expectations

- Prefer responsibility-based module splits over cosmetic extraction.
- Preserve public APIs unless the task explicitly calls for API changes.
- Keep tests close to the code they validate when practical.
