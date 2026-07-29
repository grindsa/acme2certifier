---
name: a2c-changelog
description: >-
  Updates CHANGES.md for acme2certifier by comparing git branches (default
  master..devel), grouping user-visible changes into New Features vs Bug Fixes
  and Improvements, and linking docs/issues. Use when the user asks to update
  the changelog, CHANGES.md, or release notes.
disable-model-invocation: true
---

# a2c changelog

## Goal

Maintain `CHANGES.md` as a high-level, user-facing summary of meaningful product
changes — not a commit dump.

**Style reference:** Read the existing top of [`CHANGES.md`](../../../CHANGES.md)
before writing. Match tone, one-liner density, markdown link patterns, and how
features vs fixes are phrased. Past entries are the source of truth for what
“good” looks like.

## Trigger

Manual only. The user asks to update `CHANGES.md` and may name comparison
branches. If none are given, compare **`devel` against `master`**
(`master..devel`).

## Hard rules

1. **Work on `devel`.** All changelog edits land on the `devel` branch. If not
   on `devel`, switch or stop and ask.
2. **Never edit past releases.** Only update the section for the **current
   in-progress** version (see version below). Do not rewrite, reorder, or
   “fix” older `## Changes in …` sections.
3. **Do not list every commit.** Group related commits into one entry. Each
   entry is a single concise one-liner describing user-visible functionality.
4. **Omit noise.** Do not mention:
   - documentation-only updates
   - additional / refactored unit tests
   - CI / GitHub Actions / workflow / composite-action changes
5. **Decide the section yourself.** Categorize each grouped change as either a
   new feature or a bugfix/improvement (see sections below).
6. **No auto-commit or PR.** The user reviews and approves `CHANGES.md` updates
   themselves. Do **not** create a git commit, push, or open a pull request for
   changelog changes unless the user explicitly asks in a later message.

## Version / section target

1. Read `__version__` from `acme2certifier/acme_srv/version.py` (e.g.
   `0.45.dev1` → section `## Changes in 0.45`).
2. If that heading is missing, create it at the **top** of the changelog body
   (immediately under the intro blurb), before older releases.
3. Merge new bullets into that section only. Deduplicate against entries already
   present.

## Branch comparison

```bash
# default when user omits branches
git log --oneline --no-merges master..devel

# optional richer view
git log --stat --no-merges master..devel
```

If the user specifies branches, use `base..head` as given (e.g.
`0.44..devel`, `master..feature/foo`). Still apply edits on `devel`.

Filter the log for product-relevant paths under `acme2certifier/`, handlers,
tools, Docker runtime config that affects operators, etc. Ignore pure
`docs/`, `test/`, `.github/` noise unless the same change clearly includes a
user-facing product change worth one line.

## Sections

Use these two headings under the current `## Changes in X.Y` block (create a
heading only if it has at least one bullet):

```markdown
## Changes in X.Y

**New Features**:

- …

**Bug Fixes and Improvements**:

- …
```

### New Features

- New capabilities, handlers, CLI tools, config options that enable new
  behavior, experimental protocol support, etc.
- Prefer a markdown link to documentation under `docs/` when a matching doc
  exists (same pattern as existing entries).
- Example shape (see `CHANGES.md` for many real samples):
  - `[Feature name](docs/….md) short description of what it does`

### Bug Fixes and Improvements

- Fixes, corrections, hardening, and enhancements to **existing** behavior.
- If tied to a GitHub issue or discussion, link it:
  - Issues: `https://github.com/grindsa/acme2certifier/issues/<n>`
  - Discussions: `https://github.com/grindsa/acme2certifier/discussions/<n>`
- Preferred issue entry form (match existing style):
  - `[#345 Short title](https://github.com/grindsa/acme2certifier/issues/345)`
- Discover links from commit messages, PR titles/bodies (`Fixes #123`,
  `Closes #123`), and `gh` when useful. Do not invent issue numbers.

**Note:** Older sections in `CHANGES.md` may still say **Features and
Improvements** / **Bug Fixes**. Keep those historical headings as-is. For the
**current** in-progress section only, use **New Features** and **Bug Fixes and
Improvements** as above.

## Workflow

Copy and track:

```
Changelog progress:
- [ ] Confirm on devel
- [ ] Resolve compare range (default master..devel)
- [ ] Read CHANGES.md top + version.py
- [ ] Collect & filter commits / PRs
- [ ] Group into one-liners; classify Feature vs Fix/Improvement
- [ ] Add/merge bullets in current section only
- [ ] Link docs / issues / discussions where applicable
- [ ] Brief summary of what was added for the user
```

### 1. Orient

- `git branch --show-current` must be `devel` (or switch).
- Read intro + current version section of `CHANGES.md`.
- Resolve `base..head`.

### 2. Collect

- `git log` for the range; skim messages and touched paths.
- Optionally `gh pr list` / PR bodies for issue refs when commits alone are
  unclear.
- Drop docs/tests/CI-only changes.

### 3. Group and classify

- Merge related commits (same feature, same bug, same option) into one bullet.
- **New capability or new config surface** → New Features.
- **Fix or improve existing path** → Bug Fixes and Improvements.
- When unsure, prefer Bug Fixes and Improvements unless the change clearly
  introduces something operators can newly enable.

### 4. Write

- Append or merge into the current version section only.
- Keep bullets parallel, terse, and consistent with nearby entries in
  `CHANGES.md`.
- Stop after editing the file. Leave the diff for the user to review; no
  commit, push, or PR.

### 5. Report

- List branches compared.
- List bullets added or updated (Features vs Fixes).
- Note intentionally omitted commit themes (docs/tests/CI).

## Anti-patterns

- Pasting raw commit subjects without grouping
- Updating `## Changes in` sections for already-shipped releases
- Changelog entries for coverage bumps, lint, or workflow renames
- Orphan feature bullets that have docs but no `docs/` link when one exists
- Editing `master` or feature branches for this file
- Committing, pushing, or opening a PR for `CHANGES.md` without an explicit
  user request after they have reviewed the update
