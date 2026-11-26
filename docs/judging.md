# Judging

When the engine gives no judgment (unreachable, an error, no answer in time) a tool call is
denied: the Collector defaults to `WITHHUMAN_ON_FAILURE=closed`, and `pre-tool-use.py` denies when
it cannot reach the Collector. With `WITHHUMAN_ASK=ask` (Claude Code), a grade 2 or 3 call the
engine could not judge is put to the user instead. A stored verdict is kept 5 minutes
(`WITHHUMAN_VERDICT_TTL_SECS`).

- Each call is graded 0, 1, 2-1, 2-2, 3-1 or 3-2 by how far its effect can be undone (KISA
  agentic-AI zero-trust guide, table 2-5); the grade is recorded in the trace and sets what
  happens when judging fails.
- A file change is never cleared on the first question alone, and is asked about each line it
  adds: a document the user pointed to counts only for the task it describes. A shell command
  that writes files is checked the same way, and a change that only undoes the session's own
  earlier changes to a file is allowed.
- Jev sees a several-step shell command step by step, and text built from base64, character
  codes or joined literals.
- A `---`, `***` or `___` line starts a new paragraph, so a note appended after it is traced
  apart from the text before; a Codex shell command that exits non-zero is recorded with its
  output, as Claude Code records a failed Bash command.
- After `WITHHUMAN_DEGRADED_FAILURES` (3) Jev failures in a row, or at once on 401/402/403/429,
  the rules judge alone for `WITHHUMAN_DEGRADED_SECONDS` (60): grade 0 and 1 are allowed (except a
  secret read, a web fetch or an edit of CI or hooks), grade 2 and 3 are reviewed, a safeguard
  change is denied.
