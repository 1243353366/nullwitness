# Archive

Material kept for history, not for use.

These files were uploaded to this repository in earlier commits. They are not part of
the educational material, are not built or tested, and are not maintained. They are
preserved unchanged so the record of the repository stays honest; deleting them from
the current tree would not remove them from git history, so they are labelled
instead.

## `canary-check/`

Both files do the same thing: look for a file named `attacker.txt` in the user's home
directory and delete it.

| File | What it actually is |
| --- | --- |
| `file-4tr.rs.txt` | Not Rust. It is three separate programs (Rust, then Go, then Java) concatenated into one file with shell-style `#` banner comments between them. It compiles in no language as stored, and the Java section is truncated mid-string. The `.txt` suffix reflects that. |
| `file1.python` | Extracted from the former `project.zip`. It is the same operation in Python, in a function named `poison_data()`, with no dry-run, no path validation, and no error handling. |

## Why this is not part of the lesson

The educational material in this repository argues that defensive work is bounded by
authorization and control. A tool whose purpose is to detect and clear a planted
canary file does the opposite: it exists to defeat someone else's detection on a
system, and in the usual case the canary was planted by an owner whose system is not
yours to clean. That is detection evasion, which this project does not teach and
does not ship as working code.

If you found this archive because you were looking for a canary-checking utility:
the defensive version of this idea is to *plant and monitor* canary records in
datasets you control. See [../SAFETY.md](../SAFETY.md) and
[../examples/simulation-walkthrough.md](../examples/simulation-walkthrough.md).
