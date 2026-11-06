# public-scan reads its terms from an untracked file

Kata: ai-tools-alerts#a5hk (parent jibot-code#gr5b; follows h6bx).

## Problem

`scripts/public-scan.sh` (h6bx) compiles every term it exists to keep out of
the public repo into its own regex, and skips itself. So main still lists the
fleet host names, the relay VM domain and user, the tailnet, the secrets cache
and the vault variable names, in the one file that guards against them. The
history rewrite planned after this lands cannot remove a spelling that a
tracked file still carries.

## Success criteria

1. The tracked tree spells no term: `git grep -nIiP '<the regex the scanner
   held at 541a6e8>'` (case-insensitive and Perl syntax, as the scanner
   matched) exits 1 with no output; exit 2 would be an error, not a pass. The
   command is run from a scratch file, never written into the tree.
2. The scanner reads its terms from `$PUBLIC_SCAN_TERMS`, else
   `~/.config/aitools-alerts/public-scan.terms`: one regex fragment per line;
   blank lines and lines starting with `#` are ignored; matching is
   case-insensitive on bytes, as before.
3. A missing, unreadable or empty (no fragment) terms file, or a fragment
   that does not compile (`re.error`, and the `OverflowError` a huge
   repetition count raises), is exit 2 with one line on stderr naming the path.
   Never a pass.
4. Behaviour otherwise unchanged: every tracked file read as bytes, binary
   ones included; file names scanned; `path:line: text` per hit; exit 1 on a
   hit; exit 2 when the listing or a read fails.
5. The scanner no longer skips itself: it spells no term, so it is scanned
   like every other file.
6. Tests use only fixture terms (`example-forbidden-term` style) from a
   temporary file, and cover: clean pass, hit kinds (case, space in name,
   binary, file name), word-boundary fragment, missing file, empty and
   comment-only file, bad fragment, default path under `HOME`, unreadable
   tracked file, gate passes exit 1 through.
7. `scripts/test-gate.sh` unchanged. README Tests section gains one
   contributor paragraph.
8. With the maintainers' real terms in a scratch file at
   `$PUBLIC_SCAN_TERMS`, `scripts/test-gate.sh` passes on the branch head.
9. Under 150 changed lines in the deliverable (scanner, tests, README); the
   run records are counted apart, as on the earlier runs.
10. The README's contributor example works: its fragment, `(?!)`, matches
    no text, so the scan passes and pytest runs. A fixture term would match
    the tests and the README themselves and stop the gate.

## Approach

In the Python body: resolve the path with `os.environ.get` and
`os.path.expanduser`; read it as bytes; keep stripped lines that are
non-empty and do not start with `#`; join as `(?:f1)|(?:f2)…`; compile with
`re.I`. `re.error` or `OSError` or no fragments: one stderr line, exit 2.
Drop `SELF` and its skip. `python3 -I` ignores only `PYTHON*` variables, so
`PUBLIC_SCAN_TERMS` and `HOME` reach the program.

## Alternatives considered

- Hash the terms in the tracked file (compare hashes of tokens): cannot
  express regex fragments such as a word-bounded domain or a substring inside
  a path; rejected.
- Keep the terms obfuscated (rot13, base64): still recoverable from the
  public repo, which is the leak; rejected.
- Pass when the file is missing and print a warning: a contributor's or a
  misconfigured host's gate would go green with no scan; the issue forbids it.

## Blast radius / rollback

One script, its tests, a README paragraph. A host without the terms file now
fails its gate with exit 2 until the coordinator distributes the file
(dotfiles-private) — the intended behaviour. Rollback: revert the commit
(which would put the terms back in the tree).

## Assumes

- `#` comment lines are allowed in the terms file; a fragment cannot start
  with `#` (none needs to).
- The coordinator distributes the terms file after landing; this task does
  not touch history or the fleet Macs.
