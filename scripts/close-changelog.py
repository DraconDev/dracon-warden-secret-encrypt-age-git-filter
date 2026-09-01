#!/usr/bin/env python3
"""Close CHANGELOG.md's [Unreleased] section as [VERSION].

The operation is idempotent: when a ``## [VERSION]`` header already exists,
the file is left byte-identical.
"""
import pathlib
import re
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: close-changelog.py <changelog-path> <version> <date>", file=sys.stderr)
        return 2

    path, version, date = sys.argv[1], sys.argv[2], sys.argv[3]
    p = pathlib.Path(path)
    text = p.read_text()

    if re.search(rf"^## \[{re.escape(version)}\][^\n]*$", text, re.MULTILINE):
        print(f"  {p}: [{version}] already closed; leaving unchanged", file=sys.stderr)
        return 0

    marker = "## [Unreleased]"
    if marker not in text:
        print(f"  {p}: no [Unreleased] section found; leaving unchanged", file=sys.stderr)
        return 0

    unreleased_match = re.search(r"^## \[Unreleased\][^\n]*\n", text, re.MULTILINE)
    if not unreleased_match:
        print(f"  {p}: regex miss for [Unreleased] header; leaving unchanged", file=sys.stderr)
        return 0

    start = unreleased_match.end()
    next_match = re.search(r"^## \[[^\n]*\n", text[start:], re.MULTILINE)
    if next_match:
        end = start + next_match.start()
        new_text = text[:start] + f"## [{version}] - {date}\n" + text[start:end] + text[end:]
    else:
        new_text = text[:start] + f"\n## [{version}] - {date}\n" + text[start:]
    p.write_text(new_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
