#!/usr/bin/env python3
"""Bounded installed/build binary Git lifecycle regression; synthetic inputs only.
Usage: python3 scripts/verify-filter-lifecycle.py /absolute/path/to/dracon-warden
No identity overrides, hooks bypasses, or access to watched repositories.
"""
import json
import pathlib
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve(strict=True))
with tempfile.TemporaryDirectory(prefix="warden-lifecycle-") as directory:
    root = pathlib.Path(directory)

    def run(*args, data=None):
        result = subprocess.run(args, cwd=root, input=data, capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError(f"{args[0:2]} failed: {result.stderr.decode(errors='replace')}")
        return result.stdout

    run("git", "init", "-q")
    for direction in ("clean", "smudge"):
        run("git", "config", f"filter.dracon.{direction}", f"'{binary}' filter-{direction} %f")
    run("git", "config", "filter.dracon.required", "true")
    (root / ".gitattributes").write_text("* filter=dracon\n")
    begin = "-----BEGIN "
    end = "-----END "
    fixtures = {
        "stripe.rs": ('sk_live_' + 'A' * 24).encode(),
        "gcp.rs": ('AIza' + 'B' * 34 + '-').encode(),
        "openai.rs": ('sk-proj-' + 'C' * 40).encode(),
        "pkcs8.rs": (begin + 'PRIVATE KEY-----\nQUJDRA==\n' + end + 'PRIVATE KEY-----').encode(),
        "encrypted-pkcs8.rs": (begin + 'ENCRYPTED PRIVATE KEY-----\nQUJDRA==\n' + end + 'ENCRYPTED PRIVATE KEY-----').encode(),
        "nul.rs": b'\x00' + ('sk_live_' + 'D' * 24).encode() + b'\x00',
        # Slack webhook: valid body encrypts, overlong body ending in
        # base64-style '+' stays plaintext (round-2 boundary fix).
        "slack-valid.rs": ('https://hooks.slack.com/services/' + 'Aa09+/' * 8 + 'Aa').encode(),
        "slack-overlong-plus.rs": ('https://hooks.slack.com/services/' + 'A' * 56 + '+A').encode(),
        "slug.rs": b'task-configuration-reference-guide',
        "invalid.rs": b'\xff literal _SECRET: marker',
    }
    for name, content in fixtures.items():
        (root / name).write_bytes(content)
    run("git", "add", "--", ".gitattributes", *fixtures)
    run("git", "commit", "-qm", "Synthetic filter lifecycle regression")
    for name, content in fixtures.items():
        blob = run("git", "show", f"HEAD:{name}")
        if name in ("slug.rs", "invalid.rs", "slack-overlong-plus.rs"):
            assert blob == content, name
        else:
            assert b'[DRACON_SECRET:' in blob and content not in blob, name
        (root / name).unlink()
    run("git", "checkout", "HEAD", "--", *fixtures)
    for name, content in fixtures.items():
        assert (root / name).read_bytes() == content, name
    status = run("git", "status", "--porcelain")
    assert not status, status.decode()
    # A real edit must still be reported and protected on add.
    (root / "stripe.rs").write_bytes(fixtures["stripe.rs"] + b'\n// changed\n')
    assert b'stripe.rs' in run("git", "status", "--porcelain")
    run("git", "add", "--", "stripe.rs")
    assert b'[DRACON_SECRET:' in run("git", "show", ":stripe.rs")
    run("git", "checkout", "HEAD", "--", "stripe.rs")
    assert not run("git", "status", "--porcelain")
    print(json.dumps({"binary": binary, "fixtures": len(fixtures), "encrypted_blobs": 7,
                      "roundtrips": "byte-exact", "post_checkout_status": "clean",
                      "real_edit": "detected and encrypted"}))
