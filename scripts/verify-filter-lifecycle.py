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
    # Exercise the actual installed hardening command, not a handwritten
    # approximation of its attributes. Verify its generated filter commands,
    # then pin the executable to the exact binary requested by this probe.
    run(binary, "once", str(root))
    for direction in ("clean", "smudge"):
        configured = run("git", "config", "--get", f"filter.dracon.{direction}")
        assert f"filter-{direction}".encode() in configured, configured
        run("git", "config", f"filter.dracon.{direction}", f"'{binary}' filter-{direction} %f")
    assert run("git", "config", "--get", "filter.dracon.required").strip() == b"true"
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
        "github-long.rs": ('ghp_' + 'G' * 41).encode(),
        "github-fine.rs": ('github_pat_' + 'H' * 82).encode(),
        "github-overlong.rs": ('ghp_' + 'J' * 256).encode(),
        "slug.rs": b'task-configuration-reference-guide',
        "invalid.rs": b'\xff literal _SECRET: marker',
    }
    for name, content in fixtures.items():
        (root / name).write_bytes(content)
    run("git", "add", "--", ".gitattributes", ".gitignore", ".dracon", *fixtures)
    run("git", "commit", "-qm", "Synthetic filter lifecycle regression")
    for name, content in fixtures.items():
        blob = run("git", "show", f"HEAD:{name}")
        if name in ("slug.rs", "invalid.rs", "slack-overlong-plus.rs", "github-overlong.rs"):
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
    print(json.dumps({"binary": binary, "fixtures": len(fixtures), "encrypted_blobs": 9, "hardening": "installed once command",
                      "roundtrips": "byte-exact", "post_checkout_status": "clean",
                      "real_edit": "detected and encrypted"}))
