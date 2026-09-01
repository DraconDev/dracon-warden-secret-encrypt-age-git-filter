#!/usr/bin/env bash
# Regression test for the warden monorepo release preview and rollback.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work=$(mktemp -d "${TMPDIR:-/tmp}/dracon-warden-release-dry-run-XXXXXX")
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo/dracon-warden/scripts" "$work/bin" "$work/home/.cargo"

git init -q -b main "$repo"
git -C "$repo" config core.hooksPath /dev/null
git -C "$repo" config user.name fixture
git -C "$repo" config user.email fixture@example.test
git -C "$repo" remote add origin https://github.com/DraconDev/dracon-utilities.git

cp "$SCRIPT_DIR/release.sh" "$repo/dracon-warden/scripts/release.sh"
cp "$SCRIPT_DIR/resolve-github-remote.sh" "$repo/dracon-warden/scripts/resolve-github-remote.sh"
cp "$SCRIPT_DIR/../../dracon-sync/scripts/close-changelog.py" \
    "$repo/dracon-warden/scripts/close-changelog.py"
chmod +x "$repo/dracon-warden/scripts"/*
cat > "$repo/.gitignore" <<'EOF'
target/
dracon-warden/
.publish-dry-run
.publish-real
EOF
cat > "$repo/Cargo.toml" <<'EOF'
[workspace]
members = ["dracon-warden"]
resolver = "2"
EOF
cat > "$repo/dracon-warden/Cargo.toml" <<'EOF'
[package]
name = "dracon-warden"
version = "0.1.0"
edition = "2021"

[dependencies]
dracon-security-kit = { version = "0.1.0", path = "../dracon-security" }
EOF
cat > "$repo/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "dracon-warden"
version = "0.1.0"
EOF
cat > "$repo/dracon-warden/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

- fixture
EOF

git -C "$repo" add .
git -C "$repo" add -f -- dracon-warden
git -C "$repo" commit -qm init

touch "$work/home/.cargo/credentials.toml"
cat > "$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${DRACON_FIXTURE_ROOT:?}"
case "${1:-}" in
    check)
        version=$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$root/dracon-warden/Cargo.toml")
        sed -i "/^name = \"dracon-warden\"$/{n;s/^version = .*/version = \"$version\"/;}" "$root/Cargo.lock"
        ;;
    metadata)
        printf '{"workspace_root":"%s"}\n' "$root"
        ;;
    publish)
        version=$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$root/dracon-warden/Cargo.toml")
        if [[ " $* " == *" --dry-run "* ]]; then
            mkdir -p "$root/target/package/dracon-warden-$version"
            touch "$root/.publish-dry-run"
        else
            touch "$root/.publish-real"
        fi
        ;;
    *)
        echo "unexpected cargo invocation: $*" >&2
        exit 2
        ;;
esac
EOF
cat > "$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == auth && "${2:-}" == status ]]
EOF
chmod +x "$work/bin/cargo" "$work/bin/gh"

DRACON_FIXTURE_ROOT="$repo" HOME="$work/home" PATH="$work/bin:$PATH" \
    timeout 120 "$repo/dracon-warden/scripts/release.sh" 0.1.1 --dry-run --yes \
    >"$work/dry-run.out" 2>"$work/dry-run.err"
grep -F 'dracon-warden/Cargo.toml: 0.1.0 → 0.1.1' "$work/dry-run.out" >/dev/null
test "$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$repo/dracon-warden/Cargo.toml")" = 0.1.1
test "$(awk -F'"' '/^name = "dracon-warden"$/{getline; print $2; exit}' "$repo/Cargo.lock")" = 0.1.1
test -e "$repo/.publish-dry-run"
test ! -e "$repo/.publish-real"
test -e "$repo/dracon-warden/release-notes-v0.1.1.md"
test -z "$(git -C "$repo" tag --list)"

DRACON_FIXTURE_ROOT="$repo" HOME="$work/home" PATH="$work/bin:$PATH" \
    timeout 120 "$repo/dracon-warden/scripts/release.sh" --abort \
    >"$work/abort.out" 2>"$work/abort.err"
test "$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$repo/dracon-warden/Cargo.toml")" = 0.1.0
test "$(awk -F'"' '/^name = "dracon-warden"$/{getline; print $2; exit}' "$repo/Cargo.lock")" = 0.1.0
test ! -e "$repo/dracon-warden/release-notes-v0.1.1.md"
test -z "$(git -C "$repo" status --porcelain)"

echo 'warden release dry-run regression tests: ok'
