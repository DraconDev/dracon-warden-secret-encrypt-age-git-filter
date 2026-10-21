#!/usr/bin/env bash
# Invoke from workspace root under dracon-sync maintenance. No hook bypasses.
set -euo pipefail
expected=bc1a81ee8b6288433d9f496bd74fd8654cf3d15931b7aaa12a8d0592c5ee3657
[[ $(sha256sum target/release/dracon-warden | cut -d' ' -f1) == "$expected" ]]
backup="$HOME/.local/state/dracon/rollback-binaries/warden-hook-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$backup" && chmod 700 "$backup"
printf 'started=%s\nrollback=%s\n' "$(date -u +%FT%TZ)" "$backup"
cp -p "$HOME/.local/bin/dracon-warden" "$backup/dracon-warden"
cp -p "$HOME/.config/git/hooks/pre-push" "$backup/pre-push"
sha256sum "$HOME/.local/bin/dracon-warden" "$backup/dracon-warden"
install -m 755 target/release/dracon-warden "$HOME/.local/bin/.dracon-warden.hook-new"
mv -f "$HOME/.local/bin/.dracon-warden.hook-new" "$HOME/.local/bin/dracon-warden"
cmp target/release/dracon-warden "$HOME/.local/bin/dracon-warden"
timeout 30 "$HOME/.local/bin/dracon-warden" setup-hooks --global
sha256sum target/release/dracon-warden "$HOME/.local/bin/dracon-warden" "$HOME/.config/git/hooks/pre-push"
printf 'finished=%s\n' "$(date -u +%FT%TZ)"
