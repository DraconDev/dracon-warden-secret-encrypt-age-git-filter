#!/usr/bin/env bash
# Run from the utilities workspace using dracon-sync maintenance.
set -euo pipefail
expected=ccfcafcaf80a67ba4395b61369743f4968d55601bba3b21379069ac0e45bc6c3
[[ $(sha256sum target/release/dracon-warden | cut -d' ' -f1) == "$expected" ]]
backup="$HOME/.local/state/dracon/rollback-binaries/reviewed-hook-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p -m 700 "$backup"
cp -p "$HOME/.local/bin/dracon-warden" "$backup/dracon-warden"
cp -p "$HOME/.config/git/hooks/pre-push" "$backup/pre-push"
printf 'started=%s\nrollback=%s\n' "$(date -u +%FT%TZ)" "$backup"
install -m 755 target/release/dracon-warden "$HOME/.local/bin/.dracon-warden.review-new"
mv -f "$HOME/.local/bin/.dracon-warden.review-new" "$HOME/.local/bin/dracon-warden"
cmp target/release/dracon-warden "$HOME/.local/bin/dracon-warden"
timeout 30 "$HOME/.local/bin/dracon-warden" setup-hooks --global
sh -n "$HOME/.config/git/hooks/pre-push"
sha256sum target/release/dracon-warden "$HOME/.local/bin/dracon-warden" "$HOME/.config/git/hooks/pre-push"
printf 'finished=%s\n' "$(date -u +%FT%TZ)"
