# Dracon Warden Source of Truth

`dracon-warden` is a standalone repository and the canonical source for its
implementation, embedded security crate, tests, configuration examples, and
release metadata.

The parent `dracon-utilities` repository is a meta workspace. When this repo
is checked out at `dracon-utilities/dracon-warden/`, the parent Cargo
workspace includes it by path; the parent does not mirror or overwrite its
files.

The daemon watches this repository directly and pushes its configured remotes.
Releases are cut from `scripts/release.sh` in this repository. The security
crate is intentionally kept at `src/security` so the audited local source is
part of every workspace build.

## Invariants

1. `main` is the active development branch.
2. The working tree remains buildable with `cargo test --workspace --locked`
   when used from the parent workspace or with `cargo test --locked` here.
3. The daemon's history rules in the parent `AGENTS.md` apply to this repo:
   agent loops do not rewrite published history.
4. Omitted `hygiene_patterns` use the narrow machine-local defaults; the shipped
   example policy starts from those defaults and adds product-specific
   regeneratable paths on top. An explicit empty list remains an operator
   override, and broad `*.log` matching is not a Warden default.
