# Dracon Warden

Secret, encrypt, age, git-filter — repository hardening and smudge/clean encryption for Dracon workspaces.

This repository is a feature façade for `dracon-warden`. It does **not**
duplicate the implementation code. The canonical source of truth remains the
[`DraconDev/dracon-utilities`](https://github.com/DraconDev/dracon-utilities)
monorepo, with this utility's code and docs under:

- Source: [`dracon-warden/`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden)
- User guide: [`dracon-warden/README.md`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden/README.md)
- Design notes: [`dracon-warden/BLUEPRINT.md`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden/BLUEPRINT.md)
- Example config: [`dracon-warden/dracon-warden.example.toml`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden/dracon-warden.example.toml)

## Why this name?

The descriptive name is a deliberate choice for Codeberg/Forgejo, where
descriptive repo names get upvotes and free attention because readers
immediately know what the project does. The full word list (no fillers, no
audience/UX claims) is documented in
[`docs/design/github-feature-repos.md`](https://github.com/DraconDev/dracon-utilities/blob/main/docs/design/github-feature-repos.md).

## Purpose

Encrypts secret-shaped content at rest in git while preserving normal plaintext files in the working tree. Uses age encryption and git smudge/clean filters plus a pre-commit hook for plaintext-secret prevention.

Use this repo to feature the utility on GitHub, GitLab, and Codeberg without
splitting the actual implementation out of the monorepo. Issues, project
boards, and roadmap notes can live here, while commits, releases, tests, and
packaging stay anchored in `dracon-utilities`.

## Runtime

- Binary: `dracon-warden`
- Service: No systemd service; enforced through global git hooks.
- Example policy: `dracon-warden/dracon-warden.example.toml`
- Common commands: `dracon-warden status · dracon-warden keygen · dracon-warden setup-hooks --global · dracon-warden scrub-markers`

## Relationship to the monorepo

| Boundary | Decision |
|----------|----------|
| Source code | Lives in `dracon-utilities/dracon-warden` |
| Release artifacts | Built and published from `dracon-utilities` |
| Feature surface | This façade repo (and short-name alias) |
| Operational policy | `~/.dracon/utilities/` TOML files |
| Shared libraries | Sibling `dracon-libs` workspace where applicable |

## Maintenance

When the monorepo changes the utility README, blueprint, or example config,
regenerate this façade with:

```bash
cd /path/to/dracon-utilities
./scripts/scaffold_feature_repos.py --apply --repo dracon-warden
./scripts/scaffold_feature_repos.py --push-all-remotes --repo dracon-warden \
    --ssh-target /path/to/dracon-warden-secret-encrypt-age-git-filter
```

Do not paste implementation code into this façade repo. Keep it as a stable
navigation and feature surface so the monorepo remains the single source of
truth.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
