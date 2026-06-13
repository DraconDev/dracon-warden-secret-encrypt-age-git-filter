# Dracon Warden

Git filter encryption and repository hardening for Dracon workspaces.

This repository is a GitHub feature façade for dracon-warden. It does **not**
duplicate the implementation code. The canonical source of truth remains the
[`DraconDev/dracon-utilities`](https://github.com/DraconDev/dracon-utilities)
monorepo, with this utility's code and docs under:

- Source: [`dracon-warden/`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden)
- User guide: [`dracon-warden/README.md`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden/README.md)
- Design notes: [`dracon-warden/BLUEPRINT.md`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden/BLUEPRINT.md)
- Example config: [`dracon-warden/dracon-warden.example.toml`](https://github.com/DraconDev/dracon-utilities/tree/main/dracon-warden/dracon-warden.example.toml)

## Purpose

Encrypts secret-shaped content at rest in git while preserving normal plaintext files in the working tree.

Use this repo to feature the utility on GitHub without splitting the actual
implementation out of the monorepo. Issues, project boards, and roadmap notes can
live here, while commits, releases, tests, and packaging stay anchored in
`dracon-utilities`.

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
| GitHub feature surface | This façade repo |
| Operational policy | `~/.dracon/utilities/` TOML files |
| Shared libraries | Sibling `dracon-libs` workspace where applicable |

## Maintenance

When the monorepo changes the utility README, blueprint, or example config,
regenerate this façade with:

```bash
cd /path/to/dracon-utilities
./scripts/scaffold_feature_repos.py --apply --repo dracon-warden
```

Do not paste implementation code into this façade repo. Keep it as a stable
navigation and feature surface so the monorepo remains the single source of
truth.

## License

AGPL-3.0-only — see [LICENSE](LICENSE).
