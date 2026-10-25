# Scoped audit deliverables and machine-local staging

## Demonstrated conflict

The initial deathrun backlog included PNG generator inputs and curated before /
after evidence under `audit-evidence/ninja-runner-regen-2026-10-23`. Its root
`.gitignore` explicitly includes the file types in those exact subtrees, while
the global Warden machine-local gate rejected everything under audit-evidence.
The generator `scripts/make-visual-fix-plates.py` similarly consumes archived
raw image inputs from an earlier explicitly included run. Treating every audit
subtree as disposable conflicts with committed source/provenance consumers.
Merely unstaging the images would discard no bytes but the daemon would re-add
them, so it would not repair the cause.

## Narrow non-security correction

The rendered pre-commit gate now consults Git's effective ignore result for
each audit path, using NUL-delimited plumbing. Only an effective negation from
the repository ROOT `.gitignore` qualifies. The file pattern must name an
explicit audit subtree with no wildcard parent; exact files and fixed-suffix
file-type globs (for example `*.png`) inside an explicit run/subtree qualify.
Other wildcard spellings such as `*?` and `*.[a-z]*` are rejected: they can
express a blanket exemption despite not being spelled `*` or `*.*`. Blanket `**`, directory-only,
all-file patterns, other runs, other file types, global excludes and absent
rules do not qualify. Stronger scratch, screenshot-cache and machine-state
categories cannot be overridden this way. Secret scanning and the rest of the
hook continue normally. This does not change secret/trust/ownership policies.

`pre_commit_hygiene_honors_scoped_sources_without_skipping_security` protects
included source images with spaces/newlines/non-ASCII names, and negative
cases including another run/type, blanket inclusion, scratch, screenshots,
loop state. A deliberately broken `filter.dracon.required` setting also
proves that audit permission does not short-circuit the later security gate. The retained failing-before run is
`dracon-sync/evidence/fleet-convergence-2026-10-23/checks/fleet-hygiene-scoped-red.log`;
the passing targeted run and full Warden suite are adjacent retained artifacts.
A later adversarial regression reproduced acceptance of blanket-equivalent
file globs before the fixed-suffix restriction. Its failing-before and passing-
after results are `checks/hygiene-blanket-{red,green}.log`. That tightening is
awaiting final qualification/deployment; the prior installed hook must not be
misrepresented as already containing it.
The hook renderer is exercised, not just a string-presence assertion.

## Subsequent deathrun evidence

Later local edits staged eleven small shield-adjudication report, reproduction
script and log files. They were outside the image inclusions and still failed
the same meaningful gate. Journal output on 2026-10-24 identifies every refused
path. The report `shield/VERDICT.md` names the measurement and survival logs;
the scripts make that adjudication reproducible. The convergence repair adds
ELEVEN exact file inclusions plus their parent traversal rule, with a comment
explaining their deliverable role. It does not include the entire shield tree,
change the evidence verdict, alter product assertions, or work on the unrelated
visual feature. Raw matching-rule and real-hook results are being retained in
the fleet evidence. Local source and image bytes remain on disk; publication
remains the daemon's responsibility.

## Visual-regression inputs versus frame caches (2026-10-25)

Doomtap's original pre-commit refused `docs/screenshots/baseline/README.md`
and reference images even though the README and visual-regression scripts
identify them as versioned test inputs. The broad `*/screenshots/*` category
cannot distinguish a golden from a regenerable capture. Unstaging these inputs
would neither preserve their versioning intent nor resolve the repeat refusal.

The source hook now recognizes only **exact file inclusions** from the root
`.gitignore` under the root `docs/screenshots/` subtree. Unlike the separate
audit-evidence rule, not even a file-type glob is sufficient here. `!*.png`,
`!docs/screenshots/baseline/*.png`, absent rules and other filenames remain
refused. Root screenshots dumps, nested screenshot caches, scratch, Chrome
captures and `audit-*/screenshots` stay refused even with an exact inclusion.
The original audit policy still refuses generic screenshot caches nested in
an otherwise included audit tree. Security/filter verification still runs.
This is a narrow non-security source-classification correction, not permission
to exempt an entire screenshot tree or to change visual assertions/goldens.

The two new rendered-hook regressions exercise accepted exact reference/README
inputs, reject ten broader/cache cases, and deliberately break the required
security filter after source acceptance to prove that security still refuses.
Retained red/green runs: `dracon-sync/evidence/fleet-idle-convergence-2026-10-25/`
`checks/visual-hygiene-{red,green}.log` (from the parent workspace). Four hygiene
tests pass. Doomtap now explicitly declares 74 names from its unchanged visual
comparison contract (live/reference/diff sets, capture manifest and baseline
README), guarded by two Node regressions. No image or visual tolerance changed.
No live hook has yet been installed for this change; installed original product
gates remain unverified.

The original serial Warden harness subsequently passed 232 unit, 18 integration
and 2 stream tests (`docs/design/fleet-idle-warden-development-tests-serial.log`).
An earlier exploratory parent invocation overrode RUST_TEST_THREADS to2 and
failed the existing shared-PATH counting test (231pass/1fail); its raw log is
retained as `fleet-idle-warden-development-tests.log`. The workspace explicitly
requires serial process-global mock tests in `.cargo/config.toml`; no assertion
was weakened and that override is not the original gate. Component results are
development evidence, not final coherent whole-workspace/release qualification.

## Limits

This policy is about deliberate versioning of curated non-security evidence,
not proof that the evidence's product verdict is correct. A clean hook alone
is not proof of convergence; the fleet goal still requires real commit objects,
before/after remote refs and a matching loaded daemon revision. History is not
rewritten and no exclusion or manual recovery push is introduced.
