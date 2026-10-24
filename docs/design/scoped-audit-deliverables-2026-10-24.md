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
explicit audit subtree with no wildcard parent; exact files and file-type
globs inside an explicit run/subtree qualify. Blanket `**`, directory-only,
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

## Limits

This policy is about deliberate versioning of curated non-security evidence,
not proof that the evidence's product verdict is correct. A clean hook alone
is not proof of convergence; the fleet goal still requires real commit objects,
before/after remote refs and a matching loaded daemon revision. History is not
rewritten and no exclusion or manual recovery push is introduced.
