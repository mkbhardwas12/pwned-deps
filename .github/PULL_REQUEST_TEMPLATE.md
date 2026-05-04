<!--
Thanks for the PR. Please complete the checklist below.
For new compromised-package campaigns, see CONTRIBUTING.md
§"Adding a new compromised-package campaign".
-->

## What

<!-- One-sentence summary. -->

## Why

<!-- Link the issue / advisory / blog post that motivated this. -->

## Verification

- [ ] `make release-rehearsal` passes locally (safety self-test, lint, 96-test pytest, build, dogfood).
- [ ] No new runtime dependencies, **or** I have opened an issue to discuss the new dependency first.
- [ ] No `eval` / `exec` / `subprocess` / `pickle.load` of input content.
- [ ] No malicious package archives attached anywhere in this PR (patterns and hashes in text only).

## For new campaigns only

- [ ] Entry added to `src/pwned_deps/extras_data/extras.json` with **at least one named-source citation**.
- [ ] Version numbers are **not fabricated**; unconfirmed versions use `TODO(precise-version)`.
- [ ] Fixture lockfile added under `tests/fixtures/<ecosystem>/`.
- [ ] Test asserts exit code `1` and the campaign name in output.

## Notes for reviewer

<!-- Anything else worth flagging — design tradeoffs, open questions, follow-ups. -->
