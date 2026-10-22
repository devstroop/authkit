# Pull request

## Summary

Describe the problem and the change. Focus on the effect and why it is needed.

## Related issue or RFC

Closes #

## Type of change

- [ ] Feature
- [ ] Bug fix
- [ ] Documentation
- [ ] Refactor or performance improvement
- [ ] Tests or tooling
- [ ] Build, CI, or dependency change
- [ ] Security-sensitive change
- [ ] Release promotion or hotfix

## What changed

List the key changes and any important design decisions. Link accepted RFCs or ADRs.

## How it was tested

Describe the commands, environments, and scenarios used. Include database types, browser coverage, and manual accessibility checks where relevant.

## Security and data impact

Describe any effect on authentication, authorization, sessions, tokens, secrets, personal data, migrations, or trust boundaries. State "none" when not applicable.

## UI changes

Include before/after screenshots or notes for visible changes. Confirm that core flows work with JavaScript disabled when the change affects the UI.

## Migration and rollout

Describe configuration changes, migrations, compatibility concerns, and rollback steps. State "none" when not applicable.

## Checklist

- [ ] This pull request targets `develop`, or it is an explicitly marked release promotion or hotfix targeting `main`.
- [ ] The title follows Conventional Commits.
- [ ] The change is focused and includes no unrelated work.
- [ ] Tests cover new behavior, failure paths, and regressions.
- [ ] Formatting, linting, tests, and relevant documentation checks pass locally.
- [ ] Storage changes were tested against SQLite and PostgreSQL where behavior differs.
- [ ] Documentation, configuration examples, and cross-links are updated.
- [ ] Security-sensitive changes follow the review requirements in `GOVERNANCE.md`.
- [ ] No secrets, credentials, personal data, or debug output are included.
- [ ] No `target`, `node_modules`, local databases, or generated caches are included.
