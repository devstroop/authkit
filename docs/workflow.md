# Workflow Guide

This guide describes how work moves from an idea to `develop`, and from `develop` to `main`. It covers reviews, merge strategy, release promotion, hotfixes, and the shared worktree setup. For local commands, see the [development guide](development.md). For commit and contribution expectations, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Branch and release flow

```text
idea / bug / RFC
       |
       v
issue or RFC discussion
       |
       v
feat/* or fix/* branch  --->  pull request  --->  develop
                                                   |
                                                   v
                                     promotion pull request
                                                   |
                                                   v
                                                  main
                                                   |
                                                   v
                                         annotated release tag
```

Emergency path:

```text
incident or urgent defect
       |
       v
fix/* branch from main -> pull request to main -> main
                                              |
                                              v
                              merge main back into develop
                              and publish a patch release
```

Principles:

- `develop` is the integration branch. All normal work lands there first.
- `main` is the release branch. It should always represent an accepted release state.
- Neither branch accepts direct pushes from contributors. Maintainers use reviewed pull requests, including for promotions and hotfixes.
- Every change has a clear owner, a linked issue or RFC, and a reviewable rationale.
- Security and conduct matters use private channels; see [SECURITY.md](../SECURITY.md) and [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md).

## Issue to branch

1. **Check for an existing issue or RFC.** Search open and closed issues. If the problem is already tracked, add context there instead of starting a parallel effort.
2. **Choose the right entry point.** Use a bug report for a reproducible defect, a feature request for a bounded improvement, and an RFC for a significant or hard-to-reverse decision. The RFC threshold is defined in [GOVERNANCE.md](../GOVERNANCE.md#rfc-and-adr-process).
3. **Agree on scope.** A maintainer confirms the approach or asks for an RFC before implementation. Security reports must never be opened as public issues.
4. **Create a branch from current `develop`:**

   ```sh
   git fetch origin
   git switch develop
   git pull --ff-only
   git switch -c feat/<slug>
   ```

   Use `feat/<slug>` for features and non-corrective work, and `fix/<slug>` for defects. Use lowercase kebab-case. Only an emergency hotfix starts from `main`.

5. **Work in a dedicated worktree when needed.** Each branch should have one worktree, and each worktree should contain one branch.

## Branch to pull request

Before opening the pull request:

- rebase on `origin/develop` and resolve conflicts locally;
- make sure commits are focused and messages follow Conventional Commits;
- run formatting, linting, unit tests, integration tests, and documentation checks relevant to the change;
- add or update tests for new behavior and regressions;
- update configuration examples and documentation in the same change;
- review the diff for secrets, personal data, debug output, local paths, generated files, and `target`/`node_modules` symlinks;
- ensure the pull request does one logical thing.

Open the pull request against `develop`. The title must follow Conventional Commits because it becomes the squash commit. Link the issue with `Closes #<number>` or use `Refs #<number>` when the change is only part of a larger effort. Describe the problem, the approach, alternatives considered, testing performed, and any migration or operational impact.

Draft pull requests are appropriate for early feedback. Do not request final review until the branch is rebased, CI is green, and known review comments are addressed.

## Review checklist

Reviewers should verify:

**Scope and design**

- The change solves the linked problem without unrelated cleanup.
- The design matches the architecture and any accepted RFC or ADR.
- Public behavior, configuration, and compatibility changes are documented.
- A simpler alternative was considered when the change adds abstraction or dependencies.

**Correctness**

- Error paths fail closed and return useful, non-sensitive errors.
- Authorization is checked at the boundary that owns the resource, not inferred from a caller.
- Input validation, output escaping, redirect validation, cookie attributes, and CSRF protections are appropriate for the flow.
- Session and token changes handle expiry, revocation, rotation, replay, and concurrent use.
- Migrations are additive where possible, tested on SQLite and PostgreSQL, and do not rewrite applied history.
- The change behaves correctly under retries, partial failure, and concurrent requests where relevant.

**Tests**

- New behavior has direct coverage, including failure cases.
- Regression tests reproduce the reported defect.
- Storage tests exercise both supported databases where behavior differs.
- Security-sensitive logic has negative tests for unauthorized, expired, revoked, malformed, and cross-account inputs.

**Security and privacy**

- No credentials, tokens, keys, personal data, or exploit details are introduced into logs, errors, fixtures, or screenshots.
- New dependencies are necessary, maintained, license-compatible, and free of known critical vulnerabilities.
- Security-sensitive changes receive the review required by [GOVERNANCE.md](../GOVERNANCE.md#security-sensitive-changes).
- Threat model or abuse cases are described when the change affects authentication or authorization.

**Operations and UI**

- Configuration changes have safe defaults and are documented.
- Logging, metrics, and error messages are actionable without leaking sensitive values.
- UI changes work with JavaScript disabled for core flows, are keyboard accessible, and preserve visible focus and sensible error states.
- Accessibility, layout, and copy changes include screenshots or a clear manual test note.

**Repository hygiene**

- The pull request targets the correct base branch.
- The title follows Conventional Commits.
- CI is green, and any skipped or flaky check is explained.
- Generated caches, local databases, symlinks, and editor files are not included.

At least one maintainer must approve before merge. Security-sensitive changes need the additional review described in governance. Authors should not merge their own changes without maintainer approval.

## Merge strategy

| Change | Target | Strategy |
| --- | --- | --- |
| Feature, fix, docs, tests, or tooling pull request | `develop` | Squash merge; use the Conventional Commit pull request title |
| Release promotion | `main` | Merge commit (`--no-ff`) to preserve the release boundary, then tag |
| Hotfix | `main` | Squash merge, then back-merge `main` into `develop` and tag a patch release |

Squash merging keeps `develop` readable: one reviewed pull request becomes one commit. The pull request title is the commit subject, so it must describe the user-visible effect.

Do not rebase or force-push `develop` or `main`. Do not rewrite public history or move release tags. If a merge produces a broken state, revert through a reviewed pull request or ship a forward fix.

Delete the source branch after merge unless it is needed for a coordinated release or security follow-up. Remove its worktree once there is no uncommitted work.

## Release promotion

Only maintainers promote `develop` to `main`. A promotion is not a normal feature pull request and must be treated as a release.

The release manager:

1. confirms `develop` is current, reviewed, and green on the exact commit to promote;
2. checks that all intended changes are present and that no unintended commits are included;
3. prepares release notes covering features, fixes, breaking changes, security fixes, migrations, and configuration changes;
4. verifies migration order and upgrade notes against both supported databases;
5. runs the security review requirements for any security-sensitive change included in the release;
6. opens a pull request from `develop` to `main`, describing the version and release scope;
7. obtains the required maintainer approval and merges with a merge commit;
8. tags the resulting merge commit on `main` with an annotated semantic version tag;
9. builds and publishes artifacts from the tagged commit, using the project's approved build process;
10. verifies the published artifacts and release notes, then synchronizes `develop` with `main` so the next cycle starts from the release commit.

Promotion must not bypass failing checks. If a check is broken or unavailable, the release manager records why the release is still safe and what verification was performed manually. Security fixes should not be described in public release notes before coordinated disclosure.

The project follows Semantic Versioning once stable releases exist. Before version 1.0, breaking changes are allowed in minor releases but must be called out. No release cadence or support window is promised by this workflow.

## Hotfix path

Use the hotfix path only when the normal flow cannot deliver a fix quickly enough, or when a security or availability issue affects `main`. A hotfix is still reviewed and tested; urgency changes the priority, not the quality bar.

1. Notify the maintainers privately. For a vulnerability, use the process in [SECURITY.md](../SECURITY.md) and coordinate through a private advisory when needed.
2. Create a branch from the current `main`:

   ```sh
   git fetch origin
   git switch main
   git pull --ff-only
   git switch -c fix/<slug>
   ```

3. Make the smallest safe fix and add a regression test. Do not mix in unrelated cleanup.
4. Open a pull request targeting `main`, clearly marked as a hotfix. Explain impact, affected versions, testing, and rollback.
5. Obtain maintainer review, with the security review required by governance when applicable. Merge the hotfix.
6. Tag a patch release from the updated `main` and publish artifacts from that tag.
7. Merge `main` back into `develop` through a reviewed sync pull request, or fast-forward `develop` when branch protection permits. Do not cherry-pick the same change into `develop`; back-merging preserves the shared commit and avoids divergent fixes.
8. Confirm the fix is present on both branches. If the issue was embargoed, publish the advisory and a safe summary after users can update.

If `main` cannot be released immediately, prefer a contained revert or feature toggle over a broad rewrite. Never commit directly to `main` during an incident.

## Parallel worktrees and shared caches

Worktrees allow several branches to be checked out at once without stashing or copying the repository. Use them for parallel features, a hotfix alongside normal work, or a long-running release check.

```sh
git worktree list
git worktree add ../authkit-worktrees/feat-my-change -b feat/my-change origin/develop
cd ../authkit-worktrees/feat-my-change
./scripts/setup-worktree.sh
```

Rules:

- One branch per worktree. Git prevents the same branch from being checked out twice for good reason.
- Run `scripts/setup-worktree.sh` from the worktree root after creating it. The script derives the shared cache from Git's common directory and links `target` and `node_modules` into that worktree.
- Never commit the symlinks. They are ignored and are local infrastructure, not repository content.
- `cargo clean` affects every worktree sharing the target cache. Avoid it during parallel work.
- Dependency installs affect the shared `node_modules`. Do not run conflicting installs concurrently; coordinate lockfile changes.
- Use `AUTHKIT_CACHE_ROOT` if a task needs an isolated cache. See [development.md](development.md#worktrees-and-shared-caches).
- Remove a worktree after its branch is merged and it is clean: `git worktree remove ../authkit-worktrees/<name>`.
- Do not move or delete the primary checkout while linked worktrees exist. Run `git worktree prune` after manually removing a worktree.

A hotfix worktree is created from `main` rather than `develop`:

```sh
git worktree add ../authkit-worktrees/fix-critical-session -b fix/critical-session origin/main
```

## RFCs and decisions

Significant proposals follow the RFC process in [GOVERNANCE.md](../GOVERNANCE.md#rfc-and-adr-process). In short:

1. open an RFC issue with the project template;
2. discuss the problem, alternatives, security implications, and migration path in public;
3. maintainers accept, defer, or reject it and record the rationale;
4. accepted RFCs become ADRs under `docs/adr/` and are linked from implementation pull requests.

If implementation reveals that the accepted design must change, return to the RFC or ADR rather than silently diverging. Security responses may use a private process and publish a summary after disclosure.

## Documentation and communication

Update the relevant guide whenever behavior, setup, configuration, or process changes. Keep pull request descriptions and issue threads focused so future contributors can reconstruct why a decision was made. Avoid dated announcements and schedules in durable documentation; describe the current process and the decision instead.

When in doubt about flow, ask in the issue before branching. A short scoping conversation is cheaper than a large pull request that cannot be merged.
