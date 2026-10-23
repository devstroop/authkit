# Governance

This document describes how AuthKit makes decisions, who is accountable for them, and how maintainer access changes over time. It is written for a project that intends to be open source and security-sensitive, while acknowledging that AuthKit is still in bootstrap.

Governance is expected to evolve. Changes follow the amendment process at the end of this document. Nothing here creates a promise of support, release cadence, or employment.

## Maintainers

Maintainers are the people accountable for the repository, review quality, releases, security response, and community health. They are listed here and in [`.github/CODEOWNERS`](.github/CODEOWNERS).

The current maintainer list is provisional:

| Maintainer | Areas | Status |
| --- | --- | --- |
| [@akashshah-dev](https://github.com/akashshah-dev) | Bootstrap maintainer for all areas; release and security contact | Placeholder until the initial team is confirmed |

The bootstrap maintainer is also the code owner listed in `CODEOWNERS`. Before public launch, the project must name either a second maintainer or an independent advisor so that no single person is the only reviewer for security-sensitive work and the only handler for conduct reports. GitHub private vulnerability reporting is enabled; the security and conduct addresses are published for fallback use and their delivery is rechecked before each release promotion.

Maintainer responsibilities include:

- reviewing pull requests and protecting the quality and security of `develop` and `main`;
- triaging issues, RFCs, and security reports;
- approving release promotions and signing or attesting release artifacts when the infrastructure exists;
- maintaining CI, branch protection, dependency hygiene, and repository access;
- enforcing the Code of Conduct and handling reports confidentially and without conflicts of interest;
- keeping this document, `CODEOWNERS`, and the security and conduct contacts current;
- documenting significant decisions as ADRs and explaining decisions to contributors.

## Decision-making

The default model is lazy consensus: a proposal is accepted when it has been publicly discussed and no maintainer raises a reasoned objection within the discussion period. Silence is not approval for a significant decision; a maintainer must explicitly record the decision.

Routine changes, such as a focused bug fix or documentation correction, are decided through normal pull request review. Significant decisions require an RFC and an ADR. Significant decisions include changes to:

- public APIs, configuration formats, or compatibility promises;
- the data model, migrations, or storage guarantees;
- the authentication, authorization, session, or token model;
- cryptography, key management, or secret handling;
- cross-cutting architecture, new external dependencies, or deployment infrastructure;
- governance, licensing, or the project name and trademarks;
- anything expensive to reverse or likely to affect existing deployments.

When consensus is not reached:

1. the maintainers summarize the options and tradeoffs in the issue or RFC;
2. maintainers who are not conflicted seek a resolution through discussion;
3. if disagreement remains, active maintainers vote. A quorum is more than half of active maintainers, and a simple majority of votes cast decides the matter;
4. a maintainer with a conflict of interest, including a personal or financial interest, recuses themselves from the decision and the vote.

During bootstrap, if no second maintainer exists, the bootstrap maintainer decides after a public comment period and records the rationale. Decisions about security incidents or conduct reports may be made privately and summarized publicly once doing so is safe.

Decisions are recorded in the relevant issue or pull request. Accepted significant decisions are recorded as ADRs. If a decision was made privately, maintainers publish a summary, affected versions, and mitigation once an embargo ends.

## RFC and ADR process

An RFC is required for significant decisions as defined above. An RFC may also be useful for a proposal that is not yet concrete but affects multiple areas.

1. **Open an RFC issue.** Use the RFC issue template and describe the problem before the solution. Include alternatives, security and privacy implications, operational cost, compatibility, and migration impact.
2. **Discuss in public.** The author revises the proposal in response to questions. Maintainers may ask for prototypes, threat modeling, or coordination with affected contributors.
3. **Decide.** Maintainers accept, defer, or reject the RFC and record the rationale in the issue. Deferred RFCs may be reconsidered when circumstances change.
4. **Record the decision.** An accepted RFC becomes an ADR in `docs/adr/` when that directory is introduced, using the next sequential number and a short kebab-case title. Each ADR contains context, the decision, alternatives considered, consequences, and security considerations.
5. **Link implementation.** Implementation pull requests link the RFC or ADR and note any deviation from it.

ADRs are historical records. They are not rewritten to hide a changed decision; a new ADR supersedes the old one and both remain available. Minor corrections to typos are allowed, and the status line may be updated.

Security responses and embargoed fixes may bypass a public RFC. Maintainers must document the decision and its security rationale once disclosure is safe. Conduct matters are handled under the Code of Conduct rather than the RFC process.

## Release authority

Only maintainers may merge to `main` or create release tags. `main` is protected; direct pushes are not allowed. `develop` is the integration branch and is also protected from unreviewed direct pushes.

A release promotion is a pull request from `develop` to `main`. The promotion requires:

- green required checks on the exact commit being promoted;
- a reviewed diff, including migrations and configuration changes, with release notes or a changelog summary prepared;
- approval from a maintainer other than the author when a second maintainer is available;
- a named release manager accountable for the promotion, version number, and published artifacts;
- completion of the security review requirements below for any security-sensitive change.

Promotions are merged with a merge commit so the release boundary is preserved, then tagged from `main` with an annotated version tag. Release artifacts must be built from the tagged commit. After the promotion, `develop` is synchronized with `main` so subsequent work includes the release commit.

The project intends to follow Semantic Versioning once stable releases exist. Before version 1.0, minor releases may contain breaking changes, but breaking changes must be called out in the pull request and release notes. No release cadence or support window is promised by this document.

A broken release is addressed with a forward fix or a revert through a reviewed pull request. Published tags and release history are not rewritten. Emergency fixes follow the hotfix path in [docs/workflow.md](docs/workflow.md#hotfix-path) and still require maintainer review.

## Security-sensitive changes

A change is security-sensitive if it affects authentication, authorization, session or token issuance and validation, password or credential handling, cryptography, key or secret management, account recovery, redirect and callback validation, rate limiting, security logging, tenancy boundaries, or the handling of personal data.

Security-sensitive changes require:

- a threat model or short security rationale in the pull request, including abuse cases and failure behavior;
- tests for rejection, expiry, replay, revocation, privilege boundaries, and safe error handling where applicable;
- review by a maintainer with security responsibility, plus an independent reviewer for high-risk changes when one is available;
- no unresolved security objection from a reviewing maintainer;
- dependency changes reviewed for provenance, maintenance status, license, and known vulnerabilities;
- no exposure of credentials, tokens, personal data, or exploit details in public logs or discussions before coordinated disclosure.

Embargoed work is coordinated through a private security advisory or another private channel. Maintainers may limit access to issues, pull requests, or branches during an active incident. After disclosure, the fix and an appropriate summary are made public. Report vulnerabilities according to [SECURITY.md](SECURITY.md), not through a public issue.

## Becoming a maintainer

Contributors, reviewers, and maintainers have different levels of responsibility:

- **Contributor:** anyone who participates in issues, RFCs, documentation, or pull requests.
- **Reviewer:** a trusted regular contributor who can help triage and review in a defined area. Reviewers may be nominated by a maintainer and are listed in this document once confirmed.
- **Maintainer:** a person with repository write access, merge responsibility, and a role in releases or security response.

Maintainers are selected for sustained contribution and judgment, not for a single large change. Candidates should demonstrate:

- a track record of useful, well-tested contributions and thoughtful reviews;
- sound technical and security judgment, including willingness to say no or ask for more evidence;
- reliable collaboration and adherence to the Code of Conduct;
- understanding of the project architecture, compatibility expectations, and review process;
- willingness to share the less visible work: triage, documentation, release checks, and security response.

The process is:

1. a maintainer or the candidate raises a nomination with the existing maintainers;
2. maintainers consider public contribution history and may seek feedback from other contributors;
3. the decision requires a two-thirds vote of active maintainers, with conflicts of interest recused;
4. the new maintainer is added to this document and `CODEOWNERS`, and receives the minimum access needed for their responsibilities;
5. onboarding covers two-factor authentication, branch protection, secrets handling, review expectations, release authority, and security response.

During bootstrap, the current maintainer may appoint the initial maintainer team with public notice and an opportunity for objections. All later additions use the process above. Appointment does not grant ownership of the project name, domain, or other assets.

## Maintainer emeritus and removal

A maintainer may step down at any time and be listed as emeritus. Maintainers who have been inactive for a sustained period may be moved to emeritus by the remaining active maintainers after contact and an opportunity to return.

A maintainer may be removed for repeated failure to meet responsibilities, a serious Code of Conduct violation, a security or confidentiality breach, or other conduct that puts the project or its users at risk. Removal requires a two-thirds vote of the other active maintainers, except that access may be suspended immediately by any maintainer when necessary to contain an active security incident, followed by a review. The affected person is given an explanation and an opportunity to respond when safe and appropriate.

## Access, continuity, and open items

Access is granted on the principle of least privilege. Maintainers must use strong authentication, including two-factor authentication on GitHub and any package registry or infrastructure account. Repository secrets, signing keys, deployment credentials, and security report details are never committed and are shared only through an approved secret-management channel. No one may approve their own security-sensitive change.

The following items are open and must be resolved before public launch:

- complete naming and trademark review, including the relationship to WorkOS AuthKit, before publishing packages or promoting the name;
- verify monitored delivery for `security@devstroop.com` and `conduct@devstroop.com`; GitHub private vulnerability reporting is already enabled and verified;
- name a second maintainer or independent advisor for conduct and security review;
- publish a support and release policy;
- enable and verify branch protection, required checks, and repository access controls;
- rehearse the security release and advisory procedure end to end, including a test acknowledgement.

The license decision is resolved: the project is dual-licensed under MIT OR Apache-2.0, as recorded in [ADR-0010](docs/adr/0010-dual-mit-apache-2-0-license.md).

## Amendments

Changes to this document require an RFC and a two-thirds vote of active maintainers. The RFC must be public unless it concerns an active security or conduct matter, in which case a summary is published when safe. Amendments are recorded in the repository history; this document does not use dated versions.
