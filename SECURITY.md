# Security Policy

AuthKit is an identity service and is expected to handle credentials, sessions, tokens, and other sensitive data. Security reports are taken seriously even while the project is in planning and pre-release development.

This policy is a starting point. It will be revised before the first public release and whenever the supported deployment model changes.

## Supported versions

No production releases exist yet. The following table is a placeholder until a release and support policy is established.

| Version | Security support |
| --- | --- |
| Unreleased code on `develop` | Best effort only; no support guarantee |
| Released stable versions | To be defined at the first stable release |
| Older or forked versions | Not supported |

Only code on the official repository is covered. Forks, unpublished modifications, and third-party deployments are the responsibility of their operators.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a suspected vulnerability.** Public disclosure before a fix is available puts users at risk.

Use one of these private channels:

1. **GitHub private vulnerability reporting:** [Open a private security advisory](https://github.com/devstroop/authkit/security/advisories/new). This is the preferred channel once it is enabled for the repository.
2. **Email:** `security@devstroop.com`

The email address and advisory link are **placeholders and must be confirmed before public launch**. If neither channel is available, contact a maintainer privately through the contact method listed on their GitHub profile and ask for a secure channel. Do not include exploit details in that initial contact.

Please include, when available:

- the affected commit, version, or deployment configuration;
- the component or flow affected, such as sign-in, sessions, token issuance, account recovery, or an administrative path;
- a clear reproduction or proof of concept, with prerequisites;
- the security impact and what an attacker could achieve;
- relevant logs, requests, or screenshots with secrets and personal data removed;
- whether the issue is already public or known to others;
- your preferred name and contact details for credit, or a request to remain anonymous.

Never send live production credentials, session tokens, private keys, or personal data. Redact sensitive values and use disposable test accounts.

## Scope

In scope:

- authentication, session management, token issuance and validation, account recovery, and authorization boundaries implemented by AuthKit;
- cryptographic usage, secret handling, key management, and configuration defaults defined by the project;
- injection, cross-site scripting, cross-site request forgery, open redirects, request smuggling, and similar web application flaws in project code;
- broken access control, privilege escalation, account takeover, user enumeration with material impact, and insecure defaults;
- vulnerabilities in SQLx migrations or storage logic that affect tenant or account isolation;
- supply-chain or build issues in the project's own repository and release process;
- privacy issues such as sensitive data appearing in logs, error pages, or telemetry.

Out of scope unless the impact is specific to AuthKit:

- vulnerabilities in dependencies that are already reported upstream and do not have a practical AuthKit-specific exploit; report those upstream and notify us if AuthKit needs a mitigation;
- social engineering, phishing, or physical attacks against maintainers or users;
- denial-of-service through unrealistic traffic volumes, unless a small request causes disproportionate resource use;
- spam, automated scanning noise, or reports generated solely by a scanner without a demonstrated impact;
- missing security headers or best-practice configuration with no demonstrated exploit;
- misconfigured self-hosted deployments, unsupported forks, outdated deployments, or operator-controlled infrastructure;
- issues that require an already-compromised host, browser, database, or privileged administrator.

When in doubt, report privately and let maintainers determine scope.

## Response process

Maintainers will make a best-effort effort to:

1. acknowledge the report privately and confirm a secure channel;
2. triage severity, reproducibility, and affected components;
3. ask for additional information when needed and avoid unnecessary collection of sensitive data;
4. prepare and test a fix, including tests that reproduce the issue where practical;
5. coordinate a disclosure plan and publish an advisory with affected versions, impact, and mitigation;
6. credit the reporter by name or handle if they wish.

The project does not guarantee a response time, fix time, bounty, or any particular outcome. Do not disclose the issue publicly, including in a fork or package release, before maintainers confirm that a coordinated disclosure is ready. If a report is declined as out of scope, we will explain why when possible.

Security-sensitive changes follow the additional requirements in [GOVERNANCE.md](GOVERNANCE.md#security-sensitive-changes). For contribution process and branch rules, see [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/workflow.md](docs/workflow.md).

## Good-faith research

We welcome good-faith research that respects privacy, avoids harming users, and gives the project a reasonable opportunity to fix issues before disclosure. Use test accounts and local or disposable deployments. Stop testing and report privately if you encounter real user data, credentials, or a system you do not own or have permission to test.

## Contact

Security contact: `security@devstroop.com`

This address is a placeholder and must be confirmed before public launch. The maintainer team and reporting channels will be reviewed as part of the open items in [GOVERNANCE.md](GOVERNANCE.md#access-continuity-and-open-items).
