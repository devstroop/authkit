# ADR-0010: Dual MIT and Apache-2.0 license

- Status: Accepted
- Deciders: maintainers
- Related: [Product](../product.md), [Open decisions](../open-decisions.md), [README](../../README.md)

## Context

AuthKit is a self-hostable identity service intended for use by organizations and other
open-source projects. The repository contains the MIT and Apache-2.0 license texts and the
workspace already declares `MIT OR Apache-2.0`, but older planning text still described the
license as undecided. Conflicting statements make adoption, contribution, and redistribution
ambiguous.

The common Rust ecosystem convention is a permissive dual license that lets a downstream
user choose either license. MIT is short and familiar; Apache-2.0 adds an explicit patent
grant and trademark language. Offering both avoids forcing one set of terms on every
consumer while keeping contributions inbound under the same terms.

## Decision

AuthKit is licensed under either of:

- the Apache License, Version 2.0 (`LICENSE-APACHE`); or
- the MIT license (`LICENSE-MIT`),

at the user's option. `NOTICE` records the copyright and attribution notice. The Cargo
workspace metadata declares `license = "MIT OR Apache-2.0"`.

Contributions are accepted under the same dual license (inbound = outbound). No separate
contributor license agreement is required. Contributors must have the right to submit the
work under these terms.

The project name and trademark are a separate decision. This ADR does not grant trademark
rights or resolve the naming review.

## Alternatives considered

- **MIT only.** Simple and permissive, but omits the explicit patent grant that some
  organizations require.
- **Apache-2.0 only.** Provides a patent grant, but is more verbose and incompatible with
  some projects that prefer MIT-only terms.
- **A copyleft license.** Rejected for the initial product: it would narrow adoption for a
  self-hosted authentication service and complicate embedding in other applications.
- **Leave the license undecided.** Rejected: it blocks adoption, contribution, and packaging
  and creates legal ambiguity.

## Consequences

- Downstream users choose the license that fits their policy.
- Source files and distributions must carry the license texts and `NOTICE` attribution.
- Dependency review must continue to reject licenses that cannot be combined with this
  choice.
- Changing the license later requires a new ADR and review of existing contributions.

## Security considerations

Licensing does not change runtime behavior, but clear terms make it easier for security
researchers and downstream operators to evaluate, patch, and redistribute the project.
Trademark review remains separate so that the project does not imply endorsement by an
unrelated product.
