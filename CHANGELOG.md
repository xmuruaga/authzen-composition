# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The draft builds on specifications that are still moving, so every version names
the revisions it is pinned to: ARAP at openid/authzen `6d5380c`, the Obligations
Core and the Extensibility Model at `f097170` (openid/authzen PR #697), and the
mission-bound drafts at `e6c8042`.

## [Unreleased]

## [0.1.0] - 2026-10-16

Initial public release.

### Added

- The AuthZEN Mission Composition Profile, Draft 0
  (`docs/authzen-composition-profile-1_0.md`, rendered as `.txt`): the
  composition predicate, result classes, the History Authority, the five
  ordering rules, the `mission_record` obligation and approvals through ARAP.
- An implementation of the PDP, the PEP, a Mission History Service and ARAP's
  Access Request Service, each with an HTTP binding so they run as separate
  processes (`authzen_composition/`, `docs/mission-history-service.md`).
- A conformance suite at 100% line and branch coverage, with property,
  concurrency, interleaving, differential and exhaustive tests, and a map from
  every requirement to its tests (`docs/TRACEABILITY.md`).
- 46 interop vectors and 2 policy-digest cases, with a verifier to port
  (`interop/`).
- An end-to-end run in separate processes over HTTP, with 19 workflows and
  attacks checked by an oracle, and a false-positive study (`e2e/`).
