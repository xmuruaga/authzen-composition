# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The draft builds on specifications that are still moving, so every version names
the revisions it is pinned to.

## [Unreleased]

## [0.2.0] - 2026-10-19

Pinned to ARAP at openid/authzen `6d5380c`, the Obligations Core and the
Extensibility Model at `f097170` (openid/authzen PR #697), and the mission-bound
drafts at `19b65a4`.

### Changed

- The draft is now Draft 1 (dated 2026-10-19).
- The draft, on single-use approvals and retries after a timeout
  (openid/authzen issue #737): an approval is scoped to one position, and admits
  at most one Act because rule 2 admits one there, so it carries no count and
  adds no member a PEP must understand (the Extension checklist says why). The
  draft names its guarantee, at most one admitted Act, beside the three that
  issue distinguishes, and says what each of those would need. A new "Lost
  responses" bullet says what a lost permit, a lost admission acknowledgement
  and a give-up cost, for a PDP that consumes an approval at its first permit
  and for one that does not; "Replicas" says the coordination moves to the
  History Authority's admission. A PDP that could not check an approval's
  status because its status source was unreachable should tell the PEP to
  retry (openid/authzen issue #747).
- The draft, what the approver sees: the earlier Acts at the denied request's
  target, open ones first, with their outcome, and what an open one or one an
  operator may have closed means; an Access Request Service can show this only
  where it shares the PDP's record of the denial. Where an earlier attempt is
  open, or may be one an operator closed, or the history cannot be shown, the
  approval comes from a person. The subject and the current actor, wherever the
  request carries it, are not eligible approvers. Privacy considerations say
  what the approver is shown.
- The draft, PEP rules: a PEP does not send the call of an Act admitted on a
  permit to a request that presented an approval again under its admission
  unless the earlier call had no effect or the resource deduplicates it, and
  never the call of an Act it recorded `failed`; before repeating an Open Act it
  learns the outcome from the resource where it can, `completed` only where the
  resource ties the effect to that call; where it cannot and the resource
  deduplicates by key, it sends the earlier call again under that admission, or
  the repeat with the earlier call's key. Execution Evidence with `outcome`
  `failed` is not proof of non-execution. Rule 3 keys on the approval the
  request presented, which a PEP can observe.
- The draft, ARAP binding: `mission` and `context.actor` are authorization-relevant
  Context; the adoption declarations are capability declarations, which a PDP
  records with the denial and does not list in `binding_context_members`
  (openid/authzen issue #754). An approval is held by the PEP identity the PDP
  authenticates, not by instance.
- The draft, registries: it makes no request to IANA or to OpenID Foundation
  registries; what it lists is what it would request if the AuthZEN Working
  Group adopts it, with the Working Group as change controller.
- The draft, History Authority item 7: an operator's close says the effect can no
  longer happen, not that it happened. Security considerations: "Repeated
  effects" (an approval bounds admitted Acts, not executions; a key identifies a
  call, not an effect); Open Acts and the order of the checks state rule 5's
  same-single-step exception; Accountability: the History Authority keeps which
  operator closed an Act.
- The draft: a plain deny of check (d) tells an ARAP PEP `none`; open questions
  16 (holding a repeat back) and 17 (a reason for a consumed approval) are new,
  and 5, 10, 11 and 14 are reworded; the mission-bound drafts are read at
  `19b65a4`, and Related work cites the runtime evidence draft's Cross-Entry
  Correspondence.
- Reference: the Access Request Service shows an eligible approver the earlier
  attempts at the target, never the task's result (`review`, and `GET` on the
  approval task over HTTP); it refuses a submission whose `binding_token` it
  cannot verify, even beside a valid `evaluation_id`; the PDP denies any failure
  to read a history as `history_unavailable` without failing a batch, and tells
  a PEP `none` after a plain deny; the History Authority keeps the operator that
  closed an Act, and flags with `"no_act": true` an outcome conflict for a
  position that holds no Act of the admission named (still `outcome_conflict`,
  as in 0.1.0); the PEP keeps the `failed` of an admission it gave up on, so
  refused, in `abandoned` rather than as an incident; the HTTP clients check an
  answer's nesting before parsing it, as the bindings check a request's, so a
  deeply nested answer is unavailable on every platform.
- Tests: a race test exercises the History Authority's lock; a PDP that
  does not consume an approval at its first permit is tested; an approved Act
  that loses the admission race needs a new approval; the PEP makes one call per
  admission; the approver view, the approver bar with the actor in
  `context.actor`, and a given-up admission whose position was taken.

## [0.1.0] - 2026-10-16

Initial public release. Pinned to ARAP at openid/authzen `6d5380c`, the
Obligations Core and the Extensibility Model at `f097170` (openid/authzen PR
#697), and the mission-bound drafts at `e6c8042`.

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
