"""Lasting and deferred effects, the policy pin, and request-bound approvals.

Each test reproduces a scenario in which a Restricted Sequence could be
realized, or the PDP would misbehave, without the rule it pins, and fails on
code that lacks that rule.
"""

from __future__ import annotations

import io
import json
import threading
import time
from dataclasses import replace

import pytest

from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import (
    HistoryUnavailable,
    MissionHistoryService,
    OutcomeAlreadySet,
    PolicyMismatch,
    UnauthenticatedWriter,
    UnknownAct,
)
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import CompositionDenied, EffectPending, ReferencePEP
from authzen_composition.types import (
    REASON_HISTORY_PENDING,
    REASON_HISTORY_UNAVAILABLE,
    REASON_POLICY_MISMATCH,
    REASON_PROHIBITED_COMPOSITION,
    Action,
    EvaluationRequest,
    EvaluationsSemantic,
    Mission,
    Resource,
    Subject,
)

ISSUER = "https://missions.example"  # the issuer of every Mission here
ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

PD = frozenset({"pd.salary"})


def _req(action: str, res: str, *, agent: str = "a", props: dict | None = None,
         ctx: dict | None = None) -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject("agent", agent), action=Action(action, props or {}),
        resource=Resource("r", res), mission=Mission("m", ISSUER),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",), context=ctx or {},
    )


def _run(pdp: CompositionPDP, mhs: MissionHistoryService, action: str, res: str,
         classes: frozenset[str] = frozenset(), *, finish: bool = True) -> bool:
    """Evaluate, admit and complete. Returns whether it was permitted."""
    d = pdp.evaluate(_req(action, res))
    if d.decision and d.obligations:
        seq = d.obligations[0].properties["expected_seq"]
        mhs.admit("m", seq, action, res, writer="w")
        if finish:
            mhs.set_outcome("m", seq, ActOutcome.COMPLETED, writer="w", result_classes=classes)
    return d.decision


# --- 1. Persistent effects: the order-sensitive analogue of a reusable token ---
#
# A public share link created FIRST stays live. Reading salary data and then
# writing it into the shared document realizes "read, write, share" in effect
# order although the share Act came first.

LINK = RestrictedSequence("link", (
    SequenceStep("read", result_classes=frozenset({"pd.*"})),
    SequenceStep("write", resources=frozenset({"doc/*"})),
    SequenceStep("share_public", resources=frozenset({"doc/*"}), persistent=True),
))


def _link_pdp() -> tuple[CompositionPDP, MissionHistoryService]:
    mhs = MissionHistoryService()
    return CompositionPDP(CompositionPolicy((LINK,)), mhs, access_request_endpoint=ARS), mhs


def test_write_after_read_is_denied_when_a_share_link_is_already_live() -> None:
    pdp, mhs = _link_pdp()
    assert _run(pdp, mhs, "share_public", "doc/q4")
    assert _run(pdp, mhs, "read", "hr/salaries", PD)
    d = pdp.evaluate(_req("write", "doc/q4"))
    assert (d.decision, d.reason) == (False, REASON_PROHIBITED_COMPOSITION)


def test_link_created_between_read_and_write_is_caught_too() -> None:
    pdp, mhs = _link_pdp()
    assert _run(pdp, mhs, "read", "hr/salaries", PD)
    assert _run(pdp, mhs, "share_public", "doc/q4")
    assert not pdp.evaluate(_req("write", "doc/q4")).decision


def test_persistent_step_in_its_written_position_still_completes_it() -> None:
    pdp, mhs = _link_pdp()
    assert _run(pdp, mhs, "read", "hr/salaries", PD)
    assert _run(pdp, mhs, "write", "doc/q4")
    assert not pdp.evaluate(_req("share_public", "doc/q4")).decision


def test_persistence_does_not_block_the_safe_order() -> None:
    # Writing before reading puts no salary data behind the link.
    pdp, mhs = _link_pdp()
    assert _run(pdp, mhs, "share_public", "doc/q4")
    assert _run(pdp, mhs, "write", "doc/q4")
    assert _run(pdp, mhs, "read", "hr/salaries", PD)


def test_without_the_persistent_flag_the_early_link_is_missed() -> None:
    # Documents why the flag exists: the plain predicate is order-faithful and
    # so, by itself, allows the link-first order.
    plain = RestrictedSequence("link", tuple(
        SequenceStep(s.action, s.resources, s.result_classes) for s in LINK.steps))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((plain,)), mhs, access_request_endpoint=ARS)
    assert _run(pdp, mhs, "share_public", "doc/q4")
    assert _run(pdp, mhs, "read", "hr/salaries", PD)
    assert _run(pdp, mhs, "write", "doc/q4")


def test_failed_persistent_act_has_no_lasting_effect() -> None:
    pdp, mhs = _link_pdp()
    d = pdp.evaluate(_req("share_public", "doc/q4"))
    mhs.admit("m", 1, "share_public", "doc/q4", writer="w")
    mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w")
    assert d.decision
    assert _run(pdp, mhs, "read", "hr/salaries", PD)
    assert _run(pdp, mhs, "write", "doc/q4")


def test_persistent_digest_differs_from_plain() -> None:
    plain = RestrictedSequence("link", tuple(
        SequenceStep(s.action, s.resources, s.result_classes) for s in LINK.steps))
    assert CompositionPolicy((LINK,)).digest != CompositionPolicy((plain,)).digest


# --- 2. Deferred effects: an accepted call is not a completed effect ---------

RWS = RestrictedSequence("exfil", (
    SequenceStep("read", result_classes=frozenset({"pd.*"})),
    SequenceStep("write"),
    SequenceStep("send"),
))


def test_queued_send_keeps_its_act_open_until_the_effect_lands() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((RWS,)), mhs, access_request_endpoint=ARS)
    mail = ReferencePEP(pdp, mhs, "mail")
    hr = ReferencePEP(pdp, mhs, "hr", classifier=lambda a, r, raw: PD)

    def enforce(pep: ReferencePEP, action: str, res: str, perform):  # noqa: ANN001
        return pep.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                           action=Action(action), resource=Resource("r", res), perform=perform)

    queued = enforce(mail, "send", "press", lambda: EffectPending(handle="job-1"))
    assert isinstance(queued, EffectPending)
    assert mhs.history("m")[0].outcome is ActOutcome.OPEN
    # While the queued send has not gone out, the read is held back.
    with pytest.raises(CompositionDenied) as exc:
        enforce(hr, "read", "hr/salaries", lambda: "rows")
    assert exc.value.reason == REASON_HISTORY_PENDING
    # The send goes out; only then may the read run, and its data can no
    # longer reach that send.
    mail.effect_landed(queued, "send", "press", "delivered")
    assert mhs.history("m")[0].outcome is ActOutcome.COMPLETED
    assert enforce(hr, "read", "hr/salaries", lambda: "rows") == "rows"


def test_cancelled_deferred_effect_is_recorded_failed() -> None:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((RWS,)), mhs, access_request_endpoint=ARS)
    mail = ReferencePEP(pdp, mhs, "mail")
    queued = mail.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                          action=Action("send"), resource=Resource("r", "press"),
                          perform=lambda: EffectPending())
    assert isinstance(queued, EffectPending)
    mail.effect_cancelled(queued)
    assert mhs.history("m")[0].outcome is ActOutcome.FAILED


@pytest.mark.parametrize("outcome", [ActOutcome.COMPLETED, ActOutcome.FAILED])
def test_a_deferred_effect_that_settles_before_perform_returns_is_recorded(
        outcome: ActOutcome) -> None:
    # The resource's completion callback can run before perform has returned
    # the handle: its outcome is still recorded for this Act.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((RWS,)), mhs, access_request_endpoint=ARS)
    mail = ReferencePEP(pdp, mhs, "mail")
    handle = EffectPending(handle="job-1")

    def perform() -> EffectPending:
        if outcome is ActOutcome.COMPLETED:
            mail.effect_landed(handle, "send", "press", "delivered")
        else:
            mail.effect_cancelled(handle)
        return handle

    queued = mail.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                          action=Action("send"), resource=Resource("r", "press"),
                          perform=perform)
    assert queued is handle and (handle.mission_id, handle.seq) == ("m", 1)
    assert mhs.history("m")[0].outcome is outcome
    assert mail.refused == [] and mail.unreported == []


# --- 3. The set of Restricted Sequences is fixed for the Mission ------------

RS = RestrictedSequence("rs", (SequenceStep("read"), SequenceStep("send")))


def test_policy_change_mid_mission_is_refused_not_applied_to_a_partial_history() -> None:
    # Under v1 the read matches no step: it is permitted with no obligation and
    # never admitted. A v2 PDP that added (read, send) would see an empty
    # history and permit the send.
    mhs = MissionHistoryService()
    v1 = CompositionPDP(CompositionPolicy(()), mhs, access_request_endpoint=ARS)
    v2 = CompositionPDP(CompositionPolicy((RS,)), mhs, access_request_endpoint=ARS)
    assert _run(v1, mhs, "read", "hr/salaries")
    d = v2.evaluate(_req("send", "press"))
    assert (d.decision, d.reason) == (False, REASON_POLICY_MISMATCH)


def test_replica_with_a_different_set_cannot_decide_mid_rollout() -> None:
    # Replica B lacks the sequence, so it would not apply rule 5 to the open
    # send that replica A admitted.
    mhs = MissionHistoryService()
    a = CompositionPDP(CompositionPolicy((RS,)), mhs, access_request_endpoint=ARS)
    b = CompositionPDP(CompositionPolicy(()), mhs, access_request_endpoint=ARS)
    assert _run(a, mhs, "send", "press", finish=False)
    d = b.evaluate(_req("read", "hr/salaries"))
    assert (d.decision, d.reason) == (False, REASON_POLICY_MISMATCH)
    # Replica A, holding the pinned set, still decides (and holds it back).
    assert a.evaluate(_req("read", "hr/salaries")).reason == REASON_HISTORY_PENDING


def test_policy_mismatch_in_a_batch_fails_closed() -> None:
    mhs = MissionHistoryService()
    CompositionPDP(CompositionPolicy((RS,)), mhs,
                   access_request_endpoint=ARS).evaluate(_req("read", "x"))
    other = CompositionPDP(CompositionPolicy(()), mhs, access_request_endpoint=ARS)
    (d,) = other.evaluate_batch((_req("read", "x"),)).evaluations
    assert (d.decision, d.reason) == (False, REASON_POLICY_MISMATCH)


def test_same_set_on_every_replica_is_accepted() -> None:
    mhs = MissionHistoryService()
    a = CompositionPDP(CompositionPolicy((RS,)), mhs, access_request_endpoint=ARS)
    b = CompositionPDP(CompositionPolicy((RS,)), mhs, access_request_endpoint=ARS)
    assert _run(a, mhs, "read", "x")
    assert b.evaluate(_req("send", "y")).reason == REASON_PROHIBITED_COMPOSITION


def test_pin_is_per_mission() -> None:
    mhs = MissionHistoryService()
    mhs.history("m1", policy="sha256:a")
    assert mhs.history("m2", policy="sha256:b") == []
    assert mhs.policy_of("m1") == "sha256:a"
    with pytest.raises(PolicyMismatch):
        mhs.history("m1", policy="sha256:b")


def test_policy_digest_is_stable_and_order_insensitive_within_a_step() -> None:
    a = RestrictedSequence("s", (SequenceStep("read", frozenset({"x", "y"})), SequenceStep("send")))
    b = RestrictedSequence("s", (SequenceStep("read", frozenset({"y", "x"})), SequenceStep("send")))
    assert CompositionPolicy((a,)).digest == CompositionPolicy((b,)).digest
    assert CompositionPolicy((a,)).digest.startswith("sha256:")
    c = RestrictedSequence("s", (SequenceStep("read"), SequenceStep("send")), requestable=True)
    d = RestrictedSequence("s", (SequenceStep("read"), SequenceStep("send")))
    assert CompositionPolicy((c,)).digest != CompositionPolicy((d,)).digest


# --- 4. Batch fails closed when history cannot be read -----------------------

class _Down(MissionHistoryService):
    def history(self, mission_id: str, policy: str | None = None) -> list[Act]:
        raise HistoryUnavailable("down")


def test_batch_with_unreadable_history_denies_instead_of_raising() -> None:
    pdp = CompositionPDP(CompositionPolicy((RS,)), _Down(), access_request_endpoint=ARS)
    out = pdp.evaluate_batch((_req("read", "x"), _req("send", "y")))
    assert [(d.decision, d.reason) for d in out.evaluations] == [
        (False, REASON_HISTORY_UNAVAILABLE), (False, REASON_HISTORY_UNAVAILABLE)]


def test_deny_on_first_deny_stops_at_an_unreadable_history() -> None:
    # The fail-closed denial is a denial like any other: under
    # deny_on_first_deny nothing after it is evaluated.
    pdp = CompositionPDP(CompositionPolicy((RS,)), _Down(), access_request_endpoint=ARS)
    out = pdp.evaluate_batch((_req("read", "x"), _req("send", "y")),
                             semantic=EvaluationsSemantic.DENY_ON_FIRST_DENY)
    assert [(d.decision, d.reason) for d in out.evaluations] == [
        (False, REASON_HISTORY_UNAVAILABLE)]


# --- 5. An approval covers the request a person approved, nothing else ------

RSQ = RestrictedSequence("rsq", (SequenceStep("read"), SequenceStep("send")), requestable=True)


def _approved_setup() -> tuple[CompositionPDP, dict]:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((RSQ,)), mhs, access_request_endpoint=ARS)
    assert _run(pdp, mhs, "read", "hr/1")
    d = pdp.evaluate(_req("send", "press", props={"attachment": "doc/public-faq"}))
    assert d.evaluation_id is not None
    return pdp, pdp.approve(d.evaluation_id)


def test_approval_does_not_cover_a_changed_attachment() -> None:
    pdp, apr = _approved_setup()
    d = pdp.evaluate(_req("send", "press", props={"attachment": "doc/salaries"},
                          ctx={"approval": apr}))
    assert (d.decision, d.reason) == (False, REASON_PROHIBITED_COMPOSITION)


def test_approval_does_not_cover_another_agent() -> None:
    pdp, apr = _approved_setup()
    d = pdp.evaluate(_req("send", "press", agent="b", props={"attachment": "doc/public-faq"},
                          ctx={"approval": apr}))
    assert not d.decision


def test_approval_still_covers_the_exact_request() -> None:
    pdp, apr = _approved_setup()
    d = pdp.evaluate(_req("send", "press", props={"attachment": "doc/public-faq"},
                          ctx={"approval": apr}))
    assert d.decision


def test_approval_covers_the_same_properties_in_another_member_order() -> None:
    # JSON members are unordered: the same properties sent again in another
    # order are the request the person approved.
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((RSQ,)), mhs, access_request_endpoint=ARS)
    assert _run(pdp, mhs, "read", "hr/1")
    d = pdp.evaluate(_req("send", "press", props={"attachment": "doc/faq", "priority": "low"}))
    assert d.evaluation_id is not None
    apr = pdp.approve(d.evaluation_id)
    again = pdp.evaluate(_req("send", "press", props={"priority": "low", "attachment": "doc/faq"},
                              ctx={"approval": apr}))
    assert again.decision


def test_a_missing_opt_in_is_a_plain_deny_even_with_an_approval() -> None:
    # A PEP that has not adopted mission_record gets the plain core deny for
    # an Act that needs it, approval or not: no reason, no obligation, and no
    # ARAP next_action (it cannot act on any permit for this Act).
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((RSQ,)), mhs, access_request_endpoint=ARS)
    req = replace(_req("read", "hr/1", ctx={"approval": {"id": "apr_any"}}),
                  supported_mandatory_extensions=(), supported_obligations=())
    d = pdp.evaluate(req)
    assert (d.decision, d.reason, d.obligations, d.context) == (False, None, (), {})


# --- 6. A long Mission stays evaluable ---------------------------------------

def test_one_evaluation_over_10k_acts_and_50_sequences_is_fast() -> None:
    seqs = tuple(
        RestrictedSequence(f"s{i}", (
            SequenceStep(f"a{i}", result_classes=frozenset({"pd.*"})),
            SequenceStep(f"b{i}"), SequenceStep(f"c{i}", persistent=bool(i % 2))))
        for i in range(50))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy(seqs), mhs, access_request_endpoint=ARS)
    for n in range(1, 10_001):
        mhs.admit("m", n, "noise", "r", writer="w")
        mhs.set_outcome("m", n, ActOutcome.COMPLETED, writer="w",
                        result_classes=frozenset({"public"}))
    start = time.perf_counter()
    pdp.evaluate(_req("c3", "r"))
    # Well under a second on a laptop (the candidate matches one sequence; the
    # binding document gives the worst case); the ceiling only guards against a quadratic
    # regression, with room for a loaded CI machine.
    assert time.perf_counter() - start < 10.0


# --- 7. Stranded Open Acts: liveness without hiding anything -----------------

def test_operator_closes_a_stranded_act_at_the_top_never_as_failed() -> None:
    mhs = MissionHistoryService(operators=frozenset({"ops"}))
    pdp = CompositionPDP(CompositionPolicy((RWS,)), mhs, access_request_endpoint=ARS)
    assert _run(pdp, mhs, "read", "hr/1", finish=False)  # PEP crashed: open forever
    assert pdp.evaluate(_req("read", "hr/2")).decision  # same single step: allowed
    assert pdp.evaluate(_req("write", "d")).reason == REASON_HISTORY_PENDING
    closed = mhs.close_stranded("m", 1, operator="ops")
    assert (closed.outcome, closed.result_classes) == (ActOutcome.COMPLETED, frozenset())
    # Released from rule 5, and still counted at the top: the write may run,
    # and a send after it is a prohibited composition.
    assert _run(pdp, mhs, "write", "d")
    assert pdp.evaluate(_req("send", "x")).reason == REASON_PROHIBITED_COMPOSITION


def test_only_an_operator_may_close_and_only_an_open_act() -> None:
    mhs = MissionHistoryService(operators=frozenset({"ops"}))
    mhs.admit("m", 1, "read", "r", writer="w")
    for who in ("", "w", "agent"):
        with pytest.raises(UnauthenticatedWriter):
            mhs.close_stranded("m", 1, operator=who)
    with pytest.raises(UnknownAct):
        mhs.close_stranded("m", 2, operator="ops")
    with pytest.raises(UnknownAct):
        mhs.close_stranded("m", 0, operator="ops")
    mhs.close_stranded("m", 1, operator="ops")
    with pytest.raises(OutcomeAlreadySet):
        mhs.close_stranded("m", 1, operator="ops")
    # The admitting PEP's late report of a different outcome is rejected.
    with pytest.raises(OutcomeAlreadySet):
        mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w")


# --- 8. HTTP binding carries the pin ------------------------------------------

def _get(app, query: str) -> tuple[str, dict]:  # noqa: ANN001
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/missions/m/acts", "QUERY_STRING": query,
           "wsgi.input": io.BytesIO(b""), "HTTP_AUTHORIZATION": "Bearer t"}
    got: dict = {}
    body = b"".join(app(env, lambda s, h: got.update(s=s)))
    return got["s"], json.loads(body)


def test_http_read_pins_and_refuses_another_policy() -> None:
    mhs = MissionHistoryService()
    app = MHSHttpApp(mhs, StaticTokenAuthenticator({"t": "pdp"}), pdps=frozenset({"pdp"}))
    assert _get(app, "")[0] == "200 OK"  # a read without a pin does not pin
    assert mhs.policy_of("m") is None
    assert _get(app, "policy=sha256%3Aa")[0] == "200 OK"
    assert mhs.policy_of("m") == "sha256:a"
    status, body = _get(app, "policy=sha256%3Ab")
    assert (status, body["reason"]) == ("409 Conflict", "policy_mismatch")
    # The body shape the MHS document gives: an "error" text and the reason.
    assert set(body) == {"error", "reason"} and isinstance(body["error"], str)
    for bad in ("policy=", "policy=a&policy=a"):
        status, body = _get(app, bad)
        assert status == "400 Bad Request"
        assert body == {"error": "policy must be given at most once and be non-empty"}


# --- 9. Two replicas racing to pin a fresh Mission ---------------------------

def test_concurrent_first_reads_pin_exactly_one_set() -> None:
    for _ in range(50):
        mhs = MissionHistoryService()
        pdps = [CompositionPDP(CompositionPolicy((RS,)), mhs, access_request_endpoint=ARS),
                CompositionPDP(CompositionPolicy(()), mhs, access_request_endpoint=ARS)] * 4
        barrier = threading.Barrier(len(pdps))
        reasons: list[str | None] = [None] * len(pdps)

        def go(i: int, barrier: threading.Barrier = barrier,
               reasons: list[str | None] = reasons,
               pdps: list[CompositionPDP] = pdps) -> None:
            barrier.wait()
            reasons[i] = pdps[i].evaluate(_req("read", "x")).reason

        threads = [threading.Thread(target=go, args=(i,)) for i in range(len(pdps))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winner = mhs.policy_of("m")
        for pdp, reason in zip(pdps, reasons, strict=True):
            assert (reason == REASON_POLICY_MISMATCH) is (pdp.policy.digest != winner)


# --- 10. Lasting effects at the edges of a sequence -----------------------------

def test_a_persistent_first_step_is_rejected_with_guidance() -> None:
    # (share, read, write) with share persistent catches nothing extra and
    # misses share-last; the policy is rejected, pointing to (read, write, share).
    with pytest.raises(ValueError, match="first step cannot be persistent"):
        RestrictedSequence("bad", (
            SequenceStep("share_public", persistent=True),
            SequenceStep("read"), SequenceStep("write")))


def test_mark_at_the_last_step_catches_share_first_and_share_last() -> None:
    for order in (("share_public", "read", "write"), ("read", "write", "share_public")):
        pdp, mhs = _link_pdp()
        *before, last = order
        for action in before:
            res = "hr/salaries" if action == "read" else "doc/q4"
            assert _run(pdp, mhs, action, res, PD if action == "read" else frozenset())
        res = "doc/q4"
        assert not pdp.evaluate(_req(last, res)).decision, order


def test_fan_out_admitted_per_target_catches_the_external_member() -> None:
    # A send to a list resolved to its members, one Act per target.
    ext = RestrictedSequence("ext", (
        SequenceStep("read", result_classes=frozenset({"pd.*"})),
        SequenceStep("send", resources=frozenset({"external:*"}))))
    mhs = MissionHistoryService()
    pdp = CompositionPDP(CompositionPolicy((ext,)), mhs, access_request_endpoint=ARS)
    assert _run(pdp, mhs, "read", "hr/salaries", PD)
    assert _run(pdp, mhs, "send", "internal:alice")
    d = pdp.evaluate(_req("send", "external:press@partner.example"))
    assert (d.decision, d.reason) == (False, REASON_PROHIBITED_COMPOSITION)
    # Recording the list itself is what the profile forbids: it would pass.
    assert pdp.evaluate(_req("send", "group:all-hands")).decision


def test_label_domain_is_covered_by_the_digest() -> None:
    a = CompositionPolicy((RS,), label_domain=frozenset({"pd.*"}))
    b = CompositionPolicy((RS,), label_domain=frozenset({"pd.*", "public"}))
    assert len({a.digest, b.digest, CompositionPolicy((RS,)).digest}) == 3
