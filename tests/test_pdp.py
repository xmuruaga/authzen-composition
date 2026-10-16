"""PDP tests: no-mission passthrough, opt-in, batch semantics, fail-closed."""

from __future__ import annotations

from datetime import datetime

import pytest

from authzen_composition.mhs import HistoryUnavailable, MissionHistoryService
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.scenarios import EXFIL_POLICY
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    EvaluationsSemantic,
    Mission,
    Resource,
    Subject,
)

ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

S = Subject("agent", "a")


def _req(action: str, resource: str, mission: str | None = "m1",
         ext=("obligations",)):
    return EvaluationRequest(
        subject=S,
        action=Action(action),
        resource=Resource("r", resource),
        mission=Mission(mission, "iss") if mission else None,
        supported_mandatory_extensions=ext,
        supported_obligations=("mission_record",),
    )


def build():
    mhs = MissionHistoryService()
    return CompositionPDP(EXFIL_POLICY, mhs, access_request_endpoint=ARS), mhs


def test_no_mission_is_core_passthrough() -> None:
    # Without a Mission there is no
    # history to read, so an Act that could fill a step is denied, not passed
    # through; an Act no sequence restricts is still core evaluation.
    pdp, _ = build()
    denied = pdp.evaluate(_req("send_message", "external:x", mission=None))
    assert not denied.decision and denied.reason == "history_unavailable"
    assert pdp.evaluate(_req("list_calendars", "cal:1", mission=None)).decision


def test_opt_in_required_for_extending_permit() -> None:
    pdp, _ = build()
    # read_record extends a prefix; without opt-in -> plain core deny, no reason
    d = pdp.evaluate(_req("read_record", "hr:1", ext=()))
    assert d.decision is False
    assert d.reason is None
    assert d.obligations == ()


def test_unreachable_authority_fails_closed_with_distinct_reason() -> None:

    class DownMHS(MissionHistoryService):
        def history(self, mission_id: str, policy: str | None = None):  # type: ignore[override]
            raise HistoryUnavailable("authority unreachable")

    pdp = CompositionPDP(EXFIL_POLICY, DownMHS(), access_request_endpoint=ARS)
    d = pdp.evaluate(_req("unrelated_action", "x:1"))
    assert d.decision is False
    assert d.reason == "history_unavailable"


def test_requestable_denial_carries_rfc3339_expiry() -> None:

    pdp, mhs = build()
    mhs.admit("m1", 1, "read_record", "hr:1", writer="w")
    mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"personal_data.salary"}))
    mhs.admit("m1", 2, "write_document", "doc:1", writer="w")
    mhs.set_outcome("m1", 2, ActOutcome.COMPLETED, writer="w")
    d = pdp.evaluate(_req("send_message", "external:x"))
    assert d.access_request is not None
    datetime.fromisoformat(d.access_request["expires_at"])  # parses as RFC 3339


def test_permit_attaches_mission_record_obligation() -> None:
    pdp, _ = build()
    d = pdp.evaluate(_req("read_record", "hr:1"))
    assert d.decision
    assert any(o.type == "mission_record" and o.properties["expected_seq"] == 1
               for o in d.obligations)


def test_non_extending_permit_has_no_obligation() -> None:
    pdp, _ = build()
    d = pdp.evaluate(_req("unrelated_action", "x:1"))
    assert d.decision
    assert d.obligations == ()


def test_batch_conflict_denies_all_but_one() -> None:
    pdp, _ = build()
    # Two reads of the same mission, each can start the restricted prefix.
    resp = pdp.evaluate_batch((_req("read_record", "hr:1"), _req("read_record", "hr:2")))
    decisions = resp.evaluations
    assert decisions[0].decision is True
    assert decisions[1].decision is False
    assert decisions[1].reason == "history_conflict"


def test_batch_deny_on_first_deny_short_circuits() -> None:
    pdp, _ = build()
    resp = pdp.evaluate_batch(
        (_req("read_record", "hr:1"), _req("read_record", "hr:2"), _req("read_record", "hr:3")),
        semantic=EvaluationsSemantic.DENY_ON_FIRST_DENY,
    )
    # first permit, second conflict -> stop
    assert len(resp.evaluations) == 2


def test_batch_permit_on_first_permit_short_circuits() -> None:
    pdp, _ = build()
    resp = pdp.evaluate_batch(
        (_req("read_record", "hr:1"), _req("read_record", "hr:2")),
        semantic=EvaluationsSemantic.PERMIT_ON_FIRST_PERMIT,
    )
    assert len(resp.evaluations) == 1


def test_batch_mixes_mission_and_non_mission() -> None:
    pdp, _ = build()
    resp = pdp.evaluate_batch((_req("x", "y", mission=None), _req("read_record", "hr:1")))
    assert resp.evaluations[0].decision
    assert resp.evaluations[1].decision


def test_batch_deny_on_first_deny_breaks_on_mission_denial() -> None:
    pdp, mhs = build()
    # Set up a completed prohibited composition so a send denies.
    mhs.admit("m1", 1, "read_record", "hr:1", writer="w")
    mhs.set_outcome("m1", 1, ActOutcome.COMPLETED, writer="w",
                    result_classes=frozenset({"personal_data.salary"}))
    mhs.admit("m1", 2, "write_document", "doc:1", writer="w")
    mhs.set_outcome("m1", 2, ActOutcome.COMPLETED, writer="w")
    resp = pdp.evaluate_batch(
        (_req("send_message", "external:x"), _req("read_record", "hr:9")),
        semantic=EvaluationsSemantic.DENY_ON_FIRST_DENY,
    )
    assert resp.evaluations[0].decision is False
    assert len(resp.evaluations) == 1


@pytest.mark.parametrize("mission_id, issuer", [
    ("", "https://missions.example"), (None, "https://missions.example"),
    (7, "https://missions.example"), ("m", ""), ("m", 7)])
def test_a_mission_names_a_non_empty_string_id(mission_id: object, issuer: object) -> None:
    # Profile, Request: `mission.id` is a non-empty String, the key of the
    # Mission's history; an empty one would key a history for no Mission. Each
    # case has a valid issuer but for the one it tests, so each fails for its
    # own defect.
    with pytest.raises(ValueError):
        Mission(mission_id, issuer)  # type: ignore[arg-type]


def test_a_mission_needs_an_issuer() -> None:
    # Profile, Request: `mission.issuer` is REQUIRED, as in the mission-bound
    # drafts, so one definition of `mission` serves both.
    with pytest.raises((TypeError, ValueError)):
        Mission("m")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Mission("m", None)  # type: ignore[arg-type]


class _Handing:
    """A History Authority that hands the PDP the Acts it is given."""

    def __init__(self, acts: list) -> None:
        self.acts = acts

    def history(self, mission_id: str, policy: str | None = None) -> list:
        return list(self.acts)


@pytest.mark.parametrize("act", [
    Act(1, "read_record", "hr:1", ActOutcome.FAILED, frozenset({"personal_data.salary"})),
    Act(1, "read_record", "hr:1", ActOutcome.COMPLETED, frozenset({"personal_data.*"})),
    Act(1, "read_record", "hr:1", ActOutcome.COMPLETED, frozenset({""})),
    Act(1, "", "hr:1", ActOutcome.COMPLETED),
], ids=["classes-on-failed", "star-class", "empty-class", "empty-action"])
def test_a_history_with_a_record_no_act_record_allows_is_unavailable(act: Act) -> None:
    # Rule 4: a record outside what an Act Record holds makes the history
    # unusable, whichever History Authority or client handed it over.
    pdp = CompositionPDP(EXFIL_POLICY, _Handing([act]))  # type: ignore[arg-type]
    decision = pdp.evaluate(_req("send_message", "external:press"))
    assert (decision.decision, decision.reason) == (False, "history_unavailable")


def test_a_batch_tells_two_sequences_that_share_a_name_apart() -> None:
    # PDP rules: Acts of different sequences are not denied history_conflict,
    # whatever the sequences are named.
    policy = CompositionPolicy((
        RestrictedSequence("x", (SequenceStep("rd"), SequenceStep("sd"))),
        RestrictedSequence("x", (SequenceStep("wr"), SequenceStep("sh")))))
    pdp = CompositionPDP(policy, MissionHistoryService())
    batch = pdp.evaluate_batch((_req("rd", "r1"), _req("wr", "w1")))
    assert [d.decision for d in batch.evaluations] == [True, True]
