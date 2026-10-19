"""S1-S12 scenario tests: the profile's behavior, end to end through the PEP."""

from __future__ import annotations

import pytest

from authzen_composition.model import ActOutcome
from authzen_composition.pep import CompositionDenied
from authzen_composition.scenarios import EXFIL_POLICY, Step, all_scenarios
from authzen_composition.types import (
    Action,
    EvaluationRequest,
    Mission,
    Resource,
    Subject,
)
from tests.helpers import build, enforce_step


@pytest.mark.parametrize("scenario", [s for s in all_scenarios() if s.steps])
def test_scenario_steps(scenario) -> None:
    pdp, mhs = build(scenario.policy)
    for step in scenario.steps:
        if step.expect_permit:
            enforce_step(pdp, mhs, step)
        else:
            with pytest.raises(CompositionDenied) as exc:
                enforce_step(pdp, mhs, step)
            assert exc.value.reason == step.expect_reason


def test_s3_omission_defeated_only_because_authority_holds_truth() -> None:
    # S3: a read that WAS enforced is in the MHS and cannot be hidden.
    pdp, mhs = build(EXFIL_POLICY)
    enforce_step(pdp, mhs, _step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)))
    enforce_step(pdp, mhs, _step("pep.doc", "write_document", "doc:q4"))
    with pytest.raises(CompositionDenied):
        enforce_step(pdp, mhs, _step("pep.mail", "send_message", "external:all"))


def test_s5_open_outcome_is_conservative_top() -> None:
    # An admitted-but-unreported read matches a personal_data.* step via the top.
    pdp, mhs = build(EXFIL_POLICY)
    mhs.admit("m1", 1, "read_record", "hr:emp-1", writer="pep.hr")  # left OPEN
    mhs.admit("m1", 2, "write_document", "doc:q4", writer="pep.doc")
    mhs.set_outcome("m1", 2, ActOutcome.COMPLETED, writer="pep.doc")
    req = EvaluationRequest(
        subject=Subject("agent", "a"),
        action=Action("send_message"),
        resource=Resource("mbx", "external:all"),
        mission=Mission("m1", "iss"),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
    )
    decision = pdp.evaluate(req)
    assert decision.decision is False
    assert decision.reason == "prohibited_composition"


def test_s7_crash_after_act_before_record_stays_conservative() -> None:
    # The read is admitted and performed, but the outcome report is lost.
    pdp, mhs = build(EXFIL_POLICY)
    mhs.admit("m1", 1, "read_record", "hr:emp-1", writer="pep.hr")  # outcome never set
    mhs.admit("m1", 2, "write_document", "doc:q4", writer="pep.doc")
    req = _send_request()
    assert pdp.evaluate(req).decision is False


def test_s8_mission_splitting_escapes_only_a_new_mission() -> None:
    # A fresh mission has empty history, so composition does not carry over.
    pdp, mhs = build(EXFIL_POLICY)
    enforce_step(pdp, mhs, _step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)))
    enforce_step(pdp, mhs, _step("pep.doc", "write_document", "doc:q4"))
    # Same acts under a NEW mission id: the send is permitted (empty history).
    enforce_step(pdp, mhs, _step("pep.mail", "send_message", "external:all"), mission_id="m2")


def test_s10_agent_asserted_history_is_ignored() -> None:
    # The agent puts a fake read in the request body/context; the PDP reads only
    # the MHS, which is empty, so the send is permitted.
    pdp, mhs = build(EXFIL_POLICY)
    req = EvaluationRequest(
        subject=Subject("agent", "a"),
        action=Action("send_message"),
        resource=Resource("mbx", "external:all"),
        mission=Mission("m1", "iss"),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
        context={"claimed_history": [{"action": "read_record"}]},
    )
    assert pdp.evaluate(req).decision is True


def test_s12_arap_requestable_denial_then_approval() -> None:
    pdp, mhs = build(EXFIL_POLICY)
    enforce_step(pdp, mhs, _step("pep.hr", "read_record", "hr:emp-1", ("personal_data.salary",)))
    enforce_step(pdp, mhs, _step("pep.doc", "write_document", "doc:q4"))
    req = _send_request()
    decision = pdp.evaluate(req)
    assert decision.decision is False
    assert decision.access_request is not None  # requestable (ARAP)


# --- helpers -------------------------------------------------------------

def _step(pep: str, action: str, resource: str, classes: tuple[str, ...] = ()):
    return Step(pep=pep, action=action, resource=resource, result_classes=classes)


def _send_request(mission_id: str = "m1") -> EvaluationRequest:
    return EvaluationRequest(
        subject=Subject("agent", "a"),
        action=Action("send_message"),
        resource=Resource("mbx", "external:all"),
        mission=Mission(mission_id, "iss"),
        supported_mandatory_extensions=("obligations",),
        supported_obligations=("mission_record",),
    )
