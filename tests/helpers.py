"""Shared fixtures and helpers for the test suite."""

from __future__ import annotations

from collections.abc import Callable

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import CompositionPolicy
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import ReferencePEP
from authzen_composition.scenarios import Step
from authzen_composition.types import Action, Resource, Subject

ARS = "https://ars.example/requests"  # the deployment's ARAP Access Request Endpoint

SUBJECT = Subject(type="agent", id="agent-7")


def build(policy: CompositionPolicy) -> tuple[CompositionPDP, MissionHistoryService]:
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy=policy, mhs=mhs, access_request_endpoint=ARS)
    return pdp, mhs


def make_pep(
    pdp: CompositionPDP, mhs: MissionHistoryService, writer: str, classes_for: Step | None = None
) -> ReferencePEP:
    def classifier(action: str, resource: str, raw: object) -> frozenset[str]:
        return frozenset(classes_for.result_classes) if classes_for else frozenset()

    return ReferencePEP(pdp=pdp, mhs=mhs, writer_id=writer, classifier=classifier)


def enforce_step(
    pdp: CompositionPDP,
    mhs: MissionHistoryService,
    step: Step,
    mission_id: str = "m1",
    perform: Callable[[], object] | None = None,
) -> object:
    pep = make_pep(pdp, mhs, step.pep, classes_for=step)
    return pep.enforce(
        mission_id=mission_id,
        mission_issuer="https://missions.example",
        subject=SUBJECT,
        action=Action(step.action),
        resource=Resource(type="r", id=step.resource),
        perform=perform or (lambda: "ok"),
    )
