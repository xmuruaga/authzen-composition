#!/usr/bin/env python3
"""Replay the interop vectors through the reference PDP and MHS.

Any PDP implementation can port this verifier: for each scenario, admit the
acts in order at the Mission History Service, then assert the final act's
decision matches the vector's ``expect``; for each digest case, compute the
policy digest of the policy as written. Exit non-zero on any mismatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.model import (
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.types import Action, EvaluationRequest, Mission, Resource, Subject

VECTORS = Path(__file__).resolve().parents[0] / "test-vectors" / "composition-vectors.json"
SUBJECT = Subject(type="agent", id="agent-vector")
ACCESS_REQUEST_ENDPOINT = "https://pdp.example/access/v1/requests"


def _flag(value: object, what: str) -> bool:
    # A port that reads "false" as true would make a sequence requestable
    # that its author did not mark so.
    if not isinstance(value, bool):
        raise ValueError(f"{what} must be a JSON boolean")
    return value


def _name(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty string")
    return value


def _patterns(value: object, what: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{what} must be an array of strings")
    return frozenset(value)


def _names(value: object, what: str) -> tuple[str, ...]:
    # A string here would read as one name per character.
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{what} must be an array of strings")
    return tuple(value)


def policy_from_json(spec: dict) -> CompositionPolicy:
    seqs = []
    for s in spec["restricted_sequences"]:
        steps = tuple(
            SequenceStep(
                action=_name(st.get("action"), "action"),
                resources=_patterns(st.get("resources", []), "resources"),
                result_classes=_patterns(st.get("result_classes", []), "result_classes"),
                persistent=_flag(st.get("persistent", False), "persistent"),
            )
            for st in s["steps"]
        )
        seqs.append(RestrictedSequence(_name(s.get("name"), "name"), steps,
                                       requestable=_flag(s.get("requestable", False),
                                                         "requestable")))
    domain = spec.get("label_domain")
    return CompositionPolicy(tuple(seqs),
                             label_domain=None if domain is None
                             else _patterns(domain, "label_domain"))


def run(data: dict) -> list[str]:
    failures: list[str] = []
    for scenario in data["scenarios"]:
        mhs = MissionHistoryService()
        policy = policy_from_json(scenario["policy"])
        # With an Access Request Endpoint, so that a denial can be requestable
        # and `expect_requestable: false` is checked.
        pdp = CompositionPDP(policy, mhs, access_request_endpoint=ACCESS_REQUEST_ENDPOINT)
        mission_id = scenario["id"]
        if policy.digest != scenario["policy_digest"]:
            # The profile defines the digest, so every PDP of a Mission,
            # whatever its implementation, names the same one.
            failures.append(f"{mission_id}: policy digest {policy.digest}, "
                            f"expected {scenario['policy_digest']}")
        acts = scenario["acts"]
        for act in acts[:-1]:
            seq = mhs.next_seq(mission_id)
            mhs.admit(mission_id, seq, act["action"]["name"], act["resource"]["id"], writer="pep")
            outcome = act.get("outcome", "completed")
            if outcome == "completed":
                mhs.set_outcome(
                    mission_id, seq, ActOutcome.COMPLETED, writer="pep",
                    result_classes=frozenset(act["result_classes"]),
                )
            elif outcome == "failed":
                mhs.set_outcome(mission_id, seq, ActOutcome.FAILED, writer="pep")
            # "open": admitted, outcome not reported
        final = acts[-1]
        decision = pdp.evaluate(
            EvaluationRequest(
                subject=SUBJECT,
                action=Action(final["action"]["name"]),
                resource=Resource(type="r", id=final["resource"]["id"]),
                mission=Mission(mission_id, "https://missions.example"),
                # The PEP adopts the Obligations Core and can execute
                # mission_record, unless the vector says otherwise.
                supported_mandatory_extensions=_names(final.get(
                    "supported_mandatory_extensions", ["obligations"]),
                    "supported_mandatory_extensions"),
                supported_obligations=_names(final.get(
                    "supported_obligations", ["mission_record"]), "supported_obligations"),
            )
        )
        got = "permit" if decision.decision else "deny"
        if got != final["expect"]:
            failures.append(f"{mission_id}: expected {final['expect']}, got {got}")
            continue
        if got == "deny" and decision.reason != final["expect_reason"]:
            failures.append(
                f"{mission_id}: expected reason {final['expect_reason']}, got {decision.reason}"
            )
        if "expect_obligation_seq" in final:
            seqs = [o.properties.get("expected_seq") for o in decision.obligations
                    if o.type == "mission_record"]
            want = final["expect_obligation_seq"]
            if (want == 0 and seqs) or (want != 0 and seqs != [want]):
                failures.append(f"{mission_id}: expected mission_record at {want}, got {seqs}")
        if "expect_requestable" in final:
            requestable = decision.access_request is not None
            if requestable is not final["expect_requestable"]:
                failures.append(f"{mission_id}: expected requestable="
                                f"{final['expect_requestable']}, got {requestable}")
    for case in data.get("digest_cases", []):
        # The policy as written, members out of order and repeated: the digest
        # is the one of the set it describes.
        digest = policy_from_json(case["policy"]).digest
        if digest != case["policy_digest"]:
            failures.append(f"{case['id']}: policy digest {digest}, "
                            f"expected {case['policy_digest']}")
    return failures


def main() -> int:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures = run(data)
    if failures:
        for f in failures:
            print("FAIL", f)
        return 1
    print(f"OK: {len(data['scenarios'])} scenarios and "
          f"{len(data.get('digest_cases', []))} digest cases verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
