#!/usr/bin/env python3
"""Generate interop test vectors from the scenarios, deterministically.

Writes interop/test-vectors/composition-vectors.json. Each vector is a mission
with an ordered list of acts, the policy, and the expected decision for the
final act, in a wire-shaped JSON that any PDP implementation can replay. The
vectors are produced from the same scenario definitions the test suite uses, so
they cannot drift from the reference implementation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from authzen_composition.model import RestrictedSequence, jcs
from authzen_composition.scenarios import (
    DIGEST_CASES,
    EXFIL,
    Scenario,
    Step,
    all_scenarios,
    vector_only_scenarios,
)
from interop.verify_vectors import policy_from_json

OUT = Path(__file__).resolve().parents[1] / "interop" / "test-vectors" / "composition-vectors.json"


def _seq_json(seq: RestrictedSequence) -> dict[str, object]:
    return {
        "name": seq.name,
        "requestable": seq.requestable,
        "steps": [
            {
                "action": s.action,
                "resources": sorted(s.resources),
                "result_classes": sorted(s.result_classes),
                "persistent": s.persistent,
            }
            for s in seq.steps
        ],
    }


def _scenario_json(scenario: Scenario) -> dict[str, object]:
    acts = []
    for i, step in enumerate(scenario.steps, start=1):
        act: dict[str, object] = {
            "seq": i,
            "action": {"name": step.action},
            "resource": {"id": step.resource},
            "result_classes": list(step.result_classes),
            "outcome": step.outcome,
            "expect": "permit" if step.expect_permit else "deny",
            "expect_reason": step.expect_reason,
        }
        if step.expect_obligation_seq is not None:
            act["expect_obligation_seq"] = step.expect_obligation_seq
        if step.expect_requestable is not None:
            act["expect_requestable"] = step.expect_requestable
        if step.extensions != Step.extensions:
            act["supported_mandatory_extensions"] = list(step.extensions)
        if step.obligation_types != Step.obligation_types:
            act["supported_obligations"] = list(step.obligation_types)
        acts.append(act)
    # A Policy Object (profile, Policy digest): the sequences in ascending
    # order of their canonical bytes, so its JCS form hashes to the digest.
    policy: dict[str, object] = {
        "restricted_sequences": sorted((_seq_json(s) for s in scenario.policy.sequences),
                                       key=jcs)}
    if scenario.policy.label_domain is not None:
        policy["label_domain"] = sorted(scenario.policy.label_domain)
    return {
        "id": scenario.id,
        "title": scenario.title,
        "policy": policy,
        "policy_digest": scenario.policy.digest,
        "acts": acts,
    }


def build() -> dict[str, object]:
    return {
        "version": "0.1.0",
        "profile": "AuthZEN Mission Composition Profile",
        "note": (
            "Each act is admitted in order and its outcome reported as given "
            "(completed, open or failed); the last act of a scenario carries the "
            "expected decision. Generated from the reference scenarios."
        ),
        "canonical_sequence": _seq_json(EXFIL),
        "scenarios": [
            _scenario_json(s)
            for s in (*all_scenarios(), *vector_only_scenarios())
            if s.steps
        ],
        "digest_cases": [
            {"id": case_id, "title": title, "policy": policy,
             "policy_digest": policy_from_json(policy).digest}
            for case_id, title, policy in DIGEST_CASES
        ],
    }


def main(argv: list[str]) -> int:
    text = json.dumps(build(), indent=2) + "\n"
    if "--check" in argv:
        # Compare only: a stale committed file is reported, never rewritten.
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            print(f"stale: {OUT}; run scripts/gen_vectors.py")
            return 1
        print(f"up to date: {OUT}")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
