"""The committed interop vectors verify, and are in sync with the code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from authzen_composition.scenarios import vector_only_scenarios
from interop.verify_vectors import policy_from_json, run

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "interop" / "test-vectors" / "composition-vectors.json"


def test_vectors_verify() -> None:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert run(data) == []


def test_vectors_are_regenerated_identically() -> None:
    # Regenerate in memory and compare with the committed file, so a stale
    # vectors file is caught in CI. The check never writes: a test that
    # rewrote the file would fail once and then pass on the next run.
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    before = VECTORS.read_bytes()
    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_vectors.py"), "--check"],
        env=env, cwd=str(ROOT), capture_output=True, text=True,
    )
    assert VECTORS.read_bytes() == before
    assert check.returncode == 0, check.stdout


def test_the_vector_only_scenarios_are_the_committed_ones() -> None:
    # They exist only to become vectors; checked here in process, since the
    # generator runs in a subprocess above.
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    committed = {s["id"]: s for s in data["scenarios"]}
    scenarios = vector_only_scenarios()
    assert scenarios
    for scenario in scenarios:
        vector = committed[scenario.id]
        assert vector["policy_digest"] == scenario.policy.digest
        assert [a["action"]["name"] for a in vector["acts"]] == [s.action for s in scenario.steps]
        assert [a["outcome"] for a in vector["acts"]] == [s.outcome for s in scenario.steps]


def test_the_verifier_reports_a_wrong_digest_a_wrong_reason_and_a_wrong_digest_case() -> None:
    # A verifier another implementation ports has to fail on each kind of
    # mismatch, not only pass on the committed vectors.
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    by_id = {s["id"]: s for s in data["scenarios"]}
    by_id["S1"]["policy_digest"] = "sha256:" + "0" * 64
    deny = by_id["V1"]["acts"][-1]
    assert deny["expect"] == "deny"
    deny["expect_reason"] = "history_pending"
    data["digest_cases"][0]["policy_digest"] = "sha256:" + "1" * 64
    failures = run(data)
    assert [f.split(":")[0] for f in failures] == ["S1", "V1", "D1"], failures


def test_the_verifier_reports_a_denial_that_is_requestable_where_it_must_not_be() -> None:
    # A requestable denial needs an Access Request Endpoint: the verifier's
    # PDP has one, so that `expect_requestable: false` is a check and not
    # true of every denial.
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    requestable = [
        s for s in data["scenarios"]
        if s["acts"][-1].get("expect_reason") == "prohibited_composition"
        and "supported_mandatory_extensions" not in s["acts"][-1]
        and "supported_obligations" not in s["acts"][-1]
        and all(q["requestable"] for q in s["policy"]["restricted_sequences"])]
    assert requestable
    scenario = requestable[0]
    scenario["acts"][-1]["expect_requestable"] = False
    assert run({"scenarios": [scenario]}) == [
        f"{scenario['id']}: expected requestable=False, got True"]


def test_a_policy_object_member_left_unstated_takes_its_default() -> None:
    # Profile, Policy digest: `requestable` and `persistent` default to false,
    # `resources` and `result_classes` to empty; the set, and so its digest,
    # is the one that states them.
    stated = {"restricted_sequences": [{"name": "s", "requestable": False, "steps": [
        {"action": a, "resources": [], "result_classes": [], "persistent": False}
        for a in ("rd", "sd")]}]}
    unstated = {"restricted_sequences": [{"name": "s", "steps": [
        {"action": a} for a in ("rd", "sd")]}]}
    assert policy_from_json(unstated).digest == policy_from_json(stated).digest
