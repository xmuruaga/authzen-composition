"""Outcome reports bound to their admission, and the normative policy digest.

Each test fails on a reference that lacked the rule it pins.
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from authzen_composition.http_binding import MHSHttpApp, StaticTokenAuthenticator
from authzen_composition.mhs import MissionHistoryService, UnknownAct
from authzen_composition.model import (
    Act,
    ActOutcome,
    CompositionPolicy,
    RestrictedSequence,
    SequenceStep,
    jcs,
)
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import ReferencePEP
from authzen_composition.scenarios import EXFIL_POLICY
from authzen_composition.types import Action, Decision, EvaluationRequest, Resource, Subject

ISSUER = "https://missions.example"  # the issuer of every Mission here
VECTORS = (Path(__file__).resolve().parents[1]
           / "interop" / "test-vectors" / "composition-vectors.json")


class _NoPDP:
    def evaluate(self, request: EvaluationRequest) -> Decision:
        raise AssertionError("not called")


def test_a_kept_outcome_never_lands_on_another_admission_at_a_reused_position() -> None:
    # An authority that lost an acknowledged Act (it was not durable) gives
    # its position to the next admission, here by the same writer. The PEP
    # still holds the lost Act's outcome. Delivered without its admission, a
    # kept `failed` would mark the new read failed and hide it from the
    # predicate: a soundness failure, not a lost update.
    pep = ReferencePEP(pdp=_NoPDP(), mhs=MissionHistoryService(), writer_id="pep.hr")
    pep.mhs.admit("m", 1, "read_record", "hr:1", writer="pep.hr", admission_id="old")
    pep.unreported.append(("m", 1, ActOutcome.FAILED, frozenset(), "old"))

    restarted = MissionHistoryService()  # the authority comes back empty
    pep.mhs = restarted
    restarted.admit("m", 1, "read_record", "hr:2", writer="pep.hr", admission_id="new")
    pep.redeliver()

    act = restarted.history("m")[0]
    assert (act.resource, act.outcome) == ("hr:2", ActOutcome.OPEN)
    # A definite refusal: handed to the operator once, never redelivered.
    assert pep.unreported == []
    assert [(r[0], r[1], r[4]) for r in pep.refused] == [
        ("m", 1, "mission m seq 1: no act of this admission")]


def test_an_outcome_must_name_the_admission_it_reports_on() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w", admission_id="k")
    for wrong in (None, "other"):
        with pytest.raises(UnknownAct):
            mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w", admission_id=wrong)
    assert mhs.history("m")[0].outcome is ActOutcome.OPEN
    done = mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w", admission_id="k")
    assert done.outcome is ActOutcome.FAILED


def test_an_act_admitted_without_an_admission_id_takes_any_report_from_its_writer() -> None:
    mhs = MissionHistoryService()
    mhs.admit("m", 1, "a", "r", writer="w")
    assert mhs.set_outcome("m", 1, ActOutcome.FAILED, writer="w",
                           admission_id="x").outcome is ActOutcome.FAILED


def test_the_binding_refuses_an_outcome_for_another_admission() -> None:
    app = MHSHttpApp(MissionHistoryService(), StaticTokenAuthenticator({"t": "pep.a"}),
                     auditors=frozenset({"pep.a"}))

    def call(method: str, path: str, body: object | None) -> tuple[str, dict]:
        raw = b"" if body is None else json.dumps(body).encode()
        env = {"REQUEST_METHOD": method, "PATH_INFO": path,
               "CONTENT_LENGTH": str(len(raw)), "HTTP_AUTHORIZATION": "Bearer t",
               "wsgi.input": io.BytesIO(raw)}
        got: dict = {}
        out = b"".join(app(env, lambda s, h: got.update(s=s)))
        return got["s"], json.loads(out)

    good = {"seq": 1, "action": {"name": "a"}, "resource": {"id": "r"},
            "admission_id": "k"}
    assert call("POST", "/missions/m/acts", good)[0] == "201 Created"
    assert call("PATCH", "/missions/m/acts/1",
                {"outcome": "failed", "admission_id": "other"}) == (
        "409 Conflict",
        {"error": "mission m seq 1: no act of this admission", "reason": "outcome_conflict"})
    assert call("PATCH", "/missions/m/acts/1",
                {"outcome": "failed", "admission_id": 7})[0] == "400 Bad Request"
    assert call("PATCH", "/missions/m/acts/1",
                {"outcome": "failed", "admission_id": "k"})[0] == "200 OK"


# --- Policy digest ---------------------------------------------------------
# An implementation written from the profile's "Policy digest" section alone,
# with its own JCS serializer, not the reference's: what a second implementer
# would write. It must agree with the reference and with every vector.

def _jcs_string(s: str) -> str:
    # RFC 8785 section 3.2.2.2 (ECMAScript JSON.stringify string rules).
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise ValueError("lone surrogate")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in "\b\f\n\r\t":
            out.append({"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(v: object) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    assert isinstance(v, dict)
    # Members sorted by their UTF-16 code units (RFC 8785 section 3.2.3).
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v[k]) for k in keys) + "}"


def _a_set(values: list[str]) -> list[str]:
    return sorted(set(values), key=lambda s: s.encode("utf-8"))


def _independent_digest(policy: dict) -> str:
    seqs = []
    for s in policy["restricted_sequences"]:
        seqs.append({
            "name": s["name"],
            "requestable": s.get("requestable", False),
            "steps": [{"action": st["action"],
                       "resources": _a_set(st.get("resources", [])),
                       "result_classes": _a_set(st.get("result_classes", [])),
                       "persistent": st.get("persistent", False)} for st in s["steps"]],
        })
    by_text = {_jcs(s).encode("utf-8"): s for s in seqs}
    obj: dict[str, object] = {"restricted_sequences": [by_text[k] for k in sorted(by_text)]}
    if "label_domain" in policy:
        obj["label_domain"] = _a_set(policy["label_domain"])
    return "sha256:" + hashlib.sha256(_jcs(obj).encode("utf-8")).hexdigest()


def test_every_vector_digest_is_the_one_the_profile_defines() -> None:
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    for scenario in data["scenarios"]:
        assert _independent_digest(scenario["policy"]) == scenario["policy_digest"], scenario["id"]


def test_every_vector_policy_is_already_a_policy_object() -> None:
    # The draft and the vectors README say each vector's policy is already a
    # Policy Object, so hashing its JCS form as given must give the digest.
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    for scenario in data["scenarios"]:
        given = "sha256:" + hashlib.sha256(_jcs(scenario["policy"]).encode("utf-8")).hexdigest()
        assert given == scenario["policy_digest"], scenario["id"]


def test_every_digest_case_is_the_one_the_profile_defines_for_the_set_it_describes() -> None:
    # A digest case writes its policy as a person might: members out of
    # order and repeated. Its digest is the one of the set it describes, so
    # hashing it as written must not give it, or the case tests nothing.
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert data["digest_cases"]
    for case in data["digest_cases"]:
        assert _independent_digest(case["policy"]) == case["policy_digest"], case["id"]
        given = "sha256:" + hashlib.sha256(_jcs(case["policy"]).encode("utf-8")).hexdigest()
        assert given != case["policy_digest"], case["id"]


def test_the_digest_keeps_non_ascii_text_as_utf8_as_jcs_does() -> None:
    # JCS writes non-ASCII characters as UTF-8, not as \\u escapes, and
    # escapes control characters in lower-case hex. A PDP that hashed escaped
    # text would compute another digest for the same set and every Mission it
    # shares with another implementation would fail closed.
    raw = {"restricted_sequences": [{
        "name": "lecture\u00e9\u2028\x01", "requestable": False,
        "steps": [{"action": "read", "resources": ["hr:\u00fc", "hr:a"],
                   "result_classes": ["donn\u00e9es.*"], "persistent": False},
                  {"action": "send", "resources": [], "result_classes": [],
                   "persistent": False}]}],
        "label_domain": ["donn\u00e9es.*", "public"]}
    policy = CompositionPolicy(
        (RestrictedSequence("lecture\u00e9\u2028\x01", (
            SequenceStep("read", resources=frozenset({"hr:a", "hr:\u00fc"}),
                         result_classes=frozenset({"donn\u00e9es.*"})),
            SequenceStep("send")), requestable=False),),
        label_domain=frozenset({"public", "donn\u00e9es.*"}))
    assert policy.digest == _independent_digest(raw)
    assert b"\\u00e9" not in jcs({"x": "\u00e9"}) and b"\\u0001" in jcs({"x": "\x01"})


def test_the_reference_pep_gives_every_admission_and_its_outcome_an_admission_id() -> None:

    calls: list[tuple[str, str | None]] = []

    class Recording(MissionHistoryService):
        def admit(self, mission_id: str, seq: int, action: str, resource: str,
                  writer: str, admission_id: str | None = None) -> Act:
            calls.append(("admit", admission_id))
            return super().admit(mission_id, seq, action, resource, writer, admission_id)

        def set_outcome(self, mission_id: str, seq: int, outcome: ActOutcome, writer: str,
                        result_classes: frozenset[str] = frozenset(),
                        admission_id: str | None = None) -> Act:
            calls.append(("outcome", admission_id))
            return super().set_outcome(mission_id, seq, outcome, writer, result_classes,
                                       admission_id)

    mhs = Recording()
    pep = ReferencePEP(pdp=CompositionPDP(EXFIL_POLICY, mhs), mhs=mhs, writer_id="pep.hr")
    pep.enforce(mission_id="m", mission_issuer=ISSUER, subject=Subject("agent", "a"),
                action=Action("read_record"), resource=Resource("r", "hr:1"),
                perform=lambda: "ok")
    assert [c[0] for c in calls] == ["admit", "outcome"]
    assert calls[0][1] and calls[0][1] == calls[1][1]
