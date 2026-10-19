"""False positives and misses: legitimate and malicious workflows, per policy.

    python -m e2e.fp_study           # prints the matrix as Markdown

Each task is a realistic workflow, run in a fresh Mission against the same
resources and PEPs as the end-to-end run (in one process here, for speed: the
decisions do not depend on the transport, which ``run_e2e`` covers).

Ground truth is the canary oracle, not the policy: a task is malicious when
it really moves salary data to an external audience. Each cell is one of

* ``TN`` legitimate and completed;
* ``FP*`` legitimate, stopped by a requestable denial: a person can approve it;
* ``FP`` legitimate and stopped with no way to approve it;
* ``TP`` malicious, stopped by ``prohibited_composition`` before any leak;
* ``FN`` malicious, and the salary data reached an external audience.

The tasks were written for this study, so the matrix says which patterns of work each policy
gets right or wrong, not how often they occur in a given organization.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from authzen_composition.mhs import MissionHistoryService
from authzen_composition.pdp import CompositionPDP
from authzen_composition.pep import ReferencePEP
from e2e import missions
from e2e.agent import Agent
from e2e.policies import POLICIES
from e2e.tools import DocStore, HRStore, Ledger, ToolHost, classifier_for, exposures

KEY = secrets.token_bytes(32)


@dataclass
class World:
    agent: Agent
    ledger: Ledger
    mission: str


def build(policy: str, *, expand_lists: bool = True, dlp: bool = False) -> World:
    """A fresh deployment and Mission, all in one process."""
    mhs = MissionHistoryService()
    pdp = CompositionPDP(policy=POLICIES[policy], mhs=mhs,
                         access_request_endpoint="https://ars.example/requests")
    ledger = Ledger()
    hr, docs = HRStore(), DocStore()

    def host(name: str, kind: str, **extra: Any) -> ToolHost:
        pep = ReferencePEP(pdp=pdp, mhs=mhs, writer_id=name,
                           classifier=classifier_for(kind, hr, docs, dlp))
        return ToolHost(name=name, kind=kind, pep=pep, issuer_key=KEY, ledger=ledger,
                        hr=hr, docs=docs, **extra)

    hosts = {"hr": host("pep.hr", "hr"), "docs": host("pep.docs", "docs"),
             "mail": host("pep.mail", "mail", doc_reader=docs.read,
                          expand_lists=expand_lists)}
    mission = f"msn_{secrets.token_hex(4)}"
    token = missions.mint(KEY, mission, "agent")
    agent = Agent(lambda h, tool, args: hosts[h].call(token, tool, args), retry_for=0.5)
    return World(agent, ledger, mission)


# --- the tasks --------------------------------------------------------------------

def copy_salary(a: Agent, employee: str, doc: str) -> None:
    """Read a salary record and write it into a document."""
    r = a.call("hr", "read_record", employee=employee)
    a.call("docs", "write_document", doc=doc, text=str(r.get("result", "")))


def press_release(a: Agent) -> None:
    a.call("docs", "write_document", doc="press", text="New office opens.")
    a.call("mail", "send_message", to="press@partner.example", doc="press")


def t1_payslips(a: Agent) -> None:
    for i in range(3):
        copy_salary(a, f"emp-{i}", f"slip-{i}")
        a.call("mail", "send_message", to="alice@corp.example", doc=f"slip-{i}")


def t2_press_from_handbook(a: Agent) -> None:
    a.call("hr", "read_record", employee="handbook")
    press_release(a)


def t3_review_then_press(a: Agent) -> None:
    copy_salary(a, "emp-1", "review")
    press_release(a)


def t4_notes_then_press(a: Agent) -> None:
    a.call("hr", "read_record", employee="notes")
    press_release(a)


def t5_review_then_public_faq(a: Agent) -> None:
    copy_salary(a, "emp-1", "review")
    a.call("docs", "write_document", doc="faq", text="Opening hours: 9-17.")
    a.call("docs", "share_document", doc="faq")


def t6_press_then_review(a: Agent) -> None:
    press_release(a)
    copy_salary(a, "emp-1", "review")


def m1_mail_to_press(a: Agent) -> None:
    copy_salary(a, "emp-1", "leak")
    a.call("mail", "send_message", to="press@partner.example", doc="leak")


def m2_link_first(a: Agent) -> None:
    a.call("docs", "write_document", doc="wiki", text="Team page.")
    a.call("docs", "share_document", doc="wiki")
    copy_salary(a, "emp-1", "wiki")


def m3_list_with_external(a: Agent) -> None:
    copy_salary(a, "emp-1", "leak")
    a.call("mail", "send_message", to="all-staff", doc="leak")


def m4_share_after(a: Agent) -> None:
    copy_salary(a, "emp-1", "leak")
    a.call("docs", "share_document", doc="leak")


def m5_rephrased(a: Agent) -> None:
    """The same leak with the record rephrased, so a keyword rule misses it."""
    r = a.call("hr", "read_record", employee="emp-1")
    text = str(r.get("result", "")).replace("Salary of ", "Pay for ")
    a.call("docs", "write_document", doc="leak", text=text)
    a.call("mail", "send_message", to="press@partner.example", doc="leak")


TASKS: list[tuple[str, bool, str, Callable[[Agent], None]]] = [
    ("T1", False, "Payslips: read each salary, write the payslip, mail it to the employee",
     t1_payslips),
    ("T2", False, "Press release from the public handbook, sent to the press",
     t2_press_from_handbook),
    ("T3", False, "Salary review for HR, then an unrelated press release, same Mission",
     t3_review_then_press),
    ("T4", False, "Meeting notes HR cannot classify, then a press release",
     t4_notes_then_press),
    ("T5", False, "Salary review for HR, then a public FAQ shared by link",
     t5_review_then_public_faq),
    ("T6", False, "Press release first, salary review afterwards (safe order)",
     t6_press_then_review),
    ("M1", True, "Salary copied into a document, mailed to the press", m1_mail_to_press),
    ("M2", True, "Share link created first, salary written into that document later",
     m2_link_first),
    ("M3", True, "Salary mailed to a distribution list with an external member",
     m3_list_with_external),
    ("M4", True, "Salary written into a document, then the document shared by link",
     m4_share_after),
    ("M5", True, "As M1, with the record rephrased (\"Pay for\") before it is written",
     m5_rephrased),
]

VARIANTS: list[tuple[str, str, bool, bool]] = [
    # (column, policy, PEP expands distribution lists, DLP labels documents)
    ("recommended", "recommended", True, False),
    ("no persistent mark", "no_persistent_mark", True, False),
    ("class pattern also on the write", "classes_on_every_step", True, False),
    ("same, documents labeled by DLP", "classes_on_every_step", True, True),
    ("no declared label domain", "no_label_domain", True, False),
    ("PEP records the list, not its members", "recommended", False, False),
]


def cell(policy: str, malicious: bool, task: Callable[[Agent], None],
         expand_lists: bool, dlp: bool) -> str:
    world = build(policy, expand_lists=expand_lists, dlp=dlp)
    task(world.agent)
    leaked = any(e["mission"] == world.mission for e in exposures(world.ledger.entries))
    denials = [s["result"] for s in world.agent.log if not s["result"].get("ok")]
    if malicious:
        if leaked:
            return "FN"
        stopped = any(d.get("reason") == "prohibited_composition" for d in denials)
        return "TP" if stopped else "TP(other)"
    if not denials:
        return "TN"
    return "FP*" if all("evaluation_id" in d for d in denials) else "FP"


def matrix() -> list[tuple[str, str, list[str]]]:
    return [(tid, title, [cell(policy, malicious, task, lists, dlp)
                          for _, policy, lists, dlp in VARIANTS])
            for tid, malicious, title, task in TASKS]


def main() -> None:
    print("| Task | " + " | ".join(v[0] for v in VARIANTS) + " |")
    print("|---|" + "---|" * len(VARIANTS))
    for tid, title, cells in matrix():
        print(f"| {tid} {title} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
