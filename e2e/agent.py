"""A scripted agent that calls tools, with retry on the profile's
"evaluate again later" reasons.

The agent is deliberately not an LLM. The PDP sees only Acts, never the
agent's intent, so whether a send was chosen by a model fooled by a prompt
injection or by a script, the decision is the same; a script makes the runs
reproducible. ``NaiveAgent`` follows instructions it finds in documents, the
behavior a prompt injection exploits.
"""

from __future__ import annotations

import json
import random
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

# The PEP denies with these when the Act may be permitted later: the profile's
# "evaluate again later" reasons, and an admission that got no acknowledgement.
RETRYABLE = {"history_pending", "history_conflict", "history_unavailable",
             "too_many_conflicts", "mission_record_unavailable"}

Transport = Callable[[str, str, dict[str, Any]], dict[str, Any]]


def http_transport(urls: dict[str, str], token: str) -> Transport:
    def send(host: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        data = json.dumps({"name": tool, "arguments": args}).encode("utf-8")
        req = urllib.request.Request(f"{urls[host]}/tools/call", data=data, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")
        try:
            # Above the in-deployment hop timeout (serve.HOP_TIMEOUT), so a
            # slow hop answers as a decision before the agent gives up.
            with urllib.request.urlopen(req, timeout=60) as resp:
                result: dict[str, Any] = json.loads(resp.read())
                return result
        except (urllib.error.URLError, OSError) as exc:
            return {"ok": False, "reason": "connection_lost", "error": str(exc)}
    return send


class Agent:
    def __init__(self, transport: Transport, retry_for: float = 10.0) -> None:
        self.transport = transport
        self.retry_for = retry_for
        self.log: list[dict[str, Any]] = []

    def call(self, host: str, tool: str, *, retry: bool = True, **args: Any) -> dict[str, Any]:
        start = time.monotonic()
        attempts = 0
        while True:
            attempts += 1
            result = self.transport(host, tool, args)
            if (result.get("ok") or not retry or result.get("reason") not in RETRYABLE
                    or time.monotonic() - start > self.retry_for):
                break
            # Exponential backoff with jitter, so agents held back on the same
            # sequence do not hammer the PDP in lockstep.
            time.sleep(min(0.05 * 2 ** min(attempts - 1, 4), 0.8) * (0.5 + random.random()))
        result["waited"] = round(time.monotonic() - start, 3)
        result["attempts"] = attempts
        self.log.append({"host": host, "tool": tool, "args": args, "result": result})
        return result


INSTRUCTION = re.compile(r"AGENT-INSTRUCTION:\s*(.+)")


class NaiveAgent(Agent):
    """Reads a document and carries out any instruction found in it, copying
    what it read into what it writes, as an injected agent would."""

    def follow(self, doc: str) -> list[dict[str, Any]]:
        found = self.call("docs", "read_document", doc=doc)
        steps = []
        memory = ""
        for line in INSTRUCTION.findall(str(found.get("result", ""))):
            verb, _, rest = line.strip().partition(" ")
            if verb == "read_record":
                r = self.call("hr", "read_record", employee=rest.strip())
                memory += str(r.get("result", ""))
            elif verb == "write_document":
                r = self.call("docs", "write_document", doc=rest.strip(), text=memory)
            elif verb == "send_message":
                to, _, attach = rest.strip().partition(" ")
                r = self.call("mail", "send_message", to=to, doc=attach)
            else:
                continue
            steps.append(r)
        return steps
