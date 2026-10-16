# Composition interop test vectors

`composition-vectors.json` is a set of replayable scenarios for the AuthZEN
Mission Composition Profile. Each scenario is a Mission with an ordered list of
Acts; the Acts before the last are admitted in order, and the last Act carries
the expected decision (`permit` / `deny`) and, for a denial, the expected
reason. Only the last Act is checked: the earlier Acts are history, replayed
as given, and their `expect` fields are informational (in V20 the send was
denied when evaluated and admitted after a person approved it).

The set has 46 scenarios and 2 digest cases. Scenarios with an `S`
identifier are the reference scenarios of the test suite that one evaluation
can express; those with a `V` identifier exist only as vectors and pin rules
an implementation can get wrong. Digest cases (`D1`, `D2`) check the policy
digest alone (see below). The vectors are generated from the scenario definitions
(`scripts/gen_vectors.py`), so they match running code. CI regenerates them
in memory (`scripts/gen_vectors.py --check`) and fails if the committed file is
stale; the check never rewrites it.

## Replaying

Any PDP implementation can replay the vectors. The reference verifier:

```bash
PYTHONPATH=. python interop/verify_vectors.py
```

To port the verifier to another implementation: for each scenario, admit the
Acts before the last in order at your History Authority and report each one's
`outcome` as given: `completed` with its `result_classes`, `failed`, or nothing
for `open`. Then evaluate the final Act and compare the decision and reason to
the vector. Step patterns (`external:*`, `personal_data.*`) match as the
profile's "Step patterns" section defines: exact, or a prefix when the pattern
ends in `*`. A step with `"persistent": true` takes effect at its Act's
position and at every later point (profile "Persistent steps"); vectors V6 to
V8, V15, V16, V19, V29 to V31 and V38 exercise it, V19 with one Act filling
two persistent steps, V29 with an open one, V30 and V31 with one Act filling a
step at its own position and a persistent step at a later point, and V38 with
two persistent steps taking effect between the same two consecutive Acts. V9
is the schedule of V6 without the mark, and is permitted. Every step in the
vectors carries `persistent`.

A policy may carry `label_domain`, the class patterns of the deployment's
label domain (profile "Result classes"); without it, the domain is the class
patterns the steps name. A `label_domain` that is present but empty recognizes
no class, so every class is the conservative top (V17; V18 is the same Acts
with a declared domain that recognizes the class). V32 and V33 tell the two
apart by their decision: the same Acts are denied with an empty declared
domain and permitted with none, since a class another sequence names is then
recognized.

Every scenario carries `policy_digest`, the digest of its `policy` as the
profile defines it (section "Policy digest"): the policy is already a Policy
Object, so an implementation computes the digest from it and must get the same
value, or its PDPs could not decide for the same Missions as another
implementation's. The verifier checks it first. Since every scenario's policy
is already in that form, the scenarios do not test the canonical form itself:
the digest cases do. Each gives a `policy` written as a person might, with
patterns, class patterns and sequences out of order and repeated (`D1`) and
non-ASCII patterns whose UTF-8 order differs from their UTF-16 order (`D2`),
and the `policy_digest` of the set it describes.

The final Act may also carry, and the verifier then checks:

* `expect_obligation_seq`: on a permit, the `mission_record` obligation's
  `expected_seq`, or `0` for no obligation;
* `expect_requestable`: on a denial, whether it is ARAP-requestable. Only
  `false` is ever required (where the profile says MUST NOT); being requestable
  is a MAY. The verifier evaluates with an Access Request Endpoint configured,
  since without one no denial is requestable;
* `supported_mandatory_extensions` and `supported_obligations`: evaluate
  with these lists instead of the default, a PEP that lists `obligations` and
  can execute `mission_record` (V14, V25, V26: without that adoption, an Act
  that needs serialization gets a plain deny; V28: no separate signal is
  needed, and an extension the PDP does not implement is ignored).

V21 to V24 pin rules that an implementation can get wrong while passing the
others: a completed Act that reported no class is the conservative top (V21),
an Act matching only the final step is serialized even on an empty history
(V22), an open Act that could fill two steps holds back another such Act
(V23: only a shared single step commutes), and `personal_data.*` does not match
`personal_data` (V24). V27 pins rule 5 as written (profile, open question 11):
an open write holds back an external send even when no read is in the Mission.
V29 pins that an open persistent Act holds back too: an open share link holds
back a read.

V34 to V41 pin more such rules: a read that can match only a class-keyed step
is Step-matching even on an empty history (V34); the order of the checks puts
the predicate and rule 5 before the plain deny for a PEP that did not adopt
`mission_record`, whose denial is then not requestable (V35, V36); rule 5 counts the steps of each sequence on its
own (V37); several persistent steps can take effect between the same two Acts
(V38); patterns are case-sensitive (V39); and only a final `*` is a wildcard,
any other `*` being literal (V40, V41). V2, V4 and V5 also state the
`expected_seq` of their permits: V2's counts a failed Act, so a failed Act is
seen to keep its position, and V4's and V5's count a completed and an open one.

`tests/test_adoption_pinning_and_interop.py` runs the verifier against a set of
plausible wrong implementations (classes, serialization, rule 5, patterns, the opt-in,
the candidate's classes) and against a rule 5 that is sound but more
permissive than the profile, and checks that each fails a vector.

## What the vectors do not cover

Each vector replays one Mission's history at a fresh History Authority and
evaluates one request, so the set cannot express a history read that fails, a
gap or an invalid Act Record (`history_unavailable`), a request without a
Mission, a batch (`history_conflict`), a policy pin or a designation
(`policy_mismatch`), concurrent admissions, or an approval: its binding to the
request, the actor and the position, its single use, and the `next_action` of
a re-evaluation. An implementation can pass every vector and still get those
wrong. `docs/TRACEABILITY.md` lists the reference's tests for each.

## Shape

Abridged: the file also carries `version`, `profile`, `note` and
`canonical_sequence` at the top level.

```json
{
  "scenarios": [
    {
      "id": "S1",
      "title": "...",
      "policy": { "restricted_sequences": [ { "name": "...", "requestable": true,
                    "steps": [ { "action": "read_record", "resources": [],
                                 "result_classes": ["personal_data.*"],
                                 "persistent": false }, ... ] } ] },
      "policy_digest": "sha256:...",
      "acts": [
        { "seq": 1, "action": {"name": "read_record"}, "resource": {"id": "hr:emp-1"},
          "result_classes": ["personal_data.salary"], "outcome": "completed",
          "expect": "permit", "expect_reason": null },
        ...
        { "seq": 3, "action": {"name": "send_message"}, "resource": {"id": "external:all-staff"},
          "result_classes": [], "outcome": "completed",
          "expect": "deny", "expect_reason": "prohibited_composition" }
      ]
    }
  ],
  "digest_cases": [
    { "id": "D1", "title": "...", "policy": { ... }, "policy_digest": "sha256:..." }
  ]
}
```
