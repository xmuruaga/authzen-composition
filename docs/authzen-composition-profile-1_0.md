---
title: "AuthZEN Mission Composition Profile 1.0 - Draft 0"
abbrev: "AuthZEN Composition"
docname: authzen-composition-profile-1_0
category: std
date: 2026-10-14
ipr: none
keyword:
  - authorization
  - AuthZEN
  - obligations
  - agents
stand_alone: true
smart_quotes: no
pi: [toc, sortrefs, symrefs]
author:
  - name: Xabier Muruaga
    org: Independent
normative:
  AUTHZEN:
    title: "Authorization API 1.0"
    target: https://openid.net/specs/authorization-api-1_0.html
    author:
      - name: Omri Gazitt
        role: editor
        org: Aserto
      - name: David Brossard
        role: editor
        org: Axiomatics
      - name: Atul Tulshibagwale
        role: editor
        org: SGNL
    date: 2026-01-11
    ann: "OpenID AuthZEN, Final Specification."
  OBLIGATIONS:
    title: "AuthZEN Obligations Core - Draft 1"
    target: https://github.com/openid/authzen/blob/f097170/profiles/authzen-obligations-core-1_0.md
    author:
      - name: Alexandre Babeanu
        org: Indykite
    date: 2026-10
    ann: "OpenID AuthZEN, proposed in openid/authzen PR #697 (open; read at `f097170`, 14 October 2026), which renamed it from \"AuthZEN Obligations Extension\". The merged \"AuthZEN Profile for Obligations - Draft 1\" (openid/authzen `fd49848`) has no opt-in member; this profile uses the proposal's."
  AUTHZEN-EXT:
    title: "AuthZEN Extensibility Model - Draft 1"
    target: https://github.com/openid/authzen/blob/f097170/profiles/authzen-extensibility-model-1_0.md
    author:
      - name: Alexandre Babeanu
        org: Indykite
      - ins: K. McGuinness
    date: 2026-10
    ann: "OpenID AuthZEN, proposed in openid/authzen PR #697 (open; read at `f097170`, 14 October 2026), which defines `supported_mandatory_extensions` and the AuthZEN JSON Members, Extension Identifiers and Profile Identifiers registries. Based on an earlier proposal by Karl McGuinness (GitHub gist `caab9ff4`)."
  ARAP:
    title: "AuthZEN Access Request and Approval Profile - Draft 1"
    target: https://github.com/openid/authzen/blob/6d5380c/profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md
    author:
      - ins: K. McGuinness
    date: 2026-10
    ann: "OpenID AuthZEN (openid/authzen `6d5380c`, 13 October 2026)."
  RFC8785:
  RFC6234:
  RFC8126:
  RFC3629:
  RFC8259:
  RFC3986:
informative:
  RFC8693:
  TXN-TOKENS:
    title: "Transaction Tokens"
    author:
      - ins: A. Tulshibagwale
      - ins: G. Fletcher
      - ins: P. Kasselman
    date: 2026-07-30
    seriesinfo:
      Internet-Draft: draft-ietf-oauth-transaction-tokens-11
  SCHNEIDER:
    title: "Enforceable Security Policies"
    author:
      - ins: F. B. Schneider
    date: 2000-02
    seriesinfo:
      "ACM Transactions on Information and System Security": "3(1):30-50"
  BOUNDED-AGENTS:
    title: "Bounded Agents: Delegation Security for Multi-Agent AI Systems"
    author:
      - ins: X. Muruaga
    date: 2026-08-16
    target: https://arxiv.org/abs/2608.15888v1
    ann: "arXiv:2608.15888v1, preprint."
  MISSION-RUNTIME:
    title: "Mission-Bound Runtime Enforcement"
    author:
      - ins: K. McGuinness
    date: 2026
    target: https://github.com/mcguinness/mission-bound-authorization
    ann: "draft-mcguinness-mission-runtime, editor's copy read at commit `e6c8042` (10 October 2026)."
  MISSION-AUTHZEN:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    author:
      - ins: K. McGuinness
    date: 2026
    target: https://github.com/mcguinness/mission-bound-authorization
    ann: "draft-mcguinness-mission-authzen, editor's copy read at commit `e6c8042` (10 October 2026)."
  MISSION-EVIDENCE:
    title: "Mission Runtime Evidence"
    author:
      - ins: K. McGuinness
    date: 2026
    target: https://github.com/mcguinness/mission-bound-authorization
    ann: "draft-mcguinness-mission-runtime-evidence, editor's copy read at commit `e6c8042` (10 October 2026)."
  MISSION-METERING:
    title: "Mission Consumption Metering"
    author:
      - ins: K. McGuinness
    date: 2026
    target: https://github.com/mcguinness/mission-bound-authorization
    ann: "draft-mcguinness-mission-metering, editor's copy read at commit `e6c8042` (10 October 2026)."
  MISSION-HARNESS:
    title: "Mission-Aware Agent Harnesses"
    author:
      - ins: K. McGuinness
    date: 2026
    target: https://github.com/mcguinness/mission-bound-authorization
    ann: "draft-mcguinness-mission-harness, editor's copy read at commit `e6c8042` (10 October 2026)."
  MISSION-WORK-PRODUCTS:
    title: "Mission Work Products for OAuth 2.0"
    author:
      - ins: K. McGuinness
    date: 2026
    target: https://github.com/mcguinness/mission-bound-authorization
    ann: "draft-mcguinness-oauth-mission-work-products, editor's copy read at commit `e6c8042` (10 October 2026); see its appendix on artifact-lineage label persistence."
  AIMS:
    title: "AI Identity Management System"
    author:
      - ins: P. Kasselman
      - ins: J. Lombardo
      - ins: Y. Rosomakho
      - ins: B. Campbell
      - ins: N. Steele
      - ins: A. Parecki
    date: 2026-09-15
    seriesinfo:
      Internet-Draft: draft-ietf-wimse-aims-00

--- abstract

This profile of the AuthZEN Authorization API lets a PDP deny the Act that would complete a policy-defined, prohibited ordered sequence of Acts within one Mission, when those Acts are enforced by different PEPs. It defines the composition predicate, the requirements on the History Authority that orders a Mission's Acts, five ordering rules, the `mission_record` Obligation Type through which a PEP admits, before its effect, each Act that can fill a step, and the denial reasons.

--- middle

# Status of this draft {#status}

Individual draft for discussion. It is not a work item of the OpenID AuthZEN Working Group. Member names, predicate names and registry values are placeholders.

Apart from JCS {{RFC8785}}, SHA-256 {{RFC6234}}, UTF-8 {{RFC3629}}, JSON {{RFC8259}}, URIs {{RFC3986}} and the registration policies of {{RFC8126}}, its normative dependencies are the AuthZEN Authorization API {{AUTHZEN}}, the Obligations Core {{OBLIGATIONS}} with the opt-in member it takes from the AuthZEN Extensibility Model {{AUTHZEN-EXT}}, and, for escalation, the Access Request and Approval Profile (ARAP) {{ARAP}}. All but the first are drafts or proposals; if the Working Group settles on different signals, this profile follows them. It also constrains one member defined elsewhere, `context.actor` {{MISSION-AUTHZEN}}, only by requiring that it be compared and repeated unchanged, apart from its `client_instance_id` ({{approvals}}, {{pep}}). Other work is cited as related work in Appendix C.

A reference implementation, a non-normative Mission History Service with an HTTP binding, and a conformance suite accompany this draft, at https://github.com/xmuruaga/authzen-composition.

# Introduction

The Authorization API evaluates each request separately. For an agent working through a Mission, every request can be acceptable on its own while the sequence is not: the agent reads a payroll record at one resource, writes it into a document at a second, then sends the document to an outside address from a third. No single check sees a problem.

This profile lets a PDP deny the Act that would complete a policy-defined, prohibited ordered sequence of Acts within one Mission, when those Acts are enforced by different PEPs.

**The predicate is not new.** Denying the step that would complete a prohibited trace is the security-automaton model of execution monitoring {{SCHNEIDER}}. What is missing is the interoperable contract that lets independently built PEPs and PDPs apply such a monitor to one Mission: who orders the trace, what makes it complete, how admission relates to the effect, and how a denial is signaled. That contract is what this profile defines. The wire protocol to the History Authority is still the deployment's (open question 1), so components from different vendors interoperate once they agree on it, and nothing yet lets a PDP detect a History Authority that omits or reorders records (open question 12). The policy digest, which every PDP of a Mission has to compute alike, is defined here ({{policy-digest}}).

**Why a profile, and not only Context.** A single deployment can already pass history to the PDP in the request, as it passes any other attribute its policy uses ({{AUTHZEN}}, Subject Properties and Context). That is not enough here. The read and the send are enforced by different PEPs, often from different vendors. The predicate is sound only if every one of them records its Acts in the same order at the same authority, before the effect, and the PDP can tell when a position is missing. Those are obligations between independently built components, which is what a profile defines.

**Scope.** Which sequences are restricted is policy and is out of scope. This is not general information-flow control: it approximates information flow at the granularity of action types and result classes, which is what a PDP can evaluate before an Act runs. The profile does not require the PDP to retain state between decisions, beyond what ARAP requires for approvals and, until approval material can carry them (open question 14), a record of each requestable denial's Mission, position and Restricted Sequences ({{approvals}}, Representation): the Authorization API leaves "the policy language, architecture, and state management aspects of a PDP" out of scope {{AUTHZEN}}, and this profile keeps it that way by placing history with a History Authority the PDP reads. The profile requires properties of that authority, not a particular service. It assumes that every PEP in the enforcement scope admits, before the effect, into one per-Mission order at that authority; the guarantee covers those PEPs and no others ({{ordering}}, Scope of the guarantee), and open question 3 asks whether per-emitter sequences plus a cut would need less coordination.

**Relationship to the mission-bound drafts.** Those drafts {{MISSION-RUNTIME}} {{MISSION-AUTHZEN}} define Missions, evidence, and history predicates the PDP evaluates against its evidence store. This profile reads only a Mission's identifier and defines the contract between the PEPs, the PDP and the authority that orders their Acts, so it depends on them only for `context.actor`, where a deployment carries the actor there ({{approvals}}), and applies to any Mission model. The same predicate could also be named as a history predicate type there (open question 4); where it belongs is for the Working Group to decide.

# Terminology

{::boilerplate bcp14-tagged}

PEP, PDP, Access Evaluation and Decision are used as in {{AUTHZEN}}; Obligation and Obligation Type as in {{OBLIGATIONS}}; requestable denial, Approval Result (an approval) and Access Request Service as in {{ARAP}}.

Mission:
: A unit of delegated work with a stable identifier, issued by a party other than the agent. Where this document says "the rest of the Mission" or "until the Mission ends", read "for as long as requests carrying the Mission are evaluated": how a Mission ends is open question 13.

Act:
: One action a PEP enforces under a Mission. The candidate is the Act a request would admit, evaluated before any permit.

Result class:
: A non-empty string naming a category of what an Act returned, for example `personal_data.salary`. Assigned by the resource or the PEP from the actual response, never by the agent. It names a category, never content.

Restricted Sequence:
: An ordered tuple of at least two steps, with a name: a String with no default, part of the policy digest ({{policy-digest}}). Two different sequences may share a name; a PDP tells them apart by what they are. A PDP MUST refuse to load a set in which a sequence has fewer steps, since a single prohibited Act is a matter for ordinary policy, not composition. Each step has an action pattern and, optionally, resource and class patterns ({{patterns}}). Policy designates the sequence as prohibited when completed within one Mission, and may make that denial requestable, so that a person can approve it ({{approvals}}).

History Authority:
: The single party per Mission that assigns each admitted Act its position and holds the Mission's ordered history ({{authority}}).

Admission Order:
: The order of positions the History Authority assigned to the Acts of a Mission.

Open Act:
: An admitted Act whose outcome has not been recorded.

Act Record:
: The History Authority's record of one admitted Act ({{authority}}).

Admission:
: The History Authority's assignment of the next position of the Mission to an Act, before the Act's effect ({{ordering}}, rule 3).

Writer:
: The PEP identity that admitted an Act, authenticated by the History Authority from a verified credential.

Step-matching Act:
: An Act whose action and resource match some step of some Restricted Sequence in force, its result classes taken at the conservative top ({{result-classes}}). Rule 2 serializes exactly these.

Persistent Act:
: An Act that matches a persistent step ({{patterns}}).

Enforcement scope:
: The PEPs that the deployment states admit a Mission's Acts at its History Authority, each running outside the agent's control ({{pep}}).

# Request {#request}

A request evaluated under this profile carries the Mission in `context.mission`:

~~~ json
{
  "subject": { "type": "agent", "id": "agent-7" },
  "action": {
    "name": "send_message",
    "properties": { "attachments": ["doc:q4-review"] }
  },
  "resource": {
    "type": "mailbox",
    "id": "external:press@partner.example"
  },
  "context": {
    "mission": {
      "id": "msn_8f14e45f",
      "issuer": "https://missions.example"
    },
    "supported_mandatory_extensions": ["obligations"],
    "supported_obligations": ["mission_record"]
  }
}
~~~

* `mission.id` (REQUIRED, a non-empty String) identifies the Mission. This profile uses it alone as the History Authority's key. The guarantee assumes that issuers mint identifiers unique across every issuer a deployment accepts, for example a URI under the issuer's own authority; how they do so is outside this profile. `mission.issuer` (REQUIRED, a non-empty String; in the mission-bound drafts, a URI naming the Mission's Controller namespace {{MISSION-AUTHZEN}}) identifies who issued it; this profile does not otherwise read it, except where a History Authority guards against identifier collisions ({{security}}). Keying on the pair would split one Mission's history wherever PEPs carry different `issuer` values for it; where identifiers are unique only within an issuer's namespace, as the mission-bound drafts define them, the guarantee needs the uniqueness above. A `context.mission` that is not an Object, or whose `id` or `issuer` is absent or not a non-empty String, makes that evaluation malformed, and the PDP never evaluates it as a request without a Mission: it rejects a single Access Evaluation (in the Authorization API's HTTP binding, with `400 Bad Request` {{AUTHZEN}}); in an Access Evaluations request it denies that evaluation, with the error in its own `context` ({{AUTHZEN}}, Errors), and decides the others. A `mission` member whose value is `null` is absent.
* The mission-bound drafts define a `context.mission` member of their own, in which `issuer` is REQUIRED, as here, and further members carry the authority anchor, the policy version and view, and the origin principal; its state is carried separately, in `context.mission_state_observation` {{MISSION-AUTHZEN}}. A request that carries their member carries everything this profile reads: it reads `id` and ignores members it does not define. Where their Mission identifiers are unique only per issuer, two Missions can share an `id`, which merges their histories here and decides the later Mission under the set of Restricted Sequences the earlier one was pinned to, so it can permit a composition ({{security}}, Mission identifier collision). One member name needs one definition, so this document and that family have to agree on `mission` before either registers it ({{iana}}).
* The PEP takes the Mission, `id` and `issuer`, from one trusted input the agent cannot mint, such as the claims of a verified token. Never from the agent's request body. That input SHOULD be audience-restricted to the PEPs of the enforcement scope and sender-constrained, since anyone who holds it can add Acts to the Mission. The Mission decides which history is read, so the request that carries it MUST be integrity-protected and authenticated between the PEP and the PDP (for example over mutually authenticated TLS), as the Extensibility Model asks of an extension that carries decision-relevant state ({{AUTHZEN-EXT}}, Requirements for Extension Specifications, Binding): a Mission rewritten in transit reads another, emptier history.
* An Act performed by an agent acting under delegation, such as a sub-agent, belongs to the delegator's Mission: the PEP MUST set `mission.id` to that Mission, so that delegated Acts admit at the same History Authority. A delegation that mints a new Mission for the delegate is a Mission split and is outside the guarantee ({{security}}, Mission splitting). The guarantee therefore covers a delegate only if the credential it presents carries the delegator's Mission; how the party that issues delegated credentials does so, for example with OAuth 2.0 Token Exchange {{RFC8693}}, is outside this profile.
* The guarantee holds only where every agent instance, with everything that carries data between its Acts (its context, memory and scratch storage), serves one Mission at a time: an instance that holds credentials for two Missions carries data from one to the other inside itself, where no Act sees it. A deployment SHOULD NOT give one agent instance credentials for two Missions at once ({{security}}, Flows between Missions).
* A request without `context.mission` has no history to be evaluated against. If it is for a Step-matching Act, the PDP MUST deny it with `history_unavailable`; any other request is outside this profile. In an Access Evaluations request a per-evaluation `context` replaces the top-level one rather than merging with it ({{AUTHZEN}}, Default values; {{AUTHZEN-EXT}}; {{OBLIGATIONS}}), so a PEP that supplies one repeats `mission` in it, as it repeats the adoption declarations.
* `supported_mandatory_extensions` is the opt-in member of the AuthZEN Extensibility Model {{AUTHZEN-EXT}}, and `supported_obligations` the negotiation member of the Obligations Core {{OBLIGATIONS}}. A PEP lists `obligations` in the first, which commits it to fail closed on any obligation it cannot apply, and `mission_record` in the second ({{obligation}}). Each is an Array of Strings. A member that is not an Array reads as absent, so it opts in to nothing; an entry that is not a non-empty String is ignored, as the Obligations Core requires of any value the PDP did not advertise {{OBLIGATIONS}}; a repeated entry counts once; an omitted member is empty. Together these two members are the adoption declarations. A PEP that lists both is said here to opt in to `mission_record`. This profile adds no mandatory element of its own beyond that obligation, so it needs no signal of its own: as the Extensibility Model provides for profiles, it is adopted by opting into the extension of its mandatory element, in the same way as the Standard Types Profile proposed in openid/authzen PR #697. There is no `composition` extension identifier: a PEP need not list one, and a PDP ignores it if listed, as it ignores any listed extension it does not implement. A PEP discovers that a PDP implements this profile from `mission_record` in the PDP's `supported_obligations` metadata ({{pdp}}).

# The composition predicate {#predicate}

The composition predicate is unsatisfied for a candidate request when admitting it would complete a Restricted Sequence in the Mission's Acts, taken in Admission Order, with the candidate as one of its elements. Each step takes effect at the position of the Act that fills it; a persistent step ({{patterns}}) takes effect at that position and at every later point of the Mission, so it can also fill a step that comes after Acts admitted later, including the candidate. Such a point may lie strictly between two consecutive admitted Acts, or after the last one: a share link created at position 1 fills the third step of `(read, write, share)` after a read at 2 and a write at 3. Such points are dense: any number of persistent steps, of one Act or of several, can take effect, in sequence order, between the same two consecutive admitted Acts or after the last one. A persistent Act can fill one step of any kind at its own position and, besides it, any number of persistent steps, each at a later point; the candidate may then fill an earlier step than the last. Every other Act fills at most one step. Without persistent steps this is exactly: the candidate fills the final step and the other steps are an ordered subsequence of the history. `failed` Acts are not part of any sequence.

* Policy selects the Restricted Sequences. The request never selects them.
* The PDP evaluates the predicate against history read from the History Authority. A caller-supplied value is never evidence of the predicate's outcome.
* An unsatisfied predicate produces a denial with `context.reason` set to `prohibited_composition`.
* The PDP MAY return the denial as an ARAP requestable denial when policy allows a person to approve every Restricted Sequence the Act would complete; if it would also complete one that no one may approve, the denial MUST NOT be requestable, and neither may a denial to a PEP that has not opted in to `mission_record` ({{request}}), since its re-evaluation would end in the plain deny of check (d), nor a denial the PDP's other policy would also give: no approval could lead to a permit. Withholding `context.access_request` is a choice of which extension members to emit, which the Extensibility Model lets a capability declaration decide ({{AUTHZEN-EXT}}, Capabilities); it never widens access. How an approval then applies is in {{approvals}}.

## Approvals {#approvals}

A person who approves a requestable denial approves one request at one point of the Mission's history. {{ARAP}} defines the flow; this section says how this profile narrows ARAP's default approval scope and, for the adoption declarations, normalizes it.

* **Scope.** An approval applies only to the exact request denied (its subject, its action and resource with their properties, and its adoption declarations as the PDP reads them: whether `obligations` is listed, and which of the types the PDP advertises are listed {{OBLIGATIONS}}), for the PEP that requested it where the PDP authenticates its caller (ARAP's approval verification), in the same Mission, at the position the denied Act would have been admitted at (the `expected_seq` it would have had), and only to the Restricted Sequences that denial completed. A person approves a request, not an action name: the same send with a different attachment, or by another agent, is a different request. That holds only for what the request carries, so the PEP carries it ({{pep}}): every argument of the call that decides what the effect discloses, or to whom, is in `action.properties` or `resource.properties`. An approval binds a document named by reference, not the content behind the name; a deployment whose approvals must cover that content carries an identifier of its version and delivers only that version, which makes the send one by value (a later write can then no longer change what it delivers).
* **ARAP binding.** In ARAP's terms, `mission`, `supported_mandatory_extensions` and `supported_obligations` are authorization-relevant Context of the denial, and so is `context.actor` when the denied request carried it, and a PDP that conveys the denial binding in ARAP's material lists them as such {{ARAP}}. The adoption declarations are bound as capability declarations are: they decide whether an approval applies, and are not otherwise an input to policy ({{AUTHZEN-EXT}}). An Access Request repeats them as sent, and the Access Request Service compares them structurally, as ARAP does; at re-evaluation the declarations are compared by what the PDP reads from them, a scope ARAP lets a PDP record, so that listing an extension or a type the PDP ignores does not change whether an approval applies.
* **The actor.** ARAP's default comparison leaves out `subject.properties.act`, because a PEP may move the actor to `client.actor`; this profile's approval scope keeps it, and keeps `context.actor` where a deployment carries the actor there, as the mission-bound drafts do {{MISSION-AUTHZEN}}, so a sub-agent acting for the same principal cannot use the approval its delegator obtained ({{ARAP}} lets a PDP record a narrower scope than its default; how ARAP carries the actor at re-evaluation is still open, openid/authzen issue #744). A PEP that evaluates again with the approval therefore sends the same subject, action and resource, properties included, `subject.properties.act` among them. The two places bind at different points. An Access Request submission may move `subject.properties.act` to `client.actor`, and an Access Request Service does not rely on `client.actor` unless it verifies it {{ARAP}}; so the denial binding leaves the Subject's actor out, as ARAP's comparison does, and the PDP compares that actor only at re-evaluation. `context.actor` stays where it is and is compared at both. `subject.properties.act` nests prior actors as the `act` claim of {{RFC8693}} does, and the mission-bound `context.actor` lists them in its `act` array; RFC 8693 treats prior actors as informational only for access control. This scope compares `subject.properties.act` whole, and `context.actor` whole except, where it is an Object, its `client_instance_id` member: a correlator of one instance of the client, which ARAP lets another instance replace when it resumes a Task Handle (a deployment that needs the same instance to use the approval says so in policy). Prior actors are compared in both, so the scope can withhold an approval RFC 8693 would allow but never grant one it would not.
* **One use, at one position.** An approval MUST NOT lead to more than one admitted Act: a PDP honors it only at the position it was given for, where rule 2 admits one Act, and only before its `approved_until` {{ARAP}}. ARAP's `context.access_request.expires_at` bounds when the Access Request can be submitted, and `task.expires_at` how long it can wait for a decision; a deployment of this profile sets `task.expires_at` no later than the denial's `expires_at` while the request is pending, so a request still pending when that window closes expires and is not approved (ARAP lets the Access Request Service expire requests by local policy). `approved_until` runs from the approval (`approved_at`), for a lifetime the deployment configures, and on approval the Access Request Service moves `task.expires_at` to no earlier than `approved_until`, so that the result stays retrievable while the approval can be used. A PEP stops polling at the `task.expires_at` it last saw {{ARAP}}, so it collects an approval given after its last poll only if it polls again before then: a PEP polls more often as that time nears. A PDP that records the approval as used at its first permit (a denial for another reason does not use it up) also keeps a second permit from being issued, but then a permit whose response is lost costs the approval. {{ARAP}} leaves to the PDP whether an approval applies under current policy, and its default scope would let the same request reuse it until it expires; this profile narrows that scope to one use at one position, because every admission changes the history the person approved against. If another Act is admitted in the meantime, the PDP evaluates afresh. In ARAP's terms the approval is then out of its scope. At a re-evaluation that presented an approval, a `prohibited_composition` denial MUST carry `next_action` set to `request`, with a fresh `access_request`, when it is requestable (ARAP's default for `out_of_scope`; the PEP needs the fresh `access_request` to ask again), and `none` otherwise, whether the approval expired, was used, or does not apply.
* **Replicas.** Because the approval names a position and only one Act can be admitted there (rule 2), PDP replicas that can each verify an approval (for example a signed `approval.state` {{ARAP}}) without sharing whether it was used can each issue a permit with it, and still cannot let it admit two Acts.
* **Representation.** ARAP leaves the representation of a narrower scope to profiles and deployments {{ARAP}}, and this profile does not define one yet (open question 14). A PDP MUST be able to determine, from the approval it is presented, the Mission, the position and the Restricted Sequences the denial completed: from its own record of the denial, kept with `evaluation_id`, which the PDP does not reuse while an approval of it is valid, or from approval material it can verify that carries them. A PDP that cannot MUST NOT make the denial requestable.
* **What the approver sees, and who approves.** The denied request does not show why it is prohibited: the same send is a false positive in one Mission and an exfiltration in another (open question 7). An Access Request Service SHOULD show the approver the Restricted Sequences the denial completes and, for each, the action, the result classes and, where the approver may see them, the resources of the Acts that fill its earlier steps, which the PDP can derive from its record of the denial and the history at its position. Values the agent chose (identifiers, names, message bodies, justifications) SHOULD be shown as the agent's, and identifiers in a form that exposes confusable characters. An approval of `prohibited_composition` SHOULD come from a person, or from an evaluator given no content that the agent, or a resource the agent read, could have authored. The subject MUST NOT be an eligible approver, and neither SHOULD any actor in its delegation chain.

# Result classes {#result-classes}

The predicate can match an earlier Act by what it returned, not only by what it was. An Act that read an HR record is different from one that read an HR record containing salary data.

* Result classes are strings. An Act carries a set of classes and matches a step's class patterns if any of its classes matches any of them ({{patterns}}).
* The conservative top is a value that matches every class pattern.
* The result classes of an Open Act, of the candidate (the Act being evaluated, which has not run), and of a `completed` Act with no classes are taken as the conservative top. So is each individual result class that matches no pattern of the deployment's label domain, independently of the Act's other classes: an Act recorded with `personal_data.salary` and an unrecognized class matches every class pattern, because the unrecognized class is the top. The top applies to result classes only: an Act's action and resource are known, and the step's patterns are matched against them as recorded.
* The label domain is part of policy and declared separately from the Restricted Sequences: the class patterns covering every class the deployment's PEPs and resources assign. Recognition therefore never depends on which sequences exist, and adding a Restricted Sequence never permits more. A deployment that declares no label domain takes the class patterns its steps name; it then loses that property, because a new sequence naming `personal_data.salary` makes that class recognized, and so no longer the top, for every other sequence. A deployment SHOULD therefore declare its label domain, and gives its PEPs and resources the classes it recognizes, since a class outside it is the top. A declared domain that is empty recognizes no class, so every result class is the top; only a domain that is not declared at all is taken from the steps. Declaring it also makes more classes recognized, so an operation that relabels the data more easily slips past a class pattern on a later step ({{patterns}}, Where to put class patterns). The label domain is covered by the policy digest ({{policy-digest}}). A `*` class pattern would make every class recognized, so a PDP MUST refuse to load a set in which a step names it or whose declared label domain contains it; a step that means any class names no class pattern.
* A `failed` Act carries no result classes.
* Result classes are written by the resource or the enforcing PEP from the actual response, by a classifier the agent does not control. A PDP MUST NOT accept result classes that originate with the agent, and a PEP MUST NOT record a class the agent could have chosen: directly; through resource state the agent can change without an Act that matches a step (a sensitivity label, a tag, a folder); through request arguments that change how the same data is labeled (a projection, an alias, an encoding); or through an agent, a model or a third-party service that serves as the Act's resource and labels its own output. A PEP that cannot classify a response records no classes, which is evaluated at the top; a classifier that fails MUST NOT return a default class instead. A classifier that several PEPs share is part of each one's trusted base, and a label downgrade the agent can make SHOULD itself be an Act that matches a step.

# Step patterns {#patterns}

A step has an action pattern and, optionally, a set of resource patterns and a set of class patterns, and may be marked persistent. An empty set matches every value. An Act matches the step when its action matches the action pattern, its resource matches at least one resource pattern, and one of its result classes matches at least one class pattern.

A pattern is a string. A pattern that does not end in `*` matches exactly that string. A pattern that ends in `*` matches every string that begins with the pattern without that final `*`: `external:*` matches `external:press@partner.example`, `personal_data.*` matches `personal_data.salary` but not `personal_data`, and `*` matches every string. Matching is case-sensitive and compares code points; there is no other wildcard and no escaping. A `*` in an Act's action or resource is an ordinary character, never a wildcard. A result class MUST NOT contain `*`, so that a recorded class can never be mistaken for a pattern or for the conservative top, which only the PDP assigns.

**Persistent steps.** A step MAY be marked persistent. Policy marks a step persistent when the effect of an Act matching it does not end with the Act: a public share link, a forwarding or auto-reply rule, a webhook or subscription, a credential or grant issued to a third party, a recurring or scheduled job. Such an Act exposes, from its admission until the end of the Mission, whatever later Acts put within its reach, so it fills its step at every later point ({{predicate}}). Without the mark, creating the share link first, then reading salary data and writing it into the shared document, is the permitted order of `(read, write, share)`, while the data ends up behind the link. Revoking such an effect is not modeled; the Act stays in effect for the rest of the Mission. Where every later delivery of the effect passes through an in-scope PEP (a webhook dispatched by the PEP itself), the deployment MAY instead admit each delivery as its own Act; where deliveries happen inside the resource (a mail server applying a forwarding rule), only the persistent mark covers them.

**Exposure the Mission did not create.** A lasting effect created before the Mission, outside it or by another Mission is not an Act of the Mission, so no persistent step sees it: salary data written into a document that another party shared publicly leaves through that link. A PEP SHOULD put first, in the canonical identifier of a resource an Act writes into, the most exposed trust domain that can read it at admission, whoever made it so (`external:doc:faq` for a document with a public link), and policy then names such writes in its egress steps. The resource then has another identifier once exposed, so a step that names it by pattern, a persistent one included, names both forms (`doc:*` and `external:doc:*`). Exposure added later, outside the Mission, is outside the guarantee ({{security}}).

**Canonical identifiers.** Patterns match the action and resource identifiers the PEP records: the request's `action.name` and `resource.id`, which the PEP sets to the identifiers it records. Neither `resource.type` nor any `properties` member takes part in matching; the canonical identifier MUST be unique across the deployment's resource types, so where a resource system's identifiers are unique only per type, as `resource.id` is in {{AUTHZEN}}, it includes the type, after the classification: `external:mailbox:press@partner.example`. A classification may stand for the type where identifiers of the types that share it cannot be equal, as with email addresses beside `doc:`-prefixed documents in the examples of this document. Those identifiers carry the guarantee. The PEP evaluates and records the canonical identifier of the target it actually acts on, after resolving aliases, distribution lists, redirects and shortened links, never the agent's spelling. The deployment defines that canonical form for each resource type, and every PEP of the deployment uses it. Because a pattern can only fix a prefix, where policy distinguishes trust domains the canonical form MUST put the classification first, as in `external:press@partner.example`, even when the resource system's native form puts it last (the domain of an email address). A target the PEP cannot classify MUST be recorded in the most exposed trust domain the deployment defines, as an unrecognized result class is the top, so that a step keyed on that domain still matches it.

**One target per Act.** An Act's resource denotes one target. A call with several targets, such as a send to several recipients or to a list resolved to its members, MUST be admitted as one Act per target, and the PEP MUST make the call to the targets it admitted, not to a list or alias the resource expands later. Recording the list itself (`group:all-hands`) would hide its external member from an `external:*` step, and recording one target for all would let a person's approval of that target ({{approvals}}) cover recipients the person never saw. The PEP evaluates and admits the targets one at a time, each against the history that holds the earlier ones, and starts the call only once every target is admitted; if any target is denied, the PEP does not make the call and records the targets it already admitted `failed`. Every admitted target stays open until the call has run, so rule 5 holds back a target that would fill a different step of a sequence than an earlier target fills (the PEP recognizes the case: it holds the earlier targets admitted and not started), and the PEP MUST then record those targets `failed` and split the call into one call per target. It MUST also split a call with a target denied as a requestable `prohibited_composition`: an approval covers one Act at one position, and a target admitted and then recorded `failed` because another was denied has used its approval and its position, so evaluating the whole call again can need a fresh approval every time.

**Where to put the persistent mark.** Write the sequence in the order the data flows and put the lasting effect at the step where it exposes the data, usually the last: `(read, write, share)`, with `share` persistent. The mark then also counts a share created earlier. A mark on the first step would change nothing, since no step comes before it, and a PDP MUST refuse to load a set that has one.

**Where to put class patterns.** A class pattern narrows a step to Acts whose recorded classes it covers. An operation that transforms, summarizes or encodes the data may honestly classify its output with another recognized class, such as `public`, and then no longer matches a class-keyed step, so the sequence is not completed while the data still flows. Policy authors SHOULD put class patterns only on the step that originates the sensitive data, usually the read, and leave the later steps (write, stage, send) without class patterns, so that they match however the data was relabeled. This costs false positives (a later write counts even when it carried nothing sensitive), which ARAP routes to a person.

# History Authority {#authority}

One History Authority per Mission holds the Mission's history. It may be the PDP's own evidence store, the party that issued the Mission, or a separate service; this profile requires its behavior, not its form. A log the agent reports about itself never qualifies. A non-normative Mission History Service with an HTTP binding accompanies this draft as one way to meet these requirements.

The History Authority MUST:

1. authenticate every writer from a verified credential, never from a name the caller presents and never from a credential issued to an agent, and record the writer's identity itself;
2. accept a new Act only at the next position of a gapless, Mission-wide sequence starting at 1, rejecting any other position, as one linearizable step per Mission, failover included; except that an admission retried by the same writer with the same `admission_id`, position, action and resource returns the Act already admitted, with its outcome (an Act that already has one is no acknowledgement, rule 3), and an `admission_id` the same writer reuses for a different Act is rejected (an `admission_id` is scoped to its writer and Mission);
3. acknowledge an admission or an outcome only once it is durable, and answer a read that pins the Mission's set (item 6) only once the pin is durable;
4. allow an Act's outcome to move only from open to `completed` or `failed`, once, and only by the writer that admitted it, except as item 7 allows; accept a repeat of the outcome already recorded (result classes compared as a set) and reject a different one; reject result classes on a `failed` outcome, and any result class that is empty or contains `*`; and accept an outcome for an Act admitted with an `admission_id` only from a report that names that `admission_id`, refusing any other for good: a position can be reused after a failure that loses an Act, and an outcome kept for the lost Act never lands on the Act now at its position, even one admitted by the same writer;
5. authenticate the PDP for reads and authorize it for the Mission (only a PDP the deployment designates for the Mission, for example one of its tenant, reads it or names a digest for it, besides the auditors the deployment designates, who read without naming a digest), and return the history in Admission Order with every position from 1 to the latest, holding only Acts and outcomes already durable, whether the authority or a replica serves the read: an Act that could still be lost would give a PDP a history that is not a prefix of the authority's, yet of the length that names the authority's next position, so rule 2 would not catch a decision taken on it;
6. bind the Mission to one set of Restricted Sequences ({{fixed-policy}}): the first read by a PDP authorized for the Mission that names a set, by its policy digest, pins it; a read naming another digest is refused; and no caller but a PDP can name a digest, so a writer cannot choose the set. Accept also, from the deployment, a designation of the sets new Missions may be pinned to: once one is given, a read that would pin a new Mission to any other set is refused and pins nothing, and a designation of no set lets no new Mission be pinned, so that, with a single set designated, which PDP reads first no longer decides the set;
7. never record an Act `failed` on anyone's word but the admitting writer's. An operator MAY close an Open Act whose PEP will never report, but only as `completed` with no result classes, which the PDP evaluates at the conservative top, and only once the Act's effect can no longer start or still be in progress (for example the PEP is stopped, its credential to the resource revoked, and no effect of the Act is queued or scheduled at the resource; a deferred effect the resource still holds, such as a queued send, is cancelled there first, or the Act stays open). Closed under that condition, the Act keeps counting at the top for the rest of the Mission: closing releases liveness, never the composition. Closed while its effect can still land, the Act lets a later Act's effect come first, the order rule 5 prevents;
8. never forget a Mission while a request carrying it can still be decided: delete, truncate or rewrite none of its records, for retention, erasure or any other reason, until the Mission has ended and every credential carrying it has expired, and then keep a tombstone of its identifier and refuse admissions and every read that names a policy digest for it, so that a deleted Mission reads as unusable (`history_unavailable`), never as empty; and after losing acknowledged records (a restore, or a failover to a replica that lacked them), refuse reads and admissions for every Mission that may be affected until an operator resolves them.

PDPs and PEPs MUST authenticate the History Authority they read from and write to, and reach it over a channel that protects integrity: a history read from an impostor, or altered in transit, can leave out any Act.

The History Authority SHOULD also restrict which writers may admit into a Mission to the PEPs in that Mission's enforcement scope. Any authenticated writer that can admit into a Mission can stall its sequences with an Act it never resolves, or fill positions to deny others; it cannot hide another writer's Act.

An Act Record holds `seq` (its position, an integer from 1), `action` and `resource` (the action name and the canonical resource identifier admitted, each a non-empty string), `outcome` (`open`, `completed` or `failed`), `result_classes` (the result classes recorded, each a non-empty String without `*`; empty for a `failed` Act, and those of an `open` Act are not read) and `recorded_by` (the writer, a non-empty string). This document fixes what a record holds, not how a wire encodes it, which is the deployment's (open question 1); the accompanying binding carries the action as `{"name": ...}` and the resource as `{"id": ...}`. The History Authority also keeps the `admission_id` the writer gave, if any: a String the PEP generates for one admission and reuses only to retry that admission, unique for the writer within the Mission; a read need not return it. A History Authority MAY record further members for audit; the predicate does not read them. A record that lacks `seq`, `action`, `resource`, `outcome`, `result_classes` or `recorded_by`, or holds a value outside what this paragraph allows, makes the history unusable ({{ordering}}, rule 4).

# Ordering rules {#ordering}

The predicate is sound only if the history it reads is ordered, complete, and in the order the effects happened, across every PEP that enforces the Mission. A deployment that uses the composition predicate MUST meet these five rules, and every PDP that decides for a Mission MUST apply the same set of Restricted Sequences to it. A PDP that knows fewer sequences would permit, without `mission_record`, an Act another PDP treats as Step-matching.

1. **One order.** All Acts of a Mission that can match a step of a Restricted Sequence are admitted at its History Authority.
2. **Serializable admission.** An Act is admitted only at the position the PDP evaluated against. If another Act was admitted in between, admission fails, and the PEP MUST NOT act on that permit; it MAY evaluate again. This applies to every Act that matches some step of some Restricted Sequence, including a final step on an empty history, since a concurrent admission could supply the prefix. Other Acts need not be admitted, and their PEPs MAY perform them without serialization.
3. **Admission before effect.** The PEP MUST NOT begin the action until the History Authority has acknowledged the admission; an answer that returns the Act with an outcome already recorded is not an acknowledgement. If no acknowledgement arrives, the action MUST NOT start. A PEP that retries an unacknowledged admission MUST reuse its `admission_id`. A PEP that gives up on an unacknowledged admission MUST resolve it, since it may have committed: it records the position `failed`, which it can truthfully assert because the Act never ran, and delivers that outcome again until the History Authority records or refuses it ({{pep}}); otherwise an Act admitted and never performed stays open and holds back its sequences (rule 5). Giving up is final: the PEP MUST NOT start the action on a later answer to that admission. An answer that refuses the admission for good (the position is taken, the Act is malformed, the writer is not trusted) shows that nothing was admitted, and no `failed` is owed; a timeout, a server error or an unreadable answer may hide a commit. A PEP MUST NOT admit an Act, or start its effect, after the credential carrying the Mission has expired, after the Mission has ended, or, for a permit an approval produced, after the approval's `approved_until`; it gives up instead.
4. **Completeness.** The PDP MUST deny with `history_unavailable` when it cannot read the Mission's history from the History Authority, when the positions it read are not exactly 1 to n, in that order, or when a record is not a valid Act Record ({{authority}}).
5. **Effect order.** An Open Act may not have produced its effect yet, so its effect can land after that of an Act admitted later. While an Act that matches a step of a Restricted Sequence is open, the PDP MUST NOT permit another Act that matches a step of the same sequence, unless, counting the steps of that sequence only, both match exactly one step and it is the same step. It denies with `history_pending`, and the PEP evaluates again later, after a backoff: it cannot observe the open Act's outcome, and a PDP MAY include `retry_after`.

**Order of the checks.** The PDP decides a request in this order, and the first that applies gives the decision: (a) no Mission for a Step-matching Act ({{request}}), or a history that cannot be read or used: `history_unavailable`; a read refused for its policy digest: `policy_mismatch` ({{fixed-policy}}); in a batch, a request of the same Mission earlier in the `evaluations` array that the PDP permits could fill a step of a sequence this Act could also fill: `history_conflict` ({{pdp}}); (b) the predicate is unsatisfied and no valid approval covers it: `prohibited_composition`, requestable or not as {{predicate}} and {{approvals}} say; (c) rule 5: `history_pending`; (d) a Step-matching Act whose PEP has not opted in to `mission_record` ({{obligation}}): plain deny; (e) otherwise the PDP's other policy decides, which this profile does not change, and a permit for a Step-matching Act carries `mission_record`. These checks only add denials to that policy: an approval lifts check (b) and nothing that policy decides. An Open Act is matched at the conservative top, so a completion that involves it is reported under (b), although the Act's outcome may later show that it completes nothing; a PEP MAY evaluate again after its own open Acts have outcomes before it submits an Access Request. A valid approval lifts (b) only: the approved Act still waits under (c) until the Acts of its sequences that are open have an outcome, and a PEP that has not opted in to `mission_record` never holds a valid approval: its denial is never requestable ({{predicate}}), and an approval binds the adoption declarations ({{approvals}}).

**Why these five.** The rules work together; none stands alone. Rule 2 is the only serializer across concurrent evaluations: two Acts evaluated against the same history cannot both be admitted. Rule 5 covers what rule 2 cannot see, an Act already admitted whose effect has not happened. Every effect starts after its own admission (rule 3). The resulting invariant, which a conforming deployment MUST maintain, is: **for each Restricted Sequence, no two Acts matching its steps are open at the same time, unless both match exactly one of its steps and it is the same step.** So for each sequence, effects happen in Admission Order, up to swaps that change no match. The invariant is sufficient, not necessary: it also holds back some Acts whose effects could land in either order without completing a sequence that Admission Order does not, such as a send held back by an open write of `(read, write, send)` when the Mission has no read (open question 11). Admission Order alone is not enough: a send admitted first that stalls, then a read admitted and run, then the send resuming, gives the prohibited effect order. When the send names its payload by reference, such as a document a later write fills, data the read produced reaches it.

**Stale reads.** A PDP that reads a view missing the latest Acts names a position the History Authority has already assigned, so the admission fails under rule 2 and the PEP evaluates again. A PDP MAY therefore read history from a replica, provided admission happens at the History Authority itself and the replica serves only durable records (item 5), so that every view is a prefix of the authority's history. The policy pin ({{fixed-policy}}) is different: an Act that matches no step gets no `mission_record` and is not admitted, so nothing re-checks the pin later. A replica MAY check a pin it holds, since a pin never changes once set, but a read that would set the pin MUST be served by the History Authority itself. A PDP SHOULD also read from the History Authority itself before it returns a requestable denial: an approval given for a denial decided on a stale view names a position already taken and can never be used.

**Why complete, not only authentic.** Signed records prove that each record presented is genuine. They do not prove that none is missing. For composition, omission is the attack: a history that leaves out the earlier read of salary data makes the later send look harmless. History carried by the caller, even signed, is therefore insufficient for this predicate.

**Scope of the guarantee.** It covers the PEPs that admit at the Mission's History Authority, and effects that start at those PEPs. A PEP or trust domain that does not admit there is outside the predicate, as a channel that bypasses a PEP is outside it. The deployment states which PEPs admit there, its enforcement scope.

**Data that moves through references.** The predicate sees Acts, not content. It covers a flow only if every operation through which the data moves is itself an admitted Act that a step matches. If a send carries a document by reference, the write that filled the document has to be a step of the sequence, enforced at an in-scope PEP. Policy covers such a flow only if it includes those intermediate steps; a flow through an operation outside the Restricted Sequences, or outside the enforcement scope, is not covered.

## One set of Restricted Sequences per Mission {#fixed-policy}

The set of Restricted Sequences that applies to a Mission MUST NOT change during the Mission. An Act that matches no step of the set in force gets no `mission_record` and is not admitted (rule 2), so a set that gains a sequence mid-Mission would evaluate it against a history from which earlier, now relevant Acts are missing. A PDP replica that applies an older or newer set also skips rule 5 for sequences it does not know.

To enforce this, a PDP MUST identify the set it applies by a policy digest, a stable hash of a canonical form of the set, and MUST name it on every history read it decides an Access Evaluation on. For every Access Evaluation that carries a Mission, alone or in an Access Evaluations request, including one for an Act that matches no step of its set, a PDP MUST make such a read and decide only on an answered one; a read refused for its digest is a `policy_mismatch` denial, and any other refused or failed read a `history_unavailable` one; neither is a precondition met. That read is what binds a new Mission, and an Act decided without it could run unadmitted under a set the Mission is not bound to. Every PDP deciding for a Mission MUST compute the same digest for the same set, and MUST compute it from the set as it parsed it, not from the bytes of a policy document alone: two PDPs that read one document differently (a member given twice, or `"false"` as a string where a boolean is expected) would otherwise share a digest while applying different sets. The digest is defined in {{policy-digest}}, so PDPs of different implementations and releases compute the same digest for the same set; a deployment still has to give every PDP the same set, for example from a policy document every PDP rejects unless it parses it strictly. A digest that differs for the same set fails closed: the read is refused. The History Authority pins the first digest named for the Mission and refuses reads that name another. A refused PDP denies with `policy_mismatch` and does not decide. A deployment that changes its set designates at the History Authority the sets new Missions may be pinned to ({{authority}}, item 6). The designation is the deployment's configuration, never set by a PDP or a PEP, and it is checked where the pin is set. While the old and the new set are both designated, as during a gradual rollout, the first PDP read still chooses between them. Once only the new set is designated, every new Mission is pinned to it whichever PDP decides first, and a PDP that still applies the old set denies a new Mission with `policy_mismatch`. A designation never moves a pin already set: the deployment keeps the old set available until the Missions pinned to it end (open question 13 gives the interim reading).

## Policy digest {#policy-digest}

A PDP computes the policy digest from the Policy Object of the set, a JSON object it builds from the set as it parsed it, with these members:

* `restricted_sequences`, REQUIRED: an Array with one member per Restricted Sequence, each an Object with `name` (a String, with no default), `requestable` (a Boolean) and `steps`, an Array of the steps in sequence order, each an Object with `action` (a String), `resources` (an Array of Strings, the step's resource patterns), `result_classes` (an Array of Strings, its class patterns) and `persistent` (a Boolean);
* `label_domain`: an Array of Strings, the class patterns of the label domain ({{result-classes}}), present if and only if the set declares one.

Every member listed is present, `label_domain` only as just said, with its default where the set leaves it unstated: `requestable` and `persistent` are `false`, `resources` and `result_classes` are empty. `resources`, `result_classes` and `label_domain` are sets: each value appears once, in ascending order of its UTF-8 bytes {{RFC3629}}. `restricted_sequences` is a set too: each sequence, its own sets first put in this form, appears once, in ascending order of the bytes of its own canonical serialization. The canonical serialization of a value is its JSON Canonicalization Scheme form {{RFC8785}}, in UTF-8. The policy digest is the String `sha256:` followed by the lowercase hexadecimal SHA-256 hash {{RFC6234}} of the canonical serialization of the Policy Object. So neither the order in which a deployment lists its sequences or patterns, nor a repeat, changes the digest, while any change to what the set prohibits does. The test vectors carry the digest of each scenario's policy, which is already a Policy Object.

# The `mission_record` obligation {#obligation}

On a permit for an Act that rule 2 requires to be serialized, a Step-matching Act, the PDP MUST return exactly one `mission_record` obligation {{OBLIGATIONS}}, whose `expected_seq` is the next position: one more than the latest position in the history it decided on, or 1 on an empty history:

~~~ json
{
  "decision": true,
  "context": {
    "obligations": [
      {
        "id": "obl-1",
        "type": "mission_record",
        "properties": {
          "mission": "msn_8f14e45f",
          "expected_seq": 3
        }
      }
    ]
  }
}
~~~

`mission_record` is mandatory-to-understand. Before any effect, the PEP MUST admit the Act at the Mission's History Authority at `expected_seq` and receive the acknowledgement (rule 3). If the admission is rejected, the PEP MUST NOT act on this permit; it MAY evaluate again. After the Act, the PEP MUST record the outcome, keeping one it cannot deliver and delivering it again ({{pep}}). A PEP that cannot admit the Act and record its outcome treats the permit as a deny. When the permit also carries obligations that have to be met before access, the PEP admits the Act only once they are met, so that it never admits an Act it will then not perform; the Obligations Core lets an Obligation Type set such an order {{OBLIGATIONS}}. The PEP writes only to a History Authority it is configured to trust; the obligation names the position, not the service.

Its `properties` have exactly two members, both REQUIRED: `mission`, a String equal to the request's `mission.id`, and `expected_seq`, the position at which the PEP admits the Act: an integer from 1 to 2^53 - 1, written as a JSON number {{RFC8259}} without a fraction or an exponent, so that every JSON parser reads it exactly. No member and no value is ignorable: a `mission_record` that lacks either member, gives one another JSON type, names another Mission, or carries any other member in `properties` is one the PEP cannot comply with {{OBLIGATIONS}}, so it treats the permit as a deny. A permit carries at most one `mission_record`; a PEP that receives more treats the permit as a deny. A PEP complies by admitting the Act at `expected_seq`, receiving the acknowledgement before any effect, and recording the outcome. A PEP that treats the permit as a deny, for this or any other reason, performs no Act and so has nothing to admit or record: not admitting is how it complies, and it MUST NOT knowingly admit an Act it will not perform (an admission it gave up on is resolved as rule 3 says). This is what executing `mission_record` means under the Obligations Core's rule that a PEP treating a permit as a deny still executes the obligations it understands {{OBLIGATIONS}}: with no Act, there is nothing to admit. A PDP returns `mission_record` only on a permit.

A PDP MUST NOT issue a permit for a Step-matching Act unless the PEP listed `obligations` in `supported_mandatory_extensions` and `mission_record` in `supported_obligations` (an omitted list is empty). Otherwise it returns a plain deny, with no obligation, as the Obligations Core requires when policy needs an obligation the PEP has not adopted {{OBLIGATIONS}}. An Act that matches no step needs no obligation and no opt-in.

# PDP processing rules {#pdp}

The PDP:

* MUST NOT reuse a decision for a Mission across Acts, because each admission changes the history;
* in an Access Evaluations (batch) response, MUST NOT permit two Acts of the same Mission that could each match a step of the same Restricted Sequence against the same history. Of such Acts it permits at most one: a later Act conflicts only with an earlier one the PDP permits (check (a) of {{ordering}}), so an earlier Act denied for any other reason does not stop a later one from being decided on its own. It denies the later ones with `history_conflict`, and the PEP evaluates them again in turn. Acts of different sequences are not denied by this rule, but each admission takes the Mission's next position, so of two such Acts permitted against the same history only the first admits; the second fails admission (rule 2) and is evaluated again. This holds under every `evaluations_semantic` of {{AUTHZEN}}: under `deny_on_first_deny` the conflict denial short-circuits as any other denial does;
* treats Search API results for a Mission as hypothetical. A Search result is never an admission and carries no `mission_record`, a Search reads the history, if at all, without naming a policy digest, so it does not pin the Mission's set, and every Act is evaluated with Access Evaluation before it runs;
* MUST publish what the Obligations Core requires of a PDP that issues `mission_record`: the capability URN `urn:openid:authzen:capability:obligations` in the `capabilities` metadata member {{AUTHZEN}}, and `mission_record` in the `supported_obligations` metadata member {{OBLIGATIONS}}, from which a PEP discovers this profile. This profile defines no capability URN of its own: the Extensibility Model has a PDP advertise in `capabilities` the extensions it implements that have an Extension Identifier (`context.mission`, being advisory, has none), and gives a profile a profile identifier ({{AUTHZEN-EXT}}, Placement; Requirements for Profiles; {{iana}});
* MUST set `context.reason` of each denial this document requires to the reason it names for it, in the member ARAP uses for machine-readable reasons {{ARAP}}: `prohibited_composition`, `history_unavailable`, `history_conflict`, `history_pending` or `policy_mismatch`. Only `prohibited_composition` can be requestable. The other four mean "evaluate again later", except a `history_unavailable` for a request without a Mission, which waiting cannot change. After `policy_mismatch` the request can succeed only at a PDP that applies the set the Mission is pinned to or, for a Mission not yet pinned, a set designated for new Missions; the denial does not name the set, so a deployment that applies several sets routes each Mission's requests to PDPs of its set (open question 8). A plain deny of check (d) carries no reason; an ARAP PEP takes its next action to be `none`. When the request presented an approval (`context.approval`), a denial with one of those four reasons MUST carry `next_action` set to `retry` {{ARAP}}, except a `history_unavailable` for a request without a Mission, which MUST carry `none`, since waiting cannot give it one, and a PDP that the History Authority tells the Mission was deleted ({{authority}}, item 8) sends `none` too; with `retry_after` where the PDP can estimate it, as ARAP recommends with `retry`: until the reasons are registered in ARAP's registry, an ARAP PEP does not recognize them, and one that receives no recognized `next_action`, no recognized reason and no `context.access_request` takes the next action to be `none` and abandons a valid approval. When such a denial answers a request that presented an approval, with `policy_mismatch` it SHOULD include `retry_after`: the denial is transient only because the deployment routes the retry to a PDP of the Mission's set, or the PDPs' sets converge, not at the same PDP with the same set. These reasons are distinct from `history_not_satisfied` of {{MISSION-AUTHZEN}}, which reports that a history predicate of that profile is false or cannot be established from the PDP's evidence store; outside re-evaluation, a deployment that applies both profiles tells them apart by value, and if the predicate is also named in that family (open question 4), its reasons follow that family's naming rule. At a re-evaluation that presented an approval, {{MISSION-AUTHZEN}} returns one of ARAP's five re-evaluation reasons, while this document returns its own reason with an explicit `next_action`; until the two families agree (open question 4), such a deployment returns this document's reason for the checks this document defines, and the PEP acts on `next_action`;
* applies the fail-closed rules of a single evaluation to each request of a batch: a history it cannot read or use denies that request, it does not fail the batch.

# PEP processing rules {#pep}

The PEP:

* MUST run outside the agent's control: its code, its credentials to the PDP, the History Authority and the resource, and its store of unreported outcomes MUST NOT be readable, writable or invocable by any code the agent can cause to run (tool code, a shell, an interpreter, a plug-in), for example by process, host or service separation. A PEP inside the agent's process or sandbox is not in the enforcement scope;
* MUST take the Mission from a trusted input the agent cannot mint, never from the agent's request ({{request}});
* MUST send a request that carries a Mission only to a PDP whose metadata lists `mission_record` in `supported_obligations` ({{pdp}}): a PDP that does not implement this profile ignores the Mission and permits without `mission_record`, which the PEP cannot tell from a permit for an Act that matches no step;
* MUST NOT cache a decision for a Mission, because each admission changes the history;
* when it evaluates again with an ARAP approval and the denied evaluation carried an actor in `subject.properties.act` or in `context.actor`, MUST send that actor in the same member, unchanged except for a `client_instance_id` that another instance of the client replaces as ARAP allows ({{approvals}}), and MUST NOT move it to `client.actor`, so that the approval scope ({{approvals}}) can compare it. ARAP lets a PEP normalize the actor in an Access Request submission; until the Working Group settles how the actor is carried at re-evaluation (openid/authzen issue #744), this profile requires the member the denied evaluation used;
* MUST carry in `action.properties` or `resource.properties` every argument of the call that decides what its effect discloses, or to whom (the content written or sent, each attachment; the target itself is the resource), evaluate the resource by its canonical identifier ({{patterns}}), perform exactly the evaluated action, with exactly the evaluated properties, on the resource that was evaluated, and record that identifier. The Authorization API assumes the PDP trusts the PEP on this ({{AUTHZEN}}, Trust); this profile adds no binding of its own (compare the COAZ-MCP binding, which binds a permit to the forwarded operation, openid/authzen issue #603);
* in front of a composite tool, one call that performs several operations (export a report and mail it), MUST evaluate and admit each operation as its own Act, in order, each admitted before its part runs. An Act that is not persistent fills one step, so a single call that both reads and sends never completes a sequence. A PEP that cannot split the call MUST NOT perform it unless ordinary policy permits the whole call and no part of it could fill a step of a Restricted Sequence in force: the unsplit call is not admitted, so no later decision would see it (an export that reads salary data and mails it internally leaves a later external send unchecked);
* MUST NOT record `completed` until every effect of the Act has happened. A call that returns before its effect, such as a queued or scheduled send (`202 Accepted`) or an asynchronous job, leaves the Act open until the PEP learns that the effect happened, and `failed` only if the resource confirms it never will. Recording the acceptance as completion would let a later read land before the send that carries its data. An effect that continues or recurs is a persistent step, a matter for policy ({{patterns}});
* records the outcome after the Act, and MUST NOT record `failed` unless it knows the action had no effect, for example the resource rejected the call before acting. A timeout, a lost response or a crash is not proof of non-execution: the PEP leaves the Act open, which the PDP evaluates at the conservative top;
* MUST give every admission an `admission_id` it generates for that admission (an admission without one cannot be told from another at the same position, so item 4 of {{authority}} cannot protect it; a History Authority MAY refuse such an admission), and MUST name, in every outcome it reports, the `admission_id` of the admission the outcome belongs to; if it cannot write the outcome, it MUST keep it with that `admission_id`, durably across restarts, and deliver it again later, until the History Authority records it or refuses it for good: the Act already holds another outcome, there is no Act at that position, or the Act there belongs to another admission. A refusal for good is an incident, except the refusal, for want of an Act, of a `failed` delivered for an admission the PEP gave up on (rule 3): an outcome the PEP did not write now stands for the Act (an operator closed it, {{authority}}, item 7, or another holder of the PEP's writer identity reported it), or the History Authority lost an Act it acknowledged (item 3) and may have given its position to another. Until the outcome is recorded, an Act that is still open is evaluated at the conservative top, which never weakens the predicate.

# Conformance {#conformance}

This document has four conformance targets.

* A PDP conforms if it meets the Mission rules of {{request}}, {{predicate}} and {{approvals}}, the matching and load rules of {{result-classes}} and {{patterns}} and of the Restricted Sequence (Terminology), rules 4 and 5, the order of the checks and the stale-reads rules ({{ordering}}), {{fixed-policy}} and {{policy-digest}}, the History Authority authentication rule of {{authority}}, the rules for issuing `mission_record` ({{obligation}}), and {{pdp}}.
* A PEP conforms if it meets the Mission rules of {{request}}, the result-class rules of {{result-classes}}, the canonical-identifier and one-target rules of {{patterns}}, the History Authority authentication rule of {{authority}}, rules 2 and 3 ({{ordering}}), the compliance rules of {{obligation}}, and {{pep}}.
* A History Authority conforms if it meets {{authority}}.
* A deployment conforms if its PDPs, PEPs and History Authority conform, it meets rule 1, gives every PDP of a Mission the same set of Restricted Sequences ({{fixed-policy}}), and meets the requirements this document places on it: Mission identifiers, delegation and agent instances ({{request}}), canonical forms ({{patterns}}), where its PEPs run ({{pep}}), and when an operator may close an Act ({{authority}}, item 7); where its PDPs make denials requestable, its Access Request Service meets the rules of {{approvals}} that name it (task expiry, what the approver sees, who approves).

Each target also follows the recommendations of {{security}} addressed to it.

The interop vectors that accompany this draft test PDP conformance only.

# Extension checklist

In the terms of the AuthZEN Extensibility Model {{AUTHZEN-EXT}}, this document defines an extension and a profile that selects it. The extension is `context.mission` alone: a request context member that identifies a Mission (`mission.id` identifies it; that the History Authority keys on it is this profile's use), use-case neutral, and to be defined once with the mission-bound family ({{request}}). Everything else (the predicate, the ordering and History Authority rules, the `mission_record` Obligation Type and the denial reasons) is the profile, which selects that extension, the Obligations Core {{OBLIGATIONS}} and ARAP {{ARAP}}. Neither part defines a mandatory-to-understand member of its own, so there is no Extension Identifier: the only mandatory element, `mission_record`, is carried by the Obligations Core's `obligations` member. As the Model asks of a profile, this one identifies the extensions it selects, relaxes none of their requirements, defines no adoption signal of its own ({{request}}), and registers a profile identifier ({{iana}}). The items the Model asks an extension specification to define, for both parts:

| Item | This document |
|---|---|
| Elements | `context.mission` in the request `context`, of which this profile reads only `id` (a String, the History Authority's key) and requires `issuer` without reading it, as the mission-bound family does; its definition is to be agreed with that family ({{request}}); Obligation Type `mission_record` in the Obligations Core's `obligations` member of the decision `context`; reasons `prohibited_composition`, `history_unavailable`, `history_conflict`, `history_pending`, `policy_mismatch` in the decision `context`'s `reason`. Result classes and persistent steps belong to the History Authority's records and to policy, not to the AuthZEN surface |
| Processing strength | `context.mission` and the reasons: advisory. `mission_record`: carried in the Obligations Core's `obligations` member, which is mandatory-to-understand |
| Mandatory-to-understand processing | Extension Identifier `obligations`, the Obligations Core's; the opt-in is the PEP's; item negotiation: `supported_obligations` contains `mission_record`; fail closed: a PEP that cannot comply treats the permit as a deny and admits nothing ({{obligation}}); when adoption is not established, the PDP returns a plain deny for a Step-matching Act; no separate signal for this profile |
| Unknown handling | Permits: an unknown member or value in `mission_record` means the PEP cannot comply, so the permit is a deny ({{obligation}}). Denials: an unknown reason does not alter the decision; a `mission_record` on a deny is never sent, and a PEP that receives one admits nothing. Side effects: admission and outcome are the only ones, and happen only on a permit the PEP complies with. In evaluation: an unknown result class, an open outcome and a completed Act without classes are the conservative top |
| Absence | No `context.mission`: `history_unavailable` for a Step-matching Act, core evaluation for any other. No opt-in where policy needs it: plain deny |
| Binding | `context.mission` is decision-relevant: it comes from a trusted input and is integrity-protected between PEP and PDP ({{request}}); history from the History Authority only; writer identity from a verified credential |
| Composition | Obligations Core (fail closed), ARAP (escalation, approval scope narrowed to one use at one position, {{approvals}}), delegation (delegated Acts carry the delegator's Mission, {{request}}), bounded grants (openid/authzen issue #521; both may apply) |
| Placement | Access Evaluation and Search: the request `context`. Access Evaluations (batch): the top-level `context`, or each per-evaluation `context`, which replaces it, so a PEP that supplies one repeats `mission` and the adoption declarations there ({{request}}); the reason and `mission_record` in each Decision's `context` |
{: title="The items the AuthZEN Extensibility Model asks an extension to define"}

# Security considerations {#security}

* **Omission.** Defeated by a gapless order read from the History Authority, not from the caller.
* **Forged history or classes.** The agent supplies neither. A compromised PEP can mislabel the Acts it enforces and, like any authenticated writer, deny or stall other PEPs' Acts, by filling positions or leaving an Act open ({{authority}}); it cannot hide, alter or weaken them. It cannot pin the Mission's set of Restricted Sequences either: only a PDP's read does ({{authority}}, item 6).
* **A compromised History Authority.** The History Authority is the one party every rule trusts: one that leaves out, reorders or forges records defeats the predicate, and nothing in this profile detects it. Deployments run it with the controls of an audit system (few operators, append-only storage, an independent audit of its log). Signed or transparency-logged records would let PDPs detect some misbehavior; this profile does not define them (open question 12).
* **One authority per Mission.** `mission_record` names a position, not a service. A PEP configured with another History Authority than the one the PDP read (a misconfiguration, or a sharded deployment that routes a Mission inconsistently) admits where the PDP never looks, and the completeness check (rule 4) passes on a history without the Act. Rule 1 requires one authority per Mission; a deployment that shards routes every PDP and PEP by `mission.id` the same way. Open question 12 also asks whether `mission_record` should name the authority.
* **Writer authentication.** The guarantee rests on the History Authority knowing which PEP wrote each record. A writer identity taken from a presented name lets any caller mark another PEP's read `failed`.
* **`failed` is an assertion.** The History Authority cannot verify that a `failed` Act had no effect; it trusts the PEP that admitted it. A wrong `failed` removes the Act from the predicate, so it is a soundness failure, not a false positive.
* **Races and effect order.** Rules 2, 3 and 5.
* **Open Acts.** Evaluated at the conservative top, so a crash between an Act and its record cannot hide a sensitive read. An Open Act is resolved by a later report from its PEP, by an operator closing it at the top ({{authority}}, item 7), or by the end of the Mission. Until then it holds back the Acts of its sequences (rule 5). An operator can close it only once its effect can no longer happen: for a deferred effect the resource holds, such as a queued send that names its attachment by reference, stopping the PEP is not enough. An admission that reaches the History Authority only after its PEP gave up on it, and after the `failed` that PEP delivered was refused because no Act was there yet, is stranded the same way. A `history_pending` denial is not requestable: a person cannot approve an Act past an effect that may still be in progress.
* **Decision and effect at different times.** The predicate holds at the moment each Act is admitted. It also holds for effects that happen later, if the PEP keeps the Act open until the effect has happened (deferred effects) or policy marks the step persistent (lasting effects). An integration that records `completed` on acceptance, or a lasting effect that policy did not mark, breaks the guarantee without any visible error.
* **Policy change and rollout.** Pinning the policy digest per Mission ({{fixed-policy}}) turns version skew between PDP replicas into a `policy_mismatch` denial instead of a decision taken with the wrong sequences. Once a single set is designated at the History Authority, that designation, not the PDP that happens to read first, decides which set a new Mission gets; with no designation, or several designated sets, the first PDP read still chooses, so a deployment SHOULD designate the set it means new Missions to get. A Mission keeps its set for its whole life, so a stricter set protects only the Missions pinned after it is designated.
* **Naming.** The agent chooses the strings it asks for. Matching on the PEP's canonical identifier of the resolved target ({{patterns}}) keeps an alias, a list or a differently spelled address from slipping past a pattern.
* **False positives.** Matching on action types and result classes is conservative. Policy precision narrows this, and ARAP routes the remaining cases to a person instead of refusing them. An approval covers one Act at one position ({{approvals}}), so the cost is per Act: once a Mission holds Acts that fill the earlier steps of a sequence, every later Act that completes it needs its own approval, such as each further external send after a matching read and a later write, or each further write after a matching read once a persistent share link exists. An approval also lapses when another Act is admitted before it is used. Open question 10 asks whether one approval may cover more.
* **Incomplete policy.** The guarantee is relative to the Restricted Sequences. An egress channel that no step names, such as a translation tool that calls an outside service, is not covered. Policy authors SHOULD name egress broadly, for example any action on `external:*`, rather than list the channels they thought of.
* **Aggregation.** Result classes describe each response on its own. Many reads each classified `public` can together reveal what none does; the predicate does not see that. A declared label domain that recognizes `public` recognizes it for every sequence, so such reads are not even caught by the conservative top; where aggregation matters, key the originating step on the action and resource rather than on a class.
* **Relabeling.** A result class is only as good as the classification of the response it describes. A step after the originating read that requires a sensitive class is missed when an intermediate operation honestly reclassifies its output; leaving later steps without class patterns avoids this ({{patterns}}).
* **Mission identifier collision.** Two issuers that mint the same `mission.id`, by accident or because a federated issuer mints another issuer's identifier on purpose, merge two Missions into one history. Under one set of Restricted Sequences that only adds Acts, so it never permits a composition the separate histories would deny, but it can deny Acts and invalidate approvals of the other Mission. The merged Mission also has one pin ({{fixed-policy}}): the later Mission is decided under the set the earlier one was pinned to, which can lack a sequence of the set designated when the later one started, and an Act of that sequence then runs unadmitted. A designation does not prevent this, since the History Authority sees no new Mission. Hence the uniqueness the guarantee assumes ({{request}}); a History Authority that is given the issuer with each admission and read SHOULD record the first and refuse another for the same identifier, accepting that it then refuses PEPs that carry different `issuer` values for one Mission.
* **Approval state across replicas.** A replica honors an approval only if it can verify it, from shared state or from approval material such as a signed `approval.state`, and check its current status as ARAP requires {{ARAP}}; one that cannot denies a valid approval, which is safe but stops the ARAP flow.
* **Mission splitting.** An agent that can open a new Mission at will starts a fresh, empty history and escapes the predicate. So does a delegation that gives a sub-agent its own Mission. The guarantee holds only within one Mission. Deployments SHOULD make Mission creation a governed step, and delegation carries the delegator's Mission ({{request}}).
* **Flows between Missions.** The predicate sees one Mission's Acts. Data that one Mission's Act puts in a resource another Mission can reach, at the same time or later, leaves the guarantee: a document written in Mission A and sent, by reference or after a read, in Mission B completes no sequence in either. This holds for every shared resource (a document store, a mailbox, a ticket queue, an agent's long-term memory) and needs no Mission opened at will: two governed Missions suffice, and an attacker needs to steer only the agent of the Mission that sends. A deployment that needs such flows covered persists, with each object an in-scope Act writes, the result classes of the writing Mission's Acts admitted before the write (artifact lineage, {{MISSION-WORK-PRODUCTS}}), and has the PEP admit the reading of an object a call carries by reference as its own Act, classified with those classes, before the call (open question 15). An agent instance that serves two Missions at once carries data between them itself ({{request}}).
* **Exposure the Mission did not create.** A share link, a forwarding rule or a partner sync that another Mission, a person or an earlier configuration created is not an Act of the Mission, so writing salary data into what it exposes completes no sequence unless the canonical identifier of the written resource names its exposure ({{patterns}}).
* **Approvers.** Approvals are where every false positive goes, so they are where an attacker pushes. An approver who sees only the denied request cannot tell a false positive from an exfiltration; an automated evaluator that reads content the agent authored can be steered by the same injection that steered the agent; agent-chosen names can carry confusable characters. {{approvals}} says what the approver sees and who approves.
* **A deleted or restored history.** A history deleted for retention or erasure, or rolled back by a restore, reads as a complete history with fewer Acts, which is omission ({{ordering}}, Why complete). {{authority}}, item 8, keeps a Mission's records while it can still be decided and fails closed after a loss.
* **A PEP within the agent's reach.** A PEP embedded where the agent's code runs lets a steered agent read its credentials, mark its own reads `failed` or call the resource directly. Writer authentication does not help: the agent then holds the writer's credential. {{pep}} requires the PEP to run outside the agent's control.
* **PDP authorization at the History Authority.** A PDP that may read any Mission can read every history and, by naming a digest first, pin a Mission it does not decide for to a set of its choosing, or to one no PDP of the Mission applies, which denies every Act of the Mission. {{authority}}, item 5, authorizes a PDP per Mission.
* **A PDP without this profile.** A PDP that does not implement this profile ignores `context.mission` and permits without `mission_record`, and the Act runs unadmitted. A PEP cannot tell that permit from one for an Act that matches no step, so it sends Mission requests only to PDPs that advertise `mission_record` ({{pep}}).
* **Classifiers and canonical forms that change.** The pin covers the sequences and the label domain, not the classifier or the canonical forms that produce the values they match. A classifier release, or a change to which domains are external, can stop an Act matching mid-Mission; a deployment applies such a change only to Missions pinned after it, or versions it in its policy.
* **Accountability.** An Act Record holds no subject, actor, permit or approval. A PEP SHOULD send with each admission an identifier of the permit's decision, and the History Authority SHOULD keep it; the PDP SHOULD log, for each permit with `mission_record`, the Mission, `expected_seq`, the evaluated subject, action and resource, and any approval used; and the History Authority SHOULD log every read.
* **Channels outside the PEPs.** A deployment cannot prove it routed every channel through a PEP. The predicate sees only Acts that were enforced.
* **Contention.** Every Step-matching Act takes the Mission's next position, so such Acts serialize at admission whatever sequences they belong to, and under rule 5 the Acts of one sequence run one at a time unless they match the same single step. Acts that match no step are unaffected.
* **Availability.** Every Access Evaluation that carries a Mission needs a history read ({{fixed-policy}}), so the History Authority's availability bounds every enforced Act of the Mission, and a history that grows without bound makes each read slower. Deployments size the authority as they size the PDP, bound a Mission's length, and have PEPs back off after `history_unavailable` and `history_pending`.
* **Input size.** History Authorities and PDPs bound the length of `mission.id`, action and resource identifiers and result classes, and the number of classes per Act, as they bound any input.
* **Timing.** The time a decision takes depends on whether the candidate matches a step and on how much history it scans, so it can tell an agent something about the policy. PDPs that face untrusted agents make it uniform where that matters.
* **Position probing.** A writer that may admit into a Mission learns how many Acts it holds, since positions are what it writes. Restricting writers per Mission ({{authority}}) limits who learns it.
* **The agent as adversary.** The agent chooses what it asks for. It can stall its own sequences with deferred effects that never complete, and a sub-agent under delegation can stall the delegator's Mission the same way; it can generate requestable denials to wear down approvers; and it can probe the policy through the denials it receives. Deployments rate-limit requestable denials and approvals per Mission, and need not pass the agent a denial's reason; the denial already does not name the sequence.
* **`mission_record` risks.** A PDP that omits `mission_record` on a permit for a Step-matching Act, by a defect or because it applies another set, lets the Act run unadmitted, outside rule 1. The obligation is not bound to the evaluated action and resource: a PEP that admits a different Act at that position defeats the predicate, and the profile relies there on the trust in the PEP the Authorization API already assumes. A permit's `expected_seq` is good once: replayed after that position is taken, its admission fails (rule 2).

# Privacy considerations

The history reveals what an agent did for a person and which classes of data it touched. Result classes name categories, never content, but a class together with a resource identifier (`hr:emp-4471` read with `personal_data.health`) is personal data of the resource's subject, so classes SHOULD be no more specific than the class patterns require. The History Authority SHOULD apply the access control and retention of the audit records of the resources involved, with retention running from the end of the Mission ({{authority}}, item 8).

`mission.id` correlates an agent's Acts across every PEP and vendor that enforces the Mission, and the History Authority holds all of them in one place; every PDP of the Mission reads all of it, not only the Acts its sequences match. Canonical resource identifiers can carry third parties' personal data, such as a recipient's address, and `recorded_by` reveals which PEPs a deployment runs. Deployments restrict history reads to PDPs and auditors, keep a history no longer than the Mission's audit needs, and do not link Missions through identifiers they do not need; Mission identifiers SHOULD be opaque, since they travel in paths and logs. The history exists for authorization and audit; using it for another purpose, such as monitoring the person an agent works for, is a secondary use that needs its own justification. An Access Request shows the approver the denied request, its resource included.

# Open questions {#open-questions}

1. Should the Working Group define a normative wire binding for the History Authority, so that a PEP and a History Authority from different vendors interoperate without bilateral agreement? The accompanying HTTP binding is a starting point.
2. Should denied attempts be recorded, so that policy can respond to probing?
3. Is a Mission-wide sequence the right primitive, or can a vector of per-emitter sequences plus a cut provide the same completeness with less coordination?
4. Should the predicate also be named as a history predicate type in the mission-bound drafts (Appendix C), which allow further predicate types under a naming rule, for example as `restricted_sequence_clear`, so that one definition serves both?
5. An approval is bound to the history position it was denied at, so any Act admitted in between, even one that later fails, invalidates it. Is a looser binding, such as "no new Act matching a step", worth its extra complexity?
6. A persistent Act stays in effect for the rest of the Mission. Should the profile model revocation (deleting the share link), which needs a reliable way to tie the revoking Act to the Act it revokes?
7. A Restricted Sequence relates Acts by type and order, not by object. It cannot tell a send that attaches the document the salary was written into from a send of an unrelated document later in the same Mission, so the second is a false positive that a person has to approve. Should a step be able to require that a member of its Act (the attachment of a send) equal the resource of an earlier step's Act? That removes those false positives, but a flow through an intermediate copy is then covered only if the copy is itself a step.
8. A History Authority holds one designation of the sets new Missions may be pinned to ({{fixed-policy}}). A deployment that applies different sets to different Missions at the same time, for example per tenant, designates them all and routes each Mission's first decision to a PDP of the right set. Should the Mission instead carry its policy digest, integrity-protected from its issuer? That removes the routing, but couples the issuer to the deployment's policy releases and adds a member every PEP forwards and every PDP verifies: a digest the PEP could choose would let it select an older set.
9. This draft defines the policy digest over a Policy Object whose members are those the test vectors use ({{policy-digest}}). If the Working Group defines a policy document format for Restricted Sequences, should the digest be defined over that format instead, and should a sequence's `name`, which changes no decision, stay part of it?
10. An approval covers one Act ({{approvals}}). After a matching read and a write, each later external send needs its own approval; after an approved persistent share link, each later write does. Should an approval be able to cover a bounded set of later Acts, for example every send to one recipient for the rest of the Mission, using ARAP's approval scope extensions {{ARAP}}, and what keeps such a scope as safe as single use under concurrent admissions?
11. Rule 5 holds back more than soundness needs. A send waits for an open write of `(read, write, send)` even when the Mission has no read, and an Act whose PEP stopped before reporting holds back every Act of its sequences until an operator closes it. Should rule 5 also let a candidate through when every step it could fill comes after every step an open Act could fill? That rule found no leak in an exhaustive check in the accompanying suite (`tools/rule5_exhaustive.py`), which tries every schedule of up to three Acts against every sequence of two or three steps over the actions `a` and `b` (with class patterns, and with or without a persistent last step; no resource patterns, so an open Act and the candidate fill the same steps or none in common, and partly overlapping step sets are not checked); other narrower rules are also sound, and a narrower rule changes only the PDP, permitting more only where this draft answers `history_pending`.
12. The History Authority is trusted for completeness, and `mission_record` does not name it. Should records be signed or transparency-logged, so that PDPs can detect an omission or a reordering, and should `mission_record` carry an identifier of the authority, so that a PEP configured with another one fails closed instead of admitting where the PDP never reads?
13. Several requirements refer to the end of a Mission (an Open Act resolved by it, a persistent Act in effect until it, an old set kept until its Missions end). Who ends a Mission, how does the History Authority learn of it, and what happens to a request that carries an ended Mission? The mission-bound drafts carry Mission state separately, in `context.mission_state_observation` {{MISSION-AUTHZEN}}; one answer is to take the end of a Mission from there, refuse admissions for it at the History Authority, and deny a Step-matching Act of an ended Mission with `history_unavailable`. Until this is settled, a deployment that cannot tell when a Mission has ended keeps an old set available for as long as it accepts requests carrying a Mission pinned to it.
14. An approval's scope here includes the position and the Restricted Sequences the denial completed ({{approvals}}), which ARAP's material does not carry. Should this profile define claims for them, for example in a PDP-signed `binding_token` that the Access Request Service carries into `approval.state`, so that an Access Request Service independent of the PDP can return an approval the PDP verifies without shared state?
15. Data moves between Missions through shared resources ({{security}}, Flows between Missions). Should a read of an object a call carries by reference be an Act of its own, classified with the result classes persisted with the object by the Mission that wrote it, so that such flows complete a sequence in the Mission that sends?

# IANA considerations {#iana}

To be registered, following the registries of the Extensibility Model {{AUTHZEN-EXT}}:

* in the "AuthZEN JSON Members" registry: `mission`, in the request `context`, advisory, with no Extension Identifier, described as identifying the Mission a request belongs to ({{request}}), once one definition is agreed with the mission-bound family, which defines a member of the same name {{MISSION-AUTHZEN}};
* in the "AuthZEN Obligation Types" registry {{OBLIGATIONS}}: `mission_record`, described as admitting the Act at the Mission's History Authority at a given position before any effect and recording its outcome, with a reference to {{obligation}} for its properties, compliance and handling of unknown members and values;
* in the "AuthZEN Profile Identifiers" registry: `urn:openid:authzen:profile:mission-composition` if the Working Group adopts this document, and until then an absolute URI {{RFC3986}} under the author's control (a placeholder), of kind Profile, for advertising support in metadata, which the Extensibility Model allows but for which no metadata member is defined yet (until one is, a PEP discovers this profile from `mission_record` in `supported_obligations`, {{pdp}}), selecting `context.mission` ({{request}}), the Obligations Core {{OBLIGATIONS}} and ARAP {{ARAP}}, described as ordered composition of Acts within a Mission across PEPs, with this document as its specification;
* in a new "AuthZEN Composition Denial Reasons" registry, which this document establishes for the reasons its profile part defines, as the Model recommends for reason codes: the five reasons below.

The "AuthZEN Composition Denial Reasons" registry is under the "AuthZEN Parameters" registry group, with the Specification Required policy {{RFC8126}}, after a two-week review on the mailing list the registries of {{AUTHZEN}} use. Its identifiers are carried in the decision `context`'s `reason`: short lowercase names of letters and underscores for registrations by OpenID Foundation specifications, and collision-resistant identifiers, such as absolute URIs or names prefixed with a domain name the registrant controls, for any other registrant {{AUTHZEN-EXT}}. Each registration gives the reason, a short description, whether a denial with it can be requestable, the change controller and a reference. The designated experts check that a new reason is one a PDP returns when it denies, that the registration says whether it can be requestable, and that it cannot be confused with a reason registered here or in ARAP's "AuthZEN Access Request Re-evaluation Denial Reason" registry, unless both registrations give it the same meaning. Initial contents, all with this document as reference and the change controller given below:

| Reason | Description | Requestable |
|---|---|---|
| `prohibited_composition` | Admitting the Act would complete a Restricted Sequence ({{predicate}}) | Yes, where policy allows |
| `history_unavailable` | No Mission ({{request}}), or the history cannot be read or used ({{ordering}}, rule 4) | No |
| `history_conflict` | A request of the same Mission earlier in the batch, permitted, could fill a step of the same sequence ({{pdp}}) | No |
| `history_pending` | An open Act of the same sequence ({{ordering}}, rule 5) | No |
| `policy_mismatch` | The History Authority refused the PDP's policy digest for the Mission ({{fixed-policy}}) | No |
{: title="Initial contents of the AuthZEN Composition Denial Reasons registry"}

This document registers no Extension Identifier: its only mandatory element is an Obligation Type, adopted through `obligations` ({{request}}). Change controller: the author until the Working Group adopts this document, then the OpenID Foundation AuthZEN Working Group. Until registered, every one of these values is a placeholder ({{status}}). Until then the Obligations Core accepts only registered Obligation Types and the literal value `custom`, in `supported_obligations` and as a `type` {{OBLIGATIONS}}, and the Model gives short names only to OpenID Foundation specifications {{AUTHZEN-EXT}}: a deployment that uses this individual draft before adoption does so outside both, by agreement among its own components, as the reference implementation does.

## OpenID Foundation registry considerations

ARAP keeps OpenID Foundation registry requests apart from IANA actions {{ARAP}}. All five reasons are also to be registered in ARAP's "AuthZEN Access Request Re-evaluation Denial Reason" registry, an OpenID Foundation registry:

* `prohibited_composition`: admitting the Act would complete a Restricted Sequence, and the approval presented, if any, does not apply to it; default next action `request`, which a PDP returns with a fresh `access_request` when the denial is requestable ({{approvals}});
* `history_unavailable`: the Mission's history cannot be read or used, or the request carries no Mission; default next action `retry`, except that a PDP sends `none` itself for a request without a Mission ({{pdp}});
* `history_conflict`: an earlier request of the same batch, permitted, could fill a step of the same sequence; default next action `retry`;
* `history_pending`: an open Act of the same sequence may still produce its effect; default next action `retry`;
* `policy_mismatch`: the History Authority refused the PDP's policy digest for the Mission; default next action `retry`, which succeeds at a PDP of the Mission's set ({{pdp}}).

An open proposal, openid/authzen PR #742, would remove the default next action field; nothing here depends on it, since the PDP sends `next_action` itself ({{pdp}}).

--- back

# Worked example (non-normative)

1. `read_record` on `hr:emp-4471` at the HR PEP: permitted with `mission_record` at position 1; admitted, acknowledged, performed, completed with `personal_data.salary`.
2. `write_document` on `doc:q4-review` at the documents PEP: permitted with `mission_record` at position 2; admitted, acknowledged, performed, completed.
3. `send_message` to `external:press@partner.example` (the canonical identifier of the press address) at the mail PEP: the PDP reads positions 1 and 2. The Restricted Sequence `(read with personal_data.*, write, send to an external recipient)` is completed, so the PDP returns `prohibited_composition`, as an ARAP requestable denial where the sequence is requestable, the PEP has opted in and the deployment has an Access Request Endpoint. If a person approves, the PEP evaluates again with `context.approval`; the PDP permits that one send, at that position, once.

Had the send been admitted first and stalled, the read and the write would have been denied `history_pending` until it finished.

# Formal basis (non-normative)

No requirement of this profile depends on this appendix. It records where the mechanism comes from.

Bounded Agents {{BOUNDED-AGENTS}} proves that an enforcement mechanism which denies any act completing a prohibited ordered tuple of action types, as an ordered subsequence of the session history, admits no sequence that realizes a prohibited tuple (its "Ordered k-tuple soundness" result, which extends to order the paper's pairwise, order-insensitive "Composition Soundness" theorem), given a complete set of restrictions, serialized admission, and a set that does not change during the session.

This profile supplies the conditions a protocol controls: serialized admission, complete history, and effects in Admission Order for the Acts a sequence depends on. Refinement of action types by result class, with the conservative top for unknown outcomes, and persistent steps, are this profile's extensions of the published result, not part of it. The conformance suite checks them with property tests against the true effect order.

# Related work (non-normative)

* Security automata {{SCHNEIDER}}. Covers: Execution monitors that halt a trace before it violates a safety property. How this profile differs: Same predicate. A security automaton terminates the target at the violating step, and Schneider treats replacing that step instead as not materially different; this profile denies the Act and lets the Mission go on, so the trace it keeps free of a completed sequence is that of the admitted Acts. This profile adds the multi-PEP contract: one order, admission before effect, completeness, effect order, signaling.
* Mission-Bound Runtime Enforcement {{MISSION-RUNTIME}} {{MISSION-AUTHZEN}} {{MISSION-EVIDENCE}}. Covers: Mission context, decision and execution evidence, a positive history predicate `action_class_completed`, and further predicate types under a naming rule. How this profile differs: `action_class_completed` holds when the Mission has a permitted Act of an action class and every such Act has completed. It is a positive predicate, a precondition such as "the copy completed before the delete", and the drafts define no negation. Used negated, it sees which action classes have completed, not in what order, so it cannot express `(read, write, send)`; and a read admitted but unreported leaves it unsatisfied, so the send would be permitted. The runtime draft's security considerations name the remaining gap, individually authorized steps that compose into an exfiltration. Its evidence is ordered per emitter, and cross-emitter order is best-effort.
* Mission metering {{MISSION-METERING}}. Covers: Cumulative bounds; experimental `exclusive` groups, which latch to the first selector exercised and then refuse the others. How this profile differs: A latch is order-blind: it also blocks the safe order, send then read. One latch per group does not express length-3 sequences, where the same acts in a different order get different decisions.
* Taint and artifact-lineage labels {{MISSION-HARNESS}} {{MISSION-WORK-PRODUCTS}}. Covers: Taint that gates egress after untrusted content, tracked per parameter where provenance is known and for the whole session otherwise; lineage labels joined under a declared order, with a conservative top for unknown lineage. How this profile differs: Such a label is the two-step case: any act with that class, then egress. The profile adds order and per-class specificity.
* Cross-entry evidence join (mcguinness/mission-bound-authorization issues #1019, #1051, open). Covers: Whether acts in different vocabularies refer to the same thing (reserve A, pay for B). How this profile differs: A different problem: a semantic join on a shared reference. Both need the rule, proposed there, that a missing required record is inconclusive, never a pass.
* Bounded grants (openid/authzen issue #521). Covers: Constraints on a permit, including state across requests such as a spend budget. How this profile differs: A counter summarizes history as a number; this profile evaluates the ordered history. Both may apply.
* Evidence provenance (openid/authzen issue #733). Covers: Where the inputs of one request came from. How this profile differs: This profile covers what the Mission did before the request. Complementary.
* Transaction Tokens {{TXN-TOKENS}}. Covers: User identity, workload identity and authorization context propagated through one call chain within a trust domain. How this profile differs: A Txn-Token carries the context of the chain it travels with, signed; it does not hold what the Mission's other chains did, and a signed record proves what it says, not that nothing is missing ({{ordering}}, Why complete, not only authentic).
* Indeterminate decisions (openid/authzen issue #456). Covers: "Policy says no" versus "could not evaluate". How this profile differs: Kept boolean, separated by reason. If #456 adds an indeterminate status, `history_unavailable` and `history_pending` map to it.
* AIMS {{AIMS}}. Covers: Agent Mission; an observability and remediation function that modifies authorization "based on observed behavior and system state". How this profile differs: One mechanism for that function, using only a Mission identifier.

The comparisons are with simplified models of those mechanisms' semantics, as the author reads them; the reference's tests model two of them (a negated check on open Acts, and order exclusivity), and the others are compared from their texts.

