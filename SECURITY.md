# Security

## Status

This repository holds an individual proposal for an AuthZEN profile and an
implementation of it. The implementation shows the logic of the profile; its
History Authority keeps everything in memory, and it is meant for study,
interop experiments and conformance work, not as a production authorization
service. Do not place it on the decision path of a real deployment without an
independent security review. `docs/mission-history-service.md` lists what a
production deployment has to add.

## Supported versions

Only the latest release on the default branch receives fixes. Each release
names the revisions of the specifications it is pinned to (`CHANGELOG.md`).

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private
vulnerability reporting (the repository's **Security** tab, "Report a
vulnerability"), not in a public issue. Include the affected version or commit,
the component (for example the PDP, the PEP, the History Authority binding or
the Access Request Service), a minimal reproduction, and the impact you
observed. Reports are handled on a best-effort basis. Please allow reasonable
time for a fix before any public disclosure.

A weakness in the profile itself, rather than in this code, is welcome as a
public issue, since the draft is open for discussion.

## Threat model

The draft's Security Considerations set out what the profile protects against
and what it leaves to the deployment: the agent as an adversary, a
compromised History Authority, relabeling, flows between Missions, and more.
`docs/TRACEABILITY.md` marks which requirements this implementation
demonstrates and which bind a production deployment.
