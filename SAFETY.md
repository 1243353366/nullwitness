# Safety boundaries

This project is a discussion resource. It is not a toolkit, a playbook for a live
incident, or a source of operational instructions.

## What this repository provides

- Fictional scenarios and a structured discussion walkthrough.
- Language for describing defensive, authorized response measures.
- Pointers to the legal concepts that a real response has to satisfy.

## What it does not provide

- No exploit steps, payloads, malware, or scanning instructions.
- No code that acts on remote systems, and no tooling that evades detection on
  systems you do not own.
- No advice for a live incident. If a real exposure is in progress, engage your
  incident-response process and counsel rather than experimenting.

## Acceptable, on systems the organization controls

These are ordinary defensive measures when authorized by policy and performed on
infrastructure the organization operates:

- revoke or rotate credentials and terminate sessions and tokens
- restrict access to affected systems and datasets
- replace exposed sensitive values with harmless placeholders
- add clearly marked canary records to controlled datasets
- preserve logs and forensic evidence with chain of custody
- document every action with timestamps, owners, and approvals
- minimize and redact data where possible
- notify stakeholders and regulators where required
- design detection that observes access without harming anyone

They remain defensible only when they are authorized, contained to the
organization's environment, documented, reviewed, and consistent with privacy,
employment, and contractual obligations.

## Not acceptable

Not acceptable here, and legally risky anywhere:

- accessing a system without authorization
- deception, tampering, or interference directed at a third party
- attacks, retaliation, or "counter-hacking" against an attacker's infrastructure
- malware, payload delivery, or remote sabotage
- detecting and clearing another party's monitoring or canary artifacts
- anything that harms unrelated systems, accounts, or people

A lawful defensive posture is not a license to interfere with systems outside your
control, and being targeted does not create authorization to act elsewhere.

## Decision framework

Before approving a response, answer each of these in writing:

1. Does the organization control the system being changed?
2. Is the action consistent with policy and explicit authorization?
3. Does it preserve evidence and avoid spoliation?
4. Will it affect unrelated parties or third-party infrastructure?
5. Is it necessary, proportionate, and reviewable?
6. Are privacy, employment, and regulatory obligations accounted for?
7. Are legal and compliance reviewers on the record?

If the answer to question 1 is "no," stop. The rest of the analysis does not
rescue it.

## Vocabulary that keeps a public repo safe

- "This project is a non-executable educational resource."
- "It contains fictional examples only."
- "It does not provide operational attack instructions."
- "It discusses defensive, authorized measures within systems the organization
  controls."
- "It does not endorse interference with third-party systems or retaliation."
- "Legal questions are jurisdiction-specific and require qualified advice."

## Related pages

- [Legal and risk notes](LEGAL.md)
- [Simulation walkthrough](examples/simulation-walkthrough.md)
- [Fictional scenarios](examples/scenarios.json)
