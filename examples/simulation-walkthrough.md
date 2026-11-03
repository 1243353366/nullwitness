# Simulation walkthrough: a fictional exposure scenario

This is a non-executable educational example. It contains no live exploit steps, no
real credential material, and no instructions for interfering with third-party
systems. It exists to support policy discussion, legal review, and defensive
incident planning.

Legal concepts are collected in [LEGAL.md](../LEGAL.md); the limits of what this
project will discuss are in [SAFETY.md](../SAFETY.md).

## 1. The fictional scenario

A fictional organization, "Northwind Analytics," discovers that a made-up employee
record, an example token value, and a canary identifier may have been included in a
document shared outside its controlled environment.

Everything in this scenario is invented and intentionally harmless. The exercise is
about how a lawful, responsible organization should respond. It is not permission
to access a real system without authorization, manipulate a third-party system,
retaliate against someone else's infrastructure, or use deceptive content against
systems you do not own.

A machine-readable companion to this scenario is in
[scenarios.json](scenarios.json).

## 2. Framing the exposure

In a real incident the first questions are factual, not technical:

- What data was actually exposed, and how sensitive is it?
- Was the exposure authorized or unauthorized?
- Which systems and records are under the organization's control?
- Which actions are lawful, contractually permitted, and operationally appropriate?

The response team's early work is usually:

- confirming whether the data was genuinely exposed, and to whom
- controlling internal systems and identity
- preserving logs and chain of custody
- limiting further damage to assets under the organization's authority
- coordinating with legal, privacy, and communications teams

The goal at this stage is containment and evidence, not retaliation.

## 3. Defensive actions inside authorized boundaries

Typical lawful actions, performed on systems the organization controls:

- revoke or rotate credentials; terminate active sessions and tokens
- restrict access to affected systems
- replace exposed sensitive values with harmless placeholders
- add clearly labelled canary markers to controlled datasets
- preserve forensic evidence and logs
- document each action with timestamps and approval records
- notify internal stakeholders and any regulator where required

Each is defensible only when authorized by policy, performed on systems under the
organization's control, documented and reviewed, and consistent with privacy and
employment obligations.

## 4. Reducing the value of stolen data

A common defensive principle is that you can lower the usefulness of data taken from
you without attacking whoever took it.

Low-risk, generally accepted techniques:

- replace real values with harmless placeholders
- plant obvious fake records that only a copy of your data could contain
- rotate credentials and revoke sessions
- keep evidence in a controlled, documented location
- make unauthorized disclosure easier to detect without causing harm elsewhere

This is different from:

- poisoning or manipulating data to harm third parties
- active interference with remote systems
- retaliatory or punitive action against another party

The first group is normally described as containment and detection. The second is
normally described as unauthorized interference. What separates them is control and
authorization, not intent.

## 5. A worked discussion

Walk the fictional case through the framework in [SAFETY.md](../SAFETY.md), one
question at a time, and record answers:

1. Which systems would Northwind be changing, and does it control them?
2. What authorization exists: policy, contract, change record?
3. What evidence must be preserved before anything is rewritten?
4. Would any proposed measure affect the person who holds the document, or their
   employer's systems?
5. Is each measure necessary and proportionate to the risk?
6. Who reviews and signs off?

A useful outcome of the exercise is a written decision record with the answers, the
dissents, and the approvals, not a technical plan.

## 6. Closing summary

The defensible posture:

- preserve evidence
- contain the damage
- revoke access and rotate credentials
- reduce the value of exposed data
- document decisions
- consult legal and privacy specialists

The risky posture:

- unauthorized interference with systems you do not control
- retaliation against an attacker
- deceptive or harmful action aimed at third parties
