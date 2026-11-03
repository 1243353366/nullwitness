# Legal and risk notes

This page is general education, not legal advice. Laws and obligations vary by
jurisdiction, contract, industry, and facts. Nothing here establishes that a
particular measure is lawful in your situation. Consult qualified counsel and your
organization's security, privacy, and compliance teams before acting in a real
incident.

## The question that does not settle it

"How much does the leaked data cost us?" and "who owned the original copy?" are not
the legal tests. A measure is evaluated on questions closer to these:

- Did the organization act within its rights, authorization, and policy?
- Did the action affect only systems the organization controls?
- Did it cause harm, unauthorized interference, or deception directed at others?
- Did it comply with privacy, contractual, employment, and regulatory obligations?
- Did it preserve evidence rather than destroy or alter it?

Ownership of a copy of data is rarely enough to justify an action taken on a system
you do not control.

## Legal concepts that usually matter

- **Ownership and control of the asset.** Who operates the system being changed?
- **Confidentiality obligations.** Contracts, NDAs, customer agreements, and
  employee policies may prohibit or require certain handling.
- **Employment and workplace rules.** Monitoring, discipline, and employee data
  handling are constrained even inside your own network.
- **Privacy and data-protection law.** GDPR, UK GDPR, US state privacy statutes, and
  sector rules (HIPAA, GLBA, FERPA) can restrict collection, use, retention, and
  re-use of personal data, including in decoys and test fixtures.
- **Unauthorized access and interference law.** Computer-misuse and
  unauthorized-access statutes in most jurisdictions turn on authorization, not on
  good intentions or on who "started it."
- **Fraud, deception, and misrepresentation.** Content designed to mislead real
  people can create liability independent of any hacking statute.
- **Evidence preservation and spoliation.** Deleting or altering logs and records
  after a suspected incident can create separate exposure, including sanctions and
  adverse inferences.
- **Regulatory notification duties.** Breach-notification clocks and content
  requirements often run from discovery, not from containment.

## Where the risk profile changes

- Risk is lower when the action is confined to systems the organization controls and
  is aimed at containment, evidence, and remediation.
- Risk rises sharply when an action reaches outside that control and creates effects
  on someone else's systems, accounts, or users, even if the other party acted
  unlawfully first.
- Risk also rises when an action changes or destroys records that may be needed as
  evidence, or when it misleads people who have a legal right to accurate
  information (employees, regulators, customers, courts).

## Questions worth bringing to counsel

1. Which systems, accounts, and datasets are within our authority to change?
2. Do any contracts, policies, or works-council agreements constrain what we may do
   to data or logs we hold?
3. Does the response touch personal data in a way that needs a documented basis?
4. What retention and preservation obligations attach to the records involved?
5. Do we have notification obligations, and when do their clocks start?
6. Does anything we plan to publish, including teaching material, create exposure?
7. Who signs off, and how is that approval recorded?

## Related pages

- [Safety boundaries](SAFETY.md): what this project will and will not discuss
- [Simulation walkthrough](examples/simulation-walkthrough.md): the fictional
  scenario these notes apply to
