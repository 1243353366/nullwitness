# Ethics and limits

The source dump in [`source/nerdshit.md`](source/nerdshit.md) proposes more than this
branch builds. This page says exactly what was left out and why, so the gap is not
mistaken for an oversight.

Two rules decided every case:

1. **The lab measures behavior on assets the operator controls.** Logging requests
   that arrive at your own server, or access to a document you published, is
   ordinary defensive telemetry.
2. **The lab does not identify, locate, or manipulate a person.** Producing a
   persistent identifier for an individual across networks is surveillance, whatever
   the motivation, and the techniques the source proposes do not work well enough to
   survive contact with reality anyway.

## Excluded: cross-network identity attribution

The source proposes combining JA4/TLS fingerprints, TCP quirks, and timing to build a
"Behavioral ID" that "persists even if the actor switches VPN providers," and states
that jitter lets you "estimate the user's true geographical distance from the VPN
server."

Not built, for three independent reasons:

- **It does not hold up technically.** Inter-arrival timing at a server reflects the
  server's own scheduling, congestion, and the last hop far more than the client's
  continent. Packet timing on a shared cloud instance cannot resolve geography at any
  useful precision, and a jitter "signature" is not stable across sessions the way
  the source claims. Presenting it as a geolocation method would be dressing up a
  noisy feature as an instrument.
- **It is de-anonymization of a person.** A stable cross-network identifier for an
  individual is the thing surveillance products sell. It is also the thing that turns
  a defensive log into a dossier, and dossiers about private individuals are the part
  of this architecture with the worst legal and personal exposure.
- **It assumes an adversary and returns a person.** In the counter-stalking framing
  the subject is a specific human being. A tool that locates that human is not
  symmetric with the harm it responds to, and "they started it" is not an
  authorization.

What is built instead: `fingerprint_hash` is stored as a salted, truncated hash. It
groups observations inside one salt epoch, which is enough to say "same client, same
session family," and rotating the epoch breaks the link. No address column exists in
the schema, and no feature in `lab/features/pipeline.py` is designed to re-identify.

## Excluded: active probing

The source proposes sending a "zero-window TCP packet or a malformed TLS extension"
at a suspect address to see how it responds, then matching the response for
attribution.

Not built. This is unsolicited traffic crafted to elicit a fingerprint from a system
you do not control. It is not measurement of your own property, it is interaction
with someone else's, and depending on jurisdiction and the receiving system it is
exactly the conduct unauthorized-access statutes describe. It also degrades: any
modern middlebox, CDN, or OS quirk will answer differently, so the "positive
attribution" it claims is unreliable on its own terms.

## Excluded: reflexive manipulation of a person

The source treats Lefebvre's reflexive control as an operating doctrine: feed an
adversary information designed to move their beliefs in a direction you choose.

Not built as an action. `lab/model/belief.py` implements the *defensive* half, which
is a model of analyst caution: if an input appears to benefit its source, trust it
less, and discount the belief update accordingly. It does not generate content, does
not target anyone, and does not claim to predict a real person's cognition.
Lefebvre's framework is not an empirically validated model of decision-making, and
nothing here should be read as evidence that it is.

## Excluded: bait documents that impersonate third parties

The source proposes publishing files with names like `Michigan_Property_Records.pdf`
and a hidden tracking pixel, hosted from a burner profile.

Two problems, and the source's own risk section raises both:

- **Impersonation.** A document that appears to be a public record from a government
  office is a misrepresentation, and it invites trademark, fraud, and
  impersonation exposure that a genuine canary document does not.
- **The tracking pixel is the interesting part, not the bait.** A beacon on a
  document you own, with a clear notice, is a legitimate honeytoken. The
  impersonation adds legal risk and no detection value.

What is built instead: the `honeytoken_access` channel in the event contract, so
access events from a document you published can be counted, aggregated, and reported
with the same k-anonymity floor as everything else. The lab does not generate the
decoy document, and there is no code here that produces one.

## Excluded: anything that touches the visiting machine

The source is explicit that scripts running on a visitor's machine to pull cookies or
files cross the line. The lab goes further and ships no client-side code at all: no
beacon script, no PDF payload, no document template. Telemetry is whatever the server
observes in a normal request.

## What the source gets right

Worth keeping, because the corrected material depends on it:

- The CFAA analysis is broadly correct: authorization and control, not intent, are
  the operative questions.
- The GDPR warning is correct and understated. An IP address is personal data in the
  EU, and a "defensive" purpose does not remove the obligation to have a basis, a
  notice, a retention limit, and a way to answer a subject access request. The lab
  solves this by not retaining the address at all.
- The distinction between passive logging and active countermeasures is the right
  line, and the source draws it in roughly the right place. This branch treats that
  line as the scope boundary rather than a caveat.

## If you actually have a stalker

This is a lab, not an incident-response service. The practical sequence is: preserve
what you already have, report to the platform and to law enforcement, and get a
lawyer before you build anything that collects data about a specific person. A
home-made attribution pipeline is more likely to create evidence problems and
counterclaims than to help.
