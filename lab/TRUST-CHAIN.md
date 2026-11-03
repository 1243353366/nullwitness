# The trust chain

Five properties, in the order they bind:

| # | Property | Question | Enforced by | Detected by |
| --- | --- | --- | --- | --- |
| 1 | Payload encryption | can an unauthorized reader see the contents? | `lab/crypto/envelope.py` | `plaintext_visible` when a body appears inside its own envelope |
| 2 | Authenticated encryption | can an unauthorized writer modify the ciphertext unnoticed? | `lab/crypto/envelope.py` (encrypt-then-MAC, AAD) | `ciphertext_tampered` on any header, nonce, body, or context change |
| 3 | Key protection | can an attacker obtain the keys? | `lab/crypto/keys.py` (HKDF subkeys, custody checks) | `key_permissions_loose`, `key_colocated_with_data`, `key_in_environment`, `key_not_rotated`, `key_material_weak` |
| 4 | Boot and firmware integrity | is the environment handling the plaintext the one you expect? | `lab/crypto/boot.py` (measured chain, policy) | `boot_measurement_mismatch`, `boot_chain_broken`, `boot_rollback`, `attestation_replayed`, `attestation_unauthenticated` |
| 5 | Endpoint integrity | was the data manipulated before encryption or after decryption? | `lab/crypto/seal.py` (source seal), `lab/integrity/` (host monitor) | `plaintext_tampered`, `record_removed`, `record_reordered`, `record_replayed`, `stream_head_mismatch` |

```
1  ✓ ciphertext unreadable         ─┐
2  ✓ ciphertext unmodifiable        ├─ about the record
3  ✓ keys unavailable              ─┘
4  ✓ measured, attested environment ─┐
5  ✓ untampered plaintext at source ├─ about whether the record means anything
```

## Asymmetric competition

This is competition you are not trying to win by defeating anyone. You are trying to make
exploiting you a bad trade. Four moves, and each one has an engineering form here:

| Move | What it means | Where it lives |
| --- | --- | --- |
| raise their cost | every layer they must defeat before a record is credible | envelope, seal, ledger, attested boot |
| lower their return | the more work they do, the more evidence they leave | cascade demotion, precision findings, attribution in `flow.py` |
| preserve your resources | your controls are cheap to run and cheap to keep | stdlib-only paths, one master key, no always-on third party |
| adapt faster | changing a decoy list or a policy is a config edit, not a rebuild | decoy rotation, boot policy, `generation` on the key ring |

The move that gets skipped is the third. A control that costs you more than it costs them is
a net loss even when it works: decoys you cannot be bothered to rotate, a policy nobody
updates, a rotation cadence that breaks your own pipeline. The asymmetry only holds while your
marginal cost stays lower than theirs, which is a budget question, not a cryptographic one.

The fourth move is where the time asymmetry lives, and it is the real advantage. Every control
in this repository is something they have to discover and work around; you already know what it
is. That advantage decays as they learn, so the design goal is not a wall, it is a wall they
have to keep re-climbing. `lab/COUNTER-ANTI-FORENSICS.md` is the section that assumes they
already have a map.

What this strategy does not do is produce a verdict. It produces a stream of findings whose
value is that each one costs the attacker something to explain away. A defender who reads that
as "we are secure now" has converted a position into a claim, and the claim is the part that
breaks.

## Why this order, and not a list

Properties 1 to 3 protect a record. Properties 4 and 5 decide whether the record is worth
protecting. The pair is not symmetric, and getting the priority wrong produces the specific
failure that looks most like success: **a perfectly authentic record of something that never
happened.**

Encryption of a lie is a safe lie. Its transport was flawless, its ciphertext unforgeable,
its key never leaked, and it is wrong. That is why property 5 exists on both sides of the
cipher rather than once in the middle, and why property 4 is the only one that can say
whether the machine which sealed the record is the machine you configured.

## 1 and 2: the envelope

`encrypt_then_mac` with separate subkeys for the keystream and the tag, and the associated
data inside the MAC. Three deliberate choices:

- **Encrypt-then-MAC, never the reverse.** MAC-then-encrypt is where padding oracles come
  from: an attacker who can distinguish decryption failures from authentication failures
  gets a byte-at-a-time oracle for free. Here every failure is the same failure, and the
  error message says so rather than pretending to be helpful.
- **The header is inside the MAC.** The version byte and the nonce cannot be rewritten to
  select a different reading of the same ciphertext.
- **The AAD carries the record's identity and position.** `asset-7/audit` and sequence 12 are
  authenticated with the body, so an authentic record cannot be moved into a stream or a
  position where it means something else. Without this, a valid record is authentic but
  anonymous, and relocation is a free attack. The demo's "authentic record relocated"
  scenario is exactly that attack, caught by `ciphertext_tampered`.

What property 2 does not give you: it authenticates the ciphertext, not the metadata around
it. Sizes, timing, record counts, and who shipped what stay visible, and a body of 4,096 bytes
versus 22 bytes says a great deal. Traffic analysis is out of scope here and it is not free.

## 3: key protection, honestly

Software cannot protect a key from someone with root on the machine that holds it. Every
statement downstream inherits that. What software can do is make theft expensive, make the
separation real, and make custody visible, which is what `keys.py` does:

- **one subkey per purpose.** The transport key cannot forge a source seal, the seal key
  cannot read a payload, and the ledger key cannot do either. This is why a stolen transport
  key costs confidentiality rather than history: the flow demo shows a re-encrypted forgery
  being caught by the seal that the payload key cannot mint.
- **a floor on master length**, because a 16-byte "key" is a password and guessing passwords
  is not cryptanalysis.
- **custody findings, not verdicts.** `key_colocated_with_data` (the key sits in the tree it
  protects), `key_permissions_loose` (group or other readable), `key_in_environment` (every
  child process inherits it), `key_not_rotated` (the exposure window is the key's age).

The one that gets argued about is `key_in_environment`, usually by someone whose deployment
reads it from a variable and who is right that it is convenient. It is still a finding: on a
shared host, `ps` and core dumps are part of the threat model, and the honest fix is a key
file with 0600 or a KMS, not a smaller threat model.

### The cipher: AES-256-GCM

The envelope is AES-256-GCM. A 96-bit nonce is required rather than supported: the general J0
derivation for other nonce lengths is where implementations diverge, and there is no reason to
accept that risk when 96 bits is enough.

Two implementations produce byte-identical envelopes, so a record written on one host opens on
the other:

- **`cryptography`'s AESGCM** when the package is installed. Constant-time, hardware
  accelerated. This is the path that should carry real data.
- **`lab/crypto/aesgcm.py`**, pure Python, checked against GCM specification test cases 13 to
  16 and cross-checked against the library on random keys, nonces, lengths, and AAD.

The pure-Python path is a portability fallback with an honest caveat, and the caveat is not
decoration: its S-box is a table, its GHASH is a bit-at-a-time loop, and neither has a
constant-time story. On a host where an attacker can measure timing, that implementation is a
side channel with a cipher attached. Install the package before protecting anything that
matters. The tests say which path ran.

The first version of this layer used an HMAC-based construction, and envelopes written with it
(`backend 0x01`) still open. A format change that strands old records is not a format change,
it is data loss. New records are GCM (`backend 0x02`).

HKDF for the key hierarchy is checked against RFC 5869's own vectors, because a self-consistent
derivation bug produces a system that works perfectly and is wrong.

### Hash it: the digest chain

Ciphertext authentication needs the key. Some of the checks you actually want need no key at
all, and the difference is worth a module: `lab/crypto/archive.py` hashes each envelope at
write time and puts the digest in the HMAC-chained ledger from `lab/integrity/ledger.py`.

That buys three things the tag cannot:

- **substitution.** Same stream, same sequence, a valid envelope for different content,
  encrypted with the right key: nothing about that ciphertext is wrong. The digest in the
  ledger is the only layer that knows it is not the record that was written. This is also the
  case a stolen payload key cannot cover up.
- **removal.** The ledger records what was written, so an envelope that is gone is an entry
  with nothing behind it. Surviving records all verify; the absence is the finding.
- **ledger rewriting.** Each entry carries the MAC of its predecessor, so editing one breaks
  the chain.

Verification needs the ledger key, not the payload key. An archive scanner, a backup checker,
or a colleague confirming a file has not changed can do it without decryption rights, which is
usually the difference between a check that runs continuously and one that runs never.

The limit is the ledger's existing limit, restated rather than inherited quietly: an attacker
who holds the ledger key, the anchor, and the machine can roll both back to a consistent
earlier state. The anchor has to leave the host.

## 4: boot and firmware integrity

An attestation is a signed statement about what was measured before this code ran. Four
things have to hold, and they fail separately:

- **authentic**: the report carries a signature the verifier can check with a key that did
  not travel with the report.
- **fresh**: the report answers a challenge nonce the verifier chose. Without this, an
  attacker replays last week's clean report forever, and it verifies perfectly. The demo
  shows a clean report rejected because it answered the wrong challenge, and it is rejected
  *before* any measurement is read, because measurements an attacker chose are not evidence.
- **continuous**: each stage records the digest of the next. A measurement that does not link
  to its successor was not taken by the chain it claims to belong to.
- **policy-compliant**: this is the only check that knows what correct means, and it is
  worthless if the policy is updated from the host being checked.

The stand-in here is an HMAC with an attestation subkey, not a platform signature. A shared
secret means anyone who can read the attestation key can mint a report, which is exactly what
a TPM-bound key prevents. The verification logic is the artefact; against a real attestation
service only `_sign` and the source of the report change.

Anti-rollback deserves its own line, because it is the check that gets skipped. A downgrade
to firmware with a known flaw measures consistently, signs correctly, and passes every
integrity check in this repository. It is caught only by comparing a monotone security
version against a floor the attacker cannot set (`boot_rollback`).

## 5: endpoint integrity, on both sides of the cipher

The seal is made at capture, before encryption, and verified where the plaintext re-emerges.
That placement is what makes the location of a change attributable:

| ciphertext authentic | seal authentic | where the change happened |
| --- | --- | --- |
| no | not evaluated | between the endpoints: transit or storage |
| yes | no | after decryption at the sink, or before sealing at the source |
| yes | yes | nowhere between the boundaries: any problem is inside an endpoint |

The third row is the one to sit with. A record can be sealed and authenticated and still be
false, because the endpoint that made the seal was compromised when it made it. No
cryptographic layer sees that; it is what properties 1 through 4 are protecting, and it is why
"we encrypt it" is not an answer to "is the data trustworthy".

Two further checks live here because they are plaintext problems, not cipher problems:

- **completeness.** A clean prefix of a chain verifies, because every surviving record is
  genuine. Detecting a truncated tail needs the head recorded somewhere else: the seal takes
  an `expected_head`, and a real deployment reads it from the integrity ledger. Integrity is
  not completeness, and the suite asserts the difference rather than assuming it away.
- **replay.** Authenticated encryption proves a record is genuine and says nothing about
  whether it is new. A perfect ciphertext replayed is a perfect ciphertext, so the state that
  rejects it lives in `ReplayGuard`, per stream, monotone.

## Limits, stated where they bite

1. **A compromised endpoint defeats properties 1, 2 and 5 at once.** The seal is made by the
   endpoint; an endpoint that lies seals a lie. Only code and boot measurement can address
   it, and only partially.
2. **Metadata stays visible.** Sizes, counts, timing, and existence. Padding and traffic
   shaping are out of scope.
3. **No forward secrecy.** One long-lived master secret, rotated by generation. Compromise of
   the master retroactively opens everything it derived. Real deployments want per-session
   keys and a KMS.
4. **Python timing is not constant.** HMAC comparisons use `compare_digest`, but the layers
   above are ordinary Python and should not be exposed to an attacker who can time them
   closely.
5. **The attestation key is a shared secret here.** Root on the sealing host can mint a
   report that passes. That is the laboratory stand-in, not the design.
6. **Boot policy is only as good as its distribution.** A policy fetched from the host it
   checks is a policy an attacker chooses.

## Running it

```
python3 -m lab.crypto.cli demo           # seventeen scenarios across the five properties
python3 -m lab.crypto.cli demo --json
python3 -m unittest lab.tests.test_crypto
```

Four of the seventeen are controls: proper key custody, a clean envelope, and a policy-matched
boot chain must all hold. One is a limit: a record falsified inside the endpoint before it was
sealed passes every check here, and the demo prints that instead of hiding it.
