# Forensic-integrity monitoring

> Detect when the evidence-producing environment is being tampered with, not which tool
> did it.

A signature detector answers "did something I recognise run here". That question has
three failure modes it cannot fix: custom scripts, operating-system utilities that are
supposed to be present, and techniques nobody has published yet. An integrity monitor
asks a different question, one that stays answerable: **does the evidence the endpoint
produces still agree with itself?**

An adversary who edits a log, deletes a file, silences a collector, or plants a record
has to make several independent things agree at once. That is expensive, and it is the
cost this monitor is built to raise.

## Four channels

Each channel is cheap to read, and each one fails differently when tampered with.

| Channel | Holds | Breaks when |
| --- | --- | --- |
| `ledger` | HMAC-chained checkpoints of the other channels | an entry is added, edited, reordered, or dropped: the chain stops linking, and the MAC needs a key the attacker does not have |
| `manifest` | SHA-256 of each evidence file | content changes, including a one-byte edit or a truncation |
| `metadata` | size, mtime, ctime, inode | content is rewritten, backdated, replaced, or truncated; `ctime` cannot be forged from userland |
| `status` | the collector's claim that it is running | a collector that was stopped still claims to run |

The channels are ranked by independence, and `status` is ranked lowest on purpose: it is
self-reported, so a compromised collector can lie. It stays in the set because a lie is
itself informative when the ledger contradicts it.

Findings are graded by agreement, not by confidence:

- one channel complaining is a lead, at `low`;
- two strong channels agreeing is a finding, at `medium`;
- a signal that is destructive by construction (deletion, truncation, forgery, a
  silenced channel) is `high` on its own, because there is no benign reading of it.

## What it catches

| Class | Signals | Example the demo runs |
| --- | --- | --- |
| destruction | `file_deleted`, `file_truncated`, `ledger_truncated` | `rm evidence/processes.jsonl`, or keeping the first 25 bytes of a log |
| suppression | `agent_silent`, `sampling_gap`, `channel_silenced`, `ledger_gap` | collector stopped while the endpoint keeps writing |
| manipulation | `backdated_edit`, `metadata_inconsistent`, `clock_skew`, `ledger_forged`, `ledger_reordered` | content rewritten, then `touch`ed two hours back |
| fabrication | `impossible_state`, `uncorroborated_state` | a checkpoint that records a file modified after the checkpoint itself |

`channel_silenced` is the one to read carefully. A gap in collection is ambiguous on its
own: the host may have been idle, or the operator may have stopped the collector. The
signal only escalates when evidence files kept changing during the gap. Activity plus
silence is suppression; silence alone is a question.

Two of those signals are worth calling out because they catch things a signature never
would:

- **`backdated_edit`** fires when content changed but mtime went *backwards*. No tool
  name is involved, and the operation is legal for any user. The tell is that the
  filesystem's own fields disagree with the edit.
- **`clock_skew`** compares wall-clock delta against monotonic-clock delta between two
  checkpoints. Moving the system clock is a standard way to make a timeline lie; the
  monotonic clock does not move with it.

## Running it

```bash
python3 -m lab.integrity.cli demo          # table of detections across 10 scenarios
python3 -m lab.integrity.cli demo --json   # the same reports as JSON
python3 -m unittest lab.tests.test_integrity -v
```

Output from a clean run:

```
scenario                             worst   expectation            findings
--------------------------------------------------------------------------------
clean                                none    no findings            none
delete evidence                      high    destruction            file_deleted
truncate evidence                    high    destruction            file_truncated
edit then backdate                   high    manipulation           backdated_edit
forge a ledger entry                 high    manipulation           ledger_forged
drop the ledger tail                 high    destruction            ledger_truncated
silence the collector                high    suppression            agent_silent, channel_silenced, file_modified
control: legitimate append           low     low severity at most   file_modified
control: log rotation                low     no destruction finding rotation, uncorroborated_state
limit: rollback plus anchor rewrite  none    undetected on one host none
```

The last line is the point of the exercise. Keep reading.

## Threat model

| Attacker | What survives |
| --- | --- |
| Unprivileged user, or a process running as the collector's user | Almost everything. They can edit evidence files but not recompute a MAC without the key, and `ctime` still betrays a backdated edit. |
| Compromised collection agent | `ledger` and `status` contradict each other. Deleting the agent's output leaves the anchor ahead of the body. |
| Root on the endpoint, anchor and key on the same host | **Nothing.** Root can rewrite the chain, recompute every MAC, and rewrite the anchor. The demo's final scenario does exactly that and the monitor reports nothing. |
| Root on the endpoint, anchor and key held elsewhere | Partial. The rewritten chain will not match the external witness, so the tampering shows up at the next export, even though the local state looks clean. |
| Root plus physical access, or the storage media destroyed | Nothing, unless copies already left the host. |

So the architecture, not the code, decides whether this works:

1. **Ship the anchor off-box.** Every checkpoint writes `checkpoints.jsonl.head`; that
   file belongs in append-only storage, a second host, or a timestamping service. On a
   single host it is a witness with no independence.
2. **Keep the HMAC key off the endpoint.** A key in the same filesystem as the chain
   lets an attacker forge entries that verify.
3. **Get time from somewhere else.** A host that can set its own clock can lie about
   when things happened; the external anchor's timestamp is what corrects it.
4. **Write once.** The evidence directory should be append-only for the collector's
   user where the platform allows it.

These are operational commitments. This repository can implement the first three
mechanisms and can only document the fourth.

## False positives are the design constraint

A monitor that flags every append gets disabled, and a disabled monitor is worse than
none because it creates a record of coverage that does not exist. The suite therefore
tests the boring cases as hard as the adversarial ones:

- **Legitimate append:** content changes, size grows, mtime moves forward: reported at
  `low` as `file_modified`, never as destruction.
- **Log rotation:** the file is renamed to `.1` with the same digest: recognised as
  `rotation`, and no `file_deleted` is raised.
- **NTP-sized clock step:** a two-second correction is inside the tolerance and is not
  reported. A ten-minute step is.
- **Idle endpoint:** no findings. A gap only becomes `agent_silent` when the collector
  still claims to be running, and only becomes `channel_silenced` when files kept
  changing.

Thresholds (`interval`, `gap_factor`, `clock_tolerance`) are policy, not physics. They
belong in configuration, and they belong to whoever answers the alert.

## What it does not do

- **It does not look for tools.** No signature matching, no process scanning, no
  command-line pattern lists. Those are a different product, and the source material for
  this repository is right that they are easy to route around.
- **It does not read memory, capture packets, or inspect other users' processes.** It
  reads file state under a root the operator nominates.
- **It does not prove the absence of tampering.** It shows that four channels agreed at
  the checkpoints that ran. Coverage gaps are the attack surface, which is why the
  collector's own silence is a first-class signal.
- **It does not feed the behavioural pipeline.** The traffic model in `lab/features/`
  describes visitors to an asset; this describes the observer's own environment.
  Forcing them into one schema would blur two different ontologies. Findings have their
  own report format, and `Report.as_dict()` is stable for shipping somewhere else.
- **It does not cover sources nobody watches.** A log the operator never included in
  `patterns` cannot be damaged in a way this notices.

## Where signatures still help

Not as the detector, as an input. A hit from a known-tool signature is one more channel
that can corroborate a structural finding, on the same grading rule. It should never be
the thing that decides, and a clean signature scan should never be reported as evidence
that nothing happened. Absence of a known tool is not absence of tampering; that is the
whole reason this module exists.

## The next layer

Everything above assumes an adversary who has not read this document. The layer in
`lab/integrity/counterforensics.py`, documented in
[`COUNTER-ANTI-FORENSICS.md`](COUNTER-ANTI-FORENSICS.md), assumes the opposite: someone
who knows about the ledger, the decoys, and the rotation convention, and uses them. It
adds detectors for in-place overwrites, restore-to-mask, laundered rotation, decoy-aware
precision, planted histories, stolen keys, and sub-tolerance clock walking, and it states
the limit that survives all of them: evidence outside the watched set cannot contradict
anything.
