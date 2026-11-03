# Counter-anti-forensics

The base monitor in `lab/integrity/` catches an attacker who deletes, truncates, or edits
evidence. This document is about the attacker who read it first.

That attacker has an advantage nobody should discount: the deception in this repository is
symmetric. A decoy is a lie told to catch a liar. A checkpoint is a record you can roll
back if you hold the key. Rotation is a convention that forgives deletions. Every one of
those can be turned around, and the turned-around version looks, from inside a single
channel, exactly like normal operation.

The layer in `lab/integrity/counterforensics.py` exists because turning them around is
still work, and the work leaves a shape.

## The one idea

A technique that defeats a check has to conserve the quantity that check measures. That
constraint is the whole vulnerability:

| Technique | Conserves | Cannot conserve |
| --- | --- | --- |
| Overwrite in place, padded | file size | content, so the digest moves |
| Delete, then restore identical bytes | digest, size, mtime | ctime, which userland cannot set |
| Rotate something else into the slot | the rotation convention | the rotated content |
| Burst of harmless changes | each change's plausibility | the volume against the host's own baseline |
| Avoid every decoy | the canary silence | the precision of the avoidance |
| Second ledger beside the real one | a readable history | being the file the monitor writes |
| Steal the key | every MAC | the key existing outside its store |
| Walk the clock under tolerance | each per-step comparison | the integral of the drift |

So each detector is a statement of the form: *these two facts are individually believable
and jointly impossible*. That is a stronger position than signature matching, because the
signature can be changed and the arithmetic cannot.

## The techniques, and what catches them

| Signal | Severity | Catches | Contradiction |
| --- | --- | --- | --- |
| `content_substitution` | medium | in-place overwrite padded to the original length | same size, different digest |
| `restored_from_copy` | medium | evidence deleted and put back byte-identical | same digest, later ctime |
| `rotation_laundering` | medium | a deletion dressed as log rotation | rotation slot does not hold the rotated content |
| `canary_avoidance` | low / medium | an actor who sweeps the real files and touches no decoy | clean precision against the decoy list |
| `churn_dilution` | low | one real change buried in a burst | volume far above the host's own median |
| `shadow_ledger` | high | a second chain planted beside the real one | a ledger the monitor did not write |
| `planted_artifact` | medium | a fake anchor or state file | shape without provenance |
| `key_material_copy` | high | the HMAC key copied into the tree | the key existing outside its store |
| `clock_creep` | medium | sub-tolerance clock walking | per-step deltas fine, integral not |

Run it:

```
python3 -m lab.integrity.af_demo          # thirteen scenarios: three controls, one limit
python3 -m lab.integrity.af_demo --json
```

## Precision is the tell

This is the section I find most interesting, so it gets the most space.

A decoy only works once. Once someone knows which files are bait, the bait is a map of
where not to step, and there is no way to un-know it short of rotating every decoy and
hoping they do not read it again. That makes decoy-aware evasion *better* for the evader
and *worse* for their anonymity at the same time, because the evasion is now the signal.

An actor moving through a set of lookalike files has a choice to make on every file: touch
it or not. If they cannot tell decoys from evidence, their path is a random sample. If they
can, their path is the complement of the decoy set, and that complement has a name.

The finding therefore reports a number rather than a verdict. Choosing `k` of `n` tracked
files at random and landing entirely outside the `d` decoys has probability

```
        C(n - d, k)
P  =  --------------
          C(n, k)
```

which `canary_avoidance` computes and prints in the detail line. Sweeping all five real
files in an eight-file set with three decoys is 1 in 56, about 1.8%. That is worth a
look. Two files out of four with two decoys is 1 in 6, which is not, and the detector
returns nothing rather than manufacturing a lead.

The thresholds are deliberately blunt: at or below 2% is medium, at or below 15% is low,
above that is silence. They are a starting point for an operator with a real decoy
inventory, not a calibrated statistic, and they are wrong in the direction of under-reporting
on purpose.

Two honest notes. First, this detects *knowledge of the decoy list*, which is not the same
as *guilt for the edit*: an operator who read the config and then did legitimate work has
the same fingerprint. Second, tiny sets cannot support the inference at all, which the
suite asserts (`test_small_sets_are_not_significant`) so nobody is tempted to run it on
four files and believe the result.

## Evading a threshold by staying under it

The base monitor compares wall-clock delta with monotonic delta per checkpoint and allows
a few seconds. That is the correct check for a clock being set backwards or jumped forward,
and it is trivially evaded by moving the clock 0.9 seconds on every checkpoint. No single
step is wrong. The timeline still slides.

`clock_creep` integrates instead of comparing:

```
total = Σ ( wall_delta - monotonic_delta )
```

Sub-tolerance steps sum to something above tolerance because integration does not care how
the displacement was distributed. The scenario in `af_demo` walks 0.9s per checkpoint for
six checkpoints: 5.4s of displacement, no per-step alarm.

The limit of this is honest too: a reboot resets the monotonic clock, which resets the
integral, so creep spread across a reboot needs the boot identity in the ledger. It is not
there yet.

## The cheapest attack, and the only good answer

Everything this repository claims rests on one sentence: the attacker does not have the
HMAC key. Stealing it is easier than defeating the chain, and it wins permanently.

So the layer searches the watched tree for the key bytes and reports any copy as high. That
is a crude control, and it is crude for a reason: there is no clever answer. Key material
has to live somewhere the attacker cannot read, and if it does not, the chain is
decoration. `key_material_copy` tells you when that has stopped being true.

## False positives, stated up front

A monitor that cries wolf is turned off, and this layer adds four ways to cry wolf. Each
one is documented rather than tuned away, because the operator needs to know which
findings are questions:

- `restored_from_copy` fires on backup restores, package upgrades that reinstall an
  unchanged config, and `cp -p`. The question to ask is "was anything restored on this
  host, by whom, and is that in the change record". If the answer is yes, the finding is
  explained, not disproved.
- `rotation_laundering` fires on applications with unusual rotation schemes, such as
  timestamped copies or compressed generations. Check the retention policy before
  believing it.
- `churn_dilution` fires during incidents, when everyone touches everything. It is
  deliberately low for that reason.
- `canary_avoidance` fires on the operator who read the config and then did legitimate
  work, which is most operators.

The controls in `af_demo` exist to keep these visible: a real rotation, a legitimately busy
window, and a single-file edit all stay at low or nothing, and the suite fails if they do
not.

## Limits

1. **Coverage beats cleverness.** An adversary who edits only evidence that is not being
   watched is invisible to every detector here, because there is nothing to contradict.
   This is the limit scenario in the demo, and the suite asserts it rather than hiding it.
   The only answer is wider coverage, not a better inference.
2. **Root plus no off-box witness still wins.** With write access to the ledger, the
   anchor, and the key, and nothing shipped off the host, a patient attacker can present a
   consistent shorter history. `lab/INTEGRITY.md` says this and it has not changed.
3. **Decoys decay.** Each decoy is single-use against a given adversary. Rotation is
   required, and the day the list leaks is the day the precision signal starts reporting on
   innocent operators instead.
4. **Statistical findings are leads.** `canary_avoidance` and `churn_dilution` are graded
   low for a reason. They belong in a review queue, not a verdict.
5. **No attribution.** This layer produces evidence about a *host*: that it was handled by
   someone with knowledge of the monitor. Turning that into a claim about a person is
   outside this repository and stays outside it. Evidence is not an accusation, and a
   correlator is not a judge.

## What this deliberately will not do

The tempting next step is to make the deception aggressive: plant evidence that frames
whoever takes the bait, build a decoy that calls attention to a named person, or push a
countermeasure onto the attacker's machine. None of that is here, and it will not be added:

- no decoy that exists to get a specific person accused
- no counter-attack, no retaliation, no disabling of anyone's tooling
- no correlation across hosts or networks to name an individual
- no bait that only a real human would plausibly take, as opposed to a process

The line is the same one the rest of the repository holds: detect what happened on the
assets you own, and let the human process decide what it means.
