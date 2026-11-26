# Week 11 — Control Scorecard (Privacy)

## Scorecard

| Defense | Guarantee (axis 2)? | Failure / condition | Evidence |
|---|---|---|---|
| Drop the name | **None** | Linkage on quasi-identifiers with any public auxiliary data | Task 1: 75% of rows unique; person001 named and outed as `diabetes` |
| k-anonymity | **None** — hides identity, not the attribute | Homogeneity attack; background knowledge | Task 2: k = 5 group, nobody unique, still leaks `hiv` |
| l-diversity | **Weak** — no numeric bound | Skewness (e.g. 1 in 3 is HIV vs. ~20% base rate), semantically similar values | Task 2: a diverse group returns `None` |
| **Differential privacy** | **Yes — e^ε bound against any side information** | Accuracy cost (mean \|error\| = 1/ε); budget **composes** across queries | Task 3: ±10 at ε = 0.1 → ±0.2 at ε = 5; 10 queries at ε = 0.5 spend ε = 5 |
| DP-SGD (vs. membership inference) | Yes — the same e^ε bound, applied to training | Utility loss; ε must be accounted for across training steps | Task 4: an undefended model gives **80.5%** MI accuracy vs. 50% baseline |

## Guarantee sentences (Task 3)

- **ε = 0.1:** No adversary, with any side information, can tell whether a given
  individual is in the dataset with advantage beyond a factor of e^0.1 ≈ **1.105**.
  Cost: mean error ≈ ±10 on a count of 24.
- **ε = 5:** The same claim holds only up to a factor of e^5 ≈ **148.4**. That is a
  very weak privacy promise, but the answer is accurate to about ±0.2.

## Composition (demo)

Ten answers to the same query at ε = 0.5:
`21.4, 26.4, 25.5, 22.7, 24.0, 23.8, 24.7, 25.7, 20.7, 18.3`. Their average, 23.3, is
close to the true 24. Averaging ten answers cuts the mean error from 1.95 to 0.71,
because the total budget spent is 10 × 0.5 = **ε = 5**, not 0.5. To keep the total
at ε = 0.5, each query would have to run at ε = 0.05, and its mean error would
grow to about ±19.8.

## What a membership-inference hit means

If the model was trained on "patients with diabetes", being identified as a member
**is** the sensitive fact. No table is released, so the model alone leaks it.

## Where we may have been unfair, and what we did not test

- `HOMOGENEOUS_GROUP` is constructed. On the real released table, `generalize` gives
  only 4 groups and the smallest has **3 rows** (birth band 2000), so the release is
  only **k = 3**, not 5. None of the real groups are homogeneous: they have 3–5
  distinct diagnoses. The 3-person group is still risky: 1 in 3 is HIV.
- The MI threshold is chosen using ground-truth labels on the same probe set, so the
  80.5% figure is optimistic. A real attacker would calibrate on shadow models.
- At ε = 0.1, about 5% of the noisy counts came out **negative**. We did not
  post-process (clamp or round) the answers. Post-processing does not weaken DP.
- Linkage assumes the voter roll covers every patient with matching fields. With
  partial or noisy auxiliary data, the re-identification rate would be lower.
- We did not test background-knowledge attacks on k-anonymity or l-diversity
  skewness attacks with real data, and we did not implement DP-SGD.