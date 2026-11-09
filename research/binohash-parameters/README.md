# Binohash 8-of-n planning frontier

- **Question:** For the paper's two-round, eight-selected-signature layout,
  how much exact subset space does `n=120` provide, and what `n` first reaches
  one expected hit per 42-bit puzzle under a uniform-hit model?
- **Comparison objective:** Evaluate exact `C(n,8)` counts beside the paper's
  approximate byte and opcode formulas, with their boundaries kept distinct.
- **Evidence:** The combinatorial counts and formula arithmetic are
  `locally-reproduced`. The Script byte and opcode formulas are `reported` by
  the paper and are not measurements of compiled or Core-executed scripts.
- **Execution class:** `unclassified`; this tool emits no Script or transaction.

## Reproduction and provenance

```sh
python3 tools/binohash_parameters.py --check
python3 -m unittest discover -s tools -p 'test_binohash_parameters.py'
```

The checked [JSON report](../../tests/data/binohash-parameters.json) records
the [Binohash paper](https://robinlinus.com/binohash.pdf), sections 4.4, 5.2,
6.1, and 6.2, as read on 2026-10-29. The PDF SHA-256 is
`1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a`.
The test checks both the report bytes and independently specified boundary
values. No random seed is used.

## Exact counts and conditional estimates

For one round with `t=8`, the exact nonce space is `C(n,8)`. At the paper's
`n=120`, this is `840,261,910,995 = 2^39.612...`, below `2^42`. `n=147` is
the first value for which `C(n,8) >= 2^42`.

| `n` | Exact `C(n,8)` | Entropy bits | Expected hits per round | Chance of at least one hit per round | Paper-estimated script bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 120 | 840,261,910,995 | 39.612 | 0.191 | 17.39% | 8,028 |
| 147 | 4,455,040,860,270 | 42.019 | 1.013 | 63.69% | 9,702 |
| 151 | 5,551,321,138,650 | 42.336 | 1.262 | 71.70% | 9,950 |

The expected-hit column is `C(n,8)/2^42`. The hit-probability column is
`1-(1-2^-42)^C(n,8)` **only if distinct subsets behave as independent uniform
42-bit trials**, with one fixed sighash flag per subset. Alternative flag bytes
and transaction mutations are outside this model. Squaring that probability
gives a two-round figure only with
an additional independence assumption (3.02%, 40.56%, and 51.41% for the
three rows). These are model outputs, not observed grind rates, measured
security, or a claim that a fixed transaction must succeed. They do identify
the retry/failure probability that a complete reproduction must measure.

The paper's approximate byte expression is `100 + R*(244 + 31*n)`. Applying
it only to its `t=8` layout with `R=2`, the 10,000-byte script ceiling yields
`n<=151`; at `n=151` its **estimated** margin is only 50 bytes. The separate
paper component count `13 + R*(11*t+4) + 2` gives 199 non-push opcodes for
`R=2,t=8`, two below the 201-opcode ceiling. Neither formula establishes that
the larger layouts serialize to these sizes, fit the stack, satisfy sigop
rules, or pass consensus. The calculator deliberately omits a byte estimate
for other `t`, because the paper's byte expression has no `t` term.
For `R=2,t=9`, the stated opcode components sum to 221, while the paper's
nearby example lists 220. This arithmetic discrepancy does not decide the
actual script's opcode count; the bytecode must be counted directly.

## Remaining validation

The next test is to generate the full bare legacy script at `n=120`, `147`,
and `151`, measure its actual serialized bytes and non-push opcodes, and
validate representative complete spends against pinned Bitcoin Core. A
deterministic small-difficulty grind should then measure candidate-hit
frequencies and the effect of retries before extrapolating work or cost.
No hint stack items, witness items, or stack peaks exist for this host-side
calculator; those metrics belong to the eventual complete Script fixture.
