# R10: finite parameter-root frontier and packed mining freedom

Date: 2026-09-17. Question: can the R9 readable numeric root authenticate a
small polynomial and leave enough mining freedom and Legacy opcodes for a
complete reference computation? Both finite root availability and actual
verification must be counted; no trace opening or final evaluation oracle
is granted for free.

**A fixed numeric parameter need not consume the entire numeric seed.** A
packed seed can reserve low bits for the parameter and use the remaining
signed range for mining. This changes the finite-domain frontier materially.
A complete raw affine arithmetic checker with this packing uses 143 opcodes
at 37 hash stages, leaving 58. It verifies only `y=t+7`; it does not implement
the Bitcoin reference function or bind its t/y operands to the actual spend.

No full rare root/pin witness was mined, and no full covenant is supplied.

## Executed arithmetic interface

The concrete precommitted polynomial is the integer function `F(t)=t+7`.
The root seed is

```
x = 16*q + 7.
```

Its low four bits encode the fixed coefficient. The script computes this
relation using four `DUP ADD` doublings, literal 7, ADD and NUMEQUALVERIFY.
The normalized x is the input of the R9 numeric-root fragment; x remains
readable on the altstack. q is a supplied packing hint, and the arithmetic
equality binds it to that actual x. The coefficient is fully fixed by the
locking-script literal; the toy does not pretend it needs a succinct proof
to evaluate an affine function. Packing is a demonstration of separating
semantic parameters from mining choices inside a ScriptNum, not a new
commitment to a large execution trace.

With n hash stages the entry stack is

```
reversed n-1 path selectors, x, q, t, y, P.
```

Save P,y,t,q on the altstack, run the exact-depth R9 root fragment on the
remaining inputs, and then execute

```
FROMALTSTACK FROMALTSTACK             # alpha x q
DUP ADD DUP ADD DUP ADD DUP ADD
7 ADD NUMEQUALVERIFY                  # checks x=16q+7
FROMALTSTACK 7 ADD FROMALTSTACK
NUMEQUALVERIFY                        # checks t+7=y
FROMALTSTACK                          # restores P
DUP SHA256 0 CHECKSIG DROP CHECKSIG   # same native pin/root gates as R9
```

The arithmetic consumes every auxiliary operand; successful execution would
leave one true stack item and an empty altstack. The root's mining selectors
remain isolated from all arithmetic operands, so the earlier exact-depth and
long-state routing argument still applies. No input-dependent coefficient or
final oracle is supplied after the polynomial check.

At n=37 the unmined native candidate has **185 raw script bytes, 143 counted
opcodes, 41 entry data items, 37 hints and combined stack peak 44**. The hints
are 36 routing selectors plus one packing hint q; the other four operands
are x,t,y,P. Every hint coexists at script entry. These are raw legacy
boundary counts, not optimized library metrics. No complete transaction,
serialized scriptSig, witness or spend-weight measurement is claimed because
the native root/pin witness has not been produced.

For executable host checking, a separate observable version replaces the
unmined native gates by dropping P and comparing alpha with an expected hash.
That complete arithmetic/hash predicate has 214 bytes, 140 operations and
the same peak 44. Its success is not native signature validation.

## The exact finite seed domain

ScriptNum operands have at most four bytes. Every intermediate used by the
next arithmetic operation must also fit that limit. In this particular
implementation the exact q range is

```
-(2^27-1) <= q <= 2^27-1,
K = 2^28-1 legitimate seeds.
```

The tempting extra endpoint q=`-2^27` is invalid: although `16*q+7` would
fit, the intermediate `16*q=-2^31` takes five bytes and cannot be read by
the following ADD. The positive endpoint beyond the range also fails.
Negative q values are legitimate public mining choices, not extra encodings
of one positive integer. Nonminimal encodings of an already chosen number
do not add seeds because the R9 fragment normalizes x before hashing.

More generally, a coefficient code of B low bits leaves at most roughly
`32-B` mining bits in this signed numeric domain, with the exact intermediate
limits depending on the reconstruction program. This does not fit two
independent 31-bit field coefficients into one ScriptNum. A packed coefficient
vector still needs authenticated extraction and an actual evaluator.

## Exact hash-word and prefix counts

For each n the experiment chooses the best of the same five-opcode periodic
schedules used in R1, ending in SHA256. Let N(n) be its number of distinct
primitive hash words, expanding HASH256 to `ss` and HASH160 to `sr`.
Different selector encodings producing one word are counted once.

For fixed x, syntax-admissible root expectation is `N(n)*p`, where
`p=780555/2^65` is the R5 32-byte DER-syntax probability in the uniform-root
model. The packed family has M=`K*N(n)` root candidates and expectation Mp.
This is a **syntax** count. Zero/invalid ECDSA scalars, absent recovery points,
flag requirements, collisions or correlations can reduce the usable set.

Enumerating words does not inherently require n fresh hashes per root.
Traverse their prefix trie in depth-first order, keeping the hash state on
the traversal stack. Each edge computes one primitive hash, and an accepted
node supplies a candidate. The NFA/DFA count in the program gives the exact
number T(n) of distinct prefixes, including the empty prefix. One seed
SHA256 plus `T(n)-1` edges costs exactly T(n) primitive hash evaluations for
the complete word traversal of one seed. The count is checked against
explicit prefix sets for small schedules.

Only the current path and finite automaton state need be kept; the complete
trie need not be materialized. A successful word's selector witness can be
reconstructed from an accepting subsequence of the fixed schedule. Maintain
the register holding that subsequence: update it when the next opcode is
selected and update the other register when it is skipped. This yields the
original two-register routing choices. Automaton bookkeeping, witness
reconstruction and storing usable roots are additional work and memory.

At n=37:

```
log2 N = 33.7766643472,
log2 M = 61.7766643419,
T/N    = 1.8916436841,
log2(K*T) = 62.6963047056 primitive hash evaluations.
```

**The last number is only the hash enumeration cost.** It excludes native
transaction digest generation, EC recovery and point validation, H(P) pin
checks, arithmetic/automaton overhead, setup audit, and any actual reference
proof. It must not be reported as total honest work below `2^64`.

## Finite root-plus-pin opportunities

Grant, conditionally, L genuine transactions certified by the *same* fixed
reference object after each alpha is known. Also grant one recovery branch
per syntax-valid root. In the independent syntax/pin model, put

```
s = 1-(1-p)^L,
expected syntax-valid roots = M*p,
expected root/pin pairs     = M*L*p^2,
Pr[at least one pair]       = 1-(1-p*s)^M.
```

For B independent branch opportunities replace L by B*L; the actual curve
does not guarantee B=4 or even one usable branch for every DER root. Filtering
for recoverability and correct output-binding flags has to be incorporated
before these quantities can describe a real full checker. The expression is
a finite-domain model, not an infinite geometric renewal argument or a
proven law for overlapping real hash paths.

The following uses the hypothetical **L=`2^32`**, one branch, and the packed
seed domain. This L is not provided by the affine toy: t/y are not linked to
the actual native transaction or EC recovery equation.

| Stages n | Complete toy ops | log2 root candidates | log2 full hash enumeration | Ideal syntax/pin success |
| ---: | ---: | ---: | ---: | ---: |
| 30 | 122 | 55.3307 | 56.2542 | 0.0834 |
| 34 | 134 | 59.0068 | 59.9303 | 0.6716 |
| 35 | 137 | 59.9777 | 60.9013 | 0.8872 |
| 36 | 140 | 60.8510 | 61.7743 | 0.9816 |
| 37 | 143 | 61.7767 | 62.6963 | 0.99950 |
| 40 | 152 | 64.6248 | 65.5483 | effectively 1 |
| 56 | 200 | 79.4380 | 80.3612 | effectively 1 |

A larger finite root domain is not a requirement to enumerate it all. The
last rows describe availability and full-enumeration cost separately; a
real algorithm may stop early but must analyze its stopping/failure behavior.
Conversely a finite domain with low success cannot simply restart with a
fresh semantic coefficient while claiming to keep the same reference.

For comparison, the old fixed-seed n=61 family has only about 0.147 expected
pairs at L=`2^32` before curve/flag filtering. The new packing shows that this
particular finite-root shortage is not an inherent consequence of retaining
one readable number. It does not resolve reference computation.

## Why a small randomized linear check does not complete the reference

The executed affine toy evaluates its whole function directly. Replacing a
large function by a short polynomial requires a separate reason that the
polynomial represents the actual native digest/recovery function. The root
does not supply that reason. It also does not turn later free wire values,
quotient coefficients or off-domain evaluations into authenticated data.

Even granting fully authenticated coefficients before a challenge, a uniform
polynomial-identity check cannot be transferred to a prover-selected scalar.
The exact F17 toy fixes `F(t)=t+7`. The false polynomial `G(t)=2t+6` agrees at
t=1. It passes with probability 1/17 under a uniform challenge but passes
certainly when the prover may select t=1. Across all 288 false affine
polynomials, 272 have exactly one such accepting point and 16 have none.
All 4,896 evaluations are checked locally. A native query must therefore be
bound, and the number of admissible native transactions/subsets mapping to
those accepting points must be counted, as in R4/R5. A witness integer is
not a native random challenge.

The actual BTC reference must at least connect the intended output list,
the funding-dependent sighash, alpha's recovery equation, and the same native
key/byte object tested by Script. The current complete toy does none of
those connections: for any alternative output list a retaining creator can
still use t=0,y=7 and run the same native root/pin search. Its mathematical
truth adds no output asymmetry. Similarly, placing a compact constant-context
three-key gate into the 58 spare operations would not by itself evaluate the
actual output-dependent function.

For this interface the constructive frontier is consequently precise:
37 stages and 28 packing bits leave 58 legacy operations in the raw example,
with enough *conditional* finite root opportunities for L=`2^32`. An actual
reference evaluator, authenticated query interface, usable root/flag handling
and a measured or bounded total search cost remain necessary. No universal
impossibility claim about other commitments or verifiers is made.

## Tests and evidence

Run `python3 research/covenant-2026-09-17/continuation/r10_parameter_frontier.py`.
The [JSON](r10_parameter_frontier.json) records 760 complete observable
arithmetic/hash successes, nine malformed/false rejections, nine explicit
prefix-language sizes, a fully enumerated 64-outcome finite-root/pin model,
and the F17 checks. The 64-outcome model gives expected root count 1, expected
pair count 1, but success probability 39/64; expected pairs are not themselves
a probability.

The [independent audit](r10_frontier_audit.py) checks ten explicit prefix sets
without the NFA implementation, 60 valid cases using another opcode
interpreter, 60 wrong-output rejections, packing endpoints, the 140-operation
observable count and peak 44, and exact large word/hash-count products.

Evidence: `locally-reproduced`; deployment: `unclassified`. No Core success,
complete native PoW witness, general polynomial commitment, or Bitcoin
reference verifier is claimed. No library files, field-library tests or
primitive metrics were changed.
