# Fixed-root key sharing does not close the publication budget

Question: can fewer checks or shared verification keys bring the fixed
four-root scalar commitment below 100,000 total legacy vB? A three-key
explicit representation already costs at least **112,556 vB with free
signatures and framing**. Even granting ideal key reuse, the four-key,
40-byte-opening representation costs at least **116,700 vB**. Reuse also
introduces a precise alternative-label disclosure condition.

[Executable algebra and counting probe](orbit_key_sharing_probe.py),
[results and source hashes](orbit-key-sharing-probe.json),
[underlying orbit commitment](four-root-orbit.md).

These bounds concern explicit inventories and messages encoded as subsets
of distinct orbit labels. They do not exclude other commitments, implicit
alphabets, additional secret authentication inputs, or a new SegWit setup.
The three-key variant is granted correct extraction for the cost comparison;
no such extraction theorem or native predicate is established here.

## At most two labels can own one key

Fix r0=2 and C=2^248. Let R0 and R1 be the two chosen lifts with coordinates
r0 and r0+n. The label s is canonical, 1<=s<=(n-1)/2, with orbit

```
O(s) = { sR0, -sR0, sR1, -sR1 }.
Q_H = (H-CG)/r0,       H in O(s).
```

The affine map H -> Q_H is bijective, so two packets share a verification
key exactly when they share an orbit point. For one fixed nonzero point H
and one fixed base R_i, there is exactly one canonical scalar s with
H=+/-sR_i. There are two bases. Therefore **each key belongs to at most two
distinct canonical labels**, regardless of whether anybody knows the
relation between the bases.

A selection of t labels requiring k distinct orbit keys each has k*t key
occurrences. Reusing keys perfectly still needs at least ceil(k*t/2)
different public keys. In particular, all four checks require at least
2*t supplied keys. If instead the whole inventory of N labels embeds all
its keys, it needs at least 2*N keys. At most 2^N label subsets exist, so
covering 2^2048 messages then costs at least 2048*2*33=**135,168 raw key bytes**,
even with free openings, opcodes, wrappers and framing.

The degree bound is not an assumption about independent random labels.
It includes deliberately correlated labels. An order-three known-ratio
control in the actual secp256k1 group attains six shared points for three
four-point packets. That control tests orbit geometry only; its second base
is not the x=n+2 ECDSA lift.

## What two overlapping openings reveal

Write R1=rho*R0. If distinct canonical s,t share an orbit point, they cannot
share it through the same base, which would imply s=+/-t. A cross-base
equality instead implies

```
rho in { s/t, -s/t, t/s, -t/s } mod n.
```

Testing those four public scalar candidates against rho*R0=R1 identifies the
ratio. Thus an efficient setup that prepares two distinct known scalar
openings with a shared key also computes this fixed base relation. The
current r0=2 construction has no known such ratio; this is an exact reduction,
not a measured or proved lower bound on its discrete-log difficulty.

Even if setup obtained rho privately, revealing the two overlapping labels
would reveal rho to the observer. Given one scalar s and rho, the observer
can compute the only possible neighboring labels

```
canonical(rho*s),       canonical(s/rho),
```

and check their public packets. Repeating this procedure opens the entire
connected component of the key-sharing graph. Its degree is at most two;
components are paths or cycles. Consequently a permitted selection that
contains both endpoints of a shared-key edge while omitting another label
in that component violates alternative-label privacy. For unrestricted
t-of-N choices with 2<=t<N, any component of size at least three admits such
a bad selection. Across pools, disclosure of the same global rho can also
propagate from already opened labels in other components.

This does not prove that one opening alone reveals rho, nor that every
restricted choice family using overlaps fails. The theorem identifies the
specific disclosure condition. Avoiding that condition reduces the usable
message family; the size bound below generously counts all subsets anyway.

## Size bound, including ideal key reuse

Grant one raw 20-byte commitment per candidate, authenticating the entire
packet for free. Charge only raw supplied compressed keys and the specified
signature items. Grant free pushes, table lookup, duplicate-key reuse,
checks, authorizations, funding outputs, input headers, and all transaction
framing. Everything is legacy data because this fixed-digest honest setup
uses the SINGLE constant; there is no witness discount.

For N candidates and t selected labels, suppose this optimistic cost is at
least a*N+b*t. Define R by

```
2^(-a/R) + 2^(-(a+b)/R) = 1.
```

Summing 2^(-cost/R) over all subsets gives at most one. If 2^2048 distinct
subset messages all cost at most B, then B>=2048*R. The argument permits
mixed pool sizes/cardinalities and works for any restricted subset family;
ordering the same disclosed labels does not add private message capacity.
The probe computes R with 90-digit Decimal arithmetic and checks that both
ends of its final bisection bracket give the same integer ceiling.

Without key sharing:

| Supplied keys per label | Signature B | a | b | Lower bound vB |
|---:|---:|---:|---:|---:|
| 4 | 0, granted free | 20 | 132 | 131,601 |
| 3 | 0, granted free | 20 | 99 | **112,556** |
| 3 | 40 | 20 | 139 | 135,497 |
| 2 | 40 | 20 | 106 | 116,700 |
| 1 | 40 | 20 | 73 | 96,549 |

With ideal sharing, use b=33*k/2+L, where k is the number of checked keys
and L the raw signature size. Fractional key counts grant another saving:

| Checked orbit keys per label | Signature B | b | Lower bound vB |
|---:|---:|---:|---:|
| 4 | 40 | 106 | **116,700** |
| 3, hypothetical sufficient check set | 40 | 89.5 | **106,828** |
| 2, hypothetical sufficient check set | 40 | 73 | 96,549 |
| 4 | 13 | 79 | 100,340 |
| 4 | 12 | 78 | 99,712 |

The 40-byte rows describe full-width canonical scalar openings: one DER r
byte, 32 DER s bytes and seven framing/sighash bytes. They do not silently
replace variable-length signatures by a universal 40-byte minimum. The
13-byte row shows that even far shorter uniform profiles exceed the target
with four keys. A <=12-byte signature at r0=2 has at most four DER bytes for
s, putting canonical s below 2^31; this is not a secret full-width label.
No short-label security weakening is proposed as a solution.

The two-key shared row leaves a numerical margin only after these favorable
omissions. It is a necessary cost filter, not a construction: extraction,
safe sharing, actual serialization and public garbled-label binding would
all still need to be supplied.

The [graph and disclosure follow-up](orbit-private-sharing-bound.md) closes
that numerical margin for the stated fixed-orbit inventory. Fixed two-key
packets with 40-byte openings cost at least 110,865 vB when their actual
sharing graph is counted. Requiring no unselected scalar disclosure raises
the bound to 116,643 vB, even granting a spend-dependent choice of two orbit
keys. The 96,549-vB row above remains a valid but unattainably generous
incidence relaxation in that model.

## Reproduction and scope

Five focused host tests pass. Eight full-size labels over the actual r0=2
roots verify **64 ECDSA equations**, including high-S counterparts, and have
32 different orbit points. Those samples do not prove absence of arbitrary
overlaps; the at-most-two-owner statement follows from the algebra above.

Separate known-ratio controls use R1=7R0 and its signed/inverse variations.
Eight oriented cases recover the ratio. Three choices of adjacent openings
in a four-label chain recover both unselected labels. Another control attains
the key-incidence bound with an order-three ratio. These controls use actual
secp256k1 point arithmetic, but **are not ECDSA recovery root sets** and are
not native point-lock counterexamples. The actual root ratio is not computed.

Evidence: **inspected** counting/sharing arguments and **locally-reproduced**
algebra/numerical examples. Deployment: **unclassified**. No Script, Core
transaction, setup timing, onchain hint count, stack peak, or opcode metric
is claimed for a new primitive. The probe uses no tapscript or unlimited-stack
execution helper and runs no field-arithmetic-module tests. Existing native
point-lock reports and their byte counts are unchanged.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/orbit_key_sharing_probe.py -v
```
