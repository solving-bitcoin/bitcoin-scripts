# Arithmetic representations

The table is a navigation aid, not a single benchmark: semantics and boundaries
differ. Follow each catalog configuration before comparing numbers.

| Need | Local construction | Representative script bytes | Main constraint |
| --- | --- | ---: | --- |
| Small constant product | ScriptNum × 13 | 10 | Four-byte ScriptNum domain |
| Small-field add | M31 u31 add | 18 | Canonical field input |
| Small-field variable multiply | M31 u31 multiply | 1,400 | Witness quotient relation |
| Wide add | U254 add | 190 | Nine limbs |
| Wide multiply | U254 multiply | 111,466 | Very large script |
| Bounded RNS add | Legacy RNS add | 219 | Modulo 69,300 |
| Bounded RNS multiply | Legacy RNS multiply | 1,564 | 903-item peak |
| Exact 256-bit-product RNS add | Canonical coordinatewise | 1,134 | 513-bit composite range; 151-item peak |
| Exact 256-by-256-bit RNS multiply | Affine signed-log streaming | 37,471 | 513-bit composite range; 462-item peak |
| Hinted secp256k1 modular multiply | Prime RNS quotient/complement | 69,199 | 477 hint bytes; 612-item peak; global 256-bit bindings excluded |

Selection order: choose semantics and range, then representation compatibility,
then consensus feasibility, and only then minimize bytes. The prime-log profile
keeps canonical operands and covers one unsigned 256-by-256-bit product exactly,
but longer expressions remain modular unless their bound is proved below its
513-bit composite modulus. Range checks, conversion, and terminal predicates
remain outside the listed fragments.

The hinted modular row avoids CRT reconstruction inside the arithmetic
fragment, but it is not a complete witness boundary: its five RNS vectors must
already carry externally enforced unsigned-256-bit bounds.
