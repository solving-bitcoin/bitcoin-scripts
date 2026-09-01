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

Selection order: choose semantics and range, then representation compatibility,
then consensus feasibility, and only then minimize bytes.
