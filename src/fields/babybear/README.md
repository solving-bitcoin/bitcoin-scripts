# BabyBear and BabyBear4 on the u31 backend

`u31::BabyBear` uses `p = 15 * 2^27 + 1`. `babybear4::BabyBear4` uses the
RISC Zero polynomial `x^4 + 11`, not Plonky3's `x^4 - 11` convention.

The representative degree-four multiplication is
<!-- metric:babybear4_mul -->13158<!-- /metric:babybear4_mul --> bytes and peaks
at 53 combined stack items. It excludes input pushes and a terminal result
check. Inputs must be canonical; no hints or range checks are included.
