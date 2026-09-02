# M31 and QM31 on the u31 backend

`u31::M31` configures the generic backend with `p = 2^31 - 1`. `qm31::QM31`
is the degree-four extension `F_(p²)[y]/(y² - 2 - i)` over
`F_p[i]/(i² + 1)`. Canonicality is a caller obligation.

| Fragment | Script size | Maximum stack items |
| --- | ---: | ---: |
| `u31_add::<M31>()` | <!-- metric:u31_add -->18<!-- /metric:u31_add --> bytes | 3 |
| `u31_sub::<M31>()` | <!-- metric:u31_sub -->12<!-- /metric:u31_sub --> bytes | 3 |
| `u31_mul::<M31>()` | <!-- metric:u31_mul -->1370<!-- /metric:u31_mul --> bytes | 37 |
| Constant multiply by `0x12345678` | <!-- metric:u31_mul_constant -->725<!-- /metric:u31_mul_constant --> bytes | 4 |
| `u31ext_add::<QM31>()` | <!-- metric:qm31_add -->83<!-- /metric:qm31_add --> bytes | 9 |
| `u31ext_sub::<QM31>()` | <!-- metric:qm31_sub -->62<!-- /metric:qm31_sub --> bytes | 9 |
| `u31ext_mul::<QM31>()` | <!-- metric:qm31_mul -->12901<!-- /metric:qm31_mul --> bytes | 52 |
| `u31ext_mul_u31::<QM31>()` | <!-- metric:qm31_mul_base -->4612<!-- /metric:qm31_mul_base --> bytes | 133 |
| Extension constant multiply by `0x12345678` | <!-- metric:qm31_mul_constant -->2906<!-- /metric:qm31_mul_constant --> bytes | 7 |

A binary base-field witness uses two items and serializes to
<!-- metric:u31_witness_min -->3<!-- /metric:u31_witness_min -->–<!-- metric:u31_witness_max -->11<!-- /metric:u31_witness_max -->
bytes for the measured range. A binary degree-four witness uses eight items and
serializes to <!-- metric:u31ext_witness_min -->9<!-- /metric:u31ext_witness_min -->–<!-- metric:u31ext_witness_max -->41<!-- /metric:u31ext_witness_max -->
bytes.

Sizes exclude inputs and terminal checks. No hints or hostile-input range
checks are included. Multiplication is tapscript-oriented; callers must consume
all coefficients and arrange cleanstack.
