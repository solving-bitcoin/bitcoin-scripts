# F257 generic u31 backend

`F257` configures the generic [`arithmetic::u31`](../../../arithmetic/u31/)
backend with `p = 257`. Values are canonical Script numbers in `[0, 257)`.
The backend provides windowed and compact variable multiplication, signed
constant chains, and generic direct-table strategies.

| Fragment | Script size | Maximum stack items |
| --- | ---: | ---: |
| `u31_mul::<F257>()` | <!-- metric:f257_mul_baseline -->1208<!-- /metric:f257_mul_baseline --> bytes | 37 |
| `u31_mul_compact::<F257>()` | <!-- metric:f257_mul_compact -->337<!-- /metric:f257_mul_compact --> bytes | <!-- metric:f257_mul_compact_stack -->15<!-- /metric:f257_mul_compact_stack --> |
| Centered constant multiply by 173 | <!-- metric:f257_mul_centered_173 -->129<!-- /metric:f257_mul_centered_173 --> bytes | <!-- metric:f257_mul_centered_stack -->4<!-- /metric:f257_mul_centered_stack --> |
| Full direct-table batch, 8 values | <!-- metric:f257_full_lookup_batch8 -->808<!-- /metric:f257_full_lookup_batch8 --> bytes | <!-- metric:f257_full_lookup_batch8_stack -->266<!-- /metric:f257_full_lookup_batch8_stack --> |
| Half-table batch, 8 values | <!-- metric:f257_half_lookup_batch8 -->571<!-- /metric:f257_half_lookup_batch8 --> bytes | <!-- metric:f257_half_lookup_batch8_stack -->139<!-- /metric:f257_half_lookup_batch8_stack --> |

The signed chain is best for isolated constants. The half table amortizes at
about four repeated uses, while the full table wins for larger same-constant
batches. Sizes exclude inputs and output checks; no range checks or hints are
included.
