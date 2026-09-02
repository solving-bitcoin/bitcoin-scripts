# F257 centered lookup backend

This specialization uses centered coefficients in `[-128, 128]`. `to_centered`
and `to_canonical` convert explicitly between this representation and the
canonical `u31` backend. The 385-item log/exp memory supports constant and
variable products; the independent 129-item table returns exact integer
squares rather than field-reduced squares.

| Fragment | Script size | Maximum stack items |
| --- | ---: | ---: |
| Log/exp memory | <!-- metric:f257_log_memory -->1004<!-- /metric:f257_log_memory --> bytes | 385 table items |
| Constant query, depth 511 | <!-- metric:f257_log_constant_query -->44<!-- /metric:f257_log_constant_query --> bytes | <!-- metric:f257_log_constant_stack -->900<!-- /metric:f257_log_constant_stack --> |
| Variable query, depth 510 | <!-- metric:f257_log_variable_query -->60<!-- /metric:f257_log_variable_query --> bytes | <!-- metric:f257_log_state_stack -->900<!-- /metric:f257_log_state_stack --> |
| Exact-square memory | <!-- metric:f257_square_memory -->435<!-- /metric:f257_square_memory --> bytes | 129 table items |
| Exact-square query, depth 511 | <!-- metric:f257_square_query -->11<!-- /metric:f257_square_query --> bytes | <!-- metric:f257_square_state_stack -->643<!-- /metric:f257_square_state_stack --> |

Log/exp memory can be shared across different constants and variable products;
it amortizes after roughly fourteen constant products or four variable
products. The two memories cannot coexist with a 512-item polynomial state
under the 1,000-item stack limit, so they need separate phases.

Inputs are not range-checked. Out-of-range values can address unrelated stack
items through `OP_PICK`. Sizes exclude input pushes, memory-external state, and
a terminal predicate. Callers must count all live items and arrange cleanstack.
