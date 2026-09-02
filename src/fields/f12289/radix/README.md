# F12289 radix-table backend

This specialization multiplies canonical F12289 coefficients by a
generation-time constant through reusable high- and low-radix tables. There is
no implicit radix width; measurements use seven low bits (`radix = 128`) and a
query beside a 512-coefficient state.

| Fragment | Script size | Maximum stack items |
| --- | ---: | ---: |
| Radix-128 memory | <!-- metric:f12289_radix128_memory -->781<!-- /metric:f12289_radix128_memory --> bytes | 225 table items |
| Radix-128 query, depth 511 | <!-- metric:f12289_radix128_query -->134<!-- /metric:f12289_radix128_query --> bytes | <!-- metric:f12289_radix128_state_stack -->740<!-- /metric:f12289_radix128_state_stack --> |

The table beats the average signed addition chain at roughly nine uses of one
constant. Inputs are not range-checked, and `preserved_items` must match the
actual intervening state. Sizes exclude inputs, cleanup outside the measured
memory fragment, and a terminal predicate.
