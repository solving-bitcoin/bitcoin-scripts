# F12289 generic u31 backend

`F12289` configures the generic [`arithmetic::u31`](../../../arithmetic/u31/)
backend with `p = 12,289`. Elements are canonical Script numbers in
`[0, 12,289)`.

The compact variable multiplication is
<!-- metric:f12289_mul_compact -->504<!-- /metric:f12289_mul_compact --> bytes
and peaks at
<!-- metric:f12289_mul_compact_stack -->20<!-- /metric:f12289_mul_compact_stack -->
combined stack items. It excludes input pushes, range checks, and the terminal
result predicate.
