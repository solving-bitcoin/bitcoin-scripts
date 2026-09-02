# F257

F257 has two explicit backends:

| Backend | Representation | Purpose |
| --- | --- | --- |
| [`u31`](u31/) | canonical `[0, 257)` | generic variable, constant-chain, and direct-table arithmetic |
| [`lookup`](lookup/) | centered `[-128, 128]` | shared log/exp products and exact-square queries |

Conversions between the representations are explicit. Neither backend is
re-exported at the field root.
