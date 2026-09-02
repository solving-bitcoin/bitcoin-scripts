# F12289

F12289 has two explicit backends:

| Backend | Purpose |
| --- | --- |
| [`u31`](u31/) | generic canonical field arithmetic |
| [`radix`](radix/) | reusable radix-table constant multiplication for Falcon experiments |

Both use canonical coefficients in `[0, 12,289)`. Neither backend is
re-exported at the field root.
