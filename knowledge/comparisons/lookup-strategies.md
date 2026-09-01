# Lookup strategies

## F257 measured frontier

| Strategy | Setup/memory bytes | Per operation bytes | Persistent/peak items | Suitable use |
| --- | ---: | ---: | ---: | --- |
| Centered constant chain | 0 | 132 | peak 4 | Isolated known constant |
| Half direct table, batch 8 | included in 573 | included | peak 139 | Repeated same constant |
| Full direct table, batch 8 | included in 809 | included | peak 266 | Larger same-constant batches |
| Log/exp | 1,196 | 44 constant / 60 variable | 385 memory; peak 900 at depth | Repeated mixed products |
| Exact square | 499 | 11 | 129 memory; peak 643 at depth | Repeated centered squares |

The implementation README estimates byte crossover near four uses for the half
table, fourteen constant uses or four variable uses for log/exp. Recalculate
for the actual live stack and cleanup boundary.

## RNS measured frontier

| Strategy | One-shot bytes | Peak items | Reuse behavior |
| --- | ---: | ---: | --- |
| Legacy direct-table RNS | 1,564 | 903 | Includes full memory and cleanup |
