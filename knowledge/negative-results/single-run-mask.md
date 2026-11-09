# Transition count alone does not establish a single interval

`01110` and `10001` both have two adjacent transitions. The existing checked
u4 transition fold returns two for each fixture. The first mask has one run
of true values. The second has two. Counting transitions without endpoints
therefore fails this exact predicate. Virtual zero endpoints can make the
transition count characterize the number of true runs, but the count still
does not recover start or length.

The separate-closed-flag comparator does recover both outputs. Under the
matched 32-flag fixture it costs 698 script bytes, peaks at 35 and executes
354 non-push operations. Signed length costs 602 bytes, peaks at 33 and
executes 352. Both serialize 41 data witness bytes for 32 ordinary items
and zero hints. The separate-state variant also fails at 998 flags under the
combined limit. These results are `locally-reproduced` and `unclassified`.
See the [primitive note](../primitives/single-run-mask.md) for the scripts,
execution boundary and commands.
