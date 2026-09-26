#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

init_fixture() {
    local name="$1"
    local hook_source="$2"
    local fixture="$tmp_root/$name"
    mkdir -p "$fixture/bin" "$fixture/.githooks" "$fixture/src" "$fixture/knowledge"
    cp "$hook_source" "$fixture/.githooks/pre-commit"
    chmod +x "$fixture/.githooks/pre-commit"
    cat > "$fixture/bin/python3" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == "tools/kb.py validate" ]] || exit 90
[[ "$(cat src/check.rs)" == "working-tree-good" ]] || exit 11
printf 'kb checked working-tree-good\n' >> "$CONTRACT_LOG"
[[ "${FAIL_KB:-0}" != "1" ]] || exit 17
MOCK
    cat > "$fixture/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
    'fmt --all -- --check')
        [[ "$(cat src/check.rs)" == "working-tree-good" ]] || exit 12
        printf 'fmt checked working-tree-good\n' >> "$CONTRACT_LOG"
        ;;
    'test --locked --test primitive_metrics')
        [[ "$(cat src/check.rs)" == "working-tree-good" ]] || exit 13
        printf 'metrics checked working-tree-good\n' >> "$CONTRACT_LOG"
        ;;
    *) exit 91 ;;
esac
MOCK
    chmod +x "$fixture/bin/python3" "$fixture/bin/cargo"
    git -C "$fixture" init -q
    git -C "$fixture" config user.email hook-test@example.invalid
    git -C "$fixture" config user.name 'Pre-commit contract test'
    git -C "$fixture" config commit.gpgsign false
    printf 'working-tree-good\n' > "$fixture/src/check.rs"
    printf 'keep\n' > "$fixture/src/file with spaces.rs"
    printf 'valid knowledge\n' > "$fixture/knowledge/page.md"
    printf 'delete me\n' > "$fixture/delete me.md"
    git -C "$fixture" add .
    git -C "$fixture" -c core.hooksPath=/dev/null commit -qm baseline
    git -C "$fixture" config core.hooksPath .githooks
    printf '%s' "$fixture"
}

commit_fixture() {
    local fixture="$1"
    shift
    CONTRACT_LOG="$fixture/check.log" PATH="$fixture/bin:$PATH" "$@" git -C "$fixture" commit -m contract-test
}

assert_no_checkers_ran() {
    local fixture="$1"
    [[ ! -e "$fixture/check.log" ]] || fail "checks ran before staged/working-tree mismatch was rejected"
}

# A known-good staged change, including a path with spaces and a staged deletion,
# is accepted; default behavior runs knowledge and format checks, not metrics.
fixture="$(init_fixture valid "$repo_root/.githooks/pre-commit")"
printf 'updated\n' > "$fixture/src/file with spaces.rs"
git -C "$fixture" add -- 'src/file with spaces.rs'
git -C "$fixture" rm -q -- 'delete me.md'
commit_fixture "$fixture" env
[[ "$(cat "$fixture/check.log")" == $'kb checked working-tree-good\nfmt checked working-tree-good' ]] || fail "valid control did not run only default checks"

# The original hook accepts staged-bad bytes because its mocked validators
# inspect the different, good working-tree bytes.
fixture="$(init_fixture original "$repo_root/tests/fixtures/pre-commit-original.sh")"
printf 'staged-bad\n' > "$fixture/src/check.rs"
git -C "$fixture" add src/check.rs
printf 'working-tree-good\n' > "$fixture/src/check.rs"
commit_fixture "$fixture" env || fail "original hook did not reproduce the unsafe partial-stage pass"
[[ "$(git -C "$fixture" show HEAD:src/check.rs)" == staged-bad ]] || fail "original-hook commit did not contain staged-bad bytes"
[[ "$(cat "$fixture/check.log")" == *'kb checked working-tree-good'* ]] || fail "original-hook mocks did not inspect the good checkout"

# The fixed hook rejects that same mismatch before running any checker.
fixture="$(init_fixture partial-stage "$repo_root/.githooks/pre-commit")"
printf 'staged-bad\n' > "$fixture/src/check.rs"
git -C "$fixture" add src/check.rs
printf 'working-tree-good\n' > "$fixture/src/check.rs"
[[ "$(git -C "$fixture" show :src/check.rs)" == staged-bad ]] || fail "partial-stage fixture does not contain bad index bytes"
[[ "$(cat "$fixture/src/check.rs")" == working-tree-good ]] || fail "partial-stage fixture does not contain good checkout bytes"
index_before="$(git -C "$fixture" write-tree)"
if commit_fixture "$fixture" env 2> "$tmp_root/partial-stage.err"; then
    fail "fixed hook accepted staged-bad/working-tree-good content"
fi
grep -q 'tracked working-tree changes differ from the index' "$tmp_root/partial-stage.err" || fail "partial-stage rejection did not explain the mismatch"
assert_no_checkers_ran "$fixture"
[[ "$(git -C "$fixture" write-tree)" == "$index_before" ]] || fail "partial-stage rejection changed the index"
[[ "$(cat "$fixture/src/check.rs")" == working-tree-good ]] || fail "partial-stage rejection changed the working tree"

# Unstaged knowledge dependencies and untracked Rust files can affect the
# repository-wide checks even if the staged path itself has no divergence.
fixture="$(init_fixture unstaged-dependency "$repo_root/.githooks/pre-commit")"
printf 'staged edit\n' > "$fixture/README.md"
git -C "$fixture" add README.md
printf 'unstaged dependency edit\n' >> "$fixture/knowledge/page.md"
if commit_fixture "$fixture" env 2> "$tmp_root/unstaged.err"; then
    fail "fixed hook accepted an unstaged knowledge dependency"
fi
assert_no_checkers_ran "$fixture"

# A validator error reaches Git and leaves the staged state and checkout alone.
fixture="$(init_fixture validator-failure "$repo_root/.githooks/pre-commit")"
printf 'staged edit\n' > "$fixture/README.md"
git -C "$fixture" add README.md
index_before="$(git -C "$fixture" write-tree)"
head_before="$(git -C "$fixture" rev-parse HEAD)"
if commit_fixture "$fixture" env FAIL_KB=1 2> "$tmp_root/validator-failure.err"; then
    fail "fixed hook swallowed a knowledge-validator failure"
fi
[[ "$(git -C "$fixture" rev-parse HEAD)" == "$head_before" ]] || fail "validator failure created a commit"
[[ "$(git -C "$fixture" write-tree)" == "$index_before" ]] || fail "validator failure changed the index"
[[ "$(cat "$fixture/README.md")" == 'staged edit' ]] || fail "validator failure changed the working tree"
[[ "$(cat "$fixture/check.log")" == 'kb checked working-tree-good' ]] || fail "validator failure did not stop before later checks"
fixture="$(init_fixture untracked-source "$repo_root/.githooks/pre-commit")"
printf 'untracked source\n' > "$fixture/src/untracked source.rs"
printf 'staged edit\n' > "$fixture/README.md"
git -C "$fixture" add README.md
if commit_fixture "$fixture" env 2> "$tmp_root/untracked.err"; then
    fail "fixed hook accepted an untracked Rust dependency"
fi
grep -q 'non-ignored untracked files are not checked' "$tmp_root/untracked.err" || fail "untracked-file rejection did not explain the check scope"
assert_no_checkers_ran "$fixture"
fixture="$(init_fixture restored-deletion "$repo_root/.githooks/pre-commit")"
git -C "$fixture" rm -q -- 'delete me.md'
printf 'restored untracked bytes\n' > "$fixture/delete me.md"
if commit_fixture "$fixture" env 2> "$tmp_root/deletion.err"; then
    fail "fixed hook accepted a staged deletion restored as an untracked file"
fi
assert_no_checkers_ran "$fixture"

# Explicit opt-in invokes exactly the expensive metric suite; default control
# above proves it is not selected from staged paths.
fixture="$(init_fixture metrics-opt-in "$repo_root/.githooks/pre-commit")"
printf 'updated\n' > "$fixture/README.md"
git -C "$fixture" add README.md
CONTRACT_LOG="$fixture/check.log" PATH="$fixture/bin:$PATH" RUN_PRIMITIVE_METRICS=1 git -C "$fixture" commit -m metrics-opt-in
[[ "$(cat "$fixture/check.log")" == $'kb checked working-tree-good\nfmt checked working-tree-good\nmetrics checked working-tree-good' ]] || fail "metrics opt-in did not invoke the intended suite"

# Verify Git's index and hook-root discovery in a linked worktree path with spaces.
fixture="$(init_fixture linked-source "$repo_root/.githooks/pre-commit")"
linked="$tmp_root/linked worktree"
git -C "$fixture" worktree add -q -b linked "$linked"
printf 'updated knowledge\n' > "$linked/knowledge/page.md"
git -C "$linked" add knowledge/page.md
commit_fixture "$linked" env
[[ "$(git -C "$linked" log -1 --format=%s)" == contract-test ]] || fail "linked-worktree commit did not complete"

printf 'PASS: 9 pre-commit contract scenarios (valid paths with spaces/deletion; original vulnerability; fixed partial-stage rejection; unstaged dependency; untracked source; restored deletion; validator failure propagation; metrics opt-in; linked worktree)\n'
