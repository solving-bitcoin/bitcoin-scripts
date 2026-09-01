# Knowledge record schema

`knowledge/catalog.json` is the canonical machine-readable index. Markdown
pages provide interpretation and comparison; they must not contradict the
catalog.

## Catalog envelope

The root object contains:

- `schema_version`: schema revision used by the validator.
- `as_of`: last catalog-wide review date in `YYYY-MM-DD` format.
- `cost_model`: link to the definitions used by all measurements.
- `records`: array of primitive-construction records.

## Required record fields

- `id`: stable, lowercase identifier in `class/name` form.
- `name`: human-readable construction name.
- `class`: taxonomy path.
- `summary`: one-sentence semantic description.
- `status`: `active`, `experimental`, `compatibility`, `superseded`, or
  `literature-only`.
- `evidence`: one of the levels in `evidence.md`.
- `execution`: one of the deployment classes in `evidence.md`.
- `as_of`: last substantive review date.
- `knowledge_page`: repository-relative Markdown path.
- `implementation`: repository-relative source path, or `null`.
- `documentation`: repository-relative implementation documentation, or
  `null`.
- `tests`: array of executable test names or test-file paths.
- `references`: array of IDs from `references/sources.json`.
- `techniques`: array of stable technique IDs.
- `security`: concise assumptions and caller obligations.
- `stack_contract`: concise input/output statement.
- `configurations`: zero or more comparable measurements.
- `limitations`: known non-composability, security, consensus, or evidence
  limitations.
- `open_problems`: IDs listed in `open-problems.md`.

## Configuration fields

Each configuration has a stable `id`, a human-readable `label`, and the exact
`includes` boundary. Numeric fields are nullable because an unknown value is
different from zero:

- `script_bytes`
- `witness_bytes`
- `witness_bytes_max`
- `max_stack_items`
- `executed_opcodes`
- `validation_weight`
- `setup_script_bytes`
- `per_use_script_bytes`

`parameters` is an object containing every value needed to reproduce the
configuration. `metric_keys` links measurements back to the checked README
markers in `tests/primitive_metrics.rs`.

## Evolution rules

IDs are permanent. If semantics change, create a new ID and use
`supersedes`/`superseded_by`. Additive schema changes increment the minor
version; incompatible changes increment the major version. The validator
rejects duplicate IDs, invalid enums, missing paths, unknown references, and
empty reproduction boundaries.
