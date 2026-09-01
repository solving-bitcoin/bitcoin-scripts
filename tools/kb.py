#!/usr/bin/env python3
"""Query and validate the Bitcoin Script primitive knowledge base."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "knowledge/catalog.json"
SOURCES_PATH = ROOT / "knowledge/references/sources.json"
OPEN_PROBLEMS_PATH = ROOT / "knowledge/open-problems.md"

STATUSES = {"active", "experimental", "compatibility", "superseded", "literature-only"}
EVIDENCE = {"reported", "inspected", "locally-reproduced", "differentially-validated"}
EXECUTION = {
    "consensus-validated",
    "policy-validated",
    "consensus-incompatible",
    "research-unlimited",
    "unclassified",
}
BOUNDARIES = (
    "fragment-only:",
    "fragment-with-memory:",
    "complete-leaf:",
    "complete-transaction:",
)
REQUIRED_RECORD_FIELDS = {
    "id",
    "name",
    "class",
    "summary",
    "status",
    "evidence",
    "execution",
    "as_of",
    "knowledge_page",
    "implementation",
    "documentation",
    "tests",
    "references",
    "techniques",
    "security",
    "stack_contract",
    "configurations",
    "limitations",
    "open_problems",
}
NUMERIC_CONFIGURATION_FIELDS = {
    "script_bytes",
    "witness_bytes",
    "witness_bytes_max",
    "max_stack_items",
    "executed_opcodes",
    "validation_weight",
    "setup_script_bytes",
    "per_use_script_bytes",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def load_catalog() -> dict[str, Any]:
    return load_json(CATALOG_PATH)


def selector_matches(record: dict[str, Any], selector: str) -> bool:
    return (
        record["id"] == selector
        or record["id"].startswith(selector.rstrip("/") + "/")
        or record["class"] == selector
        or record["class"].startswith(selector.rstrip("/") + "/")
    )


def filtered_records(args: argparse.Namespace) -> list[dict[str, Any]]:
    records = load_catalog()["records"]
    for field in ("class_name", "status", "evidence", "execution"):
        value = getattr(args, field, None)
        if value:
            key = "class" if field == "class_name" else field
            records = [record for record in records if record[key] == value]
    return records


def command_list(args: argparse.Namespace) -> int:
    records = filtered_records(args)
    if args.json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return 0
    for record in records:
        print(
            f"{record['id']:<38} {record['evidence']:<26} "
            f"{record['execution']:<23} {record['name']}"
        )
    print(f"\n{len(records)} record(s)")
    return 0


def command_show(args: argparse.Namespace) -> int:
    records = [record for record in load_catalog()["records"] if record["id"] == args.id]
    if not records:
        print(f"unknown record: {args.id}", file=sys.stderr)
        return 1
    record = records[0]
    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
        return 0
    print(f"{record['name']} ({record['id']})")
    print(f"class: {record['class']}")
    print(f"status/evidence/execution: {record['status']} / {record['evidence']} / {record['execution']}")
    print(f"as of: {record['as_of']}")
    print(f"summary: {record['summary']}")
    print(f"security: {record['security']}")
    print(f"stack: {record['stack_contract']}")
    print(f"knowledge: {record['knowledge_page']}")
    if record["implementation"]:
        print(f"implementation: {record['implementation']}")
    print("configurations:")
    if not record["configurations"]:
        print("  (none; instance-specific or unmeasured)")
    for config in record["configurations"]:
        metrics = ", ".join(
            f"{field}={config[field]}"
            for field in sorted(NUMERIC_CONFIGURATION_FIELDS)
            if config.get(field) is not None
        )
        print(f"  {config['id']}: {metrics or 'unmeasured'}")
        print(f"    {config['includes']}")
    return 0


def command_search(args: argparse.Namespace) -> int:
    terms = [term.casefold() for term in args.terms]
    matches = []
    for record in load_catalog()["records"]:
        haystack = json.dumps(record, sort_keys=True).casefold()
        if all(term in haystack for term in terms):
            matches.append(record)
    if args.json:
        print(json.dumps(matches, indent=2, sort_keys=True))
    else:
        for record in matches:
            print(f"{record['id']:<38} {record['summary']}")
        print(f"\n{len(matches)} match(es)")
    return 0


def command_best(args: argparse.Namespace) -> int:
    if args.metric not in NUMERIC_CONFIGURATION_FIELDS:
        print(f"unsupported metric: {args.metric}", file=sys.stderr)
        return 1
    candidates = []
    for record in load_catalog()["records"]:
        if not selector_matches(record, args.selector):
            continue
        if args.execution and record["execution"] != args.execution:
            continue
        for config in record["configurations"]:
            value = config.get(args.metric)
            if isinstance(value, (int, float)):
                candidates.append((value, record, config))
    candidates.sort(key=lambda item: item[0])
    if args.json:
        payload = [
            {
                "value": value,
                "record": record["id"],
                "configuration": config["id"],
                "includes": config["includes"],
                "execution": record["execution"],
            }
            for value, record, config in candidates
        ]
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("Candidates are sorted numerically, not declared universally comparable.")
    print("Inspect every inclusion boundary and execution class before citing a best result.\n")
    for value, record, config in candidates:
        print(f"{value:>10}  {record['id']}#{config['id']}  [{record['execution']}]")
        print(f"            {config['includes']}")
    return 0 if candidates else 1


def parse_date(value: str, location: str, errors: list[str]) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        errors.append(f"{location}: invalid ISO date {value!r}")
        return None


def validate() -> list[str]:
    errors: list[str] = []
    catalog = load_catalog()
    sources_document = load_json(SOURCES_PATH)
    records = catalog.get("records")
    sources = sources_document.get("sources")
    if catalog.get("schema_version") != 1:
        errors.append("catalog: unsupported schema_version")
    if not isinstance(records, list):
        return errors + ["catalog: records must be an array"]
    if not isinstance(sources, list):
        return errors + ["sources: sources must be an array"]

    source_ids = [source.get("id") for source in sources]
    if len(source_ids) != len(set(source_ids)):
        errors.append("sources: duplicate source id")
    source_id_set = set(source_ids)
    for index, source in enumerate(sources):
        location = f"sources[{index}]"
        for field in ("id", "title", "kind", "url", "revision"):
            if not source.get(field):
                errors.append(f"{location}: missing or empty {field}")
    open_problem_ids = set(re.findall(r"^## (OP-\d+)\b", OPEN_PROBLEMS_PATH.read_text(encoding="utf-8"), re.MULTILINE))
    metric_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [ROOT / "tests/primitive_metrics.rs", *ROOT.glob("src/**/README.md")]
    )
    metric_values = {
        key: int(value)
        for key, value in re.findall(
            r"<!-- metric:([a-zA-Z0-9_-]+) -->([0-9]+)<!-- /metric:\1 -->",
            metric_text,
        )
    }

    record_ids: set[str] = set()
    config_ids: set[str] = set()
    for index, record in enumerate(records):
        location = f"records[{index}]"
        missing = REQUIRED_RECORD_FIELDS - set(record)
        if missing:
            errors.append(f"{location}: missing fields {sorted(missing)}")
            continue
        record_id = record["id"]
        if record_id in record_ids:
            errors.append(f"{location}: duplicate id {record_id}")
        record_ids.add(record_id)
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*", record_id):
            errors.append(f"{location}: invalid id {record_id!r}")
        if record["status"] not in STATUSES:
            errors.append(f"{record_id}: invalid status {record['status']!r}")
        if record["evidence"] not in EVIDENCE:
            errors.append(f"{record_id}: invalid evidence {record['evidence']!r}")
        if record["execution"] not in EXECUTION:
            errors.append(f"{record_id}: invalid execution {record['execution']!r}")
        parse_date(record["as_of"], record_id, errors)

        for field in ("knowledge_page", "implementation", "documentation"):
            value = record[field]
            if value is not None and not (ROOT / value).is_file():
                errors.append(f"{record_id}: {field} does not exist: {value}")
        for reference in record["references"]:
            if reference not in source_id_set:
                errors.append(f"{record_id}: unknown reference {reference}")
        for problem in record["open_problems"]:
            if problem not in open_problem_ids:
                errors.append(f"{record_id}: unknown open problem {problem}")

        local_config_ids: set[str] = set()
        for config in record["configurations"]:
            config_location = f"{record_id}#{config.get('id', '?')}"
            required = {"id", "label", "parameters", "includes", "metric_keys"} | NUMERIC_CONFIGURATION_FIELDS
            missing_config = required - set(config)
            if missing_config:
                errors.append(f"{config_location}: missing fields {sorted(missing_config)}")
                continue
            if config["id"] in local_config_ids:
                errors.append(f"{record_id}: duplicate configuration id {config['id']}")
            local_config_ids.add(config["id"])
            global_config_id = f"{record_id}#{config['id']}"
            if global_config_id in config_ids:
                errors.append(f"duplicate global configuration id {global_config_id}")
            config_ids.add(global_config_id)
            if not config["includes"].startswith(BOUNDARIES):
                errors.append(f"{config_location}: includes must start with a cost-model boundary")
            for field in NUMERIC_CONFIGURATION_FIELDS:
                value = config[field]
                if value is not None and (not isinstance(value, (int, float)) or value < 0):
                    errors.append(f"{config_location}: {field} must be nonnegative or null")
            for metric_key in config["metric_keys"]:
                if metric_key not in metric_values:
                    errors.append(f"{config_location}: unknown README metric key {metric_key}")
                    continue
                numeric_values = {
                    value
                    for field in NUMERIC_CONFIGURATION_FIELDS
                    if isinstance((value := config[field]), (int, float))
                }
                if metric_values[metric_key] not in numeric_values:
                    errors.append(
                        f"{config_location}: README metric {metric_key}="
                        f"{metric_values[metric_key]} is absent from catalog numeric fields"
                    )

    if not (ROOT / catalog.get("cost_model", "")).is_file():
        errors.append("catalog: cost_model path does not exist")

    referenced_pages = {ROOT / record["knowledge_page"] for record in records}
    primitive_pages = set((ROOT / "knowledge/primitives").glob("*.md")) - {
        ROOT / "knowledge/primitives/index.md"
    }
    for page in sorted(primitive_pages - referenced_pages):
        errors.append(f"orphan primitive page: {page.relative_to(ROOT)}")

    markdown_link = re.compile(r"\[[^]]+\]\(([^)]+)\)")
    for page in ROOT.glob("knowledge/**/*.md"):
        text = page.read_text(encoding="utf-8")
        for target in markdown_link.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative_target = target.split("#", 1)[0]
            if not relative_target:
                continue
            resolved = (page.parent / relative_target).resolve()
            if not resolved.exists():
                errors.append(
                    f"{page.relative_to(ROOT)}: broken local link {target}"
                )
    parse_date(catalog.get("as_of"), "catalog", errors)
    parse_date(sources_document.get("as_of"), "sources", errors)
    return errors


def command_validate(_: argparse.Namespace) -> int:
    errors = validate()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"knowledge base invalid: {len(errors)} error(s)", file=sys.stderr)
        return 1
    catalog = load_catalog()
    configurations = sum(len(record["configurations"]) for record in catalog["records"])
    print(f"knowledge base valid: {len(catalog['records'])} records, {configurations} configurations")
    return 0


def command_stale(args: argparse.Namespace) -> int:
    today = dt.date.today()
    threshold = today - dt.timedelta(days=args.days)
    stale = []
    for record in load_catalog()["records"]:
        reviewed = dt.date.fromisoformat(record["as_of"])
        if reviewed < threshold:
            stale.append((reviewed, record["id"]))
    for reviewed, record_id in sorted(stale):
        print(f"{reviewed.isoformat()}  {record_id}")
    print(f"\n{len(stale)} record(s) older than {args.days} days as of {today.isoformat()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="list catalog records")
    list_parser.add_argument("--class", dest="class_name")
    list_parser.add_argument("--status", choices=sorted(STATUSES))
    list_parser.add_argument("--evidence", choices=sorted(EVIDENCE))
    list_parser.add_argument("--execution", choices=sorted(EXECUTION))
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(handler=command_list)

    show_parser = subparsers.add_parser("show", help="show one record")
    show_parser.add_argument("id")
    show_parser.add_argument("--json", action="store_true")
    show_parser.set_defaults(handler=command_show)

    search_parser = subparsers.add_parser("search", help="full-record keyword search")
    search_parser.add_argument("terms", nargs="+")
    search_parser.add_argument("--json", action="store_true")
    search_parser.set_defaults(handler=command_search)

    best_parser = subparsers.add_parser("best", help="sort matching configurations by one metric")
    best_parser.add_argument("selector", help="record id prefix or exact class")
    best_parser.add_argument("metric", choices=sorted(NUMERIC_CONFIGURATION_FIELDS))
    best_parser.add_argument("--execution", choices=sorted(EXECUTION))
    best_parser.add_argument("--json", action="store_true")
    best_parser.set_defaults(handler=command_best)

    stale_parser = subparsers.add_parser("stale", help="list records older than a review threshold")
    stale_parser.add_argument("--days", type=int, default=180)
    stale_parser.set_defaults(handler=command_stale)

    validate_parser = subparsers.add_parser("validate", help="validate schema, links, references, and metric keys")
    validate_parser.set_defaults(handler=command_validate)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
