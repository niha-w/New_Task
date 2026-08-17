#!/usr/bin/env python3
"""
generate_semgrep_rules.py

Generates a Semgrep taint-mode rule set from all_sensitive_columns.json (the
merged base + view-derived sensitivity catalog produced by propagate.py).

Pipeline position:
    information_schema extraction -> sqlglot lineage -> propagate.py
    -> all_sensitive_columns.json -> **this script** -> semgrep_rules.yml

--------------------------------------------------------------------------
GAPS THIS SCRIPT ADDRESSES (see project writeup for full discussion)
--------------------------------------------------------------------------
1. Column name held in a variable, then used in an f-string or via +
   concatenation, e.g.:
       column = "credit_card"
       query = f"SELECT {column} FROM customers"
   Handled by: the literal column name itself is the taint source. Semgrep's
   taint engine propagates taint through assignment by default, and
   `options.symbolic_propagation: true` additionally lets taint survive
   f-string interpolation and +-concatenation of an already-tainted value.

2. Query text assembled from string literals and stored in a separate
   variable before being executed, e.g.:
       SENSITIVE_QUERY = "SELECT credit_card FROM customers"
       cursor.execute(SENSITIVE_QUERY)
   Handled by: same mechanism as (1) -- this is ordinary intraprocedural
   assignment propagation, which Semgrep taint mode does by default. No
   special rule component is required.

3. Taint surviving a call to a *different*, syntactically-unrelated method
   on the same stateful object, e.g.:
       cursor.execute(query)          # query contains "credit_card"
       row = cursor.fetchone()
       print(row[0])                  # leak -- but fetchone() looks "clean"
   Handled by: explicit `pattern-propagators` (CURSOR_PROPAGATORS below).
   Semgrep does NOT infer this automatically -- taint on an argument to one
   method call does not by default reappear on the return value of a later,
   different call on the same object. This has to be declared.

4. Dict-style vs. attribute-style column access as independent sources:
       row["credit_card"]      # dict-style
       row.credit_card         # attribute-style / ORM-style
   Both are generated per column.

--------------------------------------------------------------------------
KNOWN, EXPLICITLY OUT-OF-SCOPE GAP (NOT solved by this script)
--------------------------------------------------------------------------
- Query returned from a different function and consumed at the call site,
  e.g. `cursor.execute(get_query())` where get_query() builds the string
  elsewhere. This is an interprocedural/interfile taint-tracking problem;
  OSS Semgrep only analyzes within a file/function by default. Semgrep Pro's
  interfile engine (`--pro`, `-pro_inter_file`) is the documented mechanism
  for this, and is out of scope for this script's OSS-targeted rules.

- Character-by-character or otherwise fully decomposed literal construction,
  e.g. "c" + "r" + "e" + "d" + "i" + "t" + "_" + "c" + "a" + "r" + "d".
  A literal-string pattern-sources rule matches the exact AST node for a
  string literal; it does not match an N-ary Concat expression tree, no
  matter how Semgrep's internal constant-folding resolves its final value.
  This is a fundamental limitation of literal-based source definitions, not
  a missing option -- held on hold per project scope, see writeup for the
  recommended long-term mitigation (accessor/model-field-based tagging
  instead of literal-name-based tagging).
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("generate_semgrep_rules")


# --------------------------------------------------------------------------- #
# Data loading
# --------------------------------------------------------------------------- #

@dataclass
class ColumnEntry:
    table: str
    category: str
    source: str  # "base" | "derived"
    derived_from: list[str] = field(default_factory=list)


def load_sensitive_columns(path: Path) -> dict[str, list[ColumnEntry]]:
    """Load all_sensitive_columns.json and group entries by bare column name.

    Grouping by column name (not table.column) is deliberate: a Semgrep rule
    operates on source code, which references a column by its bare name
    (`row["credit_card"]`, `row.credit_card`) -- it has no way to know which
    table that row came from at match time. So all tables/views that expose a
    column under the same name are folded into ONE rule, with the union of
    categories/tables recorded in the rule's metadata for audit purposes.

    Known false-positive source (documented, not fixed here): a common
    column name like `status` or `id` that happens to also be tagged
    sensitive somewhere will match ANY object's `.status` attribute in the
    codebase, not just DB row objects. See project writeup: "Semgrep
    open-source limitations."
    """
    raw = json.loads(path.read_text())
    grouped: dict[str, list[ColumnEntry]] = defaultdict(list)
    skipped = 0
    for row in raw:
        if not row.get("sensitive"):
            skipped += 1
            continue
        grouped[row["column"]].append(
            ColumnEntry(
                table=row["table"],
                category=row.get("category", "unknown"),
                source=row.get("source", "unknown"),
                derived_from=row.get("derived_from", []),
            )
        )
    if skipped:
        logger.debug("Skipped %d row(s) without sensitive=true", skipped)
    return grouped


# --------------------------------------------------------------------------- #
# Shared rule components
# --------------------------------------------------------------------------- #

# Egress points named explicitly in the problem statement: don't let a
# sensitive value reach the console, a log, an HTTP call, or a function's
# return value (which hands it to a caller outside the trusted boundary).
SINK_PATTERNS: list[dict[str, Any]] = [
    {"pattern": "print(...)"},
    {"pattern": "logging.$METHOD(...)"},
    {"pattern": "$LOGGER.$METHOD(...)"},
    {"pattern": "requests.$METHOD(...)"},
    {"pattern": "return ..."},
]

# Models a DB cursor as a stateful object: execute() taints the cursor,
# fetchone()/fetchall()/fetchmany() re-emit that taint on their return value.
# This is gap (3) above -- addresses the "row = cursor.fetchone()" loophole.
CURSOR_PROPAGATORS: list[dict[str, Any]] = [
    {"pattern": "$CURSOR.execute($QUERY, ...)", "from": "$QUERY", "to": "$CURSOR"},
    {"pattern": "$CURSOR.fetchone()", "from": "$CURSOR", "to": "$CURSOR"},
    {"pattern": "$CURSOR.fetchall()", "from": "$CURSOR", "to": "$CURSOR"},
    {"pattern": "$CURSOR.fetchmany(...)", "from": "$CURSOR", "to": "$CURSOR"},
]


def build_source_patterns(column: str) -> list[dict[str, Any]]:
    """Source variants for one column name: literal, dict-style, attribute-style."""
    quoted = json.dumps(column)  # safely escaped, e.g. "credit_card" -> '"credit_card"'
    return [
        {"pattern": quoted},
        {"pattern": f"$OBJ[{quoted}]"},
        {"pattern": f"$OBJ.{column}"},
    ]


# --------------------------------------------------------------------------- #
# Rule construction
# --------------------------------------------------------------------------- #

def build_rule(column: str, entries: list[ColumnEntry]) -> dict[str, Any]:
    tables = sorted({e.table for e in entries})
    categories = sorted({e.category for e in entries})
    derived_from = sorted({d for e in entries for d in e.derived_from})
    provenance = sorted({e.source for e in entries})

    message = (
        f"Possible leak of sensitive column '{column}' "
        f"(category: {', '.join(categories)}). Present in: {', '.join(tables)}."
    )
    if derived_from:
        message += f" Derived from base column(s): {', '.join(derived_from)}."
    message += (
        " Sensitive values must not reach print/log/HTTP-response/return "
        "sinks without explicit review."
    )

    return {
        "id": f"sensitive-data-leak.{column}",
        "mode": "taint",
        "languages": ["python"],
        "severity": "ERROR",
        "message": message,
        "metadata": {
            "category": "security",
            "subcategory": ["data-leak"],
            "confidence": "MEDIUM",
            "sensitivity_categories": categories,
            "tables": tables,
            "column_provenance": provenance,  # base and/or derived
            "derived_from": derived_from,
            "owasp": [
                "A01:2021 - Broken Access Control",
                "A09:2021 - Security Logging and Monitoring Failures",
            ],
        },
        "options": {
            # Lets taint survive f-string interpolation and +-concatenation
            # of an already-tainted value -- closes gaps (1)/(2) above.
            "symbolic_propagation": True,
        },
        "pattern-sources": [
            {"patterns": [{"pattern-either": build_source_patterns(column)}]}
        ],
        "pattern-propagators": copy.deepcopy(CURSOR_PROPAGATORS),
        "pattern-sinks": copy.deepcopy(SINK_PATTERNS),
    }


def build_ruleset(grouped: dict[str, list[ColumnEntry]]) -> dict[str, Any]:
    rules = [build_rule(col, entries) for col, entries in sorted(grouped.items())]
    return {"rules": rules}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--input", type=Path, default=Path("all_sensitive_columns.json"),
        help="Path to the merged sensitivity catalog (default: %(default)s)",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("semgrep_rules.yml"),
        help="Path to write the generated Semgrep rule file (default: %(default)s)",
    )
    parser.add_argument(
        "--split", action="store_true",
        help="Also write one file per rule into <output-dir>/split_rules/. "
             "Useful for Semgrep Playground's Save button, which only accepts "
             "a single rule per file (Run accepts multi-rule files fine).",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if not args.input.exists():
        raise SystemExit(f"Input file not found: {args.input}")

    grouped = load_sensitive_columns(args.input)
    if not grouped:
        logger.warning("No sensitive columns found in %s -- writing an empty rule set.", args.input)

    ruleset = build_ruleset(grouped)

    with args.output.open("w") as f:
        yaml.dump(ruleset, f, sort_keys=False, default_flow_style=False, width=100)

    logger.info(
        "Wrote %d rule(s) covering %d unique column name(s) to %s",
        len(ruleset["rules"]), len(grouped), args.output,
    )

    if args.split:
        split_dir = args.output.parent / "split_rules"
        split_dir.mkdir(exist_ok=True)
        for rule in ruleset["rules"]:
            rule_path = split_dir / f"{rule['id']}.yml"
            with rule_path.open("w") as f:
                yaml.dump({"rules": [rule]}, f, sort_keys=False, default_flow_style=False, width=100)
        logger.info("Also wrote %d single-rule file(s) to %s", len(ruleset["rules"]), split_dir)


if __name__ == "__main__":
    main()
