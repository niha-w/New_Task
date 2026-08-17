"""
propagate.py
Combines: information_schema extraction (seed.json/views.json/schema.json, pasted
from the online compiler) + sqlglot.lineage (parsing) + a propagation/tagging layer
(this file) -> sensitivity_lineage.json

Run:  py propagate.py
Needs: pip install sqlglot   (add --break-system-packages if pip demands it)
"""

import json
import re
from sqlglot.lineage import lineage
#gives you SQLGlot's expression classes
from sqlglot import exp

# ---- 1. load what came out of information_schema (pasted from the online compiler) ----
with open("seed.json") as f:
    seed = json.load(f)          # [{"table": "customers", "column": "ssn", "category": "pii"}, ...]

with open("views.json") as f:
    views = json.load(f)         # [{"view": "customer_orders_view", "sql": "select ..."}, ...]

with open("schema.json") as f:
    schema_rows = json.load(f)   # [{"table_name": "customers", "column_name": "id", "data_type": "int"}, ...]

# ---- 2. shape into what sqlglot expects ----
sensitive = {(r["table"], r["column"]): r["category"] for r in seed}

schema = {}
for r in schema_rows:
    schema.setdefault(r["table_name"], {})[r["column_name"]] = r["data_type"]
# will look like this:
# schema = {
#     "customers": {
#         "id": "int",
#         "ssn": "varchar"
#     },
#     "orders": {
#         "id": "int"
#     }
# }


def strip_db_qualifier(sql: str) -> str:
    """MySQL's information_schema.views output qualifies every table reference
    with the database name, e.g. `mydb`.`orders`. sqlglot's `sources` dict matches
    views by bare name, so a nested view reference like `mydb`.`customer_orders_view`
    won't be recognized as the same object unless the db prefix is stripped first."""
    return re.sub(r"`[^`]+`\.(`[^`]+`)", r"\1", sql)


sources = {v["view"]: strip_db_qualifier(v["sql"]) for v in views}  # lets sqlglot resolve nested views automatically


# ---- 3. propagation layer: walk the lineage graph sqlglot built, find sensitive leaves ----
def find_leaf_hits(node, seen=None):
    """Return list of (table, column, category) for every sensitive base-table
    column that feeds into this node, walking through any depth of views/joins/CASE."""
    if seen is None:
        seen = set()
    if id(node) in seen:
        return []
    seen.add(id(node))

    hits = []
    #Checking whether we've reached a base table
    #exp.Table is SQLGlot's representation of a SQL table expression.
    if isinstance(node.source, exp.Table):
        table = node.source.name
        column = node.name.split(".")[-1].strip('`"')  # sqlglot renders names quoted; strip before matching
        if (table, column) in sensitive:
            hits.append((table, column, sensitive[(table, column)]))

    for downstream_node in node.downstream:
        hits.extend(find_leaf_hits(downstream_node, seen))

    return hits


# ---- 4. run lineage for every column of every view, tag the ones with sensitive leaves ----
view_derived = []
for view_name, view_sql in sources.items():
    #here we ask sqlglot to parse the view SQL and build a lineage graph for all output columns at once
    node_map = lineage(None, view_sql, schema=schema, sources=sources, dialect="mysql")  # all output columns at once
    for output_column, node in node_map.items():
        #Does this output column ultimately depend on any of the sensitive base columns in my seed?
        hits = find_leaf_hits(node)
        if hits:
            derived_from = sorted({f"{t}.{c}" for t, c, _cat in hits})  # dedupe leaf references
            categories = sorted({cat for _t, _c, cat in hits})
            view_derived.append({
                "table": view_name,
                "column": output_column,
                "sensitive": True,
                "category": ",".join(categories),
                "source": "derived",
                "derived_from": derived_from,
            })

print(json.dumps(view_derived, indent=2))

with open("sensitivity_lineage.json", "w") as f:
    json.dump(view_derived, f, indent=2)

# ---- 5. merge base-table seed columns + view-derived columns into ONE flat list ----
# This is the file to point your Semgrep rule generator at: every sensitive
# column, base or derived, with an explicit sensitive:true and a consistent shape.
base_tagged = [
    {
        "table": r["table"],
        "column": r["column"],
        "sensitive": True,
        "category": r["category"],
        "source": "base",
        "derived_from": [],
    }
    for r in seed
    if r["table"] not in sources  # exclude the view rows MySQL's own comment-inheritance
                                    # sometimes copies into seed.json (see prior message) -
                                    # those get re-derived properly below instead
]

all_sensitive = base_tagged + view_derived

with open("all_sensitive_columns.json", "w") as f:
    json.dump(all_sensitive, f, indent=2)

print(f"\nWrote {len(all_sensitive)} total sensitive columns to all_sensitive_columns.json")

# SQLGlot receives approximately:
# SQL:
# SELECT id, name, ssn FROM customers

# Schema:
# customers:
#     id   int
#     name varchar
#     ssn  varchar

# Sources:
# <view definitions>