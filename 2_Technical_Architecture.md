# Technical Architecture — Sensitive Column Tracking & Semgrep Rule Generation

## Pipeline overview

```
schema_setup.sql (MySQL, run in an online compiler)
        │  produces (copy-pasted out as JSON)
        ▼
seed.json + views.json + schema.json
        │
        ▼
propagate.py   (sqlglot lineage + propagation logic)
        │  produces
        ▼
sensitivity_lineage.json  +  all_sensitive_columns.json
        │
        ▼
generate_semgrep_rules_(1).py
        │  produces
        ▼
semgrep_rules1.yml
        │
        ▼
tested manually in Semgrep Playground against stress_test.py
```

Each stage only trusts the JSON handed to it by the stage before — nothing re-reads the database or re-parses SQL twice. That keeps each stage small and independently testable.

---

## 1. Where "sensitive" starts: `schema_setup.sql`

MySQL lets you attach a `COMMENT` to a column. We (ab)use that as our tagging mechanism:

```sql
email VARCHAR(150) COMMENT 'sensitive:pii',
ssn   VARCHAR(11)  COMMENT 'sensitive:pii',
```

Three `information_schema` queries then pull out, as JSON, everything downstream stages need:

| File | Query source | What it holds |
|---|---|---|
| `seed.json` | `information_schema.columns` where comment starts with `sensitive:` | The manually-tagged base columns — the *ground truth* |
| `views.json` | `information_schema.views` | The **raw SQL text** of every view (`view_definition`) |
| `schema.json` | `information_schema.columns` (tables only, not views) | Every table/column name + data type, so sqlglot knows what exists |

Two views exist in the sample data:
- `customer_orders_view` — joins `customers` and `orders`, renames `email` to `contact_email`, and adds a `CASE WHEN status = 'flagged' THEN ssn ELSE NULL END AS flagged_ssn` column.
- `vip_view` — built **on top of** `customer_orders_view` (a view of a view), filtering `amount > 1000`.

Neither view has a taggable comment of its own — a view isn't a real table, it's a saved query — so this is exactly the case that needs tracing, not just tag-reading.

---

## 2. How the lineage tracing actually works (`propagate.py`)

### First, what "parsing" vs. "lineage" actually means here
This distinction matters, so let's be very explicit about it, because it's easy to think "parsing" already gives you the answer.

- **Parsing** = sqlglot reads the SQL text and turns it into a tree structure it understands (which columns exist, which tables are joined, what's inside the `CASE`, etc). At the end of parsing, sqlglot knows *what the query says*. It does **not** yet know *which of those columns are secrets*.
- **Lineage** = a second pass, on top of the parsed tree, that answers one specific question per output column: *"if I trace this column backwards through every alias, join, and case-expression, which original table.column(s) is it ultimately built from?"*

So parsing builds the map. Lineage is *walking* that map, backwards, from an output column to its origin(s).

### The "why do you find it, it's getting marked" mental model
Think of it like a family tree, built backwards:

```
vip_view.contact_email
        ↑ (comes from)
customer_orders_view.contact_email
        ↑ (comes from, via "AS contact_email")
customers.email
```

`propagate.py` doesn't need to *understand* what an email address is. It just needs to walk this chain of "comes from" arrows until it hits an actual table column, and then ask one question: **"is `customers.email` on my sensitive list?"** If the answer is yes at any point along that chain, everything downstream of it inherits the tag. That's the entire trick — nothing more mysterious than that.

Concretely, `sqlglot.lineage.lineage()` is called once per view, and it returns a `Node` object for every output column. Each `Node` has a `.downstream` list pointing to the nodes that feed into it, and (at the bottom of the chain) a `.source`, which — once you've walked all the way down — is the actual `exp.Table` object it came from. `find_leaf_hits()` in `propagate.py` is a small recursive function that does exactly the walk described above: keep following `.downstream` until you hit a real table, check `(table, column)` against the tagged `seed.json` dictionary, and collect every hit it finds along the way.

### The `CASE WHEN` trick
```sql
CASE WHEN o.status = 'flagged' THEN c.ssn ELSE NULL END AS flagged_ssn
```
A human might think: "well, `flagged_ssn` is only *actually* the SSN sometimes — the rest of the time it's `NULL`, so is it really sensitive?" sqlglot doesn't try to guess what happens at runtime. It only cares that `c.ssn` was **referenced** inside the expression that produces `flagged_ssn`. So `flagged_ssn` gets tagged sensitive unconditionally — which is the safe, conservative choice: you'd rather over-flag a column that's *sometimes* private than under-flag one that's *sometimes* leaking a real SSN.

### Views-of-views (multi-hop lineage)
`vip_view` selects from `customer_orders_view`, not from a real table. sqlglot handles this automatically: when we call `lineage()`, we pass in a `sources` dictionary containing every view's SQL text, keyed by view name. When sqlglot hits `FROM customer_orders_view` inside `vip_view`'s query, it looks up `customer_orders_view` in that dictionary, parses *that* SQL too, and keeps walking backwards — so the chain correctly continues all the way to `customers.email`, without us having to manually sort views into "which one depends on which" order first.

One practical gotcha that had to be handled: MySQL's `information_schema.views` output prefixes every table/view name with the database name, e.g. `` `sandbox_db`.`customer_orders_view` ``. sqlglot's `sources` lookup matches by bare name, so without stripping that prefix, `vip_view` would fail to find `customer_orders_view` in the sources dictionary and the chain would break silently. `strip_db_qualifier()` handles this with a regex before anything gets passed to sqlglot.

### Output of this stage
- `sensitivity_lineage.json` — only the *newly discovered* (derived) sensitive columns, each with a `derived_from` field showing the chain's origin(s).
- `all_sensitive_columns.json` — the merged, final list: original tagged base columns + all derived view columns, in one consistent shape (`table`, `column`, `sensitive`, `category`, `source`, `derived_from`). This is the single file everything downstream depends on.

---

## 3. How the Semgrep rules get generated (`generate_semgrep_rules_(1).py`)

### Quick primer: what a Semgrep "taint mode" rule actually is
A taint-mode rule has three parts:
- **Source** — where "dirty" (sensitive) data can first enter, e.g. `row["email"]`.
- **Propagator** — a rule that says "if X is tainted, then Y becomes tainted too," for cases Semgrep wouldn't figure out on its own.
- **Sink** — a place we don't want tainted data to reach, e.g. `print(...)`.

Semgrep then does the taint-tracking itself: does a tainted value from *some source* ever reach *some sink*, through ordinary assignment, string building, function calls, etc.? If yes, flag it.

### One rule per column *name*, not per table
The script groups `all_sensitive_columns.json` by the **bare column name** (`email`, `ssn`, `contact_email`, `flagged_ssn`) — not by `table.column`. This is deliberate, and it comes from a hard limitation: a Semgrep rule reads *source code*, like `row["email"]`. Source code has no idea which database table `row` came from at match time — that information only exists in the database, which Semgrep never sees. So instead of trying (and failing) to know the table, we fold every table/view that has a column of that name into one rule, and record the union of tables/categories in the rule's `metadata` block for a human to audit later.

### The false-positive question: `customers.email` (sensitive) vs `employees.email` (not sensitive)
This is the sharpest edge case in the whole design, and it's only **partially** solved — worth being precise about exactly where the line is.

**What sources are generated per column, and how each one behaves:**

| Source variant | Example | Table-aware? |
|---|---|---|
| Exact string literal | `"email"` | No |
| Dict-style access | `row["email"]` | No |
| Attribute-style access | `row.email` | No |
| Raw SQL string containing the column | `"SELECT email FROM customers"` | **Yes** |

The first three are **not** table-aware, and never will be under this design — this is a deliberate, documented trade-off, not an oversight. A table-aware version was actually tried (a "sanitizer" that peeks at nearby code to check which table a `row` came from) and it was **rejected** after testing, because it introduced a worse bug: a function containing *both* a genuinely sensitive query and a separate safe-looking query got its taint wiped out entirely, because the sanitizer only needed to spot one "safe" query anywhere nearby — a real false **negative** (a missed leak), which is strictly worse than an occasional false positive. So `row["email"]` and `row.email` stay intentionally "always flagged," on the principle that catching a real leak matters more than avoiding an extra five-minute manual review.

The 4th variant — matching the column name inside a **raw SQL string** — is where the table-scoping fix actually lives, because it's safe to apply there: we're only inspecting the content of one specific string literal, not reasoning about other statements nearby. The regex requires the string to contain **both** the column name **and** the name of one of the actual tables/views that column is tagged sensitive in:

```python
raw_string_regex = f"(?is)(?=.*{column})(?=.*({table_alternation})).*"
```

So `"SELECT email FROM customers"` matches (contains `email` **and** `customers`), but `"SELECT email FROM sample"` does **not** — `sample` isn't a table where `email` is tagged sensitive, so the string is left alone. This is what correctly lets `employees.email` (a different, untagged table) avoid being flagged by a query string that only mentions an unrelated table — while `customers.email` still gets caught.

**Bottom line, stated plainly:** table-scoping fixes the false-positive risk for *raw SQL query strings*. It does **not** fix it for `row["email"]` / `row.email` accessed directly on a database result object — those remain name-only matches by design, and a same-named-but-different-table column will still be (conservatively) flagged there. That's a known, accepted limitation, not a bug.

### How propagators are used
Two real gaps needed explicit propagators (`pattern-propagators`), because Semgrep's default taint-tracking doesn't cover them automatically:

1. **A cursor is a stateful object.** `cursor.execute(query)` taints the *query argument*, but by default that doesn't make `cursor` itself "remember" it was just handed something tainted. So:
   ```python
   cursor.execute("SELECT email FROM customers")   # tainted argument
   row = cursor.fetchone()                          # by default, looks "clean"
   print(row)                                        # would be missed without a propagator
   ```
   The fix is a rule that says: if the query argument passed into `execute()` is tainted, treat the cursor object itself as tainted too — and if the cursor is tainted, treat whatever comes back out of `fetchone()`, `fetchall()`, or `fetchmany()` as tainted too. In Semgrep's propagator syntax, each of those is a `from` → `to` pair, roughly:

   ```yaml
   pattern: CURSOR.execute(QUERY, ...)
   from: QUERY
   to: CURSOR
   ```

   (the real rule prefixes `QUERY` and `CURSOR` with Semgrep's metavariable marker — left off here only for clean rendering). That's exactly what the `CURSOR_PROPAGATORS` list encodes — a manual bridge across two calls that Semgrep would otherwise treat as unrelated.

2. **`options.symbolic_propagation: true`** is a built-in Semgrep setting (not a custom propagator) that lets taint survive f-string interpolation (`f"...{email}..."`) and `+` string concatenation of an already-tainted value. Without it, taint tracking can silently stop the moment a value is wrapped inside a new string.

### Sinks
Four places we treat as "leaving the trusted boundary": `print(...)`, a logger call (`logging.X(...)` or `self.logger.X(...)`/`self.log.X(...)`, matched with a `metavariable-regex` so it doesn't accidentally match unrelated objects), any `requests.X(...)` HTTP call, and `return ...` (handing the value back to whoever called the function).

### The interprocedural case — tested, and it does get caught (but as a Pro-gated finding)
If a query is built inside a completely separate function and only consumed at the call site —
```python
def get_query():
    return "SELECT email FROM customers"

def execute_indirect_query():
    cursor.execute(get_query())
    row = cursor.fetchone()
    print(row[0])
```
— catching this requires following taint *across* a function call/return boundary (`get_query()`'s return value flowing into `execute()` in a different function), and the same again one level deeper for the two-hop version (`build_query()` calling `get_query()`, then `execute_two_hop_query()` calling `build_query()`).

This was actually verified in the Semgrep Playground rather than assumed: the rule **does** catch both cases. The Playground flags both lines correctly — but marks each finding **"ONLY IN PRO,"** meaning the match itself is real, but interfile/cross-function taint tracking is a Semgrep Pro engine capability, gated behind that label in the UI. Running the identical rule through the free OSS engine (e.g. plain `semgrep` on the command line without Pro enabled) would ideally not produce this finding — the rule is correct and the analysis exists, but exercising it requires the Pro engine, not just the YAML rule itself. So the honest framing is: the rule is written to support this case, and it's confirmed to work — it's the *engine tier*, not the rule design, that decides whether you actually see the result.

---

## 4. Two YAML files in the folder — use the right one

There are two generated rule files sitting side by side, and they are **not** the same:

| File | Produced by | Has the table-scoped 4th source? |
|---|---|---|
| `semgrep_rules.yml` | `generate_semgrep_rules_(1).py` (its actual default `--output`) | **Yes** — this is the current, correct output |
| `semgrep_rules1.yml` | The older `generate_semgrep_rules.py` (no `_(1)`) | No — only the first three source variants (literal, dict-style, attribute-style) |

`generate_semgrep_rules_(1).py` writes to `semgrep_rules.yml` by default (`--output` defaults to `Path("semgrep_rules.yml")`) — it never touches the `...1.yml` name. `semgrep_rules1.yml` is a leftover from an earlier run of the simpler script, before the table-scoping fix existed, and it has since gone stale.

**Practical takeaway: test against `semgrep_rules.yml`, not `semgrep_rules1.yml`.** Only `semgrep_rules.yml` contains the 4th pattern-source — the one that requires both the column name *and* one of its tagged table names to appear together in a raw SQL string. That's the piece that correctly lets `"SELECT email FROM sample"` (unrelated table) pass while `"SELECT email FROM customers"` still gets flagged — so any stress-test case built around that distinction (e.g. `some_other_table_email()`, `get_query()`) will only behave as designed against `semgrep_rules.yml`.

The README's step 6 refers to "semgrep_rule1.yml," which is where the mix-up likely originated — worth a quick rename/cleanup so the file that's actually current isn't the one that sounds like a leftover draft.

---

## 5. Stress test summary (`stress_test.py`)

| # | Type of access | Sample from stress_test.py | Correctly handled? |
|---|---|---|---|
| 1 | Direct dict-style access on a sensitive column | `email = row["email"]` → `print(email)` | yes |
| 2 | Dict-style access on a **non**-sensitive column (should NOT flag) | `print(row["signup_date"])` | yes |
| 3 | Row fetched in one function, sensitive field read in a different function | `get_customer()` returns `cursor.fetchone()`; `print_customer()` does `row["email"]` | yes |
| 4 | Column name held in a variable, used for dict lookup | `column = "ssn"`; `row[column]` | yes |
| 5 | Column name in a variable, used inside an f-string query | `f"SELECT {column} FROM customers"` | yes |
| 6 | Tainted value passed through `+` concatenation / f-string / `.format()` | `"Customer email: " + email`, `f"...{email}"`, `"{}...".format(email)` | yes |
| 7 | Sensitive query stored in a module-level constant, executed later | `SENSITIVE_QUERY = "SELECT email FROM customers"` | yes |
| 8 | Positional row access after `fetchone()` | `row[0]` after `SELECT email FROM customers` | yes |
| 9 | Attribute-style (ORM-style) access | `customer.email` | yes |
| 10 | Same bare column name pulled from an unrelated/different table | `row["email"]` from a query against `sample`, not `customers` | yes |
| 11 | Query text returned from a separate function, executed at the call site | `cursor.execute(get_query())` | yes |
| 12 | Sensitive column name built letter-by-letter | `column = "s" + "s" + "n"` | yes |
| 13 | Sensitive column name split into two pieces, reassembled | `column = "ema" + "il"` | yes |
| 14 | Sensitive column named inside a larger, multi-column SQL string | `"SELECT id, name, email, signup_date FROM customers"` | yes, flags whole row |
| 15 | Sensitive value passed into another function before being printed | `send_to_logger(email)` | yes, flagged at function's return |
| 16 | Sensitive value passed through a no-op "sanitizer" function | `declassify_for_aggregate(email)` | yes, but script does not populate sanitizers, that should be done through a human |
| 17 | Multi-step variable aliasing | `x = email; y = x; z = y; print(z)` | yes |
| 18 | Sensitive value returned from a function | `return email` | yes |
| 19 | Sensitive value nested inside a dict or list literal | `{"customer_email": row["email"]}` | yes |
| 20 | Unrelated string that merely contains the word "email" (over-tainting check) | `"This function has nothing to do with email"` | yes, but string shouldn't contain sensitive column's table name, else would be flagged |
| 21 | Cursor object assigned to a differently-named variable | `db_cursor = cursor` | yes |
| 22 | Query string assembled piece-by-piece via concatenation | `select_part + column + from_part` | yes |
| 23 | Derived/view column (`flagged_ssn`) — direct access, concatenation, return, alias | `row["flagged_ssn"]` | yes |
| 24 | Two-hop view lineage (`vip_view` → `customer_orders_view` → `customers.ssn`) | `vip_view_flagged_ssn(row)` reading `row["flagged_ssn"]` | yes |
