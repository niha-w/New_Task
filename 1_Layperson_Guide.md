# What This Project Does (Simple Guide)

## The problem, in one line
Some columns in our database — like `email` and `ssn` — hold private information. We want a tool that automatically catches a developer if their code ever tries to print or log that private data.

## The idea, in one line
Tag the sensitive columns in the database once → figure out where that sensitive data "travels" to (views, other tables) → turn all of it into rules that a code-scanning tool (Semgrep) can check automatically.

---

## Step 1 — Mark the sensitive columns in the database
File: `schema_setup.sql`

We build a small sample database with two tables — `customers` and `orders` — and two views (a view is just a saved, reusable query) — `customer_orders_view` and `vip_view`.

In the `customers` table, `email` and `ssn` are marked with a comment: `sensitive:pii`. That comment is our tag. It's the only place in the whole system where a human manually says "this is private."

We then ask the database three simple questions and save the answers as JSON files:
- **What columns exist, and which ones are tagged sensitive?** → `seed.json`
- **What do the views actually look like, in raw SQL?** → `views.json`
- **What's the full list of tables/columns and their types?** → `schema.json`

## Step 2 — Trace where the sensitive data flows
File: `propagate.py`

Here's the catch: the two views (`customer_orders_view`, `vip_view`) don't have tags of their own — a view is just a query, not a real table, so there's nowhere to write a comment on it. But a view can still expose sensitive data. For example, `customer_orders_view` includes `c.email AS contact_email` — so `contact_email` is secretly just `email` wearing a different name.

We use a tool called **sqlglot** to read the view's SQL and figure out, for every column the view outputs, exactly which original table column it came from — even through joins, renaming, and `CASE WHEN` logic. Then we check: does this column trace back to something in our tagged list (`seed.json`)? If yes, we tag it sensitive too, and we record *why* (which original column it came from).

This also works two layers deep: `vip_view` is built on top of `customer_orders_view`, and the tool correctly figures out that `vip_view.contact_email` is sensitive too, tracing all the way back to `customers.email`.

Output: `sensitivity_lineage.json` (just the newly-discovered ones) and `all_sensitive_columns.json` (everything — original tagged columns + newly discovered ones — in one list).

## Step 3 — Turn the sensitive-column list into code-scanning rules
File: `generate_semgrep_rules_(1).py`

Now that we know every sensitive column, we generate rules for **Semgrep**, a tool that reads source code (Python, in our case) and flags risky patterns.

For every sensitive column name, the rule says: "if this value ever reaches a `print(...)`, a log line, an HTTP call, or gets `return`ed — flag it." It also understands a few tricky real-world patterns, like:
- Someone stores the query in a variable first, then runs it later.
- Someone reads a database row and grabs the sensitive field out of it — either `row["email"]` or `row.email` style.
- The value gets passed around, renamed, or glued into another string before printing.

Output: `semgrep_rules.yml` — one rule per sensitive column name.

## Step 4 — Test it
File: `stress_test.py`

This file has dozens of small, deliberately tricky Python functions — some that obviously leak sensitive data, some that are sneaky about it, and some that only *look* like they might but actually don't. We run the generated rules against this file in the Semgrep Playground and check, function by function, whether it caught what it should have and ignored what it shouldn't.

---

## In short
1. Tag it once in the database.
2. Let sqlglot trace it through every view.
3. Turn the final list into Semgrep rules.
4. Stress-test the rules against tricky code.

The full technical breakdown — including exactly how the tracing works, how we avoid mixing up two different tables that happen to share a column name, and the full stress-test results table — is in the companion document, **2_Technical_Architecture.md**.
