"""
Semgrep security-rule stress test.

Assumed sensitive columns:
    customers.email
    customers.ssn
    customer_orders_view.contact_email
    customer_orders_view.flagged_ssn
    vip_view.contact_email
    vip_view.flagged_ssn

The examples intentionally include both obvious and tricky cases.
"""


# ---------------------------------------------------------
# Mock database API
# ---------------------------------------------------------

class FakeCursor:
    def execute(self, query, params=None):
        pass
    def fetchone(self):
        return None
    def fetchall(self):
        return []

cursor = FakeCursor()


# =========================================================
# 1. BASIC / OBVIOUS CASES
# =========================================================

def direct_sensitive_lookup(row):
    email = row["email"]
    print(email)

def direct_ssn_lookup(row):
    ssn = row["ssn"]
    print(ssn)


# Should NOT be sensitive: signup_date is not marked sensitive.
def safe_non_sensitive_column(row):
    print(row["signup_date"])


#notice where it does get flagged and where it does not
def get_customer():
    cursor.execute("SELECT email FROM customers")
    row = cursor.fetchone()
    print(row)
    return cursor.fetchone()


def get_employee():
    cursor.execute("SELECT email FROM employees")
    row = cursor.fetchone()
    print(row)
    return cursor.fetchone()


def print_customer():
    row = get_customer()
    print(row["email"])


def print_employee():
    row = get_employee()
    print(row["email"])


# =========================================================
# 2. column = "credit_card"; f"...{column}..."
# =========================================================

def dynamic_column_name(row):
    column = "ssn"
    value = row[column]
    print(value)

def dynamic_column_fstring(row):
    column = "ssn"
    query = f"SELECT {column} FROM customers"
    print(cursor.execute(query))

def dynamic_column_fstring_later(column):
    query = f"SELECT {column} FROM customers"
    cursor.execute(query)
    row = cursor.fetchone()
    print(row)

dynamic_column_fstring_later("email")
# =========================================================
# 3. CONCATENATION OF AN ALREADY-TAINTED VALUE
# =========================================================

def concatenate_tainted_value(row):
    email = row["email"]

    # Tainted value is preserved through concatenation.
    message = "Customer email: " + email
    print(message)

def concatenate_tainted_value_multiple_times(row):
    email = row["email"]
    message = "EMAIL=" + email + " END"
    print(message)

def fstring_tainted_value(row):
    email = row["email"]
    message = f"Customer email: {email}"
    print(message)

def format_tainted_value(row):
    email = row["email"]
    message = "Customer email: {}".format(email)
    print(message)


# =========================================================
# 4. SENSITIVE QUERY STORED SEPARATELY
# =========================================================

SENSITIVE_QUERY = "SELECT email FROM customers"

def execute_sensitive_constant():
    cursor.execute(SENSITIVE_QUERY)

def execute_sensitive_constant_then_fetch():
    cursor.execute(SENSITIVE_QUERY)
    row = cursor.fetchone()
    print(row)

QUERY = "SELECT ssn FROM customers"

def execute_ssn_query():
    cursor.execute(QUERY)


# =========================================================
# 5. fetchone() THEN print(row[0])
# =========================================================

def positional_row_access():
    cursor.execute("SELECT email FROM customers")
    row = cursor.fetchone()
    print(row[0])

def positional_row_access_1():
    cursor.execute("SELECT email FROM sample")
    row = cursor.fetchone()
    print(row[0])

def positional_row_access_ssn():
    cursor.execute("SELECT ssn FROM customers")
    row = cursor.fetchone()
    print(row[0])


# =========================================================
# 6. DICT-STYLE VS ATTRIBUTE-STYLE ACCESS
# =========================================================

def dictionary_style(row):
    print(row["email"])

class Customer:
    def __init__(self):
        self.email = None
        self.ssn = None
        self.signup_date = None

def attribute_style(customer):
    print(customer.email)

def attribute_style_ssn(customer):
    print(customer.ssn)

def safe_attribute(customer):
    print(customer.signup_date)


# =========================================================
# 7. MULTIPLE TABLES / VIEWS WITH SAME COLUMN NAME
# =========================================================

def customers_email(row):
    print(row["email"])

# ---------------------------------------------------------------
# FIXED: previously had no table context at all. In real code you
# always need SOME evidence of which table a row came from -- here
# that's an explicit, adjacent query against a genuinely different,
# non-sensitive table. This still gets flagged, intentionally: dict
# access is a documented, conservative-by-default source (see
# `ambiguous_email` below) that does not inspect surrounding code,
# because a table-aware sanitizer was tested and found to introduce
# a worse problem -- a real false negative when a function contains
# both a safe and a sensitive query. See generate_semgrep_rules.py
# for the full writeup of that finding.
# ---------------------------------------------------------------
def some_other_table_email():
    cursor.execute("SELECT id, email FROM sample")
    row = cursor.fetchone()
    #dict access of the row by "email", if would have been row[0], doesnt get flagged
    print(row["email"])

def view_contact_email(row):
    # customer_orders_view.contact_email is derived from
    # customers.email and therefore sensitive.
    print(row["contact_email"])

def vip_contact_email(row):
    # vip_view.contact_email is also derived from
    # customers.email.
    print(row["contact_email"])

# ---------------------------------------------------------------
# FIXED: get_query() now explicitly returns from a non-sensitive
# table ('sample', not 'customers'). Should NOT fire after the
# table-scoped raw-string source fix.
# ---------------------------------------------------------------
def get_query():
    return "SELECT email FROM customers"

def execute_indirect_query():
    cursor.execute(get_query())
    row = cursor.fetchone()
    print(row[0])

def get_ssn_query():
    return "SELECT ssn FROM customers"

def execute_indirect_ssn_query():
    cursor.execute(get_ssn_query())
    ow = cursor.fetchone()
    print(row[0])

def build_query():
    return get_query()

def execute_two_hop_query():
    cursor.execute(build_query())
    row = cursor.fetchone()
    print(row[0])



# =========================================================
# 9. CHARACTER-BY-CHARACTER CONCATENATION
# =========================================================

def character_by_character():
    column = ("s" + "s" + "n")
    query = f"SELECT {column} FROM customers"
    cursor.execute(query)

def character_by_character_simple():
    column = "s" + "s" + "n"
    print(column)


# =========================================================
# 10. CONCATENATION OF A SENSITIVE LITERAL
# =========================================================

def split_sensitive_literal():
    column = "ema" + "il"
    query = f"SELECT {column} FROM customers"
    cursor.execute(query)
    row = cursor.fetchone()
    print(row[0])

def split_ssn_literal():
    column = "s" + "s" + "n"
    query = f"SELECT {column} FROM customers"
    cursor.execute(query)


# =========================================================
# 11. SENSITIVE COLUMN HIDDEN INSIDE A LARGER STRING
# =========================================================

def sensitive_column_inside_sql():
    query = "SELECT customer_id, email, signup_date FROM customers"
    cursor.execute(query)
    row = cursor.fetchone()
    print(row[0])
    print(row[1])
    print(row[2])

def sensitive_column_inside_sql_with_other_columns():
    query = """
        SELECT id, name, email, signup_date
        FROM customers
    """
    cursor.execute(query)


# =========================================================
# 12. SENSITIVE DATA PASSED THROUGH FUNCTIONS
# =========================================================

def send_to_logger(value):
    print(value)

def indirect_leak(row):
    email = row["email"]
    send_to_logger(email)

def indirect_ssn_leak(row):
    ssn = row["ssn"]
    send_to_logger(ssn)


# =========================================================
# 13. SANITIZATION / DECLASSIFICATION
# =========================================================

def declassify_for_aggregate(value):
    return value

def supposedly_safe(row):
    email = row["email"]
    safe_value = declassify_for_aggregate(email)
    print(safe_value)


# =========================================================
# 14. ALIASING
# =========================================================

def alias_sensitive_value(row):
    email = row["email"]
    x = email
    y = x
    z = y
    print(z)


# =========================================================
# 15. RETURNING SENSITIVE DATA
# =========================================================

def return_sensitive_email(row):
    email = row["email"]
    return email

def return_sensitive_ssn(row):
    ssn = row["ssn"]
    return ssn


# =========================================================
# 16. SENSITIVE VALUE INSIDE A DICT
# =========================================================

def put_sensitive_value_in_dict(row):
    result = {"customer_email": row["email"]}
    print(result)

def put_sensitive_value_in_list(row):
    values = [row["email"]]
    print(values)


# =========================================================
# 17. OVERTAINTING: UNRELATED STRING
# =========================================================

def unrelated_string():
    message = "This function has nothing to do with email"
    print(message)

def unrelated_variable():
    email_status = "verified"
    print(email_status)


# =========================================================
# 18. SHOULD NOT FIRE: DIFFERENT COLUMN
# =========================================================

def safe_signup_date(row):
    date = row["signup_date"]
    print(date)

def safe_customer_id(row):
    customer_id = row["id"]
    print(customer_id)


# =========================================================
# 19. SAME COLUMN NAME, DIFFERENT SEMANTIC SOURCE
# =========================================================

def ambiguous_email(row_from_unknown_source):
    """
    Intentionally ambiguous, documented, accepted limitation: dict-access
    sources match on column name only, since Semgrep cannot trace an
    arbitrary 'row' object back to the query that produced it without
    the false-negative-prone sanitizer approach rejected above.
    """
    print(row_from_unknown_source["email"])


# =========================================================
# 20. QUERY RESULT USED LATER
# =========================================================

def query_then_pass_around():
    cursor.execute("SELECT email FROM customers")
    row = cursor.fetchone()
    process_customer(row)

def process_customer(row):
    print(row)


# =========================================================
# 21. ALIAS OF cursor
# =========================================================

def cursor_alias():
    db_cursor = cursor
    db_cursor.execute("SELECT email FROM customers")
    row = db_cursor.fetchone()
    print(row)



# =========================================================
# 22. QUERY BUILT IN PIECES
# =========================================================

def query_built_in_pieces():
    select_part = "SELECT "
    column = "email"
    from_part = " FROM customers"
    query = select_part + column + from_part
    cursor.execute(query)
    row = cursor.fetchone()
    print(row)


# =========================================================
# 23. QUERY BUILT WITH f-string
# =========================================================

def fstring_query():
    column = "email"
    query = f"SELECT {column} FROM customers"
    cursor.execute(query)
    row = cursor.fetchone()
    print(row)


# =========================================================
# 24. QUERY BUILT WITH format()
# =========================================================

def format_query():
    column = "email"
    query = "SELECT {} FROM customers".format(column)
    cursor.execute(query)
    row = cursor.fetchone()
    print(row)


# =========================================================
# 25. FINAL MIXED CASE
# =========================================================

def complicated_case(row):
    email = row["email"]
    prefix = "Customer: "
    message = prefix + email
    print(message)

# =========================================================
# FLAGGED_SSN — DERIVED SENSITIVE COLUMN
# =========================================================

def direct_flagged_ssn_leak(row):
    flagged_ssn = row["flagged_ssn"]
    print(flagged_ssn)

def flagged_ssn_concatenation(row):
    flagged_ssn = row["flagged_ssn"]
    message = "Flagged SSN: " + flagged_ssn
    print(message)

def flagged_ssn_fstring(row):
    flagged_ssn = row["flagged_ssn"]
    message = f"Flagged SSN: {flagged_ssn}"
    print(message)

def flagged_ssn_return(row):
    flagged_ssn = row["flagged_ssn"]
    return flagged_ssn

def flagged_ssn_alias(row):
    flagged_ssn = row["flagged_ssn"]
    x = flagged_ssn
    y = x
    print(y)


# =========================================================
# FLAGGED_SSN — QUERY RESULT
# =========================================================

def query_flagged_ssn():
    cursor.execute("SELECT flagged_ssn FROM customer_orders_view")
    row = cursor.fetchone()
    print(row[0])


# =========================================================
# FLAGGED_SSN — STORED QUERY
# =========================================================

FLAGGED_SSN_QUERY = """
    SELECT flagged_ssn
    FROM customer_orders_view
"""

def execute_flagged_ssn_query():
    cursor.execute(FLAGGED_SSN_QUERY)
    row = cursor.fetchone()
    print(row)
#    =========================================================
# FLAGGED_SSN — SAME COLUMN NAME IN ANOTHER CONTEXT
# =========================================================

def ambiguous_flagged_ssn(row):
    """
    This is intentionally ambiguous.

    If Semgrep only sees row["flagged_ssn"], it may not know
    whether this row came from customer_orders_view, vip_view,
    or some unrelated source.
    """
    print(row["flagged_ssn"])


# =========================================================
# FLAGGED_SSN — VIP VIEW
# =========================================================

def vip_view_flagged_ssn(row):
    # vip_view.flagged_ssn is also sensitive because its lineage is:
    #
    # vip_view.flagged_ssn
    #        ↓
    # customer_orders_view.flagged_ssn
    #        ↓
    # customers.ssn
    #
    print(row["flagged_ssn"])