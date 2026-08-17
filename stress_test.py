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
    cursor.execute(query)


def dynamic_column_fstring_later(column):
    query = f"SELECT {column} FROM customers"
    cursor.execute(query)


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


# Another form.
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
    # customers.email is sensitive
    print(row["email"])


def some_other_table_email(row):
    # Imagine this came from a different table where email
    # is NOT sensitive.
    print(row["email"])


def view_contact_email(row):
    # customer_orders_view.contact_email is derived from
    # customers.email and therefore sensitive.
    print(row["contact_email"])


def vip_contact_email(row):
    # vip_view.contact_email is also derived from
    # customers.email.
    print(row["contact_email"])


# =========================================================
# 8. INTERPROCEDURAL:
#    cursor.execute(get_query())
# =========================================================

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


# Another level of indirection.
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
    column = (
        "s"
        + "s"
        + "n"
    )

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
        SELECT
            id,
            name,
            email,
            signup_date
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
    result = {
        "customer_email": row["email"]
    }

    print(result)


def put_sensitive_value_in_list(row):
    values = [
        row["email"]
    ]

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
    This is intentionally ambiguous.

    Without knowing which table/view 'row' came from,
    Semgrep cannot reliably determine whether row["email"]
    is customers.email or some unrelated email column.
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
    # customer_orders_view.flagged_ssn is derived from
    # customers.ssn and is therefore sensitive.
    flagged_ssn = row["flagged_ssn"]
    print(flagged_ssn)


def flagged_ssn_concatenation(row):
    # Sensitive value propagated through concatenation.
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
    cursor.execute(
        "SELECT flagged_ssn FROM customer_orders_view"
    )

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


# =========================================================
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