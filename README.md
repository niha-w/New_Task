# New_Task
Create a json of db that describes the structure of the table and whether sensitive: true or not. On basis of this json, I want to generate rules in semgrep, telling that whenever these columns or fields are accessed, dont let the developer print this to the console or if developer trying this accidently then flag it.

view the files in the following sequence for better comprehension:
1) schema_setup.sql (works in an online sql compiler like onecompiler)
2) gives three json files (schema, views, seed.json)
3) these three json files are taken as input in propagate.py, run this file
4) this python files outputs two more json files: sensitivity_lineage.json and all_sensitive_columns.json, which is an exhaustive info of sensitive cols propagating and total list of all sensitive entities.
5) these two json are taken as input in generate_semgrep_rules_(1).py, which generates the semgrep_rule1.yml file.
6) paste on of the rule from this file in a semgrep playground, and test it against the code called stress_test.py
