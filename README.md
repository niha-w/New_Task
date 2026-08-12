# New_Task
Create a json of db that describes the structure of the table and whether sensitive: true or not. On basis of this json, I want to generate rules in semgrep, telling that whenever these columns or fields are accessed, dont let the developer print this to the console or if developer trying this accidently then flag it.
