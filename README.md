iVQL: Interactive VQL prompt
============================

`iVQL` is an interactive VQL prompt similar to common command-line SQL clients. It supports auto-completion, syntax highlighting, history between sessions, results display in a tabular format and export to CSV, Excel and raw JSON.

Key features:

- Autocompletion and syntax highlighting
- Retrieve object and document field names for autocompletion
- Expansion of `*` wildcards (e.g. `select * from documents`)
- Single sign-on support
- Export to CSV, Excel and JSON

Known limitations:

- Pagination of results from *nested* queries is not resolved. If a nested query (i.e. `select (select … from …) from …`) returns more than 1000 results, only the first 1000 results from the nested query are retrieved. For instance, when querying group membership, if there are more than 1000 members per group, only the first 1000 members are retrieved.

Tabular display and CSV export automatically flatten data structures from nested queries.

Auto-completion is based on a dictionary of terms in a text file (one term per line). This allows adding new terms without updating the code (e.g. in case of new features). The names of objects available in the connected Vault are loaded at log-in. Fields can be retrieved for documents and objects during the session to add them at run-time.

`iVQL` always connects to the most recent Vault API version to support the latest features.

# 1. Usage

```
usage: ivql [-h] [-u USER] [-p PASSWORD] [-s] vault

An interactive VQL prompt

positional arguments:
  vault                 Vault server, excluding ".veevavault.com"

options:
  -h, --help            show this help message and exit
  -u USER, --user USER  User name
  -p PASSWORD, --password PASSWORD
                        Password
  -s, --sso             Authenticate with Single Sign-On (SSO)
```

Unless single sign-on is selected, if `USER` or `PASSWORD` is missing, it will be requested at the prompt.

If `--sso` is selected, a browser window will open to log in. `USER` and `PASSWORD` will then be ignored.

# 2. Prompt input

The prompt takes either a `SELECT` [VQL statement](http://developer.veevavault.com/vql), or one of the following commands. All commands are non-case-sensitive.

> `ivql` supports `select * from …` statements. It will retrieve all queriable fields for the selected entity and subsitute the wildcard in the query.

## `export <json|csv|xl>`

Export the results of the last query to a `JSON`, `CSV` or `Excel` file. The filename is defined using the current time value.

## `delimiter <char>`

Default `,`

Sets the delimiter used in the CSV output.

> Enter *delimiter* without any specifier to display the currently set delimiter.

## `outdir <folder>`

Default `.`

Sets the output directory for the results file. To set it back to the working directory, use the value `.`:

`outdir .`

> Enter *outdir* without any specifier to display the currently set output directory.

## `getfields <documents|relationships|workflows|users|groups|object name>`

Retrieves the list of (queryable) fields and relationships from the supplied object type and adds them to the auto-completion dictionary. The file `completer.txt` contains a predefined list of standard items.

## `quit|exit`

Quits the program

## `cls`

Clears the console window

# 3. Configuration file

You can define the default settings for `outdir` and `delimiter` by specifying them in a file called `ivql.ini`. The file must be located in the user profile configuration folder (e.g. `c:\Users\user\AppData\Local\ivql\ivql` on Windows). If the file does not exist, it will be initialized. The file must take the following form:

```ini
[DEFAULT]
delimiter = ,
outdir = .
complete_on_tab = False
completer_file = completer.txt
```

- `delimiter` defines the delimiter for CSV exports (`,` by default)
- `outdir` defines the output directory for exports (current directory by default)
- `complete_on_tab` defines the behavior of auto-completion:
  - If `True`, completion suggestions are displayed when pressing the Tab key
  - If `False`, completion suggestions show up while typing (default)
- `completer_file` defines the path and name of the auto-completion dictionary (`completer.txt` by default)

# Note: VQL for SQL experts

VQL has some distinct syntax that requires forgetting a few SQL assumptions:

* **There are no joins**. Relationships between objects come predefined, and no new ones can be made *ad hoc* with a `join` keyword. Relationships can be discovered in the API and can be queried in two different syntaxes:
  
  `"select id, name__v, security_model__cr.name__v, role__vr.name__v, user__vr.name__v from user_role_setup__v"` queries the `user_role_setup__v` object and also gets the `name__v` property of related objects (security model, role and user). Here, while `security_model__c` is the object, `security_model__cr` is the relationship between it and `user_role_setup__v`. This syntax applies because there Security Model has one value per document.
  
  `"select id, document_number__v, (select name__v from document_product__vr) from documents"` queries the documents and the name of the related product. This syntax is used because Product has multiple values per document.

* In SQL, a shortcut to a succession of `or` clauses is `in`: `field in ('value 1', 'value 2')`. In VQL, the keyword is `contains`: `field contains ('value 1', 'value 2')`.

* In SQL, searching a substring is usually expressed as follows: `"field like ('%value%')"`. In VQL, the wildcard cannot be used at the beginning of a field. Instead, use `"FIND('value' SCOPE field)"`. This needs to be inserted between the `FROM` and `WHERE` parts of the statement: `"select … from … find (…) where …"`. `FIND` can also be used to search the full text of a document. It's always non-case sensitive.

* In SQL, case-insensitive searches are executed using the lower or upper SQL functions: `"upper(field) = 'VALUE'"`. In VQL, a specific `caseinsensitive` function is used: `"caseinsensitive(field) = 'value'"`.

* In DQL, searching for all versions is expressed as `from documents(all)`. In VQL, use `from allversions documents`.

# Some VQL query examples

Retrieve user role information for 3 users, resolving the name of the security model:

```sql
SELECT id,
         security_model__cr.name__v,
         role__vr.name__v,
         user__vr.name__v
FROM user_role_setup__v
WHERE user__vr.username__sys contains (
  'bsmith@astrozinore.com', 'kpage@astrozinore.com', 'venkatesh@astrozinore.com')
```

Retrieve all documents whose document name contains "Flexesine".

```sql
SELECT id,
         document_number__v,
         status__v,
         name__v,
         type__v,
         subtype__v
FROM documents
FIND('Flexesine' SCOPE name__v)
WHERE classification__v = 'IT'
```

Retrieve active users who never logged in.

```sql
SELECT id,
         user_name__v
FROM users
WHERE active__v = TRUE
        AND last_login__v = NULL
```

List document numbers for two products, including the product name.

```sql
SELECT id,
         document_number__v,         
    (SELECT name__v
    FROM document_product__vr)
FROM documents
WHERE product__v IN 
    (SELECT id
    FROM document_product__vr
    WHERE name__v = 'Amovid'
            OR name__v = 'Corxane') 
```

List active users with associated application roles from user roles:

```sql
SELECT id,
       name__v,
       username__sys,
       federated_id__sys,
       security_profile__sysr.name__v,
  (SELECT application_role__sysr.name__v
   FROM user_role__sysr)
FROM user__sys
WHERE status__v = 'active__v'
```
