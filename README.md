iVQL: Interactive VQL prompt
============================

`iVQL` is an interactive VQL prompt similar to common command-line SQL clients. It supports auto-completion, history between sessions, display the results in a tabular format and export to CSV and raw JSON.

Tabular display and CSV export automatically flatten data structures from nested queries.

`iVQL` always connects to the most recent Vault API version to support the latest features.

# 1. Usage

```
usage: ivql [-h] [-u USER] [-p PASSWORD] vault

An interactive VQL prompt

positional arguments:
  vault                 Vault server, excluding ".veevavault.com"

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  User name
  -p PASSWORD, --password PASSWORD
                        Password
```

If `USER` or `PASSWORD` is missing, it will be requested at the prompt.

Note that iVQL does not support single sign-on.

# 2. Prompt input
The prompt takes either a `SELECT` [VQL statement](http://developer.veevavault.com/vql), or one of the following commands. All commands are non-case-sensitive.

## `export <json|csv>`
Export the results of the last queries to a `JSON` or `CSV` file. The filename is defined using the current time value.

## `delimiter <char>`
Default `,`

Sets the delimiter used in the CSV output.

> Enter *delimiter* without any specifier to display the currently set delimiter.

## `outdir <folder>`
Default `.`

Sets the output directory for the results file. To set it back to the working directory, use the value `.`:

`outdir .`

> Enter *outdir* without any specifier to display the currently set output directory.

## `getfields <documents|users|groups|object name>`

Retrieves the list of (queryable) fields from the supplied object type and adds them to the auto-completion lexicon. The file `completer.txt` contains a predefined list of items.

## `quit|exit`
Quits the program

## `cls`
Clears the console window

# 3. Configuration file
You can define the default settings for `outdir` and `delimiter` by specifying them in a file called `ivql.ini` in the working directory. The file must take the following form:

```ini
[DEFAULT]
delimiter = ,
outdir = .
complete_on_tab = True
```

- `delimiter` defines the delimiter for CSV exports (`,` by default)
- `outdir` defines the output directory for exports (current directory by default)
- `complete_on_tab` defines the behavior of auto-completion:
  - If `True`, completion suggestions are displayed when pressing the Tab key
  - If `False`, completion suggestions show up while typing

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
        AND last_login__v != NULL
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

