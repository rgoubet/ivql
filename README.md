iVQL: Interactive VQL prompt
============================

# 1. Usage

```
usage: ivql [-h] [-u USER] [-p PASSWORD] [-s SERVER]

An interactive VQL prompt

optional arguments:
  -h, --help            show this help message and exit
  -u USER, --user USER  User name
  -p PASSWORD, --password PASSWORD
                        Password
  -s SERVER, --server SERVER
                        Vault server, excluding ".veevavault.com"
```

If `USER`, `PASSWORD` or `SERVER` is missing, it will be requested at the prompt.

Note that iVQL does not support single sign-on.

# 2. Prompt input
The prompt takes either a `SELECT` [VQL statement](http://developer.veevavault.com/vql), or one of the following commands. All commands are non-case-sensitive.

## `verbose on|off`
Default `OFF`

Displays the results of the query on screen.

## `spool on|off`
Default `ON`

Saves the results to a file in the working directory (unless the query returns 0 results). By default, the file is named according to the current timestamp (`yyyymmddhhmmss`).

> Files are always encoded in UTF-8 to provide full Unicode support.

## `format <json|xml|csv>`
Default `JSON`

Selects the output format of the file. By default, the results are stored in native <abbr title="JavaScript Object Notation">`JSON`</abbr> format. 

For the `CSV` format, only the first level of the `JSON` structure is flattened to a table to maintain readability. In case of complex nested data, the `CSV` file may not be easy to process.

The `XML` format is exactly equivalent to `JSON` but easier to read and to open in Excel.

> The `XML` output is not the native Vault API output in XML, but a transformation to a simplified XML format that is more convenient for Excel import.

> Enter *format* without any specifier to display the currently set format.

## `delimiter <char>`
Default `,`

Sets the delimiter used in the CSV output.

> Enter *delimiter* without any specifier to display the currently set delimiter.

## `pages <number>`
Default `0`

VQL returns results by pages of 1000 records, which iVQL merges. By default, all pages are retrieved.

This command limits the number of pages to `<number>`. When pages = `0`, all pages are retrieved.

> Enter *pages* without any specifier to display the currently set pages.

> Records for some objects (like *users* and *workflows*) are always returned in a single page, regardless of the number of results. The limit must therefore be increased above 1000 (see below) to retrieve all results.

## `limit <number>`
Default `0`

Sets the limit of the number of records per page. Vault returns up to 1000 records per page, but this number can be decreased if needed. If limit is set to 0, the default Vault setting is used (i.e. no limit is specified in the query).

> Decreasing the limit will increase the number of pages to retrieve all the results (and therefore of API calls). To retrieve the first x number of results, you need to set both the limit and the maximum number of pages. So, to retrieve the first 500 results, you need to set the limit to 500. To retrieve the first 2000 results, you can either set the pages to 2 and leave limit to the default value, or set the limit to 500 and the pages to 4.

> Enter *limit* without any specifier to display the currently set limit.

## `outdir <folder>`
Default `nullstring`

Sets the output directory for the results file. To set it back to the working directory, use the value `.`:

`outdir .`

> Enter *outdir* without any specifier to display the currently set output directory.

## `filename <file name>`
Default `.`

Sets the file name for the results file. To set it back to the default timestamp value, use the value `.`:

`filename .`

> Enter *filename* without any specifier to display the currently set file name.

## `api_version <api version>`
Default `v18.3`

Sets the API version to be used by the program. It must be formatted as: `v<maj>.<min>`.

> Enter *api_version* without any specifier to display the currently set API version

## `api-limit on|off`
Default `off`

Displays the 24-hour rolling daily limit and indicates the number of API calls remaining in the current 24-hour window after each query.

## `quit|exit`
Quits the program

## `cls`
Clears the console window

## `dump`
Dumps the results of the last query into a table in an `SQlite` database file.

The file is named according to the usual rules. If a filename is specified (see [`filename`](#filename-file-name)) and the file exists, the results are added into a table of that file. The table is always named using a timestamp.

# 3. Configuration file
You can override the default settings by specifying them in a file called `ivql.ini` in the working directory. The file must take the following form:

```ini
[DEFAULT]
delimiter = ,
spool = True
verbose = False
pages = 0
limit = 0
format = json
outdir = .
filename = .
api_version = v18.3
api-limit = off
```

For Boolean settings `spool`, `verbose` and `api-limit`, valid values are `yes/no`, `on/off`, `true/false` and `1/0`. Strings must be written literally, without quotation marks.

# Note: VQL for SQL experts
VQL has some distinct syntax that requires forgetting a few SQL assumptions:

* **There are no joins**. Relationships between objects come predefined, and no new ones can be made *ad hoc*. Relationships can be discovered in the API and can be queried in two different syntaxes:

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
  'bsmith@astrozinore.com', 'kpage@@astrozinore.com', 'venkatesh@astrozinore.com')
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

