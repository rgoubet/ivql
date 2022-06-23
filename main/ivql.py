import pandas as pd
import requests
import json
import argparse
import time
import os
import configparser
import sys
import re

from dataclasses import dataclass
from http.client import responses
from urllib.parse import urlparse
from tabulate import tabulate
from getpass import getpass
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from pygments.token import Keyword, Operator, Name, String, Number
from pygments.lexer import RegexLexer, words
from appdirs import user_config_dir


class AuthenticationException(Exception):
    pass


class HttpException(Exception):
    pass


@dataclass
class session_details:
    sessionId: str
    mainvault: tuple
    allvaults: list


class VqlLexer(RegexLexer):
    name = "VQL"
    aliases = ["vql"]
    flags = re.IGNORECASE

    tokens = {
        "root": [
            (
                words(
                    (
                        "select",
                        "from",
                        "order",
                        "maxrows",
                        "from",
                        "where",
                        "allversions",
                        "caseinsensitive",
                        "like",
                        "limit",
                        "longtext",
                        "pagesize",
                        "pageoffset",
                        "offset",
                        "richtext",
                        "scope",
                        "scope all",
                        "scope content",
                        "skip",
                        "deletedstate",
                        "obsoletestate",
                        "statetype",
                        "steadystate",
                        "supersededstate",
                        "as",
                    ),
                    suffix=r"\b",
                ),
                Keyword,
            ),
            (
                words(
                    (
                        "between",
                        "contains",
                        "find",
                        "or",
                        "and",
                    ),
                    suffix=r"\b",
                ),
                Operator,
            ),
            (
                words(
                    (
                        "documents",
                        "users",
                        "binders",
                        "groups",
                        "workflows",
                        "events",
                        "relationships",
                        "picklists",
                        "roles",
                        "securitypolicies",
                        "json",
                        "csv",
                    ),
                    suffix=r"\b",
                ),
                Name.Variable,
            ),
            (
                words(
                    (
                        "deletedstate",
                        "obsoletestate",
                        "statetype",
                        "steadystate",
                        "supersededstate",
                    ),
                ),
                Name.Class,
            ),
            (
                words(
                    (
                        "exit",
                        "quit",
                        "export",
                        "delimiter",
                        "outdir",
                        "cls",
                        "getfields",
                    ),
                ),
                Name.Tag,
            ),
            (r"\b[^ ,]+__v\b", Name.Attribute),
            (r"\b[^ ,]+__c\b", Name.Attribute),
            (r"\b[^ ,]+__sys\b", Name.Attribute),
            (r"\b[^ ,]+__sysr\b", Name.Attribute),
            (r"\b[^ ,]+__cr\b", Name.Attribute),
            (r"\b[^ ,]+__vr\b", Name.Attribute),
            ("id", Name.Attribute),
            (r"'[^']+'", String.Single),
            (
                words(
                    (
                        "true",
                        "false",
                    ),
                ),
                Keyword.Constant,
            ),
            (r"\b[0-9]+\b", Number.Integer),
        ]
    }


style = Style.from_dict(
    {
        "pygments.keyword": "crimson",
        "pygments.keyword.constant": "blue",
        "pygments.name.attribute": "green",
        "pygments.operator": "teal",
        "pygments.string.single": "cyan",
        "pygments.number.integer": "cyan",
        "pygments.name.variable": "gold",
        "pygments.name.class": "purple",
        "pygments.name.tag": "deepskyblue",
    }
)


class custom_df(pd.DataFrame):
    """Custom subclass of pandas with extra method

    Args:
        DataFrame: a pandas DataFrame object
    """

    def __init__(self, *args):
        pd.DataFrame.__init__(self, *args)

    def expand(self):
        """Expand columns containing dictionaries horizontally
        and columns containing lists vertically"""

        def expand_col(col, sep="_"):
            """ "Horizontal" equivalent of pandas' vertical
            explode() function"""
            df = col.apply(pd.Series)
            if 0 in df.columns:  # this occurs for NaN rows
                df.drop(columns=0, inplace=True)
            mapping = {newcol: f"{col.name}{sep}{newcol}" for newcol in df.columns}
            df.rename(mapping, axis="columns", inplace=True)
            return df

        while True:
            processed = False
            for col in self.columns:
                first_val = self[col].first_valid_index()
                if first_val != None:
                    if type(self[col].iloc[first_val]) == list:
                        self = self.explode(col)
                        processed = True
                    elif type(self[col].iloc[first_val]) == dict:
                        self = pd.concat(
                            [self, expand_col(self[col])],
                            axis="columns",
                        ).drop(col, axis="columns")
                        processed = True
            self = self.reset_index(drop=True)
            if not processed:  # If no col was expanded
                break  # Exit the while loop
        return self

    @staticmethod
    def cjson_normalize(data, **args):
        return custom_df(pd.json_normalize(data, **args))


def authorize(vault: str, user_name: str, password: str) -> session_details:
    """Authenticates in the specified Vault and returns a session
    details object.
    In case authentication fails, raises a custom exception


    Args:
        vault (str): DNS name of the Vaylt
        user_name (str): User name
        password (str): Password

    Raises:
        HttpException: Exception in case of connection error
        AuthenticationException: Exception in case of authentication error

    Returns:
        session_details: a session details objet with Vault details
    """
    try:
        param = {"username": user_name, "password": password}
        url = f"https://{vault}.veevavault.com/api/v21.1/auth"
        auth = requests.post(url, params=param)
        if auth.status_code != 200:
            raise HttpException(responses[auth.status_code])
        auth_response_json = auth.json()
        if auth_response_json["responseStatus"] in ("FAILURE", "EXCEPTION"):
            raise AuthenticationException(
                "Authentication error: " + auth_response_json["errors"][0]["message"]
            )
        else:
            sessionId = auth_response_json["sessionId"]
            api_url = "https://" + vault + ".veevavault.com/api"
            r = requests.get(api_url, headers={"Authorization": sessionId})
            all_api = r.json()["values"]
            latest_api = list(all_api)[-1]
            mainvault = tuple()
            allvaults = list()
            for vault_details in auth_response_json["vaultIds"]:
                allvaults.append(
                    (
                        vault_details["id"],
                        vault_details["name"],
                        vault_details["url"] + "/" + latest_api,
                    )
                )
                if vault_details["id"] == auth_response_json["vaultId"]:
                    mainvault = (
                        vault_details["id"],
                        vault_details["name"],
                        vault_details["url"] + "/" + latest_api,
                    )
            print(f"Authenticated in {mainvault[1]} on API {latest_api}.")
            return session_details(sessionId, mainvault, allvaults)
    except:
        raise


def parse_args():
    """Parse command line arguments and return parameters"""
    parser = argparse.ArgumentParser(
        description="An interactive VQL prompt", prog="ivql"
    )
    parser.add_argument("-u", "--user", help="User name")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("vault", help='Vault server, excluding ".veevavault.com"')
    args = parser.parse_args()
    vars(args)["prog"] = parser.prog
    return args


def createFolder(directory):
    """Create directory if it does not exists"""
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        raise


def get_config(cfg_file: str) -> dict:
    """Parses the config file and returns the settings

    Args:
        cfg_file (str): path to the config file

    Returns:
        dict: configuration settings
    """
    config = configparser.ConfigParser()
    # Set default config values
    settings = {
        "delim": ",",
        "outdir": ".",
        "complete_while_typing": False,
        "completer_file": "completer.txt",
    }
    try:  # If the config file loads successfully (i.e. it is well-formed)
        config.read(cfg_file)
        if config.has_option("DEFAULT", "delimiter"):
            settings["delim"] = config["DEFAULT"]["delimiter"]
        if config.has_option("DEFAULT", "outdir"):
            try:
                createFolder(config["DEFAULT"]["outdir"])
                settings["outdir"] = config["DEFAULT"]["outdir"]
            except OSError:
                print("Error: Creating directory: " + config["DEFAULT"]["outdir"])
        if config.has_option("DEFAULT", "complete_on_tab"):
            settings["complete_while_typing"] = not eval(
                config["DEFAULT"]["complete_on_tab"]
            )
        if config.has_option("DEFAULT", "completer_file"):
            settings["completer_file"] = config["DEFAULT"]["completer_file"]

    except (configparser.Error, PermissionError, OSError):
        print(
            "Could not load the config file. It may not be well formed. Default values will be used."
        )
    return settings


def execute_vql(
    session: session_details,
    vql_query: str,
) -> dict:
    """Execute a VQL statement and return the results

    Args:
        session (session_details): Vault session object
        vql_query (str): the VQL query

    Returns:
        dict: results in JSON
    """
    try:
        payload = {"q": vql_query}
        http_params = {}
        r = requests.post(
            session.mainvault[2] + "/query",
            params=http_params,
            data=payload,
            headers={"Authorization": session.sessionId},
        )
        response = r.json()
        results = response
        if results["responseStatus"] not in ("FAILURE", "EXCEPTION"):
            print(results["responseStatus"])
            print("Number of results: " + str(results["responseDetails"]["total"]))
            print("Fetching page 1")
        if (
            "responseDetails" in results
        ):  # The response might be a failure and not contain this object
            i = 1
            while (
                "next_page" in response["responseDetails"]
            ):  # Check if there is a next page
                i += 1
                print("Fetching page " + str(i))
                r = requests.get(
                    "https://"
                    + urlparse(session.mainvault[2]).netloc
                    + response["responseDetails"]["next_page"],
                    headers={"Authorization": session.sessionId},
                )
                # response = json.loads(r.text)
                response = r.json()
                results["data"].extend(response["data"])
        return results
    except requests.exceptions.ConnectionError:
        return {"error": "Connection Error"}


def get_fields(session: session_details, vault_type: str) -> list:
    """Returns a list of fields and relationships for the supplied
    Vault type (documents, users, groups, workflows...)

    Args:
        session (session_details): Vault session
        vault_type (str): Vault type name

    Returns:
        list: List of fields and relationships
    """
    if vault_type == "documents":
        url = session.mainvault[2] + f"/metadata/objects/{vault_type}/properties"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            docfields = [p["name"] for p in r.json()["properties"] if p["queryable"]]
            docrelation = [
                p["relationshipName"]
                for p in r.json()["properties"]
                if "relationshipName" in p.keys()
            ]
            return docfields + docrelation
    elif vault_type in ["users", "groups"]:
        url = session.mainvault[2] + f"/metadata/objects/{vault_type}"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            return [p["name"] for p in r.json()["properties"] if p["queryable"]]
    elif vault_type == "workflows":
        url = session.mainvault[2] + f"/metadata/objects/{vault_type}"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            return [p["name"] for p in r.json()["properties"]]
    else:
        url = session.mainvault[2] + f"/metadata/vobjects/{vault_type}"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            obj_fields = [p["name"] for p in r.json()["object"]["fields"]]
            if "relationships" in r.json()["object"].keys():
                obj_rel = [
                    p["relationship_name"] for p in r.json()["object"]["relationships"]
                ]
                obj_fields.extend(obj_rel)
            return obj_fields


def main():
    args = parse_args()  # get command line arguments
    if args.user is None:
        args.user = input("User name: ")
    if args.password is None:
        args.password = getpass()

    config = get_config("ivql.ini")  # Get config settings

    # Get a Vault session
    try:
        vault_session = authorize(args.vault, args.user, args.password)
    except (
        requests.exceptions.ConnectionError,
        HttpException,
        AuthenticationException,
    ) as e:
        sys.exit(e)

    createFolder(user_config_dir("ivql"))

    vql_history = FileHistory(os.path.join(user_config_dir("ivql"), "history"))

    # Initiate the prompt with a completer if the lexicon file is found
    try:
        with open(config["completer_file"], "r") as f:
            vql_completer = WordCompleter(f.read().splitlines())
        session = PromptSession(
            completer=vql_completer,
            history=vql_history,
            complete_while_typing=config["complete_while_typing"],
            lexer=PygmentsLexer(VqlLexer),
            style=style,
        )
    except FileNotFoundError:
        print(
            f"No autocompletion configuration file found ({config['completer_file']})"
        )
        session = PromptSession(
            history=vql_history,
            complete_while_typing=config["complete_while_typing"],
            lexer=PygmentsLexer(VqlLexer),
            style=style,
        )
    # Start prompt REPL
    while True:
        query = session.prompt("VQL> ")
        if query.lower() in ("quit", "exit"):
            print("Bye!")
            break
        elif query.strip() == "":
            pass
        elif query.lower() == "cls":
            if sys.platform == "win32":
                os.system("cls")
            else:
                os.system("clear")
        elif query.lower() == "delimiter":
            print("Current delimiter: " + config["delim"])
        elif query.lower()[:9] == "delimiter":
            config["delim"] = query.split(" ")[-1]
        elif query.lower() == "outdir":
            print("Current output folder: " + config["outdir"])
        elif query.lower()[:6] == "outdir":
            outdir = query.split(" ")[-1]
            try:
                createFolder(outdir)
                config["outdir"] = outdir
            except OSError:
                print("Error: Creating directory: " + outdir)
        elif query.lower()[:6] == "export":
            exp_format = query.split(" ")[-1].lower()
            timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
            filename = os.path.join(config["outdir"], timestamp)
            try:
                if exp_format == "csv":
                    query_data.to_csv(
                        filename + ".csv",
                        sep=config["delim"],
                        encoding="utf-8-sig",
                        index=False,
                    )
                    print(f"Results exported to {filename}.csv")
                elif exp_format == "json":
                    with open(filename + ".json", "w", encoding="utf-8") as f:
                        json.dump(vql_results, f)
                        print(f"Results exported to {filename}.json")
                else:
                    print(f"Unrecognized format {exp_format}")
            except NameError:
                print("No query results to export.")
            except (FileNotFoundError, OSError, PermissionError):
                print(f"Failed to export to {filename}.{exp_format}")
        elif query.lower()[:9] == "getfields":
            vault_type = query.split(" ")[-1]
            qfields = get_fields(vault_session, vault_type.lower())
            try:
                added_fields = [f for f in qfields if f not in vql_completer.words]
                if len(added_fields) > 0:
                    print("Adding fields:\n" + ", ".join(added_fields))
                    vql_completer.words.extend(added_fields)
                    vql_completer.words.sort()
                else:
                    print("No field added.")
            except NameError:
                print("Completer not initialized.")
        elif query.lower()[:6] != "select":
            print("Not a select statement or known command.")
        else:
            vql_results = execute_vql(vault_session, query)
            if vql_results["responseStatus"] in ("FAILURE", "EXCEPTION"):
                print(
                    vql_results["errors"][0]["type"]
                    + ": "
                    + vql_results["errors"][0]["message"]
                )
                if vql_results["errors"][0]["type"] == "INVALID_SESSION_ID":
                    print("Reconnecting...")
                    try:
                        vault_session = authorize(args.vault, args.user, args.password)
                    except (
                        requests.exceptions.ConnectionError,
                        HttpException,
                        AuthenticationException,
                    ) as e:
                        sys.exit(e)
            else:
                query_data = custom_df.cjson_normalize(vql_results["data"])
                query_data = query_data.expand()
                query_data.drop(
                    columns=[
                        col for col in query_data.columns if "responseDetails" in col
                    ],
                    inplace=True,
                )  # Remove responseDetails columns (subqueries)
                query_data = query_data.convert_dtypes()
                print(
                    tabulate(
                        query_data.astype(object).fillna("").head(50),
                        headers="keys",
                        tablefmt="github",
                        showindex=False,
                    )
                )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:  # Gracefully exit on ctrl-c
        sys.exit("Bye!")
