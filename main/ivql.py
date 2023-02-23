import argparse
import configparser
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from getpass import getpass
from http.client import responses
from itertools import zip_longest
from urllib.parse import urlparse

import pandas as pd
import requests
from platformdirs import user_config_dir
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from pygments.lexer import RegexLexer, words
from pygments.token import Keyword, Name, Number, Operator, String
from tabulate import tabulate


class AuthenticationException(Exception):
    pass


class HttpException(Exception):
    pass


@dataclass
class session_details:
    sessionId: str
    api: str


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
                        "objects",
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
            (r"\b[^ ,]+__clin\b", Name.Attribute),
            (r"\b[^ ,]+__rim\b", Name.Attribute),
            (r"\b[^ ,]+__qdm\b", Name.Attribute),
            (r"\b[^ ,]+__sys\b", Name.Attribute),
            (r"\b[^ ,]+__sysr\b", Name.Attribute),
            (r"\b[^ ,]+__cr\b", Name.Attribute),
            (r"\b[^ ,]+__vr\b", Name.Attribute),
            (r"\b[^ ,]+__clinr\b", Name.Attribute),
            (r"\b[^ ,]+__rimr\b", Name.Attribute),
            (r"\b[^ ,]+__qdmr\b", Name.Attribute),
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

        def expand_col(col):
            """ "Horizontal" equivalent of pandas' vertical
            explode() function"""
            df = col.apply(pd.Series)
            if 0 in df.columns:  # this occurs for NaN rows
                df.drop(columns=0, inplace=True)
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


def authorize(
    vault: str, user_name="", password="", sso=False, browser="chrome"
) -> session_details:
    """Authenticates in the specified Vault and returns a session
    details object.
    In case authentication fails, raises a custom exception


    Args:
        vault (str): DNS name of the Vault
        user_name (str): User name
        password (str): Password
        sso (bool): authenticate with single sign-on
        browser (str): browser to use for SSO authentication

    Raises:
        HttpException: Exception in case of connection error
        AuthenticationException: Exception in case of authentication error

    Returns:
        session_details: a session details objet with Vault details
    """
    if sso:
        from selenium.common.exceptions import (
            SessionNotCreatedException,
            WebDriverException,
        )
        from selenium.webdriver import Chrome, Edge, Firefox, Safari
        from selenium.webdriver.support.ui import WebDriverWait

        try:
            match browser:
                case "chrome":
                    from selenium.webdriver.chrome.options import Options

                    opts = Options()
                    opts.add_argument("log-level=3")
                    print("Authenticating in Chrome")
                    driver = Chrome()
                case "edge":
                    from selenium.webdriver.edge.options import Options

                    opts = Options()
                    opts.add_argument("log-level=3")
                    print("Authenticating in Edge")
                    driver = Edge(options=opts)
                case "firefox":
                    print("Authenticating in Firefox")
                    driver = Firefox()
                case "safari":
                    print("Authenticating in Safari")
                    driver = Safari()
        except (SessionNotCreatedException, WebDriverException, Exception) as e:
            sys.exit(e)

    try:
        if sso:
            try:
                driver.get(f"https://{vault}.veevavault.com/")
            except WebDriverException as e:
                sys.exit(e)
            try:
                sessionId = WebDriverWait(driver, timeout=60).until(
                    lambda d: d.get_cookie("TK")
                )["value"]
                driver.quit()
            except WebDriverException:
                sys.exit("Browser closed unexpectedly")
        else:
            param = {"username": user_name, "password": password}
            url = f"https://{vault}.veevavault.com/api/v22.2/auth"
            auth = requests.post(url, data=param)
            if auth.status_code != 200:
                raise HttpException(responses[auth.status_code])
            auth_response_json = auth.json()
            if auth_response_json["responseStatus"] in ("FAILURE", "EXCEPTION"):
                raise AuthenticationException(
                    "Authentication error: "
                    + auth_response_json["errors"][0]["message"]
                )
            else:
                sessionId = auth_response_json["sessionId"]
        api_url = "https://" + vault + ".veevavault.com/api"
        r = requests.get(api_url, headers={"Authorization": sessionId})
        all_api = r.json()["values"]
        latest_api = list(all_api.values())[-1]
        print(f"Authenticated in {vault} on API {list(all_api.keys())[-1]}.")
        return session_details(sessionId, latest_api)
    except:
        raise


def parse_args():
    """Parse command line arguments and return parameters"""
    parser = argparse.ArgumentParser(
        description="An interactive VQL prompt", prog="ivql"
    )
    parser.add_argument("-u", "--user", help="User name")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument(
        "-s",
        "--sso",
        action="store_true",
        default=False,
        help="Authenticate with Single Sign-On (SSO)",
    )
    parser.add_argument(
        "-b",
        "--browser",
        choices=["chrome", "edge", "firefox", "safari"],
        default="chrome",
        help="Browser to use for SSO authentication",
    )
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
        "completer_file": os.path.join(os.path.dirname(__file__), "completer.txt"),
    }
    if not os.path.exists(cfg_file):
        print(f"Config file not found. Initializing at {cfg_file}")
        with open(cfg_file, "w", newline="") as f:
            f.writelines(
                [
                    "[DEFAULT]\r\n",
                    "delimiter = ,\r\n",
                    "outdir = .\r\n",
                    "complete_on_tab = False\r\n",
                    "completer_file = completer.txt",
                ]
            )
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
            session.api + "/query",
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
                    + urlparse(session.api).netloc
                    + response["responseDetails"]["next_page"],
                    headers={"Authorization": session.sessionId},
                )
                # response = json.loads(r.text)
                response = r.json()
                results["data"].extend(response["data"])
        return results
    except requests.exceptions.ConnectionError:
        return {"error": "Connection Error"}


def get_fields(session: session_details, vault_type: str, include_rel=True) -> list:
    """Returns a list of fields and relationships for the supplied
    Vault type (documents, users, groups, workflows...)

    Args:
        session (session_details): Vault session
        vault_type (str): Vault type name

    Returns:
        list: List of fields and relationships
    """
    if vault_type == "documents":
        url = session.api + f"/metadata/objects/{vault_type}/properties"
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
            if include_rel:
                return docfields + docrelation
            else:
                return docfields
    elif vault_type in ["users", "groups"]:
        url = session.api + f"/metadata/objects/{vault_type}"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            return [p["name"] for p in r.json()["properties"] if p["queryable"]]
    elif vault_type == "workflows":
        url = session.api + f"/metadata/objects/{vault_type}"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            return [p["name"] for p in r.json()["properties"]]
    elif vault_type == "objects":
        url = session.api + f"/metadata/vobjects"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            return [
                obj["name"]
                for obj in r.json()["objects"]
                if obj["status"][0] == "active__v"
            ]
    else:
        url = session.api + f"/metadata/vobjects/{vault_type}"
        r = requests.get(url, headers={"Authorization": session.sessionId})
        if r.json()["responseStatus"] in ("FAILURE", "EXCEPTION"):
            print(r.json()["errors"][0]["message"])
            return []
        else:
            obj_fields = [p["name"] for p in r.json()["object"]["fields"]]
            if "relationships" in r.json()["object"].keys() and include_rel:
                obj_rel = [
                    p["relationship_name"] for p in r.json()["object"]["relationships"]
                ]
                obj_fields.extend(obj_rel)
            return obj_fields


def main():
    args = parse_args()  # get command line arguments
    if not args.sso:
        if args.user is None:
            args.user = input("User name: ")
        if args.password is None:
            args.password = getpass()

    config_dir = user_config_dir("ivql")
    createFolder(config_dir)

    config = get_config(os.path.join(config_dir, "ivql.ini"))  # Get config settings

    # Get a Vault session
    try:
        if args.sso:
            vault_session = authorize(args.vault, sso=True, browser=args.browser)
        else:
            vault_session = authorize(args.vault, args.user, args.password)
    except (
        requests.exceptions.ConnectionError,
        HttpException,
        AuthenticationException,
    ) as e:
        sys.exit(e)

    vql_history = FileHistory(os.path.join(config_dir, "history"))

    vault_objects = get_fields(vault_session, "objects")

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
        vql_completer.words.extend(
            [f for f in vault_objects if f not in vql_completer.words]
        )
        vql_completer.words.sort()
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
            print("Current output folder: " + os.path.realpath(config["outdir"]))
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
                        # date_format="%Y-%m-%d",
                    )
                    print(f"Results exported to {filename}.csv")
                elif exp_format == "json":
                    with open(filename + ".json", "w", encoding="utf-8") as f:
                        json.dump(vql_results, f)
                        print(f"Results exported to {filename}.json")
                elif exp_format == "xl":
                    query_data.to_excel(filename + ".xlsx", index=False)
                    print(f"Results exported to {filename}.xlsx")
                else:
                    print(f"Unrecognized format {exp_format}")
            except NameError:
                print("No query results to export.")
            except (FileNotFoundError, OSError, PermissionError):
                print(f"Failed to export to {filename}.{exp_format}")
        elif query.lower()[:9] == "getfields":
            vault_type = query.split(" ")[-1]
            qfields = get_fields(vault_session, vault_type.lower()) + [
                vault_type.lower()
            ]
            try:
                added_fields = [f for f in qfields if f not in vql_completer.words]
                if len(added_fields) > 0:
                    added_fields.sort()
                    chunk = (  # equivalent of math.ceil
                        len(added_fields) // 3 + 1
                        if len(added_fields) % 3 > 0
                        else len(added_fields) // 3
                    )  # number of rows for a 3 column table
                    fields_table = [
                        added_fields[i : chunk + i]
                        for i in range(0, len(added_fields), chunk)
                    ]
                    print("Adding fields:")
                    print(
                        tabulate([list(sl) for sl in list(zip_longest(*fields_table))])
                    )
                    vql_completer.words.extend(added_fields)
                    vql_completer.words.sort()
                else:
                    print("No field added.")
            except NameError:
                print("Completer not initialized.")
        elif query.lower()[:6] != "select":
            print("Not a select statement or known command.")
        else:
            if query.split()[1] == "*":
                all = get_fields(vault_session, query.split()[3], include_rel=False)
                query = query.replace("*", ",".join(all))
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
                        if args.sso:
                            vault_session = authorize(
                                args.vault, sso=True, browser=args.browser
                            )
                        else:
                            vault_session = authorize(
                                args.vault, args.user, args.password
                            )
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
                # try to convert any column with date in the name
                for col in [c for c in query_data.columns if "date" in c]:
                    try:
                        query_data[col] = pd.to_datetime(query_data[col])
                        query_data[col] = query_data[col].dt.tz_localize(None)
                    except pd.ParserError:
                        pass
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
