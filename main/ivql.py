import json
import csv
import sys
import time
import os
import configparser
import argparse
import sqlite3
import pandas as pd
from http.client import responses

from pprint import pprint
from re import match
from xml.dom.minidom import parseString
from dataclasses import dataclass

import dicttoxml
import requests

settings = str()
forbidden_chars = str()


# define custom exceptions and object class for handle authorization
class AuthenticationException(Exception):
    pass


class HttpException(Exception):
    pass


@dataclass
class session_details:
    sessionId: str
    mainvault: tuple
    allvaults: dict


class custom_df(pd.DataFrame):
    def __init__(self, *args):
        pd.DataFrame.__init__(self, *args)

    def expand(self):
        def expand_col(col, sep="_"):
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
            self = self.reset_index(drop=True)
            for col in self.columns:
                first_val = self[col].first_valid_index()
                if first_val != None:
                    if type(self[col].iloc[first_val]) == dict:
                        self = pd.concat(
                            [self, expand_col(self[col])],
                            axis="columns",
                        ).drop(col, axis="columns")
                        processed = True
            if not processed:
                break
        return self


def cjson_normalize(data):
    return custom_df(pd.json_normalize(data))


def string_to_bool(str_value):
    """
    Converts a string representation of a boolean value
    into a boolean data type
    """
    if str_value.lower() in ("true", "yes", "y", "1", 1, "on"):
        return True
    elif str_value.lower() in ("false", "no", "n", "0", 0, "off"):
        return False
    else:
        return False  # Would normally raise an exception, but here it would be handled as False anyway


def createFolder(directory):
    """
    Create a folder if it does not exist
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Creating directory " + directory)


def dump_to_db(json_data, connection, table):
    """
    Dump a JSON array into a database table
    """
    df = cjson_normalize(json_data)
    df = df.expand()
    df.to_sql(table, connection, index=False)


def get_connection():
    """
    Get connection details from command line arguments
    """
    parser = argparse.ArgumentParser(
        description="An interactive VQL prompt", prog="ivql"
    )
    parser.add_argument("-u", "--user", help="User name")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument(
        "-s", "--server", help='Vault server, excluding ".veevavault.com"'
    )
    args = parser.parse_args()
    __connection = dict()
    if args.user is None:
        __connection["username"] = input("User name: ")
    else:
        __connection["username"] = args.user
    if args.password is None:
        __connection["password"] = input("Password: ")
    else:
        __connection["password"] = args.password
    if args.server is None:
        __connection["server"] = input("Vault server: ")
    else:
        __connection["server"] = args.server
    return __connection


def get_authorization(vault, user_name, password):
    """
    Authenticates in the specified Vault and returns a session
    details object.
    In case authentication fails, raises a custom exception
    """
    try:
        param = {"username": user_name, "password": password}
        url = "https://" + vault + ".veevavault.com/api/v19.1/auth"
        auth = requests.post(url, params=param)
        if auth.status_code != 200:
            raise HttpException(responses[auth.status_code])
        auth_response_json = auth.json()
        if auth_response_json["responseStatus"] == "FAILURE":
            raise AuthenticationException(
                "Authentication error: " + auth_response_json["errors"][0]["message"]
            )
        else:
            mainvault = tuple()
            allvaults = dict()
            for vault in auth_response_json["vaultIds"]:
                allvaults[vault["id"]] = vault["name"]
                if vault["id"] == auth_response_json["vaultId"]:
                    mainvault = (vault["id"], vault["name"])
            sessionId = auth_response_json["sessionId"]
            return session_details(sessionId, mainvault, allvaults)
    except:
        raise


def execute_query(base_url, vql_query, vql_authorization, tokenize=False):
    try:
        if settings["limit"] == 0:
            strLimit = ""
        else:
            strLimit = " LIMIT " + str(settings["limit"])
        http_params = {"q": vql_query + strLimit}
        if tokenize:
            http_params["tokenize"] = str(tokenize)
        r = requests.get(
            "https://"
            + base_url
            + ".veevavault.com/api/"
            + settings["api_version"]
            + "/query",
            params=http_params,
            headers={"Authorization": vql_authorization},
        )
        # response = json.loads(r.text)
        response = r.json()
        results = response
        if results["responseStatus"] != "FAILURE":
            print(results["responseStatus"])
            print("Number of results: " + str(results["responseDetails"]["total"]))
            print("Fetching page 1")
        if (
            "responseDetails" in results
        ):  # The response might be a failure and not contain this object
            i = 1
            while "next_page" in response["responseDetails"] and (
                i < settings["pages"] or settings["pages"] == 0
            ):  # Check if there is a next page
                i += 1
                print("Fetching page " + str(i))
                r = requests.get(
                    "https://"
                    + base_url
                    + ".veevavault.com"
                    + response["responseDetails"]["next_page"],
                    headers={"Authorization": vql_authorization},
                )
                # response = json.loads(r.text)
                response = r.json()
                results["data"].extend(response["data"])
        if settings["api-limit"]:
            print("API limit: " + r.headers["X-VaultAPI-DailyLimitRemaining"])
        return results
    except requests.exceptions.ConnectionError:
        return {"Connection Error"}


def get_settings():
    # Setting default values
    global settings
    settings = {
        "spool": True,
        "verbose": False,
        "delim": ",",
        "pages": 0,
        "format": "json",
        "limit": 0,
        "outdir": "",
        "filename": ".",
        "api_version": "v18.3",
        "tokenize": False,
        "api-limit": False,
    }
    config = configparser.ConfigParser()
    if os.path.exists("ivql.ini"):  # Look for a config file
        try:  # If the config file loads successfully (i.e. it is well-formed)
            config.read("ivql.ini")
            # Look for each setting in the config file and assign the value to the settings dictionary
            if config.has_option("DEFAULT", "spool"):
                settings["spool"] = config["DEFAULT"].getboolean("spool")
            if config.has_option("DEFAULT", "verbose"):
                settings["verbose"] = config["DEFAULT"].getboolean("verbose")
            if config.has_option("DEFAULT", "api-limit"):
                settings["api-limit"] = config["DEFAULT"].getboolean("api-limit")
            if config.has_option("DEFAULT", "delimiter"):
                settings["delim"] = config["DEFAULT"]["delimiter"]
            if config.has_option("DEFAULT", "pages"):
                settings["pages"] = int(config["DEFAULT"]["pages"])
            if config.has_option("DEFAULT", "format"):
                settings["format"] = config["DEFAULT"]["format"]
            if config.has_option("DEFAULT", "limit"):
                settings["limit"] = int(config["DEFAULT"]["limit"])
            if config.has_option("DEFAULT", "outdir"):
                if any(char in config["DEFAULT"]["outdir"] for char in forbidden_chars):
                    print(
                        config["DEFAULT"]["outdir"]
                        + " is not a valid folder name. Default will be used."
                    )
                else:
                    settings["outdir"] = config["DEFAULT"]["outdir"]
                    settings["outdir"] = (
                        settings["outdir"] + "\\"
                        if settings["outdir"][-1:] != "\\" and settings["outdir"] != ""
                        else settings["outdir"]
                    )  # append a backslash if outdir doesn't end with one
                    createFolder(settings["outdir"])
            if config.has_option("DEFAULT", "filename"):
                settings["filename"] = config["DEFAULT"]["filename"]
            if config.has_option("DEFAULT", "api_version"):
                settings["api_version"] = config["DEFAULT"]["api_version"]
            if config.has_option("DEFAULT", "tokenize"):
                settings["tokenize"] = config["DEFAULT"].getboolean("tokenize")
        except:
            print(
                "Could not load the config file. It may not be well formed. Default values will be used."
            )


def spool(__json):
    # Computing the file name from the current timestamp
    now = time.localtime()
    if settings["filename"] == "" or settings["filename"] == ".":
        file_name = settings["outdir"] + time.strftime("%Y%m%d%H%M%S", now)
    else:
        file_name = settings["outdir"] + settings["filename"]
    # Different processing according to the format
    if settings["format"] == "json":
        try:
            with open(file_name + ".json", "w", encoding="utf8") as outfile:
                json.dump(__json, outfile, indent=4, ensure_ascii=False)
        except:
            print("Could not write file " + file_name + ".json")
    elif settings["format"] == "xml":
        xml_data = dicttoxml.dicttoxml(
            __json["data"], custom_root="data", attr_type=False
        )
        strXML = xml_data.decode("utf8")
        dom = parseString(strXML)
        try:
            with open(file_name + ".xml", "wb") as outfile:
                outfile.write(dom.toprettyxml(encoding="UTF-8"))
        except:
            print("Could not write file " + file_name + ".xml")
    elif settings["format"] == "csv":
        df = cjson_normalize(__json["data"])
        df = df.expand()
        try:
            df.to_csv(
                file_name + ".csv",
                sep=settings["delim"],
                index=False,
                encoding="utf-8-sig",
            )
        except:
            print("Could not write file " + file_name + ".csv")


def main():
    global forbidden_chars

    forbidden_chars = "<>:'/|?*" + '"'  # Forbidden characters that can't be used in folder of file name
    rjson = None

    get_settings()

    query = ""

    connection = get_connection()

    if connection["username"] == "":
        sys.exit("No user name provided.")
    elif connection["password"] == "":
        sys.exit("No password provided.")
    elif connection["server"] == "":
        sys.exit("No server provided.")

    try:
        authorization = get_authorization(
            connection["server"], connection["username"], connection["password"]
        )
    except AuthenticationException as e:
        sys.exit(str(e))
    except requests.exceptions.ConnectionError as e:
        sys.exit(str(e))
    except HttpException as e:
        sys.exit(str(e))

    while True:
        query = input("VQL> ")
        if query.lower() in ("quit", "exit"):
            print("Bye!")
            break
        elif query == "":
            pass
        elif query.lower() == "cls":
            os.system("cls")
        elif match("verbose ", query.lower()):
            settings["verbose"] = string_to_bool(query[query.rindex(" ") + 1 :])
        elif match("spool ", query.lower()):
            settings["spool"] = string_to_bool(query[query.rindex(" ") + 1 :])
        elif match("api-limit ", query.lower()):
            settings["api-limit"] = string_to_bool(query[query.rindex(" ") + 1 :])
        elif match("tokenize ", query.lower()):
            settings["tokenize"] = string_to_bool(query[query.rindex(" ") + 1 :])
        elif match("delimiter ", query.lower()):
            settings["delim"] = query[-1:]
        elif query.lower() == "delimiter":
            print("Current delimiter is: " + settings["delim"])
        elif match("pages ", query.lower()):
            try:
                settings["pages"] = int(
                    query[query.rindex(" ") + 1 :]
                )  # Grab all characters after the rightmost space
            except ValueError:  # there might be an exception if the characters after the pages command are not digits
                print("Invalid number of pages.")
        elif match("limit ", query.lower()):
            try:
                settings["limit"] = int(
                    query[query.rindex(" ") + 1 :]
                )  # Grab all characters after the rightmost space
            except ValueError:  # there might be an exception if the characters after the limit command are not digits
                print("Invalid limit.")
        elif match("format ", query.lower()):
            substr = query[query.rindex(" ") + 1 :].lower()
            if substr in ("json", "csv", "xml"):
                settings["format"] = substr
            else:
                print('Unknown format "' + substr + '". Please use json, xml or csv.')
        elif match("filename ", query.lower()):
            if any(char in query for char in forbidden_chars):
                print(query + " is not a valid file name.")
            else:
                settings["filename"] = query[query.index(" ") + 1 :]
        elif match("outdir ", query.lower()):
            if any(char in query for char in forbidden_chars):
                print(query + " is not a valid folder name.")
            else:
                settings["outdir"] = query[query.index(" ") + 1 :]
                settings["outdir"] = (
                    settings["outdir"] + "\\"
                    if settings["outdir"][-1:] != "\\" and settings["outdir"] != ""
                    else settings["outdir"]
                )  # append a backslash if outdir doesn't end with one
                createFolder(settings["outdir"])
        elif match("api_version ", query.lower()):
            settings["api_version"] = query[query.index(" ") + 1 :]
        elif query.lower() == "format":
            print("Current format is: " + settings["format"])
        elif query.lower() == "limit":
            print("Current limit is: " + str(settings["limit"]))
        elif query.lower() == "pages":
            print("Current pages is: " + str(settings["pages"]))
        elif query.lower() == "outdir":
            print("Current output directory is " + settings["outdir"])
        elif query.lower() == "filename":
            print("Current filename is " + settings["filename"])
        elif query.lower() == "api_version":
            print("Current API version is " + settings["api_version"])
        elif query.lower() == "dump":
            now = time.localtime()
            if rjson != None:
                db = sqlite3.Connection
                try:
                    dump_to_db(rjson["data"], db, time.strftime("%Y%m%d%H%M%S", now))
                except (NameError, TypeError):
                    if settings["filename"] == "" or settings["filename"] == ".":
                        db_file_name = settings["outdir"] + time.strftime(
                            "%Y%m%d%H%M%S", now
                        )
                    else:
                        db_file_name = settings["outdir"] + settings["filename"]
                    db = sqlite3.connect(db_file_name + ".sqlite")
                    dump_to_db(rjson["data"], db, time.strftime("%Y%m%d%H%M%S", now))
                except KeyError:
                    print("Nothing to dump.")
        elif query.lower() == "close":
            try:
                db.close()
                del db
            except (NameError, sqlite3.DatabaseError):
                print("No open connection.")
        elif not match("SELECT ", query.upper()):
            print("Not a select statement or known command.")
        else:
            rjson = execute_query(
                connection["server"],
                query,
                authorization.sessionId,
                tokenize=settings["tokenize"],
            )
            if rjson["responseStatus"] == "FAILURE":
                if rjson["errors"][0]["type"] == "INVALID_SESSION_ID":
                    print("Session expired, initiating new session.")
                    try:
                        authorization = get_authorization(
                            connection["server"],
                            connection["username"],
                            connection["password"],
                        )
                    except AuthenticationException as e:
                        sys.exit(str(e))
                    except requests.exceptions.ConnectionError as e:
                        sys.exit(str(e))
                    except HttpException as e:
                        sys.exit(str(e))
                    rjson = execute_query(
                        connection["server"],
                        query,
                        authorization.sessionId,
                        tokenize=settings["tokenize"],
                    )
                    if rjson["responseStatus"] == "FAILURE":
                        print(
                            rjson["errors"][0]["type"]
                            + ": "
                            + rjson["errors"][0]["message"]
                        )
                else:
                    print(
                        rjson["errors"][0]["type"]
                        + ": "
                        + rjson["errors"][0]["message"]
                    )
            if rjson["responseStatus"] == "SUCCESS":
                if settings["spool"] and rjson["responseDetails"]["total"] > 0:
                    spool(rjson)
                if settings["verbose"]:
                    pprint(rjson)


try:
    main()
except KeyboardInterrupt:
    sys.exit("Bye!")
