import requests
from getpass import getuser
from dataclasses import dataclass
from http.client import responses
from reportlab.lib import colors, pdfencrypt
from reportlab.lib.pagesizes import A3, A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Table, TableStyle
from secrets import choice
from string import ascii_letters, digits, punctuation
from datetime import datetime
from tzlocal import get_localzone
from urllib.parse import urlparse


# define custom exceptions and object class to handle authorization
class AuthenticationException(Exception):
    pass


class HttpException(Exception):
    pass


@dataclass
class session_details:
    sessionId: str
    mainvault: tuple
    allvaults: dict


@dataclass
class user:
    firstName: str
    lastName: str
    userName: str
    email: str
    securityProfile: str
    securityPolicy: str
    group: str
    activationDate: str


def authorize(vault: str, user_name: str, password: str) -> session_details:
    """
    Authenticates in the specified Vault and returns a session
    details object.
    In case authentication fails, raises a custom exception
    """
    try:

        param = {"username": user_name, "password": password}
        url = "https://" + vault + ".veevavault.com/api/v20.3/auth"
        auth = requests.post(url, params=param)
        if auth.status_code != 200:
            raise HttpException(responses[auth.status_code])
        auth_response_json = auth.json()
        if auth_response_json["responseStatus"] == "FAILURE":
            raise AuthenticationException(
                "Authentication error: " + auth_response_json["errors"][0]["message"]
            )
        else:
            sessionId = auth_response_json["sessionId"]
            api_url = "https://" + vault + ".veevavault.com/api"
            r = requests.get(api_url, headers={"Authorization": sessionId})
            all_api = r.json()["values"]
            latest_api = all_api[list(all_api)[-1]]
            mainvault = tuple()
            allvaults = dict()
            for vault_details in auth_response_json["vaultIds"]:
                allvaults[vault_details["id"]] = vault_details["name"]
                if vault_details["id"] == auth_response_json["vaultId"]:
                    mainvault = (
                        vault_details["id"],
                        vault_details["name"],
                        latest_api,
                    )
            print(f"Authenticated in {mainvault[1]}")
            return session_details(sessionId, mainvault, allvaults)
    except:
        raise


def execute_vql(
    session: session_details,
    vql_query: str,
    limit: int = 0,
    pages: int = 0,
    tokenize: bool = False,
) -> dict:
    try:
        if limit == 0:
            strLimit = ""
        else:
            strLimit = " LIMIT " + str(limit)
        http_params = {"q": vql_query + strLimit}
        if tokenize:
            http_params["tokenize"] = str(tokenize)
        r = requests.get(
            session.mainvault[2] + "/query",
            params=http_params,
            headers={"Authorization": session.sessionId},
        )
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
                i < pages or pages == 0
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
