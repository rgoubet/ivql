import requests
import pandas as pd
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


def df_to_pdf(data, pdf_file):
    """
    Generates a PDF report from a Pandas DataFrame object
    """

    def addPageNumber(
        canvas, doc
    ):  # this subfunction will be called to add page numbers
        page_num = canvas.getPageNumber()
        text = "Page %s" % page_num
        canvas.drawCentredString(200 * mm, 20 * mm, text)

    # build paragraph styles
    styles = getSampleStyleSheet()
    styleH = styles["Heading1"]
    styleC = ParagraphStyle("small", parent=styles["Normal"], fontSize=8)
    enc_pw = "".join(
        choice(ascii_letters + digits + punctuation) for i in range(12)
    )  # build a strong 12-char password
    enc = pdfencrypt.StandardEncryption(
        "", ownerPassword=enc_pw, canModify=0
    )  # set encryption
    data.fillna("", inplace=True)
    table_data = data.values.tolist()
    # convert the dataframe to a list of list,
    # enclose the content of cell values in a Paragraph object in order to apply word wrapping
    formatted_data = [data.columns.values.tolist()] + [
        [Paragraph(str(cell), styleC) for cell in row] for row in table_data
    ]
    table_style = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.black),  # full grid on the whole table
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),  # first row in bold
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),  # cell content aligned to the top
    ]
    pdf_table = Table(
        data=formatted_data,
        repeatRows=1,
        style=TableStyle(table_style),
        spaceBefore=24,
        hAlign="LEFT",
    )
    title = Paragraph(
        "Report generated on "
        + datetime.now(tz=get_localzone()).strftime("%d %b %Y %H:%M:%S %Z %z"),
        styleH,
    )
    doc = SimpleDocTemplate(
        pdf_file,
        pagesize=landscape(A3),
        leftMargin=36,
        rightMargin=36,
        title="Vault Audit Trail Report",
        author=getuser(),
        encrypt=enc,
    )
    element = []
    element.append(title)
    element.append(pdf_table)
    doc.build(element, onFirstPage=addPageNumber, onLaterPages=addPageNumber)
    print("Exported %s audit records to PDF" % str(len(data.index)))
