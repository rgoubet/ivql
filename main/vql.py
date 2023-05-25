import re

from prompt_toolkit.styles import Style
from pygments.lexer import RegexLexer, words
from pygments.token import Keyword, Name, Number, Operator, String


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
