import re
from pygments.token import *
from pygments.lexer import RegexLexer, words
from prompt_toolkit.lexers import Lexer


class CustomLexer(RegexLexer):
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
                        "between",
                        "contains",
                        "find",
                    ),
                    suffix=r"\b",
                ),
                Keyword,
            )
        ]
    }
