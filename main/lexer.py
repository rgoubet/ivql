from pygments.token import *
from pygments.lexers import load_lexer_from_file
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style

__all__ = ['CustomLexer']

VqlLexer = load_lexer_from_file(r'lexer\vql_lexer.py', lexername="CustomLexer")

with open("completer.txt", "r") as f:
    vql_completer = WordCompleter(f.read().splitlines())


style = Style.from_dict(
    {
        "pygments.keyword": "bg:#ffffff #000000",
    }
)

session = PromptSession(
    completer=vql_completer, complete_while_typing=False, lexer=VqlLexer, style=style
)


while True:
    query = session.prompt("VQL> ")
    print(query)
