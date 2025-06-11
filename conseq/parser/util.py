from . import depfile
from .semantics import Semantics


def parse_str(text, filename=None):
    parser = depfile.depfileParser(parseinfo=False)
    statements = parser.parse(
        text,
        "all_declarations",
        filename=filename,
        trace=False,
        nameguard=None,
        parseinfo=True,
        semantics=Semantics(filename),
    )
    if statements is None:
        return []
    return statements


def parse(filename):
    with open(filename) as f:
        text = f.read()
    return parse_str(text, filename)
