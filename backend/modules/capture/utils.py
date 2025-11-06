import re

def strip_ansi_codes(text):
    """Remove ANSI color codes from log lines."""
    ansi_escape = re.compile(r"(?:\x1B[@-_][0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)
