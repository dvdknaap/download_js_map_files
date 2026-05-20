"""Terminal color constants."""

_COLOR_CODES = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


class Colors:
    """ANSI color codes used by the CLI output."""

    HEADER = _COLOR_CODES["HEADER"]
    BLUE = _COLOR_CODES["BLUE"]
    CYAN = _COLOR_CODES["CYAN"]
    GREEN = _COLOR_CODES["GREEN"]
    YELLOW = _COLOR_CODES["YELLOW"]
    RED = _COLOR_CODES["RED"]
    RESET = _COLOR_CODES["RESET"]
    BOLD = _COLOR_CODES["BOLD"]


def set_color_enabled(enabled: bool) -> None:
    """Enable or disable ANSI color constants for this process."""

    for name, value in _COLOR_CODES.items():
        setattr(Colors, name, value if enabled else "")
