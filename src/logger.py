"""Centralized logging for audit-agents using stdlib logging."""

import logging
import sys
from typing import Literal

# ANSI color codes
COLORS = {
    "DEBUG": "\033[90m",      # Gray
    "INFO": "\033[32m",       # Green
    "WARNING": "\033[33m",    # Yellow
    "ERROR": "\033[31m",      # Red
    "CRITICAL": "\033[1;31m", # Bold Red
}
RESET = "\033[0m"

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class ColoredFormatter(logging.Formatter):
    """Formatter with ANSI colors and aligned columns."""

    def __init__(self, use_color: bool = True):
        # Format: [HH:MM:SS] LEVEL    module.name          message
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s %(name)-28s %(message)s",
            datefmt="%H:%M:%S",
        )
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        # Truncate long module names
        if len(record.name) > 28:
            record.name = "..." + record.name[-25:]

        if self.use_color and sys.stderr.isatty():
            color = COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{RESET}"
            record.name = f"\033[36m{record.name}{RESET}"  # Cyan for module
            record.asctime = f"\033[90m{self.formatTime(record, self.datefmt)}{RESET}"  # Gray time

        return super().format(record)


def setup_logger(
    level: LogLevel = "INFO",
    use_color: bool = True,
) -> None:
    """
    Configure root logger with colored output.

    Call once at application startup (cli/main.py).
    Other modules just use: logging.getLogger(__name__)
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColoredFormatter(use_color=use_color))

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)

    # Suppress noisy third-party loggers
    for name in ("httpx", "httpcore", "urllib3", "asyncio", "web3"):
        logging.getLogger(name).setLevel(logging.WARNING)
