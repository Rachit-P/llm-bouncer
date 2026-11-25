"""llm-bouncer: label every piece of text an LLM agent reads with its source."""

__version__ = "0.8.0"

from .labels import Label, SourceType, Trust  # noqa: F401
from .scan import scan_text  # noqa: F401
