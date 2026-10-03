"""Parsers package init."""
from .npm_lock import parse_npm_lock, ParseResult, ParsedPackage
from .requirements_txt import parse_requirements_txt, RequirementsResult
