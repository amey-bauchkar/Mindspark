"""
requirements.txt adapter (limited: vulnerabilities and licenses only, no edges).
Only accepts lines of the form: name==version
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field

PINNED_RE = re.compile(r'^([A-Za-z0-9_.\-]+)==([^\s;]+)', re.MULTILINE)
COMMENT_RE = re.compile(r'#.*$', re.MULTILINE)


@dataclass
class RequirementEntry:
    name: str
    version: str
    purl: str
    line: str


@dataclass
class RequirementsResult:
    packages: list[RequirementEntry]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_requirements_txt(content: str) -> RequirementsResult:
    warnings: list[str] = []
    packages: list[RequirementEntry] = []

    clean = COMMENT_RE.sub("", content)
    matched_names: set[str] = set()

    for m in PINNED_RE.finditer(clean):
        name, version = m.group(1), m.group(2)
        purl = f"pkg:pypi/{name.lower()}@{version}"
        packages.append(RequirementEntry(name=name, version=version, purl=purl, line=m.group(0)))
        matched_names.add(name.lower())

    # Find unpinned lines
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-r"):
            continue
        if "==" not in line and line:
            warnings.append(f"Unpinned requirement ignored (cannot resolve): {line!r}")

    if not packages:
        warnings.append("No pinned packages found. Only name==version lines are supported.")

    return RequirementsResult(packages=packages, warnings=warnings)
