#!/usr/bin/env python3
"""Validate the public website-audit-360 skill package."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "website-audit-360" / "SKILL.md"
REFERENCE = (
    ROOT
    / "skills"
    / "website-audit-360"
    / "references"
    / "russia-legal-readiness-nov-2026.md"
)

REQUIRED = [
    ROOT / "README.md",
    ROOT / "LICENSE",
    ROOT / "ACKNOWLEDGEMENTS.md",
    ROOT / "CHANGELOG.md",
    ROOT / "SECURITY.md",
    ROOT / ".gitignore",
    ROOT / "examples" / "report-example.md",
    SKILL,
    REFERENCE,
]

SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "OpenAI-style key": re.compile(r"\bsk-(?:proj-|or-)?[A-Za-z0-9_-]{20,}\b"),
    "Telegram bot token": re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "password assignment": re.compile(
        r"(?i)\b(?:password|passwd|secret|token|api_key)\s*[:=]\s*['\"][^<${}'\"\s]{12,}['\"]"
    ),
}

PERSONAL_PATTERNS = {
    "internal path": re.compile(r"/(?:root|Users|home)/[^\s)`]+"),
    "Russian phone": re.compile(r"(?<!\d)\+7\d{10}(?!\d)"),
    "personal email": re.compile(
        r"(?i)\b[A-Z0-9._%+-]+@(?:gmail|yandex|mail|icloud|outlook)\.[A-Z]{2,}\b"
    ),
    "personal name": re.compile(r"(?i)\b(?:Dmitry|Дмитрий|Ledovsk|Ледовск)\w*\b"),
}


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def main() -> int:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED if not path.exists()]
    if missing:
        fail("missing required files: " + ", ".join(missing))

    skill = SKILL.read_text(encoding="utf-8")
    if not skill.startswith("---\n") or "name: website-audit-360" not in skill:
        fail("invalid SKILL.md frontmatter")
    if "description: Use when auditing a website before launch." not in skill:
        fail("routing description changed or missing")
    if "author: mcdenil-skills" not in skill or "license: MIT" not in skill:
        fail("public author/license metadata missing")

    start = skill.index("## Чек-лист из 30 пунктов")
    end = skill.index("## Критические оговорки", start)
    numbers = [
        int(match.group(1))
        for match in re.finditer(r"(?m)^(\d+)\. \*\*", skill[start:end])
    ]
    if numbers != list(range(1, 31)):
        fail(f"checklist numbering is not 1..30: {numbers}")

    required_terms = [
        "PASS / FAIL / UNTESTED / N/A",
        "Passive public",
        "Active security",
        "№265-ФЗ",
        "№376-ФЗ",
        "24 часов",
        "72 часов",
        "тег 1125",
        "WCAG 2.2 AA",
        "OWASP ASVS audit",
        "Запрет на выдумывание и заполнение квоты",
        "Finding без evidence удаляется из отчёта",
    ]
    for term in required_terms:
        if term not in skill:
            fail(f"required coverage marker missing: {term}")

    text_files = [path for path in ROOT.rglob("*") if path.is_file()]
    findings: list[str] = []
    for path in text_files:
        if path == Path(__file__).resolve() or ".git" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(ROOT)
        for label, pattern in {**SECRET_PATTERNS, **PERSONAL_PATTERNS}.items():
            if pattern.search(text):
                findings.append(f"{rel}: {label}")

    if findings:
        fail("secret/PII findings: " + "; ".join(findings))

    if "09.11.2026" not in REFERENCE.read_text(encoding="utf-8"):
        fail("legal reference verification date missing")

    print(f"PASS: {len(REQUIRED)} required files")
    print("PASS: checklist 1..30")
    print(f"PASS: secret/PII scan ({len(text_files) - 1} files)")
    print("PASS: public metadata and safety gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
