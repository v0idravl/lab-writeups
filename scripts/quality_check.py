#!/usr/bin/env python3
"""Quality gates for public lab writeups.

Checks are intentionally lightweight and local-only:
- relative markdown/image links resolve
- machine writeups are non-empty
- public writeups avoid common unsanitized lab artifacts
- machine writeups include remediation, detection, and lessons sections
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import os
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
IN_GHA = os.environ.get("GITHUB_ACTIONS") == "true"
EXCLUDE_NAMES = {"README.md", "index.md", "writeup-template.md", "oscp-findings-reference.md"}
EXCLUDE_DIRS = {".git", "_layouts", "assets", "scripts", "vendor", "_site", ".bundle"}
PRIVATE_IP = re.compile(r"\b10\.(?:10|129)\.\d{1,3}\.\d{1,3}\b")
HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")
# SHA-256 hashes of known lab credential literals that must not appear in
# public writeups. Store hashes instead of the literal values so the quality
# gate does not preserve secrets while checking for regressions.
SECRET_HASHES = {
    "4b9508059af87e90c37d78e3feec4358e43e413799ac878feac84cf1f74d9781",
    "22ea11e2244b82f1cbe7fada7cbfe8ad0edd0fe02ce9896b56fadc2f602ddb5a",
    "37f8175aa8551c8cdbf2667f8f6172ed0ba954789d146dbf38a98507f844c2fb",
    "54f28781c0ca278aae34f896a8b6522511131ba1a59fbf16570f24d8dc5d42b6",
    "01a1cd5a5f94709e51c65ccb727e96e4adabae04e557ff8f7502e0be039d58fa",
}
SECRET_TOKEN_RE = re.compile(r"[A-Za-z0-9@!#$%^&*_.+\-]{6,}")


def is_machine_writeup(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if any(part in EXCLUDE_DIRS for part in rel.parts):
        return False
    if path.name in EXCLUDE_NAMES:
        return False
    return path.suffix == ".md" and (len(rel.parts) >= 3 or (len(rel.parts) > 1 and rel.parts[0] == "report"))


def markdown_files() -> list[Path]:
    return [p for p in ROOT.rglob("*.md") if not EXCLUDE_DIRS.intersection(p.parts)]


def has_heading(text: str, heading: str) -> bool:
    return re.search(rf"^##\s+{re.escape(heading)}\b", text, re.I | re.M) is not None


def check_links(errors: list[str]) -> None:
    link_re = re.compile(r"(!?)\[[^\]]*\]\(([^)]+)\)")
    for path in markdown_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in link_re.finditer(text):
            target = match.group(2).split("#", 1)[0].strip()
            if not target or re.match(r"^(https?://|mailto:|#)", target):
                continue
            if not (path.parent / target).resolve().exists():
                errors.append(f"missing link: {path.relative_to(ROOT)} -> {target}")


def check_writeups(errors: list[str]) -> None:
    for path in ROOT.rglob("*.md"):
        if not is_machine_writeup(path):
            continue
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not text.strip():
            errors.append(f"empty writeup: {rel}")
            continue
        for token in SECRET_TOKEN_RE.findall(text):
            if hashlib.sha256(token.encode("utf-8")).hexdigest() in SECRET_HASHES:
                errors.append(f"unsanitized known lab credential literal in {rel}: [REDACTED]")
                break
        if PRIVATE_IP.search(text):
            errors.append(f"unsanitized lab IP in {rel}")
        for line in text.splitlines():
            if "BuildID" in line:
                continue
            if HEX32.search(line) and re.search(r"(user\.txt|root\.txt|hash|proof|aad3b435|Administrator:500|krbtgt:)", line, re.I):
                errors.append(f"unsanitized 32-hex proof/hash in {rel}: {line[:100]}")
                break
        if not has_heading(text, "Remediation"):
            errors.append(f"missing Remediation: {rel}")
        if not (has_heading(text, "Detection Opportunities") or has_heading(text, "Detection")):
            errors.append(f"missing Detection Opportunities: {rel}")
        if not has_heading(text, "Lessons Learned"):
            errors.append(f"missing Lessons Learned: {rel}")


def _gha_annotation(err: str) -> str:
    """Render one error as a GitHub Actions ``::error::`` workflow command.

    Surfaces the failure at the top of the run summary instead of buried in
    stdout. When a writeup path is present in the message, attach it as the
    ``file`` property so the annotation is clickable.
    """
    msg = err.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    path_match = re.search(r"\b([\w./-]+\.md)\b", err)
    if path_match:
        return f"::error file={path_match.group(1)}::{msg}"
    return f"::error::{msg}"


def main() -> int:
    errors: list[str] = []
    check_links(errors)
    check_writeups(errors)
    if errors:
        print("QUALITY CHECK FAILED")
        for err in errors:
            print(f"- {err}")
            if IN_GHA:
                print(_gha_annotation(err))
        return 1
    print("QUALITY CHECK PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
