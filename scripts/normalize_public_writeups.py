#!/usr/bin/env python3
"""Normalize lab writeups for public portfolio quality.

This script keeps the existing narrative intact, but applies repo-wide public-safety
and reporting polish:
- redact target-specific IPs, proof hashes/flags, NT hashes, and known lab passwords
- convert common mitigation heading to remediation terminology
- append missing Root Cause / Impact / Remediation / Detection / Lessons sections
- create a non-empty placeholder for intentionally unpublished writeups
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1]

EXCLUDE_NAMES = {"README.md", "index.md", "writeup-template.md", "oscp-findings-reference.md"}
EXCLUDE_DIRS = {".git", "_layouts", "assets", "scripts"}

# SHA-256 hash -> replacement. This keeps known lab credential/proof literals out
# of the public maintenance script while still allowing old drafts to be cleaned.
KNOWN_SECRET_HASH_REPLACEMENTS = {
    "4b9508059af87e90c37d78e3feec4358e43e413799ac878feac84cf1f74d9781": "<redacted-password>",
    "22ea11e2244b82f1cbe7fada7cbfe8ad0edd0fe02ce9896b56fadc2f602ddb5a": "<redacted-password>",
    "37f8175aa8551c8cdbf2667f8f6172ed0ba954789d146dbf38a98507f844c2fb": "<redacted-password-old>",
    "54f28781c0ca278aae34f896a8b6522511131ba1a59fbf16570f24d8dc5d42b6": "<redacted-password-current>",
    "01a1cd5a5f94709e51c65ccb727e96e4adabae04e557ff8f7502e0be039d58fa": "<redacted-temp-password>",
    "79dad98d9756cfc39c16f183a13b4ef731056b29242fcd8ea67e5709213c817d": "<redacted-nt-hash>",
    "3ac48fef3011059a7728c3411a36a6c10cfd0d2bf2f7e138fc5894f4961f250a": "<redacted-nt-hash>",
    "3144271dd8311c081d389df41554df51a3db13e27fc76351c1a1385af7fa0112": "<redacted-nt-hash>",
    "2f87fa55cb3d4b38eee64b5bb775fa9a059b540ac6c3d2fa78da460c25dbdec8": "<redacted-nt-hash>",
    "ea2e9a4323aa7c6a421932cdffde371a78faa4a236b388f2c18fc8b7d0116557": "<redacted-nt-hash>",
    "d4f6f3b30b1d680305026c21f6946df09c2fe32a92be5f4c07b0c93c95d6f1c4": "<redacted-nt-hash>",
}
SECRET_TOKEN_RE = re.compile(r"[A-Za-z0-9@!#$%^&*_.+\-]{6,}")

# Commands/output containing these words are normally proof/credential material.
SENSITIVE_LINE_HINTS = re.compile(
    r"(user\.txt|root\.txt|NT hash|Got hash|hashes\b|NTLMv2-SSP Hash|secretsdump|DCSync|aad3b435|krbtgt:|Administrator:500|DeviceID|'[0-9a-f]{32}'|proof)",
    re.I,
)
HEX32 = re.compile(r"\b[0-9a-fA-F]{32}\b")
HEX64PLUS = re.compile(r"\b[0-9a-fA-F]{64,}\b")
PRIVATE_IP = re.compile(r"\b10\.(?:10|129|0|1|2|3|4|5|6|7|8|9)\.\d{1,3}\.\d{1,3}\b")


def is_machine_writeup(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if any(part in EXCLUDE_DIRS for part in rel.parts):
        return False
    if path.name in EXCLUDE_NAMES:
        return False
    # category/machine/file.md or report/*.md
    return path.suffix == ".md" and (len(rel.parts) >= 3 or rel.parts[0] == "report")


def title_from_path(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
    m = re.search(r"^#\s+(.+)$", text, re.M)
    if m:
        return m.group(1).strip()
    stem = path.parent.name if path.parent.name != "report" else path.stem
    return stem.replace("-", " ").title()


def category_for(path: Path) -> str:
    rel = path.relative_to(ROOT)
    return rel.parts[0]


def redact_known_secret_token(match: re.Match[str]) -> str:
    token = match.group(0)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return KNOWN_SECRET_HASH_REPLACEMENTS.get(digest, token)


def redact_text(text: str, category: str) -> str:
    text = PRIVATE_IP.sub("<target-ip>", text)
    text = re.sub(r"LHOST=<target-ip>", "LHOST=<vpn-ip>", text)
    text = SECRET_TOKEN_RE.sub(redact_known_secret_token, text)

    redacted_lines: list[str] = []
    for line in text.splitlines():
        # Keep binary BuildID/SHA1 examples in reversing notes; redact proof/hash contexts elsewhere.
        if "BuildID[sha1]" in line or "BuildID" in line:
            redacted_lines.append(line)
            continue
        if SENSITIVE_LINE_HINTS.search(line):
            line = HEX64PLUS.sub("<redacted-long-hash>", line)
            line = HEX32.sub("<redacted-32-hex>", line)
        elif category != "reversing":
            # In infra writeups, standalone 32-hex values are usually flags or hashes.
            line = HEX32.sub("<redacted-32-hex>", line)
        redacted_lines.append(line)
    return "\n".join(redacted_lines) + ("\n" if text.endswith("\n") else "")


def normalize_headings(text: str) -> str:
    text = re.sub(r"^## Mitigations\s*$", "## Remediation", text, flags=re.M)
    text = re.sub(r"^## Recommendations\s*$", "## Remediation", text, flags=re.M)
    return text


def infer_vectors(text: str, category: str) -> dict[str, str]:
    lower = text.lower()
    if category == "active-directory":
        return {
            "root": "excessive identity, delegation, certificate, or credential exposure in an Active Directory environment",
            "impact": "domain credential compromise, lateral movement, or administrative control over sensitive Windows systems",
            "remediation": "tighten ACLs and group memberships, remove exposed credentials, harden ADCS templates, restrict administrative protocols, and rotate affected secrets",
            "detection": "monitor LDAP/SMB enumeration, Kerberos roasting, certificate enrollment anomalies, DACL ownership changes, WinRM logons, and unusual service-account authentication",
        }
    if category == "reversing":
        return {
            "root": "the challenge binary embedded enough validation logic or static material for offline recovery",
            "impact": "static and dynamic analysis could recover the protected value without needing to defeat a live service",
            "remediation": "do not rely on client-side secrecy for real systems; move trust decisions server-side and protect secrets with layered controls",
            "detection": "for production binaries, monitor unexpected debugging, tracing, and tampering where endpoint telemetry is available",
        }
    if category == "windows":
        return {
            "root": "exposed Windows services, weak credential handling, or outdated software created a direct path to code execution or privilege escalation",
            "impact": "an attacker could gain interactive access and escalate toward Administrator or SYSTEM-level control",
            "remediation": "patch affected services, disable legacy protocols, remove plaintext credentials, harden service permissions, and restrict administrative interfaces",
            "detection": "monitor service exploitation attempts, suspicious process creation, new local administrators, abnormal SMB/WinRM traffic, and credential access events",
        }
    # linux / default
    return {
        "root": "exposed services, credential reuse, unsafe file permissions, or vulnerable software allowed the attack path to progress",
        "impact": "an attacker could obtain shell access, recover sensitive files or credentials, and escalate to root-level control",
        "remediation": "patch vulnerable applications, remove exposed secrets, enforce least privilege on sudo/cron/service paths, and restrict unnecessary network exposure",
        "detection": "monitor web exploitation attempts, suspicious child processes, credential-file reads, privilege-escalation commands, and unexpected changes in writable service paths",
    }


def has_heading(text: str, name: str) -> bool:
    return re.search(rf"^##\s+{re.escape(name)}\b", text, re.M | re.I) is not None


def has_any_heading(text: str, names: tuple[str, ...]) -> bool:
    return any(has_heading(text, name) for name in names)


def append_quality_sections(text: str, path: Path) -> str:
    category = category_for(path)
    vec = infer_vectors(text, category)
    additions: list[str] = []

    if not has_any_heading(text, ("Root Cause",)):
        additions.append(f"## Root Cause\n\nThe core weakness was a failure of least privilege or secure exposure: {vec['root']}. The exact trigger varies by target, but the lesson is consistent: each step worked because a service, identity, credential, or permission boundary exposed more trust than it should have.\n")

    if not has_any_heading(text, ("Impact",)):
        additions.append(f"## Impact\n\nSuccessful exploitation demonstrated that {vec['impact']}. In a real environment, this class of weakness would create risk beyond the single host because credentials, administrative access, and trust relationships can compound quickly.\n")

    if not has_any_heading(text, ("Remediation", "Mitigations", "Recommendations")):
        additions.append(f"## Remediation\n\n- {vec['remediation'].capitalize()}.\n- Rotate any credentials that were exposed or reused during the attack path.\n- Review adjacent systems for the same pattern instead of treating the issue as isolated to one host.\n- Validate fixes by replaying the relevant enumeration and exploitation checks with safe test accounts.\n")

    if not has_any_heading(text, ("Detection Opportunities", "Detection")):
        additions.append(f"## Detection Opportunities\n\n- {vec['detection'].capitalize()}.\n- Alert on authentication from unusual sources, abnormal administrative tool use, and newly created or modified privileged access paths.\n- Preserve enough command, process, and authentication telemetry to reconstruct the chain from initial contact through privilege escalation.\n")

    if not has_any_heading(text, ("Lessons Learned",)):
        additions.append("## Lessons Learned\n\n- Prioritize findings that connect enumeration output to a concrete next action.\n- Treat credentials, writable paths, and trust relationships as escalation primitives, not just isolated observations.\n- Document both the command sequence and the reasoning so the writeup remains useful after the lab is no longer fresh.\n")

    if additions:
        text = text.rstrip() + "\n\n---\n\n" + "\n".join(additions).rstrip() + "\n"
    return text


def ensure_admin_placeholder() -> None:
    path = ROOT / "active-directory/htb-administrator/htb-administrator.md"
    if not path.exists() or path.read_text(encoding="utf-8", errors="ignore").strip() == "":
        path.write_text("""---
layout: default
title: "HackTheBox - Administrator"
status: "Draft / private notes pending sanitization"
---

# HackTheBox - Administrator

**OS:** Windows Active Directory  
**Status:** Draft / pending public-safe writeup

This entry is intentionally present as a placeholder while the private notes are converted into a public-safe report. It remains listed in the Active Directory category so the backlog is visible, but exact attack details, credentials, proofs, and target-specific artifacts are omitted until the writeup is complete.

---

## Publication Checklist

- [ ] Convert private notes into a coherent attack-path narrative.
- [ ] Remove flags, exact hashes, plaintext passwords, target IPs, and proof-only output.
- [ ] Add remediation, detection opportunities, and lessons learned.
- [ ] Verify all screenshots and links before publication.

## Summary

Administrator is reserved for a future Active Directory writeup. The final version should focus on the enterprise lesson, not just the lab solution.

## Root Cause

TODO: summarize the confirmed misconfiguration or vulnerability once the private notes have been sanitized.

## Impact

TODO: describe the demonstrated access level and realistic enterprise risk without exposing lab-sensitive proof material.

## Remediation

- TODO: add the highest-value corrective actions after the attack path is finalized.
- Rotate any credentials disclosed during testing.
- Validate the fix by re-running the safe enumeration checks that originally exposed the path.

## Detection Opportunities

- TODO: identify logs or telemetry that would reveal the attack path.
- Monitor abnormal authentication, directory enumeration, and privilege changes.

## Lessons Learned

- Keep placeholder entries explicit so incomplete work does not look accidentally broken.
- Publish only after private proof material has been removed or redacted.
""", encoding="utf-8")


def update_indexes() -> None:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    text = text.replace("AttacktivDirectory", "Attacktive Directory")
    if "Public-safe note" not in text:
        text += "\n> **Public-safe note:** writeups intentionally redact target IPs, proof values, exact hashes, and reusable credentials where those details are not needed to teach the attack path.\n"
    readme.write_text(text, encoding="utf-8")

    index = ROOT / "index.md"
    text = index.read_text(encoding="utf-8")
    if "Public-Safe Reporting Standard" not in text:
        text = text.rstrip() + "\n\n---\n\n## Public-Safe Reporting Standard\n\nThese writeups preserve methodology, reasoning, tooling, remediation, and detection opportunities while redacting target-specific secrets such as flags, exact hashes, plaintext passwords, and lab IP addresses when they are not required for learning value.\n"
    index.write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")


def main() -> None:
    ensure_admin_placeholder()
    changed = []
    for path in ROOT.rglob("*.md"):
        if not is_machine_writeup(path):
            continue
        original = path.read_text(encoding="utf-8", errors="ignore")
        text = original
        text = normalize_headings(text)
        text = redact_text(text, category_for(path))
        text = append_quality_sections(text, path)
        if text != original:
            path.write_text(text, encoding="utf-8")
            changed.append(path.relative_to(ROOT).as_posix())
    update_indexes()
    print(f"normalized {len(changed)} writeups")
    for rel in changed:
        print(rel)


if __name__ == "__main__":
    main()
