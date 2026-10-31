#!/usr/bin/env python3
"""agenttrail-scrub-lite: read-only scan of Claude Code transcripts for leaked secrets.

Single file, Python 3.9+ standard library only. Finds common provider API keys
and tokens in ~/.claude/projects/*.jsonl (or a --path you pass). Reports masked
previews; never modifies files.

    python agenttrail_scrub_lite.py
    python agenttrail_scrub_lite.py --path /custom/dir
    python agenttrail_scrub_lite.py --help

Full version (other agents, entropy checks, --redact with backups, allowlist,
retention, rotation checklist):
https://py-forge.com/products/agenttrail-scrub-ai-transcript-secret-cleaner?utm_source=github&utm_medium=code&utm_content=agenttrail-scrub-lite
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

# High-confidence provider signatures. Lite uses regex only (no entropy filter).
# Patterns report the captured secret group when present, else the full match.
SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    (
        "Anthropic API Key",
        re.compile(r"\b(sk-ant-api03-[A-Za-z0-9_-]{80,120})\b"),
    ),
    (
        "Anthropic Legacy Key",
        re.compile(r"\b(sk-ant-(?!api03)[A-Za-z0-9_-]{32,80})\b"),
    ),
    (
        "OpenAI API Key",
        re.compile(r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,120})\b"),
    ),
    (
        "Google Gemini / Cloud API Key",
        re.compile(r"\b(AIzaSy[A-Za-z0-9_-]{33})\b"),
    ),
    (
        "GitHub Personal Access / OAuth Token",
        re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
    ),
    (
        "GitHub Fine-Grained Token",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
    ),
    (
        "AWS Access Key ID",
        re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
    ),
    (
        "AWS Secret Access Key",
        re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b"),
    ),
    (
        "Slack Token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    ),
    (
        "Private Key Header",
        re.compile(r"(-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----)"),
    ),
    (
        "JSON Web Token (JWT)",
        re.compile(
            r"\b(eyJh[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
    ),
    (
        "Generic Token Assignment (.env style)",
        re.compile(
            r"(?i)\b(?:api_key|apikey|secret|token|auth_token|access_token|"
            r"private_key|app_secret)\s*[:=]\s*"
            r"['\"]?([A-Za-z0-9_\-+=/]{16,128})['\"]?"
        ),
    ),
]


def default_claude_projects_dir() -> pathlib.Path:
    return pathlib.Path.home() / ".claude" / "projects"


def mask_secret(value: str) -> str:
    """Produce a safe masked preview of a secret string."""
    clean = value.strip().replace("\n", "").replace("\r", "")
    if len(clean) <= 8:
        return "[REDACTED]"
    return f"{clean[:4]}...{clean[-3:]}"


def collect_jsonl_files(root: pathlib.Path) -> List[pathlib.Path]:
    """Collect .jsonl files under root (or return root if it is a .jsonl file)."""
    if not root.exists():
        return []
    if root.is_file():
        return [root] if root.suffix.lower() == ".jsonl" else []
    found: List[pathlib.Path] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        current = pathlib.Path(dirpath)
        for fname in filenames:
            if fname.lower().endswith(".jsonl"):
                found.append(current / fname)
    return sorted(found)


def scan_file(file_path: pathlib.Path) -> List[Dict[str, Any]]:
    """Scan one transcript file line by line for provider secret patterns."""
    hits: List[Dict[str, Any]] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as exc:
        return [
            {
                "provider": "UNREADABLE_FILE",
                "path": str(file_path),
                "line": 0,
                "masked": "",
                "description": f"Cannot read file: {exc}",
            }
        ]

    seen: set[Tuple[int, str, str]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for provider, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                raw = match.group(1) if match.lastindex else match.group(0)
                key = (line_no, provider, raw)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    {
                        "provider": provider,
                        "path": str(file_path),
                        "line": line_no,
                        "masked": mask_secret(raw),
                        "description": f"{provider} match (masked preview)",
                    }
                )
    return hits


class LiteScanner:
    """Read-only Claude Code transcript secret scanner (lite)."""

    def __init__(self, target: pathlib.Path) -> None:
        self.target = target
        self.files_scanned = 0
        self.findings: List[Dict[str, Any]] = []

    def run(self) -> Dict[str, Any]:
        files = collect_jsonl_files(self.target)
        if not self.target.exists():
            self.findings.append(
                {
                    "provider": "PATH_NOT_FOUND",
                    "path": str(self.target),
                    "line": 0,
                    "masked": "",
                    "description": "Scan target path does not exist",
                }
            )
        elif self.target.is_file() and self.target.suffix.lower() != ".jsonl":
            self.findings.append(
                {
                    "provider": "NOT_JSONL",
                    "path": str(self.target),
                    "line": 0,
                    "masked": "",
                    "description": "Target file is not a .jsonl transcript",
                }
            )
        else:
            for fpath in files:
                self.files_scanned += 1
                self.findings.extend(scan_file(fpath))

        secret_hits = [
            f
            for f in self.findings
            if f["provider"]
            not in ("PATH_NOT_FOUND", "NOT_JSONL", "UNREADABLE_FILE")
        ]
        return {
            "summary": {
                "target": str(self.target),
                "files_scanned": self.files_scanned,
                "findings": len(self.findings),
                "secrets_found": len(secret_hits),
            },
            "findings": self.findings,
        }


def format_text_report(results: Dict[str, Any]) -> str:
    summary = results["summary"]
    findings = results["findings"]
    lines = [
        "================================================================================",
        "                   AGENTTRAIL-SCRUB-LITE SCAN REPORT                           ",
        "================================================================================",
        f"Target                 : {summary['target']}",
        f"JSONL Files Scanned    : {summary['files_scanned']}",
        f"Findings               : {summary['findings']}",
        f"Secrets Reported       : {summary['secrets_found']}",
        "--------------------------------------------------------------------------------",
    ]
    if summary["secrets_found"] == 0 and not any(
        f["provider"] in ("PATH_NOT_FOUND", "NOT_JSONL", "UNREADABLE_FILE")
        for f in findings
    ):
        lines.append(
            "[+] Status: CLEAN. No common provider secret patterns detected "
            "in scanned transcripts."
        )
    else:
        lines.append(f"Findings ({len(findings)} total):")
        for i, f in enumerate(findings, start=1):
            lines.append(f"\n{i}. Provider  : {f['provider']}")
            lines.append(f"   Path      : {f['path']}")
            if f["line"]:
                lines.append(f"   Line      : {f['line']}")
            if f["masked"]:
                lines.append(f"   Preview   : {f['masked']}")
            lines.append(f"   Details   : {f['description']}")
    lines.append("================================================================================")
    lines.append(
        "Read-only scan. No files were modified. Rotate any real credentials "
        "at the provider."
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agenttrail-scrub-lite",
        description=(
            "Read-only scan of Claude Code JSONL transcripts for common "
            "provider API keys and tokens (Anthropic, OpenAI, Google, GitHub, "
            "AWS, Stripe, Slack, JWT, private-key headers, .env-style "
            "assignments). Stdlib only; never modifies files."
        ),
        epilog=(
            "Full version: https://py-forge.com/products/"
            "agenttrail-scrub-ai-transcript-secret-cleaner"
            "?utm_source=github&utm_medium=cli&utm_content=agenttrail-scrub-lite"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "--path",
        metavar="DIR_OR_FILE",
        help=(
            "Override the default Claude Code projects dir "
            "(~/.claude/projects). Pass a directory of .jsonl files or one "
            ".jsonl file."
        ),
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.path:
        target = pathlib.Path(args.path).expanduser()
    else:
        target = default_claude_projects_dir()

    results = LiteScanner(target).run()
    print(format_text_report(results))
    return 1 if results["summary"]["secrets_found"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
