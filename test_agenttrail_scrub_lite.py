"""Tests for agenttrail-scrub-lite. Fixture secrets are built by concatenation
so the source never contains a full real-looking live key (GitHub push protection).
"""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import agenttrail_scrub_lite as ats


def run_main(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        return ats.main(argv), buf.getvalue()


def fake_anthropic() -> str:
    # sk-ant-api03- + 90 safe chars (within 80..120)
    return "sk-ant-api03-" + ("A" * 90)


def fake_openai() -> str:
    return "sk-" + ("B" * 48)


def fake_github() -> str:
    return "ghp_" + ("C" * 36)


def fake_aws_akia() -> str:
    return "AKIA" + ("D" * 16)


def fake_stripe() -> str:
    return "sk_test_" + ("E" * 24)


def fake_slack() -> str:
    return "xoxb-" + ("F" * 12) + "-" + ("G" * 12)


def fake_google() -> str:
    return "AIzaSy" + ("H" * 33)


def fake_jwt() -> str:
    # eyJh + payload-ish segments
    return "eyJh" + ("I" * 20) + "." + ("J" * 20) + "." + ("K" * 20)


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_jsonl(self, name: str, lines: list[str]) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def test_clean_transcript(self):
        self._write_jsonl(
            "clean.jsonl",
            [
                '{"type":"user","text":"hello world"}',
                '{"type":"assistant","text":"no secrets here"}',
            ],
        )
        results = ats.LiteScanner(self.root).run()
        self.assertEqual(results["summary"]["files_scanned"], 1)
        self.assertEqual(results["summary"]["secrets_found"], 0)
        rc, out = run_main(["--path", str(self.root)])
        self.assertEqual(rc, 0)
        self.assertIn("CLEAN", out)

    def test_detects_anthropic_openai_github(self):
        self._write_jsonl(
            "leaky.jsonl",
            [
                '{"msg":"key ' + fake_anthropic() + '"}',
                '{"msg":"openai ' + fake_openai() + '"}',
                '{"msg":"gh ' + fake_github() + '"}',
            ],
        )
        results = ats.LiteScanner(self.root).run()
        providers = {f["provider"] for f in results["findings"]}
        self.assertIn("Anthropic API Key", providers)
        self.assertIn("OpenAI API Key", providers)
        self.assertIn("GitHub Personal Access / OAuth Token", providers)
        self.assertEqual(results["summary"]["secrets_found"], 3)
        for f in results["findings"]:
            self.assertIn("...", f["masked"])
            self.assertNotIn(fake_anthropic(), f["masked"])
        self.assertEqual(run_main(["--path", str(self.root)])[0], 1)

    def test_detects_aws_stripe_slack_google_jwt(self):
        self._write_jsonl(
            "more.jsonl",
            [
                fake_aws_akia(),
                "aws_secret_access_key=" + ("Z" * 40),
                fake_stripe(),
                fake_slack(),
                fake_google(),
                fake_jwt(),
                "-----BEGIN RSA PRIVATE KEY-----",
            ],
        )
        results = ats.LiteScanner(self.root).run()
        providers = {f["provider"] for f in results["findings"]}
        self.assertIn("AWS Access Key ID", providers)
        self.assertIn("AWS Secret Access Key", providers)
        self.assertIn("Stripe Secret Key", providers)
        self.assertIn("Slack Token", providers)
        self.assertIn("Google Gemini / Cloud API Key", providers)
        self.assertIn("JSON Web Token (JWT)", providers)
        self.assertIn("Private Key Header", providers)

    def test_generic_env_assignment(self):
        self._write_jsonl(
            "env.jsonl",
            ['{"text":"API_KEY=' + ("M" * 20) + '"}'],
        )
        results = ats.LiteScanner(self.root).run()
        self.assertTrue(
            any(f["provider"] == "Generic Token Assignment (.env style)" for f in results["findings"])
        )

    def test_nested_project_jsonl(self):
        nested = self.root / "proj-abc" / "session.jsonl"
        nested.parent.mkdir(parents=True)
        nested.write_text('{"k":"' + fake_github() + '"}\n', encoding="utf-8")
        results = ats.LiteScanner(self.root).run()
        self.assertEqual(results["summary"]["files_scanned"], 1)
        self.assertEqual(results["summary"]["secrets_found"], 1)

    def test_single_file_path(self):
        f = self._write_jsonl("one.jsonl", ['"' + fake_stripe() + '"'])
        results = ats.LiteScanner(f).run()
        self.assertEqual(results["summary"]["files_scanned"], 1)
        self.assertGreaterEqual(results["summary"]["secrets_found"], 1)

    def test_non_jsonl_file_ignored_in_dir(self):
        (self.root / "notes.txt").write_text(fake_openai() + "\n", encoding="utf-8")
        results = ats.LiteScanner(self.root).run()
        self.assertEqual(results["summary"]["files_scanned"], 0)
        self.assertEqual(results["summary"]["secrets_found"], 0)

    def test_non_jsonl_direct_file(self):
        f = self.root / "x.log"
        f.write_text(fake_openai() + "\n", encoding="utf-8")
        results = ats.LiteScanner(f).run()
        self.assertEqual(results["findings"][0]["provider"], "NOT_JSONL")
        self.assertEqual(results["summary"]["secrets_found"], 0)

    def test_missing_path(self):
        missing = self.root / "nope"
        results = ats.LiteScanner(missing).run()
        self.assertEqual(results["findings"][0]["provider"], "PATH_NOT_FOUND")
        self.assertEqual(run_main(["--path", str(missing)])[0], 0)

    def test_mask_short_and_long(self):
        self.assertEqual(ats.mask_secret("abcd"), "[REDACTED]")
        masked = ats.mask_secret("abcdefghijklmnop")
        self.assertTrue(masked.startswith("abcd"))
        self.assertTrue(masked.endswith("nop"))
        self.assertIn("...", masked)

    def test_default_path_uses_claude_projects(self):
        # Without --path, main targets ~/.claude/projects (may or may not exist).
        # Just ensure it does not crash and returns 0 or 1.
        rc, out = run_main([])
        self.assertIn(rc, (0, 1))
        self.assertIn("AGENTTRAIL-SCRUB-LITE SCAN REPORT", out)

    def test_report_header(self):
        report = ats.format_text_report(
            {
                "summary": {
                    "target": "/tmp/x",
                    "files_scanned": 0,
                    "findings": 0,
                    "secrets_found": 0,
                },
                "findings": [],
            }
        )
        self.assertIn("AGENTTRAIL-SCRUB-LITE SCAN REPORT", report)
        self.assertIn("CLEAN", report)
        self.assertIn("Read-only", report)

    def test_no_file_modification(self):
        secret = fake_anthropic()
        f = self._write_jsonl("immutable.jsonl", ['{"s":"' + secret + '"}'])
        before = f.read_bytes()
        ats.LiteScanner(self.root).run()
        run_main(["--path", str(self.root)])
        self.assertEqual(f.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
