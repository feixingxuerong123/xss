"""Config file support for XSSentinel.

Loads scan options from a JSON config file so complex scan profiles can be
saved, shared, and reused instead of typing long CLI flags every time.

Config schema (all keys optional -- missing keys fall back to CLI defaults):

    {
      "url": "https://target.com/search",
      "method": "GET",
      "data": "q=test&page=1",
      "headers": {"X-Custom": "value"},
      "cookies": {"session": "abc123"},
      "proxy": "http://127.0.0.1:8080",
      "crawl": true,
      "crawl_depth": 3,
      "scope": "https://target.com/app/",
      "timeout": 20,
      "max_transforms": 15,
      "max_payloads": 20,
      "threads": 8,
      "dom_engine": "auto",
      "headless": false,
      "oob": "self",
      "oob_timeout": 15,
      "output": "report.html",
      "format": "html",
      "verify_ssl": true,
      "verbose": false,
      "rate_limit": 0,
      "login": {
        "type": "form",
        "url": "https://target.com/login",
        "fields": {"username": "admin", "password": "pass"},
        "success_marker": "Welcome",
        "failure_marker": "Invalid"
      },
      "custom_payloads": "path/to/payloads.txt",
      "batch_file": "urls.txt"
    }

Usage:
    cfg = Config.load("scan.json")
    args = cfg.merge_args(cli_args)  # CLI overrides config
"""
from __future__ import annotations

import json
import os
from typing import Any


class Config:
    """Load and merge scan configuration from a JSON file."""

    def __init__(self, data: dict | None = None):
        self.data = data or {}

    @classmethod
    def load(cls, path: str) -> "Config":
        """Load config from a JSON file.  Returns empty Config on error."""
        if not path or not os.path.isfile(path):
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return cls()
            return cls(data)
        except (json.JSONDecodeError, OSError):
            return cls()

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def merge_args(self, cli_args: dict) -> dict:
        """Merge config with CLI args.  CLI args take precedence when set.

        ``cli_args`` is a dict of argparse-style key=value pairs.  Values that
        are None / empty / False in cli_args fall back to config values so the
        config can provide defaults without being overridden by absent flags.
        """
        merged = dict(self.data)
        for k, v in cli_args.items():
            # CLI overrides config when the CLI value is explicitly set.
            # We treat None, "", and False as "not set" for flags that have
            # config equivalents.  For 0, keep it (could be rate_limit=0).
            if v is None or v == "" or v is False:
                continue
            merged[k] = v
        # Special: verify_ssl is stored as no_verify_ssl in CLI (inverted).
        if "no_verify_ssl" in cli_args and cli_args["no_verify_ssl"]:
            merged["verify_ssl"] = False
        elif "verify_ssl" not in merged:
            merged["verify_ssl"] = True
        return merged

    @property
    def login(self) -> dict | None:
        """Login config dict, or None if no login configured."""
        login = self.data.get("login")
        if not login or not isinstance(login, dict):
            return None
        return login

    @property
    def batch_urls(self) -> list[str]:
        """Load URLs from batch_file if configured."""
        path = self.data.get("batch_file")
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()
                        and not line.startswith("#")]
            return urls
        except OSError:
            return []

    @property
    def custom_payloads(self) -> list[str]:
        """Load custom payloads from file if configured."""
        path = self.data.get("custom_payloads")
        if not path or not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()
                            and not line.startswith("#")]
            return payloads
        except OSError:
            return []

    def to_dict(self) -> dict:
        return dict(self.data)


def save_config(path: str, data: dict) -> bool:
    """Save a config dict to a JSON file (for --save-config)."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except OSError:
        return False
