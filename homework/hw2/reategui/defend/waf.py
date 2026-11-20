"""The intentionally imperfect SQLi blocklist used in Part B1."""

import re

# Deliberately broad enough to block ordinary names containing SQL words.
RULES = [
    (re.compile(r"or", re.I), "substring OR"),
    (re.compile(r"union", re.I), "substring UNION"),
    (re.compile(r"select", re.I), "substring SELECT"),
    (re.compile(r"drop", re.I), "substring DROP"),
]


def waf_block(text: str) -> str | None:
    for pattern, label in RULES:
        if pattern.search(text):
            return label
    return None
