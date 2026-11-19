"""Measure WAF coverage on a 20-payload XSS corpus and verify proxy behavior."""
from __future__ import annotations
import argparse
import csv
import json
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from waf import check
from cases import PART_A_XSS, XSS_ADDITIONAL, XSS_BYPASSES

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self.links.extend(value or "" for name, value in attrs if name.lower() == "href")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=None, help="Optional live target/proxy URL, e.g. http://127.0.0.1:8001")
    args = ap.parse_args()
    cases = [{"id": "A-XSS-01", "kind": "Part-A baseline", "payload": PART_A_XSS}]
    cases += [{"id": f"XSS-{i:02d}", "kind": "Additional XSS corpus", "payload": payload}
              for i, payload in enumerate(XSS_ADDITIONAL, 1)]
    cases += [{"id": item["id"], "kind": "B1 bypass", "payload": item["payload"]} for item in XSS_BYPASSES]
    rows = []
    for item in cases:
        verdict = check("search_or_name", item["payload"])
        parser = LinkParser(); parser.feed(item["payload"])
        decoded_href = parser.links[0] if parser.links else ""
        row = {"id": item["id"], "kind": item["kind"], "payload": item["payload"],
               "blocked": verdict.blocked, "fired_rule": verdict.rule or "",
               "decoded_href": decoded_href, "endpoint_status": "not_run",
               "reflected_unescaped": "not_run",
               "parsed_javascript_uri": decoded_href.lower().startswith("javascript:")}
        if args.base_url:
            url = args.base_url.rstrip("/") + "/?name=" + quote(item["payload"], safe="")
            try:
                with urlopen(url, timeout=5) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    row["endpoint_status"] = response.status
                    row["reflected_unescaped"] = item["payload"] in body
            except HTTPError as exc:
                row["endpoint_status"] = exc.code
                row["reflected_unescaped"] = False
            except (URLError, TimeoutError, OSError) as exc:
                row["endpoint_status"] = f"error: {exc}"
                row["reflected_unescaped"] = False
        rows.append(row)

    total = len(rows); blocked = sum(bool(row["blocked"]) for row in rows)
    part_a_rows = [row for row in rows if row["kind"] == "Part-A baseline"]
    bypass_rows = [row for row in rows if row["kind"] == "B1 bypass"]
    part_a_blocked = sum(bool(row["blocked"]) for row in part_a_rows)
    bypass_allowed = sum(not row["blocked"] for row in bypass_rows)
    report = {"selected_class": "xss", "total_payloads": total, "blocked": blocked,
              "allowed": total - blocked, "combined_sample_coverage": blocked / total if total else 0,
              "part_a_payloads": len(part_a_rows), "part_a_blocked": part_a_blocked,
              "part_a_coverage": part_a_blocked / len(part_a_rows) if part_a_rows else 0,
              "b1_bypass_attempts": len(bypass_rows), "bypasses_allowed": bypass_allowed,
              "bypass_success_rate": bypass_allowed / len(bypass_rows) if bypass_rows else 0,
              "parsed_javascript_uri_count": sum(bool(row["parsed_javascript_uri"]) for row in rows),
              "scope": "20-payload sample: one Part-A payload, 16 additional XSS inputs, and three same-intent bypass attempts."}
    with (HERE / "coverage.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys())); writer.writeheader(); writer.writerows(rows)
    with (HERE / "bypass_results.csv").open("w", newline="", encoding="utf-8") as f:
        selected = [row for row in rows if row["kind"] == "B1 bypass"]
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys())); writer.writeheader(); writer.writerows(selected)
    if args.base_url:
        mismatches = [r for r in rows if (r['blocked'] and r['endpoint_status'] != 403) or (not r['blocked'] and (r['endpoint_status'] != 200 or not r['reflected_unescaped']))]
        report['live_proxy_probe'] = {'base_url': args.base_url, 'checked': len(rows),
                                      'matched_expected_behavior': len(rows)-len(mismatches),
                                      'mismatches': [r['id'] for r in mismatches]}
        print(f"Live proxy: {len(rows)-len(mismatches)}/{len(rows)} decisions matched expected block/allow+reflection behavior.")
        if mismatches:
            for row in mismatches: print(f"  MISMATCH {row['id']}: status={row['endpoint_status']} reflected={row['reflected_unescaped']}")
    else:
        report['live_proxy_probe'] = None
    (HERE / "coverage_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Part-A coverage: {part_a_blocked}/{len(part_a_rows)} ({report['part_a_coverage']:.1%})")
    print(f"B1 bypasses allowed: {bypass_allowed}/{len(bypass_rows)} ({report['bypass_success_rate']:.1%})")
    print(f"Combined sample: {blocked}/{total} blocked ({report['combined_sample_coverage']:.1%})")
    for row in rows:
        print(f"{row['id']}: {'BLOCK' if row['blocked'] else 'ALLOW'}; status={row['endpoint_status']}; parsed_js_uri={row['parsed_javascript_uri']}")
    print(f"Wrote {HERE / 'coverage.csv'} and {HERE / 'bypass_results.csv'}")

if __name__ == "__main__":
    main()
