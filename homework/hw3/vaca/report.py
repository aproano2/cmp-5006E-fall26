"""Turn results/*.json into the tables quoted in README.md (results/summary.md).

Every number in the README comes from this file's output, so a reader can
re-run `python3 run_all.py` and diff summary.md instead of trusting prose.
"""
from __future__ import annotations

import json
from pathlib import Path

R = Path(__file__).resolve().parent / "results"


def load(name):
    p = R / name
    return json.loads(p.read_text()) if p.exists() else None


def kn(row):
    e = f" ({row['errors']} err)" if row.get("errors") else ""
    return f"{row['k']}/{row['n']}{e}"


def part_a(lines):
    a_o, a_m = load("part_a_ollama.json"), load("part_a_mock.json")
    lines += ["## Part A — k/5 per payload (canary oracle)", "",
              "| Attack | Payload | Role | qwen2.5:1.5b | mock |", "|---|---|---|---|---|"]
    names = {"direct": "1 direct /chat", "indirect": "2 indirect /summarize",
             "rag_exfil": "3a RAG exfil", "rag_poison": "3b RAG poison",
             "agent": "4 confused deputy"}
    for key, title in names.items():
        mock_rows = {r["label"]: r for r in a_m["attacks"][key]} if a_m else {}
        for r in a_o["attacks"][key]:
            m = mock_rows.get(r["label"])
            lines.append(f"| {title} | `{r['label']}` | {r.get('role', '')} | {kn(r)} | "
                         f"{kn(m) if m else '—'} |")
    lines.append("")


def part_b1(lines):
    for backend in ("ollama", "mock"):
        b = load(f"b1_{backend}.json")
        if not b:
            continue
        lines += [f"## Part B1 — block rate by defense level ({backend})", "",
                  "| Level | Surface | Payloads | Leaking trials | Block rate |",
                  "|---|---|---|---|---|"]
        a = load(f"part_a_{backend}.json")
        surf = {"direct": "chat", "indirect": "summarize", "rag_exfil": "rag", "rag_poison": "rag"}
        by = {}
        for k in ("direct", "indirect", "rag_exfil", "rag_poison"):
            for r in a["attacks"][k]:
                if r.get("role") == "attack":
                    by.setdefault((0, surf[k]), []).append(r)
        for lvl, rows in b["levels"].items():
            for r in rows:
                by.setdefault((int(lvl), r["surface"]), []).append(r)
        for (lvl, s), rows in sorted(by.items()):
            leak = sum(r["k"] for r in rows)
            n = sum(r["n"] for r in rows)
            lines.append(f"| {lvl} | {s} | {len(rows)} | {leak}/{n} | {1 - leak / n:.0%} |")
        for lvl in sorted({k[0] for k in by}):
            rows = [r for (l, _), rs in by.items() if l == lvl for r in rs]
            leak = sum(r["k"] for r in rows)
            n = sum(r["n"] for r in rows)
            lines.append(f"| **{lvl}** | **all** | {len(rows)} | {leak}/{n} | **{1 - leak / n:.0%}** |")
        lines += ["", f"Agent exfil at defense level 3 ({backend}): " + ", ".join(
            f"`{r['label']}` {kn(r)}" for r in b["agent_level3"]), "",
            f"### Bypass of the literal filter ({backend}, decoded-canary oracle)", "",
            "| Payload | Level 2 | Level 3 | How the canary was recovered |", "|---|---|---|---|"]
        l2 = {r["label"]: r for r in b["bypass"]["2"]}
        for r3 in b["bypass"]["3"]:
            r2 = l2[r3["label"]]
            hows = sorted({t["how"] for t in r2["trials"] + r3["trials"] if t["hit"]})
            lines.append(f"| `{r3['label']}` | {kn(r2)} | {kn(r3)} | {', '.join(hows) or '—'} |")
        lines.append("")


def part_b2(lines):
    for planner in ("llm", "mock"):
        b = load(f"b2_{planner}.json")
        if not b:
            continue
        lines += [f"## Part B2 — coverage vs containment (planner={planner})", "",
                  "| Payload | Policy | Injection fired | Email sent to attacker | Secret exfiltrated | `sent == []` |",
                  "|---|---|---|---|---|---|"]
        for key, pol in (("attack_open", "all tools"), ("attack_least", "`[get_faq]`")):
            for r in b[key]:
                lines.append(f"| `{r['label']}` | {pol} | {r['fired']}/{r['n']} | "
                             f"{r.get('to_attacker', r['exfil'])}/{r['n']} | {r['exfil']}/{r['n']} | {r['contained']}/{r['n']} |")
        tot = lambda key, f: (sum(r[f] for r in b[key]), sum(r["n"] for r in b[key]))  # noqa: E731
        fired, n = tot("attack_least", "fired")
        cont, _ = tot("attack_least", "contained")
        lines += ["", f"**Least privilege, planner={planner}: injection fired {fired}/{n} "
                  f"(coverage {1 - fired / n:.0%}); damage contained {cont}/{n} "
                  f"(containment {cont / n:.0%}).**", "",
                  "| Benign corpus | Served |", "|---|---|"]
        for key, pol in (("benign_open", "all tools"), ("benign_least", "`[get_faq]`"),
                         ("benign_balance_role", "`[get_faq, lookup_balance]`")):
            s = sum(r["served"] for r in b[key])
            n = sum(r["n"] for r in b[key])
            lines.append(f"| {pol} | {s}/{n} ({s / n:.0%}) |")
        lines.append("")
        if "fuzz" in b:
            lines += ["| Fuzz policy | Plans | Disallowed calls planned | Executed | Violations |",
                      "|---|---|---|---|---|"]
            for pol, f in b["fuzz"].items():
                lines.append(f"| `{pol}` | {f['requests']} | {f['disallowed_calls_planned']} | "
                             f"{f['calls_executed']} | **{f['violations']}** |")
            p = b["precondition"]
            lines += ["", f"Precondition: under `[get_faq]` exfil={p['before']['exfil']}; after an "
                      f"unauthenticated `POST /policy` widening it, exfil={p['after']['exfil']}.", ""]


def main():
    lines = ["# HW3 results summary (generated by report.py — do not edit)", ""]
    part_a(lines)
    part_b1(lines)
    part_b2(lines)
    out = R / "summary.md"
    out.write_text("\n".join(lines) + "\n")
    print(out.read_text())


if __name__ == "__main__":
    main()
