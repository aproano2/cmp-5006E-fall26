import ast
import json
import re
import shutil
import subprocess
from pathlib import Path

from seclab.llm import LLM
from seclab.scan import ScanResult


def _find_root() -> Path:
    root = Path(__file__).resolve()

    while root != root.parent and not (root / "seclab").is_dir():
        root = root.parent

    return root


ROOT: Path = _find_root()

SOURCE_PATH = ROOT / "labs/vuln-web/app/vulnweb_app.py"
GROUND_TRUTH = ROOT / "homework/hw2/duel-2-web/ground_truth.json"


def load_ground_truth() -> set[tuple]:
    data = json.loads(GROUND_TRUTH.read_text())

    return {(f["rule"].lower(), f["location"].lower()) for f in data["findings"]}


SEMGREP_OUTPUT = Path(__file__).resolve().parent / "semgrep_output.json"
SEMGREP_CONFIGS = ("auto", "p/security-audit", "p/python")


def _enclosing_function(source_path: Path, line: int) -> str | None:
    tree = ast.parse(Path(source_path).read_text(encoding="utf-8"))
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.lineno <= line <= (node.end_lineno or node.lineno):
                # Innermost wins: a later-starting enclosing def is nested deeper.
                if best is None or node.lineno > best.lineno:
                    best = node
    return best.name if best else None


def _run_semgrep_live(source_path: Path) -> list[dict]:
    runs = []
    for config in SEMGREP_CONFIGS:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", config, "--json", "--metrics", "on",
             str(source_path)],
            capture_output=True, text=True, check=False,
        )
        runs.append({"config": config, "output": json.loads(proc.stdout)})
    return runs


def run_semgrep(
    source_path,
    output_path: Path = SEMGREP_OUTPUT,
) -> list[ScanResult]:
    source_path = Path(source_path)
    output_path = Path(output_path)

    runs = _run_semgrep_live(source_path)
    output_path.write_text(json.dumps(runs, indent=2), encoding="utf-8")

    results: dict[tuple, ScanResult] = {}
    for run in runs:
        config, output = run["config"], run["output"]
        for err in output.get("errors", []):
            print(f"[semgrep:{config}] error: {err.get('message', err)}")

        for res in output.get("results", []):
            line = res["start"]["line"]
            rule = canonical_rule(res) or res["check_id"]
            location = (_enclosing_function(source_path, line)
                        or f"{Path(res['path']).name}:{line}")
            sr = ScanResult(
                rule=rule,
                location=location,
                tool="semgrep",
                severity=res["extra"].get("severity", "unknown").lower(),
                confidence=res["extra"].get("metadata", {}).get("confidence", ""),
                raw=f"[{config}] {res['check_id']}: "
                    f"{res['extra'].get('message', '').strip()}",
            )
            results.setdefault(sr.key(), sr)

    return list(results.values())


def run_llm_review(
    source_text,
    seed: int | None = 0,
    temperature: float = 0,
    prompt_version: str = "v2",
    dropped: list[str] | None = None,
) -> list[ScanResult]:
    """Run one LLM review. ``prompt_version`` selects the prompt:

    - ``"v1"``: the original prompt (kept so the v1 results stay reproducible).
    - ``"v2"``: v1 plus an explicit security-only scope rule, added AFTER seeing
      v1 report non-security findings (missing type hints). Report both.

    Lines of the answer that are not findings are appended to ``dropped``.
    """
    builders = {"v1": _build_prompt_v1, "v2": _build_prompt}
    if prompt_version not in builders:
        raise ValueError(f"unknown prompt_version {prompt_version!r}; use 'v1' or 'v2'")
    llm = LLM(backend="ollama", model="qwen2.5:3b", seed=seed, temperature=temperature)
    raw = llm.complete(builders[prompt_version](source_text)).text
    return parse_llm_review(raw, dropped)


def _build_prompt_v1(source_text: str) -> str:
    instructions = (
        "You are a security code reviewer. Review the Python source code below "
        "and report every security vulnerability you find.\n\n"
        "Report each vulnerability on its own line, in EXACTLY this format:\n"
        "[SEVERITY] <vulnerability type> in <function name>: <one-sentence reason>\n\n"
        "where SEVERITY is HIGH, MEDIUM, or LOW, and <function name> is the "
        "function the vulnerability occurs in, written exactly as it appears in "
        "the code.\n\n"
        "Example of the format (not a real finding):\n"
        "[HIGH] Some Vulnerability in some_function: brief explanation of the risk.\n\n"
        "Output only these lines and nothing else. "
        "If you find no vulnerabilities, output exactly: NONE\n"
    )
    return f"{instructions}\n```python\n{source_text}\n```\n"


def _build_prompt(source_text: str) -> str:
    """Prompt v2: v1 + a security-only scope rule (generic; names no finding)."""
    instructions = (
        "You are a security code reviewer. Review the Python source code below "
        "and report every security vulnerability you find.\n\n"
        "Report each vulnerability on its own line, in EXACTLY this format:\n"
        "[SEVERITY] <vulnerability type> in <function name>: <one-sentence reason>\n\n"
        "where SEVERITY is HIGH, MEDIUM, or LOW, and <function name> is the "
        "function the vulnerability occurs in, written exactly as it appears in "
        "the code.\n\n"
        "Example of the format (not a real finding):\n"
        "[HIGH] Some Vulnerability in some_function: brief explanation of the risk.\n\n"
        "Output only these lines and nothing else. \n\n"
        "Report only security vulnerabilities (OWASP Top 10 / CWE classes). Do not report code style, typing, naming, or other code-quality issues.\n\n"
        "If you find no vulnerabilities, output exactly: NONE\n"
    )
    return f"{instructions}\n```python\n{source_text}\n```\n"


# Prose vulnerability name -> canonical rule. Canonical names match
# ground_truth.json; the extra classes exist so that a hallucinated finding is
# still *recorded* (and scored as a false positive) instead of silently dropped.
RULE_ALIASES = {
    # sqli
    "sql injection": "sqli",
    "sql-injection": "sqli",
    "sqli": "sqli",
    # xss
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "xss": "xss",
    # cmdi
    "os command injection": "cmdi",
    "command injection": "cmdi",
    "shell injection": "cmdi",
    # broken access control (ground truth: NOT present -> any hit is a hallucination)
    "broken access control": "broken-access-control",
    "access control": "broken-access-control",
    "insecure direct object reference": "broken-access-control",
    "idor": "broken-access-control",
    "missing authorization": "broken-access-control",
    "authorization bypass": "broken-access-control",
    "privilege escalation": "broken-access-control",
    # other classes a model commonly claims; none are in the ground truth
    "authentication": "auth-failure",
    "hardcoded": "hardcoded-secret",
    "hard-coded": "hardcoded-secret",
    "information disclosure": "info-disclosure",
    "information leak": "info-disclosure",
    "sensitive data exposure": "info-disclosure",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "path traversal": "path-traversal",
    "directory traversal": "path-traversal",
    "denial of service": "dos",
    "code injection": "code-injection",
    "remote code execution": "code-injection",
    "security misconfiguration": "security-misconfiguration",
}

# A "type" that names no vulnerability class. When the model writes one of these
# (or just repeats the function name, e.g. "LOW do_ping in do_ping: ... command
# injection ..."), the class it is claiming is stated in the reason instead.
_GENERIC_TYPES = {
    "injection", "vulnerability", "security vulnerability", "security issue",
    "security risk", "issue", "code review", "security",
}

_SEVERITIES = ("critical", "high", "medium", "low", "info")

# The format the prompt asks for:  [SEVERITY] <type> in <function>: <reason>
# Tolerates what small models actually emit: a missing "[" (seen in our runs as
# "LOW] XSS in ..."), list markers / bold, backticks, "the function", "foo()",
# dotted names (Handler.do_GET), and "-" instead of ":" before the reason.
_FINDING_RE = re.compile(
    r"""^\s*(?:[-*•]|\d+[.)])?\s*\**\s*
        \[?\s*(?P<sev>critical|high|medium|low|info)\s*\]?\**\s*[:\-–]?\s*
        (?P<type>.+?)\s+in\s+(?:the\s+)?(?:function\s+|method\s+)?
        `?(?P<func>[A-Za-z_][\w.]*)(?:\(\))?`?(?:\s+function)?\s*
        [:\-–]\s*(?P<reason>.*)$""",
    re.IGNORECASE | re.VERBOSE,
)
_NONE_RE = re.compile(r"^\s*\[?\s*none\s*\]?\s*\.?\s*$", re.IGNORECASE)


def _alias_in(text: str) -> str | None:
    """Canonical rule of the alias that appears EARLIEST in `text` (the model's
    primary claim); on a tie, the longer alias wins ("reflected xss" > "xss")."""
    low = text.lower()
    best = None  # (position, -len(alias), canon)
    for alias, canon in RULE_ALIASES.items():
        m = re.search(rf"(?<![a-z]){re.escape(alias)}(?![a-z])", low)
        if m and (best is None or (m.start(), -len(alias)) < best[:2]):
            best = (m.start(), -len(alias), canon)
    return best[2] if best else None


def _canonical_type(type_text: str, func: str = "", reason: str = "") -> tuple[str, str]:
    """Map the model's vulnerability name to a canonical rule.

    Returns (rule, source) where source says which part of the line decided it:
      - "type":   the <vulnerability type> field names a known class (normal case).
      - "reason": the type field is generic ("Injection") or just repeats the
                  function name, so the class is read from the reason instead.
                  The reason is NOT consulted when the type names a class, so a
                  reason mentioning a second bug cannot change the rule.
      - "slug":   an unknown class, kept verbatim so it still counts as an FP.
    """
    # Drop bracketed tags the model copies from the prompt: "[SEVERITY]", "[LOW]".
    t = re.sub(r"\[[^\]]*\]", " ", type_text).strip().lower()
    rule = _alias_in(t)
    if rule:
        return rule, "type"
    if t in _GENERIC_TYPES or t == func.lower() or not t:
        rule = _alias_in(reason)
        if rule:
            return rule, "reason"
    slug = re.sub(r"[^a-z0-9]+", "-", t).strip("-")
    return slug or "unknown", "slug"


def parse_llm_review(raw: str, dropped: list[str] | None = None) -> list[ScanResult]:
    """Parse a model's free-text vulnerability review into ScanResults.

    Parse FAITHFULLY — including dubious claims (Broken Access Control, a finding
    on ``do_reflect_safe``, a class that is not in the ground truth). Whether a
    finding is real is decided by scoring against the ground truth, not here.

    Strategy, per line:
      1. Structured: the ``[SEVERITY] <type> in <function>: <reason>`` format.
         Any function name is accepted (not only ``do_*``), so a claim about
         ``make_db`` or ``Handler._form`` is scored rather than lost. The rule
         comes from the type field (see ``_canonical_type`` for when the reason
         is used instead).
      2. Fallback for prose lines: a known alias plus a location — a ``do_*``
         name, or a backticked name followed by "function"/"method".
      3. Otherwise the line is not a finding. ``NONE`` is skipped; every other
         non-empty line is appended to ``dropped`` (if given) so the caller can
         check that nothing was lost. A ``NONE`` that follows real findings is
         also recorded there: it is a self-contradicting answer worth reporting.

    How each rule was decided is kept in ``ScanResult.confidence`` as
    ``model:type`` / ``model:reason`` / ``model:slug`` / ``model:prose``, so a
    reader can audit every non-literal mapping.

    One ScanResult per (rule, location) per review; repeats are collapsed.
    """
    out: list[ScanResult] = []
    seen: set[tuple] = set()

    def emit(rule: str, func: str, sev: str, line: str, how: str) -> None:
        sr = ScanResult(
            rule=rule,
            location=func.split(".")[-1],  # Handler.do_GET -> do_GET
            tool="llm",
            severity=sev,
            confidence=f"model:{how}",
            raw=line.strip(),
        )
        if sr.key() not in seen:
            seen.add(sr.key())
            out.append(sr)

    for line in raw.splitlines():
        if not line.strip():
            continue

        if _NONE_RE.match(line):
            if out and dropped is not None:
                dropped.append(f"{line.strip()}  <- NONE after {len(out)} finding(s)")
            continue

        m = _FINDING_RE.match(line)
        if m:
            rule, how = _canonical_type(m["type"], m["func"], m["reason"])
            emit(rule, m["func"], m["sev"].lower(), line, how)
            continue

        # Fallback: free prose that still names a known class and a location.
        low = line.lower()
        loc_m = (re.search(r"\b(do_\w+)", line)
                 or re.search(r"`([A-Za-z_][\w.]*)`\s+(?:function|method)", line))
        rule = _alias_in(line)
        if rule and loc_m:
            sev_m = re.search(rf"\b({'|'.join(_SEVERITIES)})\b", low)
            emit(rule, loc_m.group(1), sev_m.group(1) if sev_m else "unknown",
                 line, "prose")
            continue

        if dropped is not None:
            dropped.append(line.strip())

    return out


CWE_TO_RULE = {"89": "sqli", "79": "xss", "78": "cmdi"}


def canonical_rule(result) -> str | None:
    cwes = result["extra"].get("metadata", {}).get("cwe", [])

    for c in cwes:
        num = "".join(ch for ch in c.split(":")[0] if ch.isdigit())
        if num in CWE_TO_RULE:
            return CWE_TO_RULE[num]

    return None
