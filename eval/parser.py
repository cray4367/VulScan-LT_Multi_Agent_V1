import json
import re
from typing import Optional


def normalise_cwe(cwe_str: Optional[str]) -> Optional[str]:
    if not cwe_str:
        return None
    cwe_str = cwe_str.strip().upper()
    m = re.search(r"CWE[-_]?(\d+)", cwe_str)
    if m:
        return f"CWE-{int(m.group(1))}"
    if cwe_str.isdigit():
        return f"CWE-{int(cwe_str)}"
    return None


def _try_json_parse(text: str) -> Optional[tuple[bool, Optional[str]]]:
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            vulnerable = data.get("vulnerable", False)
            if isinstance(vulnerable, str):
                vulnerable = vulnerable.lower() in ("true", "yes", "1")
            cwe = None
            for key in ("cwe_id", "cwe", "CWE", "CWE_ID"):
                val = data.get(key)
                if val:
                    cwe = normalise_cwe(str(val))
                    break
            return (bool(vulnerable), cwe)
    except json.JSONDecodeError:
        pass
    return None


def _try_json_substring(text: str) -> Optional[tuple[bool, Optional[str]]]:
    brace_stack: list[int] = []
    for i, ch in enumerate(text):
        if ch == "{":
            brace_stack.append(i)
        elif ch == "}":
            if brace_stack:
                start = brace_stack.pop()
                candidate = text[start : i + 1]
                try:
                    data = json.loads(candidate)
                    if isinstance(data, dict):
                        vulnerable = data.get("vulnerable", False)
                        if isinstance(vulnerable, str):
                            vulnerable = vulnerable.lower() in ("true", "yes", "1")
                        cwe = None
                        for key in ("cwe_id", "cwe", "CWE", "CWE_ID"):
                            val = data.get(key)
                            if val:
                                cwe = normalise_cwe(str(val))
                                break
                        return (bool(vulnerable), cwe)
                except json.JSONDecodeError:
                    pass
    return None


def _try_cwe_pattern(text: str) -> Optional[tuple[bool, Optional[str]]]:
    m = re.search(r"CWE[-_]?(\d+)", text, re.IGNORECASE)
    if m:
        return (True, f"CWE-{int(m.group(1))}")
    return None


def parse_response(response: str) -> tuple[bool, Optional[str]]:
    strategies = [_try_json_parse, _try_json_substring, _try_cwe_pattern]
    for strategy in strategies:
        result = strategy(response)
        if result is not None:
            return result
    return (False, None)
