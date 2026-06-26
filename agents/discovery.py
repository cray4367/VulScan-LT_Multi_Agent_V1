"""
Discovery Agent - scans code for ALL potential vulnerabilities.

Goal: Find as many potential issues as possible (high recall).
It's better to flag something harmless than to miss a real vulnerability.
"""

import json
import re

from agents.models import make_finding
from prompts.agent_prompts import DISCOVERY_PROMPT


def _parse_findings_json(text):
    """
    Try to extract a list of finding dictionaries from the model's response.

    The model might wrap the JSON in markdown ``` fences, so we try
    multiple strategies to extract it.
    """
    text = text.strip()

    # Strategy 1: Remove markdown ```json fences
    cleaned = re.sub(r"^```(?:json)?\s*", "", text)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    # Try to parse the cleaned text as JSON
    try:
        data = json.loads(cleaned)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    # Strategy 2: Find the first [ ... ] in the text
    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(text[start: end + 1])
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

    return []


def _finding_from_dict(d):
    """Convert a raw dictionary from the model into a proper finding dict."""
    return make_finding(
        finding_type=str(d.get("finding_type", d.get("type", "Unknown"))),
        evidence=str(d.get("evidence", "")),
        location=str(d.get("location", "")),
        cwe_candidate=str(d.get("cwe_candidate", d.get("cwe", ""))),
    )


def run_discovery(generate_fn, code, verbose=False):
    """
    Run the Discovery Agent on a code snippet.

    Args:
        generate_fn: A function that takes a prompt and returns a response
        code: The source code to analyze
        verbose: If True, print debug information

    Returns:
        A list of finding dicts (not yet validated by the Skeptic)
    """
    prompt = DISCOVERY_PROMPT.format(code=code)

    if verbose:
        print("\n[Discovery Agent] Sending prompt...")

    response = generate_fn(prompt)

    if verbose:
        print(f"[Discovery Agent] Raw response ({len(response)} chars):")
        print(response[:500])
        print()

    raw_findings = _parse_findings_json(response)
    findings = [_finding_from_dict(d) for d in raw_findings if isinstance(d, dict)]

    if verbose:
        print(f"[Discovery Agent] Extracted {len(findings)} finding(s)")

    return findings
