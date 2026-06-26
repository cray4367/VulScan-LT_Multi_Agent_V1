"""
Skeptic Agent - tries to disprove each finding from the Discovery Agent.

Goal: Reduce false positives (high precision).
Each finding is checked against category-specific security patterns.
"""

import json
import re

from agents.models import make_skeptic_verdict
from prompts.agent_prompts import SKEPTIC_PROMPT


def _parse_verdict_json(text):
    """Extract a verdict JSON object from the Skeptic's response."""
    text = text.strip()

    # Remove markdown ```json fences
    cleaned = re.sub(r"^```(?:json)?\s*", "", text)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    # Strategy 1: Try to parse the whole thing as JSON
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Strategy 2: Find the first { ... } in the text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(text[start: end + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    # Fallback: treat as uncertain
    return {"status": "uncertain", "reasoning": "Could not parse Skeptic response", "confidence": 0.5}


def run_skeptic(generate_fn, finding, code, verbose=False):

    prompt = SKEPTIC_PROMPT.format(
        finding_type=finding["finding_type"],
        evidence=finding["evidence"],
        location=finding["location"],
        cwe_candidate=finding["cwe_candidate"],
        code=code,
    )

    if verbose:
        print(f"\n[Skeptic Agent] Evaluating: {finding['finding_type']} ({finding['cwe_candidate']})...")

    response = generate_fn(prompt)

    if verbose:
        print(f"[Skeptic Agent] Raw response ({len(response)} chars):")
        print(response[:400])
        print()

    verdict_data = _parse_verdict_json(response)

    status = str(verdict_data.get("status", "uncertain")).lower()
    if status not in ("confirmed", "false_positive", "uncertain"):
        status = "uncertain"

    reasoning = str(verdict_data.get("reasoning", ""))

    try:
        confidence = float(verdict_data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    verdict = make_skeptic_verdict(
        finding=finding,
        status=status,
        reasoning=reasoning,
        confidence=confidence,
    )

    if verbose:
        print(f"[Skeptic Agent] Verdict: {verdict['status']} (confidence={verdict['confidence']:.2f})")

    return verdict
