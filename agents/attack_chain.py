"""
Attack Chain Agent - links confirmed vulnerabilities into exploit chains.

Uses a larger model (120B) for deeper reasoning about how individual
vulnerabilities can be combined into multi-step attack paths.
"""

import json
import re

from agents.models import make_attack_chain
from prompts.agent_prompts import ATTACK_CHAIN_PROMPT


def _parse_chain_json(text):
    """Extract the attack chain JSON object from the LLM response."""
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

    # Strategy 2: Find the outermost { ... }
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            data = json.loads(text[start: end + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    return {}


def _chain_from_dict(d):
    """Convert a raw dictionary from the model into a proper attack chain dict."""
    return make_attack_chain(
        chain_steps=[str(s) for s in d.get("chain", [])],
        severity=str(d.get("severity", "Medium")),
        preconditions=[str(p) for p in d.get("preconditions", [])],
        business_impact=str(d.get("business_impact", "")),
        exploit_narrative=str(d.get("exploit_narrative", "")),
    )


def run_attack_chain(generate_fn, confirmed_findings, code, verbose=False):

    findings_json = json.dumps(confirmed_findings, indent=2)

    prompt = ATTACK_CHAIN_PROMPT.format(
        findings_json=findings_json,
        code=code,
    )

    if verbose:
        print(f"\n[Attack Chain Agent] Analyzing {len(confirmed_findings)} confirmed finding(s)...")

    response = generate_fn(prompt)

    if verbose:
        print(f"[Attack Chain Agent] Raw response ({len(response)} chars):")
        print(response[:500])
        print()

    parsed = _parse_chain_json(response)

    chains = []
    raw_chains = parsed.get("attack_chains", [])
    if isinstance(raw_chains, list):
        for item in raw_chains:
            if isinstance(item, dict):
                chains.append(_chain_from_dict(item))

    overall_severity = str(parsed.get("overall_severity", "Medium"))

    # If no chains were parsed but we have confirmed findings, create
    # simple single-step chains as a fallback
    if not chains and confirmed_findings:
        for f in confirmed_findings:
            chains.append(make_attack_chain(
                chain_steps=[f["finding_type"]],
                severity="Medium",
                preconditions=[],
                business_impact=f"Potential exploitation of {f['finding_type']}",
                exploit_narrative=f["evidence"],
            ))
        overall_severity = "Medium"

    if verbose:
        print(f"[Attack Chain Agent] Built {len(chains)} chain(s), overall severity: {overall_severity}")

    return chains, overall_severity
