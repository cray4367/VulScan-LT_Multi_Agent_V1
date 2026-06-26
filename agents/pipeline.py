"""
Multi-agent pipeline - runs three agents in sequence:
1. Discovery Agent - finds all potential vulnerabilities
2. Skeptic Agent - validates each finding (tries to disprove)
3. Attack Chain Agent - links findings into exploit chains
"""

import time

from agents.attack_chain import run_attack_chain
from agents.discovery import run_discovery
from agents.models import make_report
from agents.skeptic import run_skeptic
from models.registry import get_model


def run_multi_agent_pipeline(
    code,
    discovery_model_key="auto-gpt-oss-20b",
    skeptic_model_key="auto-gpt-oss-20b",
    chain_model_key="auto-gpt-oss-120b",
    discovery_temperature=0.3,
    skeptic_temperature=0.0,
    chain_temperature=0.0,
    language="",
    verbose=False,
    on_step=None,
):

    discovery_generate = get_model(discovery_model_key, temperature=discovery_temperature)
    skeptic_generate = get_model(skeptic_model_key, temperature=skeptic_temperature)
    chain_generate = get_model(chain_model_key, temperature=chain_temperature)

    report = make_report()

    # Helper for progress callbacks
    def notify(step, detail):
        if on_step is not None:
            on_step(step, detail)

    # ========================
    # Step 1: Discovery Agent
    # ========================
    notify("discovery", "Running Discovery Agent...")
    t0 = time.time()
    all_findings = run_discovery(discovery_generate, code, verbose=verbose)
    report["all_findings"] = all_findings
    notify("discovery_done", f"Found {len(all_findings)} potential finding(s) in {time.time() - t0:.1f}s")

    # If nothing found, we're done
    if not all_findings:
        report["overall_severity"] = "None"
        notify("complete", "No findings - code appears clean.")
        return report

    # ========================
    # Step 2: Skeptic Agent
    # ========================
    notify("skeptic", f"Running Skeptic Agent on {len(all_findings)} finding(s)...")
    t0 = time.time()
    confirmed = []
    false_positives = []

    for finding in all_findings:
        verdict = run_skeptic(skeptic_generate, finding, code, verbose=verbose)
        if verdict["status"] == "confirmed":
            confirmed.append(finding)
        elif verdict["status"] == "false_positive":
            false_positives.append(verdict)
        else:
            # "uncertain" findings are kept as confirmed to be safe
            confirmed.append(finding)

    report["confirmed_findings"] = confirmed
    report["false_positives"] = false_positives
    notify("skeptic_done",
           f"{len(confirmed)} confirmed, {len(false_positives)} false positive(s) in {time.time() - t0:.1f}s")

    # If nothing confirmed, we're done
    if not confirmed:
        report["overall_severity"] = "None"
        notify("complete", "All findings disproved by Skeptic.")
        return report

    # ================================
    # Step 3: Attack Chain Agent
    # ================================
    notify("attack_chain",
           f"Running Attack Chain Agent on {len(confirmed)} confirmed finding(s)...")
    t0 = time.time()
    chains, overall_severity = run_attack_chain(chain_generate, confirmed, code, verbose=verbose)
    report["attack_chains"] = chains
    report["overall_severity"] = overall_severity

    # Collect exploit narratives
    report["exploit_explanations"] = [
        chain["exploit_narrative"]
        for chain in chains
        if chain["exploit_narrative"]
    ]

    notify("attack_chain_done",
           f"Built {len(chains)} attack chain(s), overall severity: {overall_severity} "
           f"in {time.time() - t0:.1f}s")

    notify("complete", "Pipeline complete.")
    return report
