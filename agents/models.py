


def make_finding(finding_type, evidence, location, cwe_candidate):

    return {
        "finding_type": finding_type,
        "evidence": evidence,
        "location": location,
        "cwe_candidate": cwe_candidate,
    }


def make_skeptic_verdict(finding, status, reasoning, confidence):

    return {
        "finding": finding,
        "status": status,
        "reasoning": reasoning,
        "confidence": confidence,
    }


def make_attack_chain(chain_steps, severity, preconditions, business_impact, exploit_narrative):

    return {
        "chain": chain_steps,
        "severity": severity,
        "preconditions": preconditions,
        "business_impact": business_impact,
        "exploit_narrative": exploit_narrative,
    }


def make_report(all_findings=None, confirmed_findings=None, false_positives=None,
                attack_chains=None, overall_severity="None", exploit_explanations=None):

    return {
        "all_findings": all_findings or [],
        "confirmed_findings": confirmed_findings or [],
        "false_positives": false_positives or [],
        "attack_chains": attack_chains or [],
        "overall_severity": overall_severity,
        "exploit_explanations": exploit_explanations or [],
    }


def report_to_dict(report):
    """Convert a report dict to a serializable form (for JSON output)."""
    return {
        "findings": report["all_findings"],
        "confirmed": report["confirmed_findings"],
        "false_positives": report["false_positives"],
        "attack_paths": report["attack_chains"],
        "severity": report["overall_severity"],
        "exploit_explanations": report["exploit_explanations"],
    }


def report_to_json(report, indent=2):
    """Convert a report dict to a JSON string."""
    import json
    return json.dumps(report_to_dict(report), indent=indent)


def report_summary(report):
    """
    Create a human-readable summary of the report.

    Returns a string that can be printed to the console.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("MULTI-AGENT VULNERABILITY REPORT")
    lines.append("=" * 60)

    lines.append(f"\nOverall Severity: {report['overall_severity']}")
    lines.append(f"Total Findings:   {len(report['all_findings'])}")
    lines.append(f"Confirmed:        {len(report['confirmed_findings'])}")
    lines.append(f"False Positives:  {len(report['false_positives'])}")
    lines.append(f"Attack Chains:    {len(report['attack_chains'])}")

    if report["confirmed_findings"]:
        lines.append("\n-- Confirmed Findings --")
        for i, f in enumerate(report["confirmed_findings"], 1):
            lines.append(
                f"  {i}. [{f['cwe_candidate']}] {f['finding_type']}"
                f"\n     Evidence: {f['evidence']}"
                f"\n     Location: {f['location']}"
            )

    if report["false_positives"]:
        lines.append("\n-- False Positives (filtered) --")
        for v in report["false_positives"]:
            lines.append(
                f"  [x] {v['finding']['finding_type']} ({v['finding']['cwe_candidate']})"
                f"\n    Reason: {v['reasoning']}"
            )

    if report["attack_chains"]:
        lines.append("\n-- Attack Chains --")
        for i, chain in enumerate(report["attack_chains"], 1):
            lines.append(f"  Chain {i} -- Severity: {chain['severity']}")
            lines.append(f"    Steps: {' -> '.join(chain['chain'])}")
            if chain["preconditions"]:
                lines.append(f"    Preconditions: {', '.join(chain['preconditions'])}")
            lines.append(f"    Business Impact: {chain['business_impact']}")

    if report["exploit_explanations"]:
        lines.append("\n-- Exploit Explanations --")
        for i, expl in enumerate(report["exploit_explanations"], 1):
            lines.append(f"  {i}. {expl[:200]}...")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)
