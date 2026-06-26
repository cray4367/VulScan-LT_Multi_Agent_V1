"""
CLI entry point for the vulnerability analysis pipeline.

Two modes:
  - basic: Evaluate a single model with different prompt strategies
  - multi-agent: Run the Discovery -> Skeptic -> Attack Chain pipeline

Usage examples:
  python main.py --mode basic --models groq-gpt-oss-20b --prompts baseline
  python main.py --mode multi-agent --func_file sample.c
  python main.py --scan-dir /path/to/code
"""

import argparse
import json
import os
import time

from data.dir_scanner import scan_directory
from eval.metrics import build_summary_table, compute_metrics
from eval.parser import parse_response
from models.registry import get_model, MODEL_REGISTRY
from prompts.templates import build_prompt, TEMPLATES
from tqdm import tqdm


def run_evaluation(model_key, prompt_type, data, output_dir, verbose=False, temperature=0.0):
    """
    Run a single model+prompt evaluation on a dataset.

    Args:
        model_key: Key from MODEL_REGISTRY (e.g. "groq-gpt-oss-20b")
        prompt_type: Key from TEMPLATES (e.g. "baseline", "cot")
        data: List of dicts with "func" and "cwe_id"
        output_dir: Directory to save results
        verbose: Print detailed output
        temperature: Model temperature

    Returns:
        Dictionary of metrics
    """
    # get_model now returns a generate function, not an object
    generate_fn = get_model(model_key, temperature=temperature)
    run_label = f"{model_key}_{prompt_type}"
    results = []

    for i, item in enumerate(tqdm(data, desc=run_label, unit="sample")):
        func = item["func"]
        true_cwe = item.get("cwe_id", "")

        prompt = build_prompt(prompt_type, func)

        if verbose:
            print(f"\n{'='*60}\n[Sample {i+1}/{len(data)}] True CWE: {true_cwe}")
            print(f"--- Prompt Sent ---\n{prompt}\n" + "-"*19)

        # Call the model (generate_fn is a function, not an object)
        start = time.time()
        response = generate_fn(prompt)
        latency = time.time() - start

        if verbose:
            print(f"--- Raw Response ({latency:.2f}s) ---\n{response}\n" + "-"*19)

        predicted_vulnerable, predicted_cwe = parse_response(response)

        if verbose:
            if predicted_cwe is None and not predicted_vulnerable:
                print("=> Not vulnerable or PARSE FAILED")
            elif predicted_cwe is None:
                print("=> Vulnerable (true) but CWE PARSE FAILED")
            else:
                is_correct = (predicted_cwe.lower() == true_cwe.lower())
                print(f"=> Predicted: vulnerable={predicted_vulnerable}, CWE={predicted_cwe} " +
                      ("(Correct)" if is_correct else "(Incorrect)"))

        results.append({
            "index": i,
            "func_preview": func[:100],
            "true_cwe": true_cwe,
            "predicted_vulnerable": predicted_vulnerable,
            "predicted_cwe": predicted_cwe or "",
            "raw_response": response,
            "latency": latency,
            "parse_failed": predicted_cwe is None and not predicted_vulnerable,
        })

    import pandas as pd
    df = pd.DataFrame(results)

    os.makedirs(output_dir, exist_ok=True)
    per_sample_path = os.path.join(output_dir, f"{run_label}_per_sample.csv")
    df.to_csv(per_sample_path, index=False)

    metrics = compute_metrics(df, output_dir, run_label)
    metrics["model"] = model_key
    metrics["prompt_type"] = prompt_type

    print(
        f"[{run_label}] CWE Top-1 Acc: {metrics['cwe_top1_accuracy']:.3f} | "
        f"F1 Weighted: {metrics.get('f1_weighted', 0):.3f} | "
        f"Parse Failed: {metrics['parse_failed_rate']:.3f} | "
        f"Avg Latency: {metrics['avg_latency']:.2f}s"
    )

    return metrics


def _run_multi_agent_file(args):
    """Run the multi-agent pipeline on a single file."""
    from agents.pipeline import run_multi_agent_pipeline
    from agents.models import report_summary

    with open(args.func_file) as f:
        code = f.read()
    print(f"Loaded code from {args.func_file} ({len(code)} chars)")
    print(f"Mode: multi-agent")
    print(f"  Discovery model:    {args.discovery_model}")
    print(f"  Skeptic model:      {args.skeptic_model}")
    print(f"  Attack Chain model: {args.chain_model}")
    print()

    report = run_multi_agent_pipeline(
        code,
        discovery_model_key=args.discovery_model,
        skeptic_model_key=args.skeptic_model,
        chain_model_key=args.chain_model,
        verbose=args.verbose,
    )

    # Print human-readable summary
    print(report_summary(report))

    # Save JSON report
    os.makedirs(args.output_dir, exist_ok=True)
    report_path = os.path.join(args.output_dir, "multi_agent_report.json")
    with open(report_path, "w") as f:
        from agents.models import report_to_json
        f.write(report_to_json(report))
    print(f"\nJSON report saved to {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Analysis Pipeline")
    parser.add_argument(
        "--mode", choices=["basic", "multi-agent"], default="basic",
        help="Pipeline mode: 'basic' (single model) or 'multi-agent' (3-agent pipeline)",
    )
    parser.add_argument(
        "--models", nargs="+", default=None,
        help="[basic mode] Model keys (e.g. groq-gpt-oss-20b). Default: all",
    )
    parser.add_argument(
        "--prompts", nargs="+", default=None,
        help="[basic mode] Prompt types (e.g. baseline cot taxonomy). Default: all",
    )
    parser.add_argument(
        "--output_dir", type=str, default="results",
        help="Output directory for results",
    )
    parser.add_argument("--verbose", action="store_true", help="Print detailed debug output")
    parser.add_argument("--temperature", type=float, default=0.0, help="Model temperature")
    parser.add_argument(
        "--func_file", type=str, default=None,
        help="Path to a file containing code to analyze (skips dataset)",
    )
    parser.add_argument(
        "--scan-dir", type=str, default=None,
        help="Scan a directory of code files and analyze each one",
    )
    # Multi-agent specific args
    parser.add_argument(
        "--discovery-model", type=str, default="auto-gpt-oss-20b",
        help="[multi-agent] Model for Discovery Agent",
    )
    parser.add_argument(
        "--skeptic-model", type=str, default="auto-gpt-oss-20b",
        help="[multi-agent] Model for Skeptic Agent",
    )
    parser.add_argument(
        "--chain-model", type=str, default="auto-gpt-oss-120b",
        help="[multi-agent] Model for Attack Chain Agent",
    )
    args = parser.parse_args()

    # ============================================================
    # Directory Scan mode
    # ============================================================
    if args.scan_dir:
        print(f"Scanning directory: {args.scan_dir}")
        files = scan_directory(args.scan_dir)
        print(f"Found {len(files)} code files\n")

        models = args.models or list(MODEL_REGISTRY.keys())
        prompt_types = args.prompts or list(TEMPLATES.keys())
        results = []

        for sf in tqdm(files, desc="Scanning files", unit="file"):
            for model_key in models:
                for prompt_type in prompt_types:
                    generate_fn = get_model(model_key, temperature=args.temperature)
                    prompt = build_prompt(prompt_type, sf["content"])
                    # generate_fn is a function, call it directly
                    response = generate_fn(prompt)
                    vulnerable, cwe = parse_response(response)
                    results.append({
                        "File": sf["rel_path"],
                        "Model": model_key,
                        "Prompt": prompt_type,
                        "Vulnerable": "Yes" if vulnerable else "No",
                        "Predicted CWE": cwe or "N/A",
                    })

        import pandas as pd
        df = pd.DataFrame(results)
        print(f"\n{'=' * 60}")
        print("Directory Scan Results:")
        print(df.to_string(index=False))
        out_path = os.path.join(args.output_dir, "directory_scan_results.csv")
        os.makedirs(args.output_dir, exist_ok=True)
        df.to_csv(out_path, index=False)
        print(f"\nResults saved to {out_path}")
        return

    # ============================================================
    # Multi-agent mode
    # ============================================================
    if args.mode == "multi-agent":
        if not args.func_file:
            print("Error: --func_file is required in multi-agent mode")
            return
        _run_multi_agent_file(args)
        return

    # ============================================================
    # Basic mode
    # ============================================================
    models = args.models or list(MODEL_REGISTRY.keys())
    prompt_types = args.prompts or list(TEMPLATES.keys())

    if not args.func_file:
        print("Error: --func_file is required in basic mode")
        return

    with open(args.func_file) as f:
        code = f.read()
    print(f"Loaded code from {args.func_file} ({len(code)} chars)\n")
    for model_key in models:
        for prompt_type in prompt_types:
            print(f"Running {model_key} + {prompt_type}...")
            generate_fn = get_model(model_key, temperature=args.temperature)
            prompt = build_prompt(prompt_type, code)
            if args.verbose:
                print(f"\n--- Prompt ---\n{prompt}\n")
            # generate_fn is a function, call it directly
            response = generate_fn(prompt)
            vulnerable, cwe = parse_response(response)
            print(f"  Result: vulnerable={vulnerable}, CWE={cwe or 'N/A'}")
            if args.verbose:
                print(f"  Raw: {response[:500]}")
            print()


if __name__ == "__main__":
    main()
