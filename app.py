"""
Streamlit frontend for the vulnerability analysis pipeline.

Provides a web UI with two modes:
- Basic (Single Model): Test different models and prompt strategies
- Multi-Agent Pipeline: Run the 3-agent pipeline for in-depth analysis
"""

import streamlit as st
import pandas as pd
import os
import time
import json
import plotly.express as px

from models.registry import MODEL_REGISTRY, get_model
from prompts.templates import TEMPLATES, build_prompt
from data.dir_scanner import scan_directory
from eval.parser import parse_response
from main import run_evaluation

from agents.pipeline import run_multi_agent_pipeline
from agents.models import report_to_dict, report_to_json, report_summary

st.set_page_config(page_title="IIT Palakkad - Vulnerability Analysis Pipeline", layout="wide")

# Session state for persisting data across reruns
for key in ("ask_messages", "scanned_files", "selected_file_indices", "last_results_context", "scanned_dir_path"):
    if key not in st.session_state:
        st.session_state[key] = [] if key in ("ask_messages", "scanned_files", "selected_file_indices") else ""

for key in ("basic_single_results", "multi_single_report"):
    if key not in st.session_state:
        st.session_state[key] = None

# Severity colors for badges
SEVERITY_COLORS = {
    "Critical": "#dc3545",
    "High": "#fd7e14",
    "Medium": "#ffc107",
    "Low": "#28a745",
    "None": "#6c757d",
}

def severity_badge(severity):
    color = SEVERITY_COLORS.get(severity, "#6c757d")
    return (
        f'<span style="background:{color};color:#fff;padding:4px 14px;'
        f'border-radius:12px;font-weight:700;font-size:1.1rem">{severity}</span>'
    )

def _display_multi_dir_results():
    all_reports = st.session_state.multi_dir_reports
    st.markdown("## Multi-Agent Directory Scan Results")

    file_options = {r["file"]: r for r in all_reports}
    selected_file = st.selectbox("Select a file to view its report", options=list(file_options.keys()), key="multi_dir_file_sel")
    report = file_options[selected_file]["_raw"]

    col_badge, col_stats = st.columns([1, 3])
    with col_badge:
        st.markdown(
            f"<div style='text-align:center;padding:20px'>"
            f"<div style='font-size:0.9rem;color:#8b949e;margin-bottom:8px'>Overall Severity</div>"
            f"{severity_badge(report['overall_severity'])}"
            f"</div>",
            unsafe_allow_html=True,
        )
    with col_stats:
        mcol1, mcol2, mcol3, mcol4 = st.columns(4)
        mcol1.metric("Total Findings", len(report["all_findings"]))
        mcol2.metric("Confirmed", len(report["confirmed_findings"]))
        mcol3.metric("False Positives", len(report["false_positives"]))
        mcol4.metric("Attack Chains", len(report["attack_chains"]))

    with st.expander(f"Discovery Findings ({len(report['all_findings'])})", expanded=True):
        if report["all_findings"]:
            findings_data = [{
                "Type": f["finding_type"],
                "CWE": f["cwe_candidate"],
                "Location": f["location"],
                "Evidence": f["evidence"],
            } for f in report["all_findings"]]
            st.dataframe(pd.DataFrame(findings_data), use_container_width=True)
        else:
            st.info("No potential vulnerabilities discovered.")

    with st.expander("Skeptic Verdicts", expanded=True):
        verdict_rows = []
        for f in report["confirmed_findings"]:
            verdict_rows.append({
                "Status": "Confirmed",
                "Type": f["finding_type"],
                "CWE": f["cwe_candidate"],
                "Location": f["location"],
                "Reason": "-",
            })
        for v in report["false_positives"]:
            verdict_rows.append({
                "Status": "False Positive",
                "Type": v["finding"]["finding_type"],
                "CWE": v["finding"]["cwe_candidate"],
                "Location": v["finding"]["location"],
                "Reason": v["reasoning"],
            })
        if verdict_rows:
            st.dataframe(pd.DataFrame(verdict_rows), use_container_width=True)
        else:
            st.info("No findings to validate.")

    with st.expander(f"Attack Chains ({len(report['attack_chains'])})", expanded=True):
        if report["attack_chains"]:
            for i, chain in enumerate(report["attack_chains"], 1):
                st.markdown(
                    f"**Chain {i}** {severity_badge(chain['severity'])}",
                    unsafe_allow_html=True,
                )
                st.markdown(f"**Steps:** {' -> '.join(chain['chain'])}")
                if chain["preconditions"]:
                    st.markdown(f"**Preconditions:** {', '.join(chain['preconditions'])}")
                st.markdown(f"**Business Impact:** {chain['business_impact']}")
                if chain.get("exploit_narrative"):
                    st.markdown(f"**Exploit Narrative:**\n\n{chain['exploit_narrative']}")
                if i < len(report["attack_chains"]):
                    st.divider()
        else:
            st.info("No attack chains generated.")

    if report.get("exploit_explanations"):
        with st.expander("Exploit Explanations", expanded=False):
            for i, expl in enumerate(report["exploit_explanations"], 1):
                st.markdown(f"**{i}.** {expl}")

    st.download_button(
        "Download Full JSON Report",
        data=report_to_json(report),
        file_name=f"{selected_file.replace('/', '_')}_report.json",
        mime="application/json",
    )

# Custom CSS styling
st.markdown("""
    <style>
    .stApp {
        background-color: #0d1117;
        color: #e6edf3;
    }
    .app-header {
        display: flex;
        align-items: center;
        gap: 20px;
        padding: 0.5rem 0 1rem 0;
        border-bottom: 1px solid #21262d;
        margin-bottom: 1.5rem;
    }
    .app-header-text h1 {
        font-size: 1.6rem;
        font-weight: 600;
        color: #f0f6fc;
        margin: 0;
        line-height: 1.3;
    }
    .app-header-text .subtitle {
        font-size: 0.85rem;
        color: #8b949e;
        margin: 2px 0 0 0;
    }
    .app-header-text .institution {
        font-size: 0.75rem;
        color: #58a6ff;
        letter-spacing: 0.5px;
        font-weight: 500;
        text-transform: uppercase;
        margin: 0 0 4px 0;
    }
    .metric-card {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 18px 16px;
        text-align: center;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #f0f6fc;
        margin: 6px 0;
    }
    .metric-label {
        font-size: 0.8rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }
    .section-title {
        font-size: 1.1rem;
        font-weight: 600;
        color: #f0f6fc;
        margin: 1.5rem 0 0.75rem 0;
        padding-bottom: 0.4rem;
        border-bottom: 1px solid #21262d;
    }
    </style>
""", unsafe_allow_html=True)

# Header with logo
col_logo, col_title = st.columns([0.12, 0.88])
with col_logo:
    st.image("iitpkd_logo.png", width=60)
with col_title:
    st.markdown("""
        <div class="app-header-text">
            <p class="institution">Indian Institute of Technology Palakkad</p>
            <h1>Vulnerability Analysis Pipeline</h1>
            <p class="subtitle">Multi-model evaluation with single-model and multi-agent analysis modes</p>
        </div>
    """, unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.image("iitpkd_logo.png", width=50)
    st.markdown(
        "<p style='font-size:0.75rem;color:#8b949e;margin:0 0 8px 0;'>"
        "IIT Palakkad - Security Research</p>",
        unsafe_allow_html=True,
    )

    st.markdown("### Configuration")
    st.subheader("API Status")
    groq_key = os.environ.get("GROQ_API_KEY", "")
    openrouter_key = os.environ.get("OPENROUTER_API_KEY", "")
    nvidia_key = os.environ.get("NVIDIA_API_KEY", "")

    for provider, key in [("Groq", groq_key), ("OpenRouter", openrouter_key), ("NVIDIA", nvidia_key)]:
        status = "Configured" if key else "Not configured"
        color = "#3fb950" if key else "#8b949e"
        st.markdown(
            f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;'
            f'background:{color};margin-right:6px;"></span>'
            f'<span style="color:#e6edf3">{provider}</span>'
            f'<span style="color:#8b949e;font-size:0.8rem;margin-left:6px">- {status}</span>',
            unsafe_allow_html=True,
        )

    st.divider()

    mode = st.radio("Pipeline Mode", ["Basic (Single Model)", "Multi-Agent Pipeline"], index=0)
    st.divider()

    if mode == "Basic (Single Model)":
        st.subheader("Model & Prompt")
        available_models = list(MODEL_REGISTRY.keys())
        selected_models = st.multiselect("Select Models", options=available_models, default=["groq-gpt-oss-20b"])

        available_prompts = list(TEMPLATES.keys())
        selected_prompts = st.multiselect("Select Prompts", options=available_prompts, default=["baseline"])
    else:
        st.subheader("Agent Configuration")

        model_keys = list(MODEL_REGISTRY.keys())

        def default_index(key):
            try:
                return model_keys.index(key)
            except ValueError:
                return 0

        discovery_model = st.selectbox(
            "Discovery Agent (20B, high recall)",
            options=model_keys,
            index=default_index("auto-gpt-oss-20b"),
        )
        skeptic_model = st.selectbox(
            "Skeptic Agent (20B, high precision)",
            options=model_keys,
            index=default_index("auto-gpt-oss-20b"),
        )
        chain_model = st.selectbox(
            "Attack Chain Agent (120B, reasoning)",
            options=model_keys,
            index=default_index("auto-gpt-oss-120b"),
        )

# --- MAIN PANEL - INPUT ---
st.markdown('<p class="section-title">Source Input</p>', unsafe_allow_html=True)

input_source = st.radio(
    "Choose input source",
    ["Paste Code", "Upload File", "Scan Directory"],
    index=0,
    horizontal=True,
)

code_input = ""

if input_source == "Paste Code":
    code_input = st.text_area(
        "Paste source code here...",
        height=250,
        placeholder="// Paste C, C++, Java, or Python code to analyze...",
    )
elif input_source == "Upload File":
    uploaded_file = st.file_uploader(
        "Choose a code file",
        type=["c", "cpp", "cxx", "java", "py", "txt", "js", "ts", "go", "rs", "rb", "php"],
    )
    if uploaded_file is not None:
        code_input = uploaded_file.getvalue().decode("utf-8")
else:
    # Scan Directory
    dir_path = st.text_input("Directory path", placeholder="/path/to/code/directory")
    col_s1, col_s2 = st.columns([1, 3])
    with col_s1:
        scan_btn = st.button("Scan Directory", use_container_width=True, type="secondary")
    if scan_btn and dir_path:
        try:
            st.session_state.scanned_files = scan_directory(dir_path)
            st.session_state.scanned_dir_path = dir_path
        except Exception as e:
            st.error(f"Error scanning directory: {e}")
    scanned = st.session_state.scanned_files
    if scanned:
        st.success(f"Found {len(scanned)} code files - select files below to analyze")
        col_sel, col_desel, _ = st.columns([1, 1, 3])
        with col_sel:
            if st.button("Select All", use_container_width=True, key="select_all_btn"):
                for j in range(len(scanned)):
                    st.session_state[f"sf_{j}"] = True
        with col_desel:
            if st.button("Deselect All", use_container_width=True, key="deselect_all_btn"):
                for j in range(len(scanned)):
                    st.session_state[f"sf_{j}"] = False
        selected = []
        for i, f in enumerate(scanned):
            checked = st.checkbox(f"{f['rel_path']}  ({f['size']} chars)", key=f"sf_{i}")
            if checked:
                selected.append(i)
        st.session_state.selected_file_indices = selected
        if selected:
            st.info(f"{len(selected)} file(s) selected")

run_btn = st.button(
    "Run Evaluation" if mode == "Basic (Single Model)" else "Run Multi-Agent Analysis",
    use_container_width=True,
    type="primary",
)

st.divider()

# --- RESULTS ---
if run_btn:
    # --- Directory Scan ---
    if input_source == "Scan Directory":
        scanned_files = st.session_state.scanned_files
        sel_indices = st.session_state.selected_file_indices
        selected_files = [scanned_files[i] for i in sel_indices] if scanned_files and sel_indices else []
        if not selected_files:
            st.error("No files selected! Please select at least one file from the directory listing.")
            st.stop()

        if mode == "Basic (Single Model)":
            if not selected_models:
                st.error("Please select at least one model!")
                st.stop()
            if not selected_prompts:
                st.error("Please select at least one prompt!")
                st.stop()

            all_results = []
            progress_bar = st.progress(0)
            status_text = st.empty()
            total = len(selected_files) * len(selected_models) * len(selected_prompts)
            current = 0

            for sf in selected_files:
                for model_key in selected_models:
                    generate_fn = get_model(model_key, temperature=0.0)
                    for prompt_type in selected_prompts:
                        current += 1
                        status_text.text(f"[{sf['filename']}] {model_key} + {prompt_type} ... ({current}/{total})")
                        prompt = build_prompt(prompt_type, sf["content"])
                        response = generate_fn(prompt)
                        vulnerable, cwe = parse_response(response)
                        all_results.append({
                            "File": sf["rel_path"],
                            "Model": model_key,
                            "Prompt": prompt_type,
                            "Vulnerable": "Yes" if vulnerable else "No",
                            "Predicted CWE": cwe or "N/A",
                            "Raw Response": response,
                        })
                        progress_bar.progress(current / total)

            status_text.text("Evaluation complete.")
            time.sleep(0.5)
            status_text.empty()
            progress_bar.empty()

            st.markdown("## Directory Scan Results")
            results_df = pd.DataFrame(all_results)
            display_cols = ["File", "Model", "Prompt", "Vulnerable", "Predicted CWE"]
            st.dataframe(results_df[display_cols], use_container_width=True)

            with st.expander("Show Raw Responses"):
                for r in all_results:
                    st.markdown(f"**{r['File']}** - {r['Model']} + {r['Prompt']}")
                    st.code(r["Raw Response"])

            st.session_state.last_results_context = results_df.to_string()
        else:
            all_reports = []
            progress_bar = st.progress(0)
            status_text = st.empty()
            for i, sf in enumerate(selected_files):
                status_text.text(f"Analyzing {sf['filename']} ({i+1}/{len(selected_files)})...")
                report = run_multi_agent_pipeline(
                    sf["content"],
                    discovery_model_key=discovery_model,
                    skeptic_model_key=skeptic_model,
                    chain_model_key=chain_model,
                    verbose=False,
                )
                report_dict = report_to_dict(report)
                report_dict["file"] = sf["rel_path"]
                report_dict["_raw"] = report
                all_reports.append(report_dict)
                progress_bar.progress((i + 1) / len(selected_files))

            status_text.text("Analysis complete.")
            time.sleep(0.5)
            status_text.empty()
            progress_bar.empty()

            st.session_state.multi_dir_reports = all_reports
            _display_multi_dir_results()

        st.stop()

if st.session_state.get("multi_dir_reports"):
    _display_multi_dir_results()
    st.stop()

if mode == "Basic (Single Model)":
        # ========================================================
        # BASIC MODE
        # ========================================================
        if not selected_models:
            st.error("Please select at least one model!")
            st.stop()
        if not selected_prompts:
            st.error("Please select at least one prompt!")
            st.stop()

        if not code_input.strip():
            st.error("Please provide source code to analyze.")
            st.stop()

        st.markdown("### Single-File Analysis")
        with st.expander("Show Input Code", expanded=False):
            st.code(code_input, language="auto")

        if run_btn:
            progress_bar = st.progress(0)
            status_text = st.empty()

            results = []
            total_runs = len(selected_models) * len(selected_prompts)
            current_run = 0

            for model_key in selected_models:
                generate_fn = get_model(model_key, temperature=0.0)
                for prompt_type in selected_prompts:
                    current_run += 1
                    status_text.text(f"Evaluating {model_key} with {prompt_type} prompt... ({current_run}/{total_runs})")

                    prompt = build_prompt(prompt_type, code_input)
                    response = generate_fn(prompt)
                    vulnerable, cwe = parse_response(response)

                    results.append({
                        "Model": model_key,
                        "Prompt": prompt_type,
                        "Vulnerable": "Yes" if vulnerable else "No",
                        "Predicted CWE": cwe or "N/A",
                        "Raw Response": response,
                    })
                    progress_bar.progress(current_run / total_runs)

            status_text.text("Evaluation complete.")
            time.sleep(0.5)
            status_text.empty()
            progress_bar.empty()

            results_df = pd.DataFrame(results)
            st.session_state.basic_single_results = (results_df, results)
            st.session_state.last_results_context = results_df.to_string()

        if st.session_state.basic_single_results is not None:
            results_df, results = st.session_state.basic_single_results
            st.markdown("## Results")
            st.dataframe(results_df[["Model", "Prompt", "Vulnerable", "Predicted CWE"]], use_container_width=True)

            with st.expander("Show Raw Responses"):
                for r in results:
                    st.markdown(f"**{r['Model']} + {r['Prompt']}**")
                    st.code(r["Raw Response"])
else:
        # ========================================================
        # MULTI-AGENT MODE
        # ========================================================
        if not code_input.strip():
            st.error("Please provide source code to analyze.")
            st.stop()

        st.markdown("### Multi-Agent Analysis")
        with st.expander("Show Input Code", expanded=False):
            st.code(code_input, language="auto")

        if run_btn:
            status = st.status("Initializing multi-agent pipeline...", expanded=True)

            def on_step(step, detail):
                if step == "discovery":
                    status.update(label="[1/3] Discovery Agent: scanning for vulnerabilities...", state="running")
                elif step == "discovery_done":
                    status.write(f"[1/3] Discovery complete - {detail}")
                elif step == "skeptic":
                    status.update(label="[2/3] Skeptic Agent: validating findings...", state="running")
                elif step == "skeptic_done":
                    status.write(f"[2/3] Skeptic complete - {detail}")
                elif step == "attack_chain":
                    status.update(label="[3/3] Attack Chain Agent: correlating exploits...", state="running")
                elif step == "attack_chain_done":
                    status.write(f"[3/3] Attack Chain complete - {detail}")
                elif step == "complete":
                    status.update(label="Analysis complete.", state="complete")
                else:
                    status.write(f"  {detail}")

            report = run_multi_agent_pipeline(
                code_input,
                discovery_model_key=discovery_model,
                skeptic_model_key=skeptic_model,
                chain_model_key=chain_model,
                verbose=False,
                on_step=on_step,
            )

            st.session_state.multi_single_report = report

            ctx_lines = [
                f"Severity: {report['overall_severity']}",
                f"Findings: {len(report['all_findings'])}",
                f"Confirmed: {len(report['confirmed_findings'])}",
                f"False Positives: {len(report['false_positives'])}",
                f"Attack Chains: {len(report['attack_chains'])}",
            ]
            if report["all_findings"]:
                ctx_lines.append("--- Findings ---")
                for f in report["all_findings"]:
                    ctx_lines.append(f"  {f['finding_type']} | CWE: {f['cwe_candidate']} | {f['location']}")
            if report["attack_chains"]:
                ctx_lines.append("--- Attack Chains ---")
                for c in report["attack_chains"]:
                    ctx_lines.append(f"  Severity: {c['severity']} | Steps: {' -> '.join(c['chain'])}")
            st.session_state.last_results_context = "\n".join(ctx_lines)

        if st.session_state.multi_single_report is not None:
            report = st.session_state.multi_single_report

            st.markdown("---")
            st.markdown("## Vulnerability Report")

            col_badge, col_stats = st.columns([1, 3])
            with col_badge:
                st.markdown(
                    f"<div style='text-align:center;padding:20px'>"
                    f"<div style='font-size:0.9rem;color:#8b949e;margin-bottom:8px'>Overall Severity</div>"
                    f"{severity_badge(report['overall_severity'])}"
                    f"</div>",
                    unsafe_allow_html=True,
                )
            with col_stats:
                mcol1, mcol2, mcol3, mcol4 = st.columns(4)
                mcol1.metric("Total Findings", len(report["all_findings"]))
                mcol2.metric("Confirmed", len(report["confirmed_findings"]))
                mcol3.metric("False Positives", len(report["false_positives"]))
                mcol4.metric("Attack Chains", len(report["attack_chains"]))

            with st.expander(f"Discovery Findings ({len(report['all_findings'])})", expanded=True):
                if report["all_findings"]:
                    findings_data = [{
                        "Type": f["finding_type"],
                        "CWE": f["cwe_candidate"],
                        "Location": f["location"],
                        "Evidence": f["evidence"],
                    } for f in report["all_findings"]]
                    st.dataframe(pd.DataFrame(findings_data), use_container_width=True)
                else:
                    st.info("No potential vulnerabilities discovered.")

            with st.expander("Skeptic Verdicts", expanded=True):
                verdict_rows = []
                for f in report["confirmed_findings"]:
                    verdict_rows.append({
                        "Status": "Confirmed",
                        "Type": f["finding_type"],
                        "CWE": f["cwe_candidate"],
                        "Location": f["location"],
                        "Reason": "-",
                    })
                for v in report["false_positives"]:
                    verdict_rows.append({
                        "Status": "False Positive",
                        "Type": v["finding"]["finding_type"],
                        "CWE": v["finding"]["cwe_candidate"],
                        "Location": v["finding"]["location"],
                        "Reason": v["reasoning"],
                    })
                if verdict_rows:
                    st.dataframe(pd.DataFrame(verdict_rows), use_container_width=True)
                else:
                    st.info("No findings to validate.")

            with st.expander(f"Attack Chains ({len(report['attack_chains'])})", expanded=True):
                if report["attack_chains"]:
                    for i, chain in enumerate(report["attack_chains"], 1):
                        st.markdown(
                            f"**Chain {i}** {severity_badge(chain['severity'])}",
                            unsafe_allow_html=True,
                        )
                        st.markdown(f"**Steps:** {' -> '.join(chain['chain'])}")
                        if chain["preconditions"]:
                            st.markdown(f"**Preconditions:** {', '.join(chain['preconditions'])}")
                        st.markdown(f"**Business Impact:** {chain['business_impact']}")
                        if chain.get("exploit_narrative"):
                            st.markdown(f"**Exploit Narrative:**\n\n{chain['exploit_narrative']}")
                        if i < len(report["attack_chains"]):
                            st.divider()
                else:
                    st.info("No attack chains generated.")

            if report.get("exploit_explanations"):
                with st.expander("Exploit Explanations", expanded=False):
                    for i, expl in enumerate(report["exploit_explanations"], 1):
                        st.markdown(f"**{i}.** {expl}")

            st.download_button(
                "Download Full JSON Report",
                data=report_to_json(report),
                file_name="multi_agent_report.json",
                mime="application/json",
            )

# --- Ask about Results ---
if st.session_state.last_results_context:
    st.markdown("---")
    st.markdown('<p class="section-title">Ask about Results</p>', unsafe_allow_html=True)

    available = list(MODEL_REGISTRY.keys())
    if "ask_model_key" not in st.session_state:
        st.session_state.ask_model_key = available[0] if available else "groq-gpt-oss-20b"

    col_ask_m, _ = st.columns([2, 4])
    with col_ask_m:
        st.session_state.ask_model_key = st.selectbox(
            "Model for Q&A",
            options=available,
            index=available.index(st.session_state.ask_model_key) if st.session_state.ask_model_key in available else 0,
            key="ask_model_selector",
        )

    ask_msgs = st.session_state.ask_messages
    for msg in ask_msgs:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if q := st.chat_input("Ask a question about the analysis results..."):
        ask_msgs.append({"role": "user", "content": q})
        with st.chat_message("user"):
            st.markdown(q)

        ctx = st.session_state.last_results_context
        prompt = f"""You are a vulnerability analysis assistant. Based on the analysis results below, answer the user's question concisely.

Results:
{ctx}

User: {q}"""
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    # get_model returns a function - call it directly
                    generate_fn = get_model(st.session_state.ask_model_key, temperature=0.3)
                    answer = generate_fn(prompt)
                    st.markdown(answer)
                    ask_msgs.append({"role": "assistant", "content": answer})
                except Exception as e:
                    st.error(f"Failed to generate answer: {e}")
