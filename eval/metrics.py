import os
from typing import Any, Optional

import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

from eval.parser import normalise_cwe

CWE_FAMILIES: dict[str, str] = {
    "CWE-20": "Input Validation",
    "CWE-22": "Input Validation",
    "CWE-23": "Input Validation",
    "CWE-24": "Input Validation",
    "CWE-36": "Input Validation",
    "CWE-59": "Input Validation",
    "CWE-73": "Input Validation",
    "CWE-77": "Input Validation",
    "CWE-78": "Input Validation",
    "CWE-79": "Input Validation",
    "CWE-80": "Input Validation",
    "CWE-81": "Input Validation",
    "CWE-82": "Input Validation",
    "CWE-83": "Input Validation",
    "CWE-84": "Input Validation",
    "CWE-85": "Input Validation",
    "CWE-86": "Input Validation",
    "CWE-87": "Input Validation",
    "CWE-88": "Input Validation",
    "CWE-89": "Input Validation",
    "CWE-90": "Input Validation",
    "CWE-91": "Input Validation",
    "CWE-113": "Input Validation",
    "CWE-114": "Input Validation",
    "CWE-115": "Input Validation",
    "CWE-116": "Input Validation",
    "CWE-134": "Input Validation",
    "CWE-601": "Input Validation",
    "CWE-606": "Input Validation",
    "CWE-611": "Input Validation",
    "CWE-643": "Input Validation",
    "CWE-652": "Input Validation",
    "CWE-918": "Input Validation",
    "CWE-119": "Buffer Errors",
    "CWE-120": "Buffer Errors",
    "CWE-121": "Buffer Errors",
    "CWE-122": "Buffer Errors",
    "CWE-123": "Buffer Errors",
    "CWE-124": "Buffer Errors",
    "CWE-125": "Buffer Errors",
    "CWE-126": "Buffer Errors",
    "CWE-127": "Buffer Errors",
    "CWE-128": "Buffer Errors",
    "CWE-129": "Buffer Errors",
    "CWE-130": "Buffer Errors",
    "CWE-131": "Buffer Errors",
    "CWE-132": "Buffer Errors",
    "CWE-133": "Buffer Errors",
    "CWE-170": "Buffer Errors",
    "CWE-172": "Buffer Errors",
    "CWE-188": "Buffer Errors",
    "CWE-787": "Buffer Errors",
    "CWE-788": "Buffer Errors",
    "CWE-190": "Numeric Errors",
    "CWE-191": "Numeric Errors",
    "CWE-192": "Numeric Errors",
    "CWE-193": "Numeric Errors",
    "CWE-194": "Numeric Errors",
    "CWE-195": "Numeric Errors",
    "CWE-196": "Numeric Errors",
    "CWE-197": "Numeric Errors",
    "CWE-369": "Numeric Errors",
    "CWE-681": "Numeric Errors",
    "CWE-682": "Numeric Errors",
    "CWE-264": "Permissions & Access",
    "CWE-269": "Permissions & Access",
    "CWE-270": "Permissions & Access",
    "CWE-271": "Permissions & Access",
    "CWE-272": "Permissions & Access",
    "CWE-273": "Permissions & Access",
    "CWE-274": "Permissions & Access",
    "CWE-275": "Permissions & Access",
    "CWE-276": "Permissions & Access",
    "CWE-277": "Permissions & Access",
    "CWE-278": "Permissions & Access",
    "CWE-279": "Permissions & Access",
    "CWE-280": "Permissions & Access",
    "CWE-281": "Permissions & Access",
    "CWE-282": "Permissions & Access",
    "CWE-283": "Permissions & Access",
    "CWE-284": "Permissions & Access",
    "CWE-285": "Permissions & Access",
    "CWE-286": "Permissions & Access",
    "CWE-732": "Permissions & Access",
    "CWE-862": "Permissions & Access",
    "CWE-863": "Permissions & Access",
    "CWE-287": "Authentication",
    "CWE-288": "Authentication",
    "CWE-289": "Authentication",
    "CWE-290": "Authentication",
    "CWE-291": "Authentication",
    "CWE-292": "Authentication",
    "CWE-293": "Authentication",
    "CWE-294": "Authentication",
    "CWE-295": "Authentication",
    "CWE-296": "Authentication",
    "CWE-297": "Authentication",
    "CWE-298": "Authentication",
    "CWE-299": "Authentication",
    "CWE-300": "Authentication",
    "CWE-301": "Authentication",
    "CWE-302": "Authentication",
    "CWE-303": "Authentication",
    "CWE-304": "Authentication",
    "CWE-305": "Authentication",
    "CWE-306": "Authentication",
    "CWE-307": "Authentication",
    "CWE-308": "Authentication",
    "CWE-309": "Authentication",
    "CWE-310": "Cryptography",
    "CWE-311": "Cryptography",
    "CWE-312": "Cryptography",
    "CWE-313": "Cryptography",
    "CWE-314": "Cryptography",
    "CWE-315": "Cryptography",
    "CWE-316": "Cryptography",
    "CWE-317": "Cryptography",
    "CWE-318": "Cryptography",
    "CWE-319": "Cryptography",
    "CWE-320": "Cryptography",
    "CWE-321": "Cryptography",
    "CWE-322": "Cryptography",
    "CWE-323": "Cryptography",
    "CWE-324": "Cryptography",
    "CWE-325": "Cryptography",
    "CWE-326": "Cryptography",
    "CWE-327": "Cryptography",
    "CWE-328": "Cryptography",
    "CWE-329": "Cryptography",
    "CWE-330": "Cryptography",
    "CWE-331": "Cryptography",
    "CWE-332": "Cryptography",
    "CWE-333": "Cryptography",
    "CWE-334": "Cryptography",
    "CWE-335": "Cryptography",
    "CWE-336": "Cryptography",
    "CWE-337": "Cryptography",
    "CWE-338": "Cryptography",
    "CWE-339": "Cryptography",
    "CWE-340": "Cryptography",
    "CWE-341": "Cryptography",
    "CWE-342": "Cryptography",
    "CWE-343": "Cryptography",
    "CWE-344": "Cryptography",
    "CWE-345": "Cryptography",
    "CWE-346": "Cryptography",
    "CWE-347": "Cryptography",
    "CWE-348": "Cryptography",
    "CWE-349": "Cryptography",
    "CWE-350": "Cryptography",
    "CWE-351": "Cryptography",
    "CWE-352": "Cryptography",
    "CWE-353": "Cryptography",
    "CWE-354": "Cryptography",
    "CWE-358": "Cryptography",
    "CWE-359": "Cryptography",
    "CWE-360": "Cryptography",
    "CWE-361": "Cryptography",
    "CWE-798": "Cryptography",
    "CWE-362": "Race Conditions",
    "CWE-363": "Race Conditions",
    "CWE-364": "Race Conditions",
    "CWE-365": "Race Conditions",
    "CWE-366": "Race Conditions",
    "CWE-367": "Race Conditions",
    "CWE-368": "Race Conditions",
    "CWE-370": "Race Conditions",
    "CWE-377": "Race Conditions",
    "CWE-379": "Race Conditions",
    "CWE-384": "Race Conditions",
    "CWE-385": "Race Conditions",
    "CWE-386": "Race Conditions",
    "CWE-387": "Race Conditions",
    "CWE-390": "Race Conditions",
    "CWE-391": "Race Conditions",
    "CWE-399": "Resource Management",
    "CWE-400": "Resource Management",
    "CWE-401": "Resource Management",
    "CWE-402": "Resource Management",
    "CWE-403": "Resource Management",
    "CWE-404": "Resource Management",
    "CWE-405": "Resource Management",
    "CWE-406": "Resource Management",
    "CWE-407": "Resource Management",
    "CWE-408": "Resource Management",
    "CWE-409": "Resource Management",
    "CWE-410": "Resource Management",
    "CWE-411": "Resource Management",
    "CWE-412": "Resource Management",
    "CWE-413": "Resource Management",
    "CWE-414": "Resource Management",
    "CWE-415": "Resource Management",
    "CWE-416": "Resource Management",
    "CWE-459": "Resource Management",
    "CWE-562": "Resource Management",
    "CWE-664": "Resource Management",
    "CWE-665": "Resource Management",
    "CWE-666": "Resource Management",
    "CWE-667": "Resource Management",
    "CWE-668": "Resource Management",
    "CWE-669": "Resource Management",
    "CWE-670": "Resource Management",
    "CWE-671": "Resource Management",
    "CWE-672": "Resource Management",
    "CWE-673": "Resource Management",
    "CWE-674": "Resource Management",
    "CWE-675": "Resource Management",
    "CWE-676": "Resource Management",
    "CWE-677": "Resource Management",
    "CWE-678": "Resource Management",
    "CWE-679": "Resource Management",
    "CWE-680": "Resource Management",
    "CWE-770": "Resource Management",
    "CWE-771": "Resource Management",
    "CWE-772": "Resource Management",
    "CWE-773": "Resource Management",
    "CWE-774": "Resource Management",
    "CWE-775": "Resource Management",
    "CWE-776": "Resource Management",
    "CWE-789": "Resource Management",
    "CWE-799": "Resource Management",
    "CWE-822": "Resource Management",
    "CWE-823": "Resource Management",
    "CWE-824": "Resource Management",
    "CWE-825": "Resource Management",
    "CWE-826": "Resource Management",
    "CWE-827": "Resource Management",
    "CWE-828": "Resource Management",
    "CWE-829": "Resource Management",
    "CWE-830": "Resource Management",
    "CWE-835": "Resource Management",
    "CWE-908": "Resource Management",
    "CWE-909": "Resource Management",
    "CWE-910": "Resource Management",
    "CWE-911": "Resource Management",
    "CWE-912": "Resource Management",
    "CWE-913": "Resource Management",
    "CWE-476": "Null Pointer Dereference",
    "CWE-690": "Null Pointer Dereference",
    "CWE-502": "Deserialization",
    "CWE-693": "Protection Mechanism",
    "CWE-694": "Protection Mechanism",
    "CWE-695": "Protection Mechanism",
    "CWE-696": "Protection Mechanism",
    "CWE-697": "Protection Mechanism",
    "CWE-698": "Protection Mechanism",
    "CWE-703": "Error Handling",
    "CWE-704": "Type Errors",
    "CWE-705": "Type Errors",
    "CWE-706": "Type Errors",
    "CWE-707": "Neutralization Errors",
    "CWE-710": "Coding Standards",
    "CWE-754": "Error Handling",
    "CWE-755": "Error Handling",
    "CWE-756": "Error Handling",
    "CWE-757": "Error Handling",
    "CWE-758": "Error Handling",
    "CWE-759": "Error Handling",
    "CWE-760": "Error Handling",
    "CWE-761": "Error Handling",
    "CWE-762": "Error Handling",
    "CWE-763": "Error Handling",
    "CWE-764": "Error Handling",
    "CWE-765": "Error Handling",
    "CWE-766": "Error Handling",
    "CWE-767": "Error Handling",
    "CWE-768": "Error Handling",
    "CWE-769": "Error Handling",
    "CWE-843": "Type Errors",
}


def get_family(cwe_id: Optional[str]) -> Optional[str]:
    if cwe_id is None:
        return None
    return CWE_FAMILIES.get(cwe_id, "Other")


def compute_metrics(
    results_df: pd.DataFrame,
    output_dir: str,
    run_label: str,
) -> dict[str, Any]:
    df = results_df.copy()
    df["predicted_normalized"] = df["predicted_cwe"].apply(
        lambda x: normalise_cwe(str(x)) if x and str(x).strip() else None
    )
    df["true_normalized"] = df["true_cwe"].apply(
        lambda x: normalise_cwe(str(x)) if x and str(x).strip() else None
    )
    df["predicted_family"] = df["predicted_normalized"].apply(get_family)
    df["true_family"] = df["true_normalized"].apply(get_family)

    valid = df[df["predicted_normalized"].notna()]
    parse_failed = df["predicted_normalized"].isna().sum()
    total = len(df)

    metrics: dict[str, Any] = {}
    metrics["total"] = total
    metrics["parse_failed"] = int(parse_failed)
    metrics["parse_failed_rate"] = parse_failed / total if total > 0 else 0.0
    metrics["avg_latency"] = float(df["latency"].mean()) if "latency" in df.columns else 0.0
    metrics["cwe_top1_accuracy"] = float(
        (valid["predicted_normalized"] == valid["true_normalized"]).mean()
    ) if len(valid) > 0 else 0.0
    metrics["cwe_family_accuracy"] = float(
        (valid["predicted_family"] == valid["true_family"]).mean()
    ) if len(valid) > 0 else 0.0

    if len(valid) > 1:
        all_cwe_labels = sorted(set(valid["true_normalized"].tolist() + valid["predicted_normalized"].tolist()))
        metrics["f1_weighted"] = float(
            f1_score(
                valid["true_normalized"], valid["predicted_normalized"],
                labels=all_cwe_labels, average="weighted", zero_division=0.0,
            )
        )
        metrics["f1_macro"] = float(
            f1_score(
                valid["true_normalized"], valid["predicted_normalized"],
                labels=all_cwe_labels, average="macro", zero_division=0.0,
            )
        )
        metrics["precision_weighted"] = float(
            precision_score(
                valid["true_normalized"], valid["predicted_normalized"],
                labels=all_cwe_labels, average="weighted", zero_division=0.0,
            )
        )
        metrics["recall_weighted"] = float(
            recall_score(
                valid["true_normalized"], valid["predicted_normalized"],
                labels=all_cwe_labels, average="weighted", zero_division=0.0,
            )
        )

        fam_labels = sorted(set(valid["true_family"].tolist() + valid["predicted_family"].tolist()))
        metrics["f1_family_weighted"] = float(
            f1_score(
                valid["true_family"], valid["predicted_family"],
                labels=fam_labels, average="weighted", zero_division=0.0,
            )
        )

        per_class: dict[str, dict[str, float]] = {}
        for cwe in all_cwe_labels:
            tc = [1 if v == cwe else 0 for v in valid["true_normalized"]]
            pc = [1 if v == cwe else 0 for v in valid["predicted_normalized"]]
            per_class[cwe] = {
                "f1": float(f1_score(tc, pc, zero_division=0.0)),
                "precision": float(precision_score(tc, pc, zero_division=0.0)),
                "recall": float(recall_score(tc, pc, zero_division=0.0)),
            }
        metrics["per_class"] = per_class
    else:
        metrics["f1_weighted"] = 0.0
        metrics["f1_macro"] = 0.0
        metrics["precision_weighted"] = 0.0
        metrics["recall_weighted"] = 0.0
        metrics["f1_family_weighted"] = 0.0
        metrics["per_class"] = {}

    os.makedirs(output_dir, exist_ok=True)
    results_path = os.path.join(output_dir, f"{run_label}_results.csv")
    df.to_csv(results_path, index=False)

    return metrics


def build_summary_table(all_metrics: dict[str, dict[str, Any]], output_dir: str) -> pd.DataFrame:
    rows = []
    for run_label, m in all_metrics.items():
        rows.append({
            "run": run_label,
            "total": m["total"],
            "parse_failed_rate": f"{m['parse_failed_rate']:.3f}",
            "cwe_top1_accuracy": f"{m['cwe_top1_accuracy']:.3f}",
            "cwe_family_accuracy": f"{m['cwe_family_accuracy']:.3f}",
            "f1_weighted": f"{m['f1_weighted']:.3f}",
            "f1_macro": f"{m['f1_macro']:.3f}",
            "precision_weighted": f"{m['precision_weighted']:.3f}",
            "recall_weighted": f"{m['recall_weighted']:.3f}",
            "f1_family_weighted": f"{m['f1_family_weighted']:.3f}",
            "avg_latency": f"{m['avg_latency']:.3f}",
        })
    df = pd.DataFrame(rows)
    summary_path = os.path.join(output_dir, "summary_table.csv")
    df.to_csv(summary_path, index=False)
    return df
