"""
RAG (Retrieval-Augmented Generation) for CWE definitions.

This module was removed to reduce resource usage (it required ~1.5-3 GB of
dependencies: faiss-cpu, transformers, torch).

If you want to add RAG back, here is what you need to do:
"""

# ────────────────────────────────────────────────────────────────────────────
# HOW TO ADD RAG BACK TO THIS PROJECT
# ────────────────────────────────────────────────────────────────────────────
#
# Step 1: Install the dependencies
#   pip install faiss-cpu>=1.7.4 transformers>=4.35.0 torch>=2.0.0
#
# Step 2: Uncomment the full RAG implementation below, which:
#   - Loads CodeBERT embeddings model
#   - Builds a FAISS index of CWE definitions
#   - Retrieves the top-k most relevant CWE definitions for a given code snippet
#
# Step 3: In prompts/templates.py, add the rag_cwe template back:
#   Add this block before SECURITY_AUDIT_TEMPLATE:
#
#   RAG_CWE_TEMPLATE = """\
#   You are a vulnerability analyst. Below are CWE definitions that may be \
#   relevant to the function being analyzed. Your task is to determine if the \
#   function is vulnerable and, if so, which CWE best describes the root cause.
#
#   **Relevant CWE Definitions (retrieved based on code similarity):**
#   {cwe_context}
#
#   **Analysis Instructions:**
#   1. For each CWE definition above, check whether the function exhibits \
#   the described weakness pattern.
#   2. Look for the specific conditions described in each CWE — does the code \
#   actually do what the CWE describes?
#   3. If a match exists, select the CWE whose description most precisely \
#   matches the vulnerability's root cause.
#   4. If none of the provided CWEs match, you may identify a different CWE \
#   that better fits, or determine the function is not vulnerable.
#
#   Output ONLY a JSON object:
#   - If vulnerable: {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
#   - If not vulnerable: {{"vulnerable": false}}
#
#   Function:
#   ```
#   {func}
#   ```"""
#
#   Add to TEMPLATES dict:
#   "rag_cwe": RAG_CWE_TEMPLATE,
#
#   Update build_prompt to accept cwe_context again:
#   def build_prompt(prompt_type, func, cwe_context=""):
#       ...
#       return template.format(func=func, cwe_context=cwe_context)
#
# Step 4: In main.py and app.py, add back the RAG import and logic:
#   from rag.cwe_index import retrieve_cwe_definitions
#
#   Then before build_prompt, add:
#   cwe_context = ""
#   if prompt_type == "rag_cwe":
#       retrieved = retrieve_cwe_definitions(code, k=3)
#       cwe_context = "\n".join(f"{cid}: {desc}" for cid, desc, _ in retrieved)
#   prompt = build_prompt(prompt_type, code, cwe_context=cwe_context)

# ────────────────────────────────────────────────────────────────────────────
# The full original implementation is below (commented out).
# To restore it, remove the triple-quote block markers.
# ────────────────────────────────────────────────────────────────────────────
"""
import os
import pickle

import faiss
import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

CWE_DEFINITIONS = {
    "CWE-20": "Improper Input Validation: The product does not validate or incorrectly validates input...",
    "CWE-78": "OS Command Injection: The software constructs all or part of an OS command using externally-influenced input...",
    "CWE-79": "Cross-site Scripting: The software does not neutralize user-controllable input before it is placed in output...",
    "CWE-89": "SQL Injection: The software constructs a SQL query using externally-influenced input...",
    "CWE-119": "Buffer Overflow: The software performs operations on a memory buffer but reads or writes outside the intended boundary...",
    "CWE-190": "Integer Overflow: The software performs a calculation that can produce an integer overflow...",
    "CWE-416": "Use After Free: The software uses memory after it has been freed...",
    "CWE-476": "NULL Pointer Dereference: The software dereferences a pointer that is NULL...",
    "CWE-502": "Deserialization of Untrusted Data: The software deserializes untrusted data...",
    "CWE-787": "Out-of-bounds Write: The software writes outside the bounds of a buffer...",
    # ... (add all CWE definitions here - see git history for full list)
}

_EMBEDDING_MODEL = None
_INDEX_CACHE = None
_CWE_IDS_CACHE = None
INDEX_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache", "cwe_index")


def _get_embedding_model():
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None:
        device = "cpu"
        tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        model = AutoModel.from_pretrained("microsoft/codebert-base").to(device).eval()
        _EMBEDDING_MODEL = (tokenizer, model, device)
    return _EMBEDDING_MODEL


def _embed_single(text, tokenizer, model, device):
    inputs = tokenizer(text, padding=True, truncation=True, return_tensors="pt", max_length=512).to(device)
    with torch.no_grad():
        outputs = model(**inputs)
    return outputs.last_hidden_state[:, 0, :].cpu().numpy()


def _embed_texts(texts):
    tokenizer, model, device = _get_embedding_model()
    embeddings_list = [_embed_single(t, tokenizer, model, device) for t in texts]
    embeddings = np.ascontiguousarray(np.concatenate(embeddings_list, axis=0))
    faiss.normalize_L2(embeddings)
    return embeddings


def build_cwe_index():
    global _INDEX_CACHE, _CWE_IDS_CACHE
    os.makedirs(INDEX_DIR, exist_ok=True)
    index_path = os.path.join(INDEX_DIR, "cwe_index.faiss")
    mapping_path = os.path.join(INDEX_DIR, "cwe_mapping.pkl")

    if os.path.exists(index_path) and os.path.exists(mapping_path):
        index = faiss.read_index(index_path)
        with open(mapping_path, "rb") as f:
            _CWE_IDS_CACHE = pickle.load(f)
        _INDEX_CACHE = index
        return index

    cwe_ids = sorted(CWE_DEFINITIONS.keys())
    texts = [CWE_DEFINITIONS[cid] for cid in cwe_ids]
    embeddings = _embed_texts(texts)
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)

    with open(mapping_path, "wb") as f:
        pickle.dump(cwe_ids, f)
    faiss.write_index(index, index_path)

    _INDEX_CACHE = index
    _CWE_IDS_CACHE = cwe_ids
    return index


def load_cwe_index():
    global _INDEX_CACHE, _CWE_IDS_CACHE
    if _INDEX_CACHE is not None and _CWE_IDS_CACHE is not None:
        return _INDEX_CACHE, _CWE_IDS_CACHE
    index_path = os.path.join(INDEX_DIR, "cwe_index.faiss")
    mapping_path = os.path.join(INDEX_DIR, "cwe_mapping.pkl")
    if not os.path.exists(index_path) or not os.path.exists(mapping_path):
        build_cwe_index()
    else:
        _INDEX_CACHE = faiss.read_index(index_path)
        with open(mapping_path, "rb") as f:
            _CWE_IDS_CACHE = pickle.load(f)
    return _INDEX_CACHE, _CWE_IDS_CACHE


def retrieve_cwe_definitions(query, k=3):
    index, cwe_ids = load_cwe_index()
    query_emb = _embed_texts([query])
    scores, indices = index.search(query_emb, k)
    results = []
    for score, idx in zip(scores[0], indices[0]):
        cid = cwe_ids[idx]
        results.append((cid, CWE_DEFINITIONS.get(cid, ""), float(score)))
    return results
"""
