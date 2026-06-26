from typing import Any


BASELINE_TEMPLATE = """\
You are a senior software security researcher with deep expertise in \
vulnerability analysis and the CWE (Common Weakness Enumeration) taxonomy.

Analyze the following function and determine:
1. Is this function vulnerable to a security issue?
2. If vulnerable, identify the **root cause** CWE ID (not a symptom or parent category).

Output ONLY a JSON object in one of these two forms:
- If vulnerable: {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
- If not vulnerable: {{"vulnerable": false}}

Do NOT output any other text, explanation, or markdown. Only the JSON object.

Function:
```
{func}
```"""


COT_TEMPLATE = """\
You are a senior vulnerability researcher. Analyze the following function \
step by step to determine if it contains a security vulnerability.

Perform this analysis in order:

**Step 1 — Identify Inputs**: What external/untrusted inputs does this \
function receive? (parameters, user data, file contents, network data, \
environment variables, etc.)

**Step 2 — Trace Data Flow**: Follow each untrusted input through the \
function. Is it used directly in any dangerous operation without being \
validated, sanitized, or escaped first?

**Step 3 — Identify Dangerous Sinks**: Does the untrusted data reach any \
of these without proper protection?
- String concatenation into queries (SQL, LDAP, XPath, OS commands)
- Memory operations without bounds checking (memcpy, strcpy, buffer indexing)
- Pointer arithmetic or dereference without null/bounds checks
- Deserialization of untrusted data
- File path construction without traversal prevention
- Cryptographic operations with weak algorithms or hardcoded keys
- Missing authentication or authorization checks on sensitive operations

**Step 4 — Classify**: If a vulnerability exists, determine the specific \
root-cause CWE ID. Choose the most specific CWE, not a parent category.

Think through each step, then output ONLY a JSON object as the very last \
line of your response:
- If vulnerable: {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
- If not vulnerable: {{"vulnerable": false}}

Function:
```
{func}
```"""

TAXONOMY_TEMPLATE = """\
You are a vulnerability classifier. Analyze the function below and \
determine if it is vulnerable. If it is, classify the vulnerability using \
the CWE taxonomy.

First, identify which **vulnerability category** applies:

| Category | Common CWEs | What to Look For |
|----------|-------------|------------------|
| Memory Safety | CWE-119, CWE-120, CWE-121, CWE-122, CWE-125, CWE-787, CWE-788 | Buffer overflows, out-of-bounds read/write, missing size checks |
| Null/Pointer Errors | CWE-476, CWE-690, CWE-824, CWE-416, CWE-415 | NULL dereference, use-after-free, double free, uninitialized pointers |
| Integer Errors | CWE-190, CWE-191, CWE-193, CWE-194, CWE-681 | Integer overflow/underflow, off-by-one, sign errors, truncation |
| Injection | CWE-78, CWE-79, CWE-89, CWE-90, CWE-91, CWE-611, CWE-917 | SQL/OS/LDAP/XML injection, XSS, unsanitized input in queries |
| Path Traversal | CWE-22, CWE-23, CWE-36, CWE-73 | Directory traversal, unvalidated file paths |
| Auth & Access | CWE-287, CWE-306, CWE-862, CWE-863, CWE-639, CWE-284 | Missing auth, broken access control, IDOR, privilege escalation |
| Cryptography | CWE-327, CWE-328, CWE-330, CWE-338, CWE-798, CWE-321, CWE-259 | Weak crypto, hardcoded keys/passwords, weak PRNG |
| Resource Mgmt | CWE-400, CWE-401, CWE-404, CWE-770, CWE-772, CWE-835 | Memory leaks, resource exhaustion, infinite loops, missing cleanup |
| Info Disclosure | CWE-200, CWE-209, CWE-532, CWE-359 | Sensitive data in logs/errors, privacy violations |
| Deserialization | CWE-502 | Deserializing untrusted data |
| Race Conditions | CWE-362, CWE-367 | TOCTOU, unprotected shared state |
| Error Handling | CWE-252, CWE-754, CWE-755, CWE-390 | Unchecked returns, improper exception handling |

Then narrow down to the **specific CWE** that best describes the root cause.

Output ONLY a JSON object:
- If vulnerable: {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
- If not vulnerable: {{"vulnerable": false}}

Function:
```
{func}
```"""


SECURITY_AUDIT_TEMPLATE = """\
You are a principal application security engineer conducting a code audit. \
You have reviewed thousands of CVEs and have deep expertise in identifying \
subtle vulnerabilities that automated tools miss.

**Audit this function using the following methodology:**

**Phase 1 — Attack Surface**: Identify all entry points where untrusted \
data can enter (function parameters, global state, file I/O, network data, \
environment variables, database results) somewhat like taint analysis.

**Phase 2 — Vulnerability Pattern Matching**: Check for these patterns:

For C/C++ code, prioritize:
- Buffer operations without bounds checking (memcpy, strcpy, sprintf, \
  array indexing)
- Pointer dereference without NULL checks
- Integer arithmetic that could overflow before being used as a size/index
- Use-after-free or double-free patterns
- Format string vulnerabilities (printf with user-controlled format)

For Java/Python/PHP/JavaScript code, prioritize:
- String concatenation into SQL/OS/LDAP queries (injection)
- User input reflected in HTML output without escaping (XSS)
- Deserialization of untrusted data
- Path construction with user-controlled segments (traversal)
- Missing authentication or authorization checks
- Hardcoded secrets, weak cryptographic choices

For all languages:
- Race conditions in shared resource access
- Missing error/return value checking
- Information leakage through error messages or logs
- Resource exhaustion (unbounded allocation, infinite loops)

**Phase 3 — Root Cause Classification**: If a vulnerability is found, \
classify it by the most specific CWE that describes the root cause. \
Avoid parent/abstract CWEs (e.g., prefer CWE-787 over CWE-119, prefer \
CWE-78 over CWE-77).

Output ONLY a JSON object:
- If vulnerable: {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
- If not vulnerable: {{"vulnerable": false}}

Function:
```
{func}
```"""


ADVERSARIAL_TEMPLATE = """\
You are a security researcher participating in a bug bounty program. \
The following function has been flagged by static analysis as potentially \
vulnerable. Your job is to determine if a real exploitable vulnerability \
exists and classify it.

**Your approach:**
1. Assume the function IS vulnerable and actively look for the bug. \
Consider all possible inputs, including malicious ones crafted by an attacker.
2. For each potential vulnerability you find, verify it by asking: \
"Can an attacker actually control the input that reaches this dangerous \
operation? Is there any sanitization or validation that prevents exploitation?"
3. If you confirm a real vulnerability, classify it with the most specific \
CWE ID.
4. If after thorough analysis you cannot find a real exploitable issue, \
report it as not vulnerable.

Think carefully — some bugs are subtle (off-by-one, sign extension, \
missing edge cases in validation). Don't dismiss potential issues too quickly.

Output ONLY a JSON object:
- If vulnerable: {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
- If not vulnerable: {{"vulnerable": false}}

Function:
```
{func}
```"""


STRICT_TEMPLATE = """\
Is this function vulnerable? If yes, identify the root-cause CWE ID.

Rules:
- No explanation, no reasoning, no markdown, no extra text.
- Output MUST be exactly one of these two JSON forms:
  {{"vulnerable": true, "cwe_id": "CWE-XXX"}}
  {{"vulnerable": false}}
- Replace XXX with the actual CWE number.

Function:
```
{func}
```"""

TEMPLATES = {
    "baseline": BASELINE_TEMPLATE,
    "cot": COT_TEMPLATE,
    "taxonomy": TAXONOMY_TEMPLATE,
    "security_audit": SECURITY_AUDIT_TEMPLATE,
    "adversarial": ADVERSARIAL_TEMPLATE,
    "strict": STRICT_TEMPLATE,
}


def build_prompt(prompt_type, func):
    template = TEMPLATES.get(prompt_type)
    if template is None:
        raise ValueError(
            f"Unknown prompt type '{prompt_type}'. Available: {list(TEMPLATES.keys())}"
        )
    return template.format(func=func)
