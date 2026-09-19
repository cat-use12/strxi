---
name: cve_research
description: CVE research methodology — zero-day discovery, patch diff analysis, CVSS scoring, responsible disclosure, PoC development
---

# CVE Research & Zero-Day Discovery

## Research Methodology

### 1. Target Selection

```bash
# Pick targets with large attack surface and active development:
# - Open source projects on GitHub with many stars/forks
# - Libraries used in critical infrastructure (OpenSSL, curl, expat, libxml2)
# - Web frameworks (Django, Laravel, Spring, Express)
# - Network services (Nginx, Apache, OpenSSH, Samba)

# Find old CVEs in target to understand vuln patterns:
searchsploit <project_name>
curl "https://cve.circl.lu/api/search/<vendor>/<product>"
curl "https://osv.dev/v1/query" -d '{"package": {"name": "<pkg>", "ecosystem": "PyPI"}}'
```

### 2. Patch Diff Analysis (Finding Vulns in Patches)

```bash
# Get two versions to diff
git clone https://github.com/target/project
cd project
git log --oneline | head -20

# Security-relevant commit keywords:
git log --oneline --all --grep="fix\|security\|vuln\|CVE\|sanitize\|escape\|validate\|overflow\|injection" | head -30

# Diff between tags/versions:
git diff v1.0.0 v1.0.1 -- '*.c' '*.php' '*.py'

# Focus on:
# - Removed/added bounds checks
# - Added input validation
# - Changed memory allocation sizes
# - New sanitization functions
# - Changed authentication logic

# Semgrep for common patterns in diff:
git stash  # stash current
git checkout v1.0.0  # old (vulnerable) version
semgrep --config p/security-audit .

git checkout v1.0.1  # new (patched) version
semgrep --config p/security-audit .
# Compare output — what did the patch fix?
```

### 3. Fuzzing for Zero-Days

```bash
# AFL++ (coverage-guided fuzzing for C/C++ binaries)
# Install: apt install afl++ or build from source

# Instrument target:
CC=afl-cc CXX=afl-c++ ./configure && make
# or: afl-clang-fast -o target_fuzz target.c

# Create seed corpus:
mkdir corpus_in corpus_out
echo "test input" > corpus_in/seed1.txt
cp /path/to/valid/inputs/* corpus_in/

# Run AFL++:
afl-fuzz -i corpus_in -o corpus_out -m none -- ./target_fuzz @@
# @@ = AFL replaces with input file path
# -m none = no memory limit

# Parallel fuzzing (multiple cores):
afl-fuzz -i corpus_in -o corpus_out -M fuzzer01 -- ./target @@  # master
afl-fuzz -i corpus_in -o corpus_out -S fuzzer02 -- ./target @@  # secondary

# Check for crashes:
ls corpus_out/default/crashes/
adb corpus_out/default/hangs/

# Minimize crashing input:
afl-tmin -i corpus_out/default/crashes/crash_001 -o minimized_crash -- ./target @@
```

```python
# boofuzz (Python, for network protocols/APIs)
from boofuzz import *

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 8080)))

s_initialize("HTTP GET")
s_string("GET", fuzzable=False)
s_delim(" ")
s_string("/", fuzzable=True)  # fuzz the path
s_delim(" ")
s_string("HTTP/1.1\r\nHost: localhost\r\n\r\n", fuzzable=False)

session.connect(s_get("HTTP GET"))
session.fuzz()
```

### 4. Code Auditing (Manual)

```bash
# Dangerous functions to grep (C/C++):
grep -rn "strcpy\|strcat\|sprintf\|gets\|scanf\|memcpy\|memmove\|strncat\|strncpy" \
  --include="*.c" --include="*.cpp" . 2>/dev/null

# Integer overflow patterns:
grep -rn "malloc.*\+\|malloc.*\*\|calloc.*\+" --include="*.c" . 2>/dev/null

# Format string bugs:
grep -rn "printf\s*([^\"]\|fprintf\s*([^,]*," --include="*.c" . 2>/dev/null

# Use-after-free patterns:
grep -rn "free(.*)" --include="*.c" . 2>/dev/null
# Then trace where freed pointer is used after

# PHP dangerous functions:
grep -rn "eval\|exec\|system\|passthru\|shell_exec\|popen\|proc_open\|`\|include\s*(\$\|require\s*(\$" \
  --include="*.php" . 2>/dev/null

# Python dangerous:
grep -rn "eval\|exec\|os.system\|subprocess.call\|pickle.loads\|yaml.load[^_]" \
  --include="*.py" . 2>/dev/null

# Deserialization:
grep -rn "unserialize\|pickle.loads\|yaml.load\|ObjectInputStream\|JsonConvert.DeserializeObject" . 2>/dev/null
```

## CVSS v3.1 Scoring

### Attack Vector (AV)
| Value | Meaning | Score |
|-------|---------|-------|
| N (Network) | Exploitable remotely | Highest |
| A (Adjacent) | Same network segment | High |
| L (Local) | Local access required | Medium |
| P (Physical) | Physical access required | Lowest |

### Full Score Calculation Template

```
AV: N/A/L/P
AC: L/H         (Attack Complexity: Low/High)
PR: N/L/H       (Privileges Required: None/Low/High)
UI: N/R         (User Interaction: None/Required)
S:  U/C         (Scope: Unchanged/Changed)
C:  N/L/H       (Confidentiality: None/Low/High)
I:  N/L/H       (Integrity: None/Low/High)
A:  N/L/H       (Availability: None/Low/High)

Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 (Critical)

Calculate at: https://www.first.org/cvss/calculator/3.1
```

### Common Severity Scores
| Vuln Type | Typical CVSS | Severity |
|-----------|-------------|---------|
| Unauthenticated RCE | 9.8 | Critical |
| Auth RCE | 8.8 | High |
| SQLi (data exfil) | 8.1–9.8 | High-Critical |
| SSRF internal | 7.5–9.0 | High |
| LPE (local) | 7.8 | High |
| Stored XSS | 6.1–8.8 | Medium-High |
| IDOR sensitive data | 6.5–8.1 | Medium-High |
| Reflected XSS | 5.4–6.1 | Medium |
| CSRF | 4.3–8.8 | Medium-High |

## CVE Assignment Process

### 1. Check If Already Reported
```bash
# Search NVD
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<software+name>&resultsPerPage=20"

# Search CVE Details
curl "https://www.cvedetails.com/json-feed.php?vendor_id=<id>"

# GitHub advisory database
curl "https://api.github.com/repos/<owner>/<repo>/security-advisories"

# OSV.dev
curl -X POST "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "target-package", "ecosystem": "npm"}}'
```

### 2. Request CVE ID (Before Public Disclosure)

**Option A: Direct MITRE request**
- Email: cve-assign@mitre.org
- Subject: CVE Request: [Product] [Version] — [Brief Description]
- Include: product name, version, vuln type, impact, PoC (minimal)

**Option B: CNA (CVE Numbering Authority)**
- If vendor has their own CNA: report directly to them
- List: https://www.cve.org/ProgramOrganization/CNAs

**Option C: GitHub Security Advisory**
- If it's a GitHub project: Create a Security Advisory → auto-requests CVE

### 3. Responsible Disclosure Timeline

```
Day 0:   Discover vulnerability, start analysis, create PoC
Day 1:   Verify and document completely
Day 5:   Contact vendor (security@vendor.com or HackerOne/Bugcrowd private program)
Day 7:   Follow up if no response
Day 14:  Second follow up; escalate to CERT if vendor unresponsive
Day 90:  Default disclosure deadline (Google Project Zero standard)
Day 90+: Publish advisory if vendor hasn't patched (coordinated disclosure)

Template for vendor contact:
Subject: [SECURITY] Vulnerability in [Product] [Version]: [Type] 

Hi Security Team,

I discovered a security vulnerability in [Product] [Version]:

Type: Remote Code Execution / SQLi / etc.
CVSS 3.1: 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Summary:
[2-3 sentence description of the vuln]

Steps to Reproduce:
1. ...
2. ...
3. ...

Impact:
An unauthenticated attacker can...

Suggested Fix:
[Brief remediation]

I would appreciate acknowledgment within 5 business days. I plan to 
publicly disclose this vulnerability 90 days from the date of this report.

Best regards,
[Your name / handle]
```

## Writing a Quality PoC

```python
#!/usr/bin/env python3
"""
CVE-XXXX-XXXXX: [Product] [Version] — [Vulnerability Type]
Author: [Your Handle]
Severity: Critical (CVSS 3.1: 9.8)

Description:
  [Vulnerability description — one paragraph]

Affected Versions:
  - Product <= X.Y.Z

Fixed in:
  - Product X.Y.Z+1

References:
  - https://vendor.com/security/advisory/CVE-XXXX-XXXXX

Usage:
  python3 poc.py --target http://victim.com --cmd "id"
"""

import argparse
import requests

def exploit(target: str, cmd: str) -> str:
    """
    Core exploit logic.
    Returns output of executed command.
    """
    # ... exploit code ...
    pass

def main():
    parser = argparse.ArgumentParser(description='CVE-XXXX-XXXXX PoC')
    parser.add_argument('--target', required=True, help='Target URL')
    parser.add_argument('--cmd', default='id', help='Command to execute')
    args = parser.parse_args()
    
    print(f"[*] Targeting: {args.target}")
    result = exploit(args.target, args.cmd)
    print(f"[+] Command output:\n{result}")

if __name__ == '__main__':
    main()
```

## Public CVE Disclosure Format (Markdown)

```markdown
# CVE-XXXX-XXXXX: [Product] [Vulnerability Type]

**Severity:** Critical (CVSS 3.1: 9.8)
**Affected versions:** <= X.Y.Z
**Fixed in:** X.Y.Z+1
**Researcher:** [Your name/handle]
**Disclosure date:** YYYY-MM-DD

## Summary

[2-3 sentence description]

## Technical Details

[Detailed technical explanation of root cause]

## Proof of Concept

```bash
# Steps to reproduce
```

## Impact

An unauthenticated remote attacker can...

## Remediation

Update to version X.Y.Z+1 or apply the following patch:
[patch description or diff]

## Timeline

- YYYY-MM-DD: Discovered
- YYYY-MM-DD: Vendor notified
- YYYY-MM-DD: Vendor confirmed
- YYYY-MM-DD: Patch released
- YYYY-MM-DD: Public disclosure
```
