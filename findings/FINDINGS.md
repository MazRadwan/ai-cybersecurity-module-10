# Module 10 Capstone - Vulnerability Findings

## App: Vulnerable Archive (Django + Ollama LLM)
- Repo: https://github.com/MazRadwan/ai-cybersecurity-module-10
- Running on: http://localhost:8001

---

## Vulnerability Tracker

| # | Type | Vulnerability | Location | Scan Tool | Test Written | Fixed | Verified |
|---|------|--------------|----------|-----------|:---:|:---:|:---:|
| 1 | Secrets | Hardcoded JWT Secret (`do_not_share_this`) | `views.py:40` | Semgrep | [x] | [x] | [x] |
| 2 | Secrets | Django SECRET_KEY exposed in source | `settings.py:23` | Manual | N/A | [x] | [x] |
| 3 | XSS | Stored XSS via `\|safe` filter on notes/content | `view_archive.html:28,35` | Manual | [x] | [x] | [x] |
| 4 | SQLi | SQL Injection in search (f-string interpolation) | `views.py:134` | Semgrep | [x] | [x] | [x] |
| 5 | Broken Access Control | IDOR - no ownership check on view/edit/delete | `views.py:98-125` | Manual | [x] | [x] | [x] |
| 6 | Prompt Injection | LLM data exfiltration via enrich (tool calling) | `views.py:243-310` | Manual | [x] | [x] | [x] |
| 7 | Prompt Injection | Path traversal - LLM controls file write path | `views.py:198-239` | Manual | [x] | [x] | [x] |
| 8 | Prompt Injection / SQLi | Unrestricted LLM-generated SQL executed directly | `views.py:148-194` | Manual | [x] | [x] | [x] |
| 9 | Info Disclosure | DEBUG = True | `settings.py:26` | Manual | N/A | [x] | [x] |
| 10 | Misconfiguration | Empty ALLOWED_HOSTS | `settings.py:28` | Manual | N/A | [x] | [x] |
| 11 | SSRF | Server fetches user-supplied URL with no validation | `views.py:70` | Semgrep | [x] | [x] | [x] |
| 12 | Info Disclosure | Raw SQL errors exposed to user | `views.py:142` | Manual | [x] | [x] | [x] |

---

## Data Leaks Identified

| # | Secret / Data | Location | Leak Vector | Status |
|---|--------------|----------|-------------|--------|
| 1 | JWT Secret `"do_not_share_this"` | `views.py:40` | Hardcoded in source - enables token forgery | FIXED - env var |
| 2 | Django SECRET_KEY `"django-insecure-^3!*..."` | `settings.py:23` | Hardcoded - session hijacking | FIXED - env var |
| 3 | User passwords `"password123"` for all accounts | `seed_data.py:22,25,26` | Hardcoded in seed script | Seed data only |
| 4 | Password hashes (`pbkdf2_sha256$...`) | Database | Extracted via SQLi UNION attack | FIXED - ORM |
| 5 | Bob's private archive notes | Database | Accessed via IDOR | FIXED - ownership check |
| 6 | PII: `"Hunter2"` password + SSN `123-45-6789` | `seed_data.py:83` | Exfiltrated via prompt injection | FIXED - domain allowlist |
| 7 | Full stack traces, settings, DB paths | Runtime | Exposed via `DEBUG = True` | FIXED - DEBUG=False |
| 8 | AWS IAM credentials / cloud metadata | Internal network | Stolen via SSRF | FIXED - URL validation |
| 9 | Internal service info (Ollama models) | Internal network | Probed via SSRF | FIXED - URL validation |
| 10 | DB table structure and query shape | Error messages | SQL error disclosure | FIXED - generic errors |

---

## Scan Results (Before Fix)

| Tool | Date | Findings | Report File |
|------|------|----------|-------------|
| Semgrep (auto) | 2026-03-19 | 11 findings | `scans/semgrep-before.txt` |
| Semgrep (custom) | 2026-03-19 | 0 findings | `scans/semgrep-custom-before.txt` |
| TruffleHog (default) | 2026-03-19 | 0 findings | `scans/trufflehog-before.txt` |
| TruffleHog (custom) | 2026-03-19 | 1 finding | `scans/trufflehog-custom-before.txt` |
| Exploit Tests | 2026-03-19 | 15/15 PASS (all vulns exploitable) | `scans/exploit-tests-before.txt` |

### Semgrep Before - Findings Breakdown
- JWT hardcoded secret (`jwt-python-hardcoded-secret`) - views.py:49
- SQL Injection - 4 rules flagging same f-string query (views.py:134-138)
- SSRF - user-controlled URL in `requests.get()` (views.py:65-70)
- Missing SRI integrity on CDN links (base.html:7,73)
- CSRF token warnings x3 (false positives - tokens are present)

## Scan Results (After Fix)

| Tool | Date | Findings | Report File |
|------|------|----------|-------------|
| Semgrep (auto) | 2026-03-19 | 7 findings (4 removed) | `scans/semgrep-after.txt` |
| TruffleHog (default) | 2026-03-19 | 0 findings | `scans/trufflehog-after.txt` |
| Exploit Tests | 2026-03-19 | 15/15 FAIL + 15/15 functionality PASS | `scans/exploit-tests-after.txt` |

### Semgrep After - What Changed
**Removed (fixed):**
- JWT hardcoded secret - now uses env var
- SQL Injection (4 rules) - replaced with Django ORM

**Remaining (expected/acceptable):**
- 3x CSRF token warnings - false positives (tokens are present in templates)
- 2x Missing SRI integrity on Bootstrap CDN - not in vuln scope
- 1x JWT hardcoded in `tests.py` - exploit test code, not production
- 1x SSRF flag on `requests.get()` - Semgrep can't trace the `_is_url_safe()` guard

---

## Exploit Test Summary (Before Fix)

All 15 tests PASS = all vulnerabilities are exploitable:

| Test | Class | Result | What It Proves |
|------|-------|--------|---------------|
| SQLi UNION attack | `SQLInjectionTest` | PASS | Alice extracts Bob's username via UNION injection |
| SQLi password extraction | `SQLInjectionTest` | PASS | Alice extracts pbkdf2 password hashes from auth_user |
| IDOR view | `IDORTest` | PASS | Alice reads Bob's private archive |
| IDOR edit | `IDORTest` | PASS | Alice overwrites Bob's notes to "HACKED BY ALICE" |
| IDOR delete | `IDORTest` | PASS | Alice deletes Bob's archive entirely |
| XSS in notes | `StoredXSSTest` | PASS | `<script>` tag renders unescaped in browser |
| XSS in content | `StoredXSSTest` | PASS | `<img onerror>` payload renders unescaped |
| JWT forgery | `HardcodedJWTSecretTest` | PASS | Forged token decodes identically to real token |
| Prompt injection exfil | `PromptInjectionToolCallTest` | PASS | LLM tool call fetches attacker URL with stolen data |
| Path traversal | `PathTraversalTest` | PASS | LLM writes file to /tmp/ outside intended directory |
| LLM SQL cross-user | `UnrestrictedLLMSQLTest` | PASS | LLM-generated query returns all users' data |
| LLM SQL destructive | `UnrestrictedLLMSQLTest` | PASS | LLM DELETE query actually executes and destroys data |
| SSRF cloud metadata | `SSRFTest` | PASS | Server fetches AWS metadata endpoint, stores IAM creds |
| SSRF internal scan | `SSRFTest` | PASS | Server probes internal Ollama service |
| SQL error disclosure | `SQLErrorDisclosureTest` | PASS | Malformed SQL leaks table structure to user |

## Exploit Test Summary (After Fix)

All 15 exploit tests FAIL/ERROR = all vulnerabilities are patched:
All 15 functionality tests PASS = app still works correctly:

| Test | Class | Before | After | Fix Applied |
|------|-------|--------|-------|-------------|
| SQLi UNION | `SQLInjectionTest` | PASS | FAIL | Django ORM replaces raw SQL |
| SQLi passwords | `SQLInjectionTest` | PASS | FAIL | Django ORM replaces raw SQL |
| IDOR view | `IDORTest` | PASS | FAIL | `user=request.user` in query |
| IDOR edit | `IDORTest` | PASS | FAIL | `user=request.user` in query |
| IDOR delete | `IDORTest` | PASS | FAIL | `user=request.user` in query |
| XSS notes | `StoredXSSTest` | PASS | FAIL | Removed `\|safe` filter |
| XSS content | `StoredXSSTest` | PASS | FAIL | Removed `\|safe` filter |
| JWT forgery | `HardcodedJWTSecretTest` | PASS | ERROR | Secret from env var, old key invalid |
| Prompt injection | `PromptInjectionToolCallTest` | PASS | FAIL | Domain allowlist blocks evil.com |
| Path traversal | `PathTraversalTest` | PASS | FAIL | Deterministic path, no LLM control |
| LLM SQL cross-user | `UnrestrictedLLMSQLTest` | PASS | FAIL | user_id filter enforced |
| LLM SQL destructive | `UnrestrictedLLMSQLTest` | PASS | FAIL | SELECT-only restriction |
| SSRF cloud | `SSRFTest` | PASS | FAIL | `_is_url_safe()` blocks private IPs |
| SSRF internal | `SSRFTest` | PASS | FAIL | `_is_url_safe()` blocks internal hosts |
| SQL error disclosure | `SQLErrorDisclosureTest` | PASS | FAIL | Generic error message |

| Test | Class | Result | What It Proves |
|------|-------|--------|---------------|
| Search works | `SearchFunctionalityTest` | PASS | Title search returns correct results |
| Empty search | `SearchFunctionalityTest` | PASS | Empty query handled gracefully |
| No cross-user search | `SearchFunctionalityTest` | PASS | Only own archives returned |
| Owner can view | `ArchiveAccessControlTest` | PASS | Users access their own archives |
| Owner can edit | `ArchiveAccessControlTest` | PASS | Users edit their own archives |
| Owner can delete | `ArchiveAccessControlTest` | PASS | Users delete their own archives |
| Other user gets 404 | `ArchiveAccessControlTest` | PASS | Non-owners get 404 |
| Notes escaped | `XSSProtectionTest` | PASS | Script tags are HTML-escaped |
| Content escaped | `XSSProtectionTest` | PASS | HTML content is escaped |
| Token works | `JWTTokenTest` | PASS | JWT endpoint still generates tokens |
| Old secret fails | `JWTTokenTest` | PASS | Old hardcoded secret can't decode |
| Internal URL blocked | `SSRFProtectionTest` | PASS | 169.254.x.x rejected |
| Localhost blocked | `SSRFProtectionTest` | PASS | localhost rejected |
| LLM SELECT works | `LLMSQLRestrictionTest` | PASS | Valid queries still return data |
| Export to correct dir | `PathTraversalProtectionTest` | PASS | File written to exported_summaries/ |

---

## Fixes Applied

### Files Modified
| File | Changes |
|------|---------|
| `views.py` | JWT from env var, SSRF validation, IDOR ownership checks, ORM search, generic errors, SELECT-only LLM SQL, deterministic file paths, prompt injection defenses |
| `settings.py` | dotenv integration, SECRET_KEY/DEBUG/ALLOWED_HOSTS from env vars |
| `view_archive.html` | Removed `\|safe` filter from notes and content |
| `docker-compose.yml` | Added `env_file: .env` |
| `.env` (new) | Generated secrets for DJANGO_SECRET_KEY and JWT_SECRET |
| `.gitignore` | Added `.env` to prevent secret commits |
| `tests.py` | Added 15 functionality tests |

---

## Folder Structure
```
findings/
├── FINDINGS.md          <- this file (tracker)
├── scans/               <- scan output files (before/after)
│   ├── semgrep-before.txt
│   ├── semgrep-custom-before.txt
│   ├── semgrep-after.txt
│   ├── trufflehog-before.txt
│   ├── trufflehog-custom-before.txt
│   ├── trufflehog-after.txt
│   ├── exploit-tests-before.txt
│   └── exploit-tests-after.txt
├── screenshots/         <- browser screenshots (before/after)
└── tests/               <- exploit test scripts
```

## Test Credentials
- admin / password123
- alice / password123
- bob / password123
