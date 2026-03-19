# Vulnerable Archive - Security Assessment

Module 10 Capstone Project - AI Cybersecurity Course

A Django 6.0 + Ollama LLM application with **12 intentional vulnerabilities** that were identified, exploited, and fixed using a test-based approach.

## [View the Full Interactive Security Report](https://mazradwan.github.io/ai-cybersecurity-module-10/)

The report includes before/after code comparisons, scan results, exploit test results, and detailed fix documentation for all 12 vulnerabilities.

## Vulnerabilities Found & Fixed

| # | Type | Vulnerability | Severity |
|---|------|--------------|----------|
| 1 | Secrets | Hardcoded JWT Secret | HIGH |
| 2 | Secrets | Django SECRET_KEY exposed in source | CRITICAL |
| 3 | XSS | Stored XSS via `\|safe` filter | HIGH |
| 4 | SQLi | SQL Injection in search (f-string) | CRITICAL |
| 5 | Broken Access Control | IDOR - no ownership check | HIGH |
| 6 | Prompt Injection | LLM data exfiltration via tool calling | HIGH |
| 7 | Prompt Injection | Path traversal - LLM controls file path | HIGH |
| 8 | Prompt Injection / SQLi | Unrestricted LLM-generated SQL | CRITICAL |
| 9 | Info Disclosure | DEBUG = True | MEDIUM |
| 10 | Misconfiguration | Empty ALLOWED_HOSTS | MEDIUM |
| 11 | SSRF | Server fetches user URL with no validation | HIGH |
| 12 | Info Disclosure | Raw SQL errors exposed to user | MEDIUM |

## Approach

1. **Scan** - Semgrep (SAST), TruffleHog (secrets), manual code review
2. **Exploit** - 15 tests that prove each vulnerability is exploitable (all PASS before fix)
3. **Fix** - Patched all 12 vulnerabilities without breaking app functionality
4. **Verify** - Same 15 exploit tests now FAIL (blocked) + 15 new functionality tests PASS

## Tools Used

- **Semgrep** - Static analysis (11 findings before, 7 after - 4 fixed, rest false positives)
- **TruffleHog** - Secret scanning
- **Django TestCase** - 30 tests total (15 exploit + 15 functionality)
- **Manual Code Review** - LLM/AI vulnerabilities, IDOR, XSS

## Running the App

```bash
docker compose up -d
```

App runs at `http://localhost:8001` (port mapped from 8000).

Test credentials: `alice` / `password123`, `bob` / `password123`, `admin` / `password123`

The app works with or without a `.env` file. Without it, fallback values are used for secrets. To use custom secrets, create a `.env` at the project root:

```
DJANGO_SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-here
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1
```

## Running Tests

```bash
docker compose exec app-mod10 python manage.py test archiver -v 2
```

Expected results after fixes:
- 15 exploit tests: FAIL/ERROR (all vulnerabilities blocked)
- 15 functionality tests: PASS (app still works)

## Project Structure

```
ai-cybersecurity-module-10/
├── report.html                  <- Interactive security assessment report
├── findings/                    <- Scan outputs and evidence
│   ├── FINDINGS.md              <- Vulnerability tracker
│   └── scans/                   <- Raw tool output (before/after)
│       ├── semgrep-before.txt
│       ├── semgrep-after.txt
│       ├── trufflehog-before.txt
│       ├── trufflehog-after.txt
│       ├── exploit-tests-before.txt
│       └── exploit-tests-after.txt
├── vulnerable_archive/          <- Django application
│   ├── archiver/
│   │   ├── views.py             <- Main fixes (8 of 12 vulns)
│   │   ├── tests.py             <- 30 tests (exploit + functionality)
│   │   ├── models.py
│   │   ├── llm_utils.py         <- Ollama LLM integration
│   │   └── templates/           <- XSS fix in view_archive.html
│   └── vulnerable_archive/
│       └── settings.py          <- Secrets/config fixes (3 of 12 vulns)
├── docker-compose.yml
├── Dockerfile
└── .gitignore                   <- .env excluded from commits
```

## Files Modified

| File | Changes |
|------|---------|
| `views.py` | JWT env var, SSRF validation, IDOR checks, ORM search, generic errors, SELECT-only LLM SQL, deterministic paths, prompt injection defenses |
| `settings.py` | dotenv integration, SECRET_KEY/DEBUG/ALLOWED_HOSTS from env vars |
| `view_archive.html` | Removed `\|safe` filter from notes and content |
| `docker-compose.yml` | Added env_file (optional) |
| `.gitignore` | Added `.env` |
| `tests.py` | Added 15 functionality tests |
