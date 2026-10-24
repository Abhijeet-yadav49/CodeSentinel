# CodeSentinel

**CodeSentinel** is a small, runnable Python static-analysis web app. It parses source with Python's built-in `ast` module and applies deterministic rules for common risky patterns. It does not import or execute analyzed code, and it does not call an AI service.

## Features

- Browser UI for pasting source or selecting a local `.py` file
- 11 rule IDs covering dynamic execution, shell invocation, unsafe deserialization, possible hardcoded credentials, weak hashes, possible SQL injection, disabled TLS verification, bare `except`, and mutable defaults
- Line/column references, source snippets, severity, and remediation advice
- FastAPI JSON endpoint and health endpoint; interactive API docs are disabled
- JSON report export from the UI
- Tests for analyzer rules and HTTP endpoints
- Dockerfile for local container runs

## Requirements

- Python 3.10+
- pip

## Run locally

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## Run tests

```bash
python -m pytest -q
```

## API

`POST /api/analyze`

Request:

```json
{"code": "eval(user_input)"}
```

Response contains `tool`, `version`, `analysis_mode`, a summary, findings, and a disclaimer. Source is limited to 200,000 characters per request.

Other endpoints:

- `GET /health`
- `GET /api/rules`

Interactive API documentation and the OpenAPI schema are disabled. The analysis endpoint
is still used by the website and remains discoverable to anyone who can inspect browser
network requests. Add authentication, rate limiting, and deployment hardening before
exposing this app publicly; disabling API docs does not make the API private.

## Try the demo

The UI has a **Load sample** button. The same intentionally risky example is stored in `samples/vulnerable_example.py`. It is a demo fixture and should not be treated as production code. Click **Analyze code** to see the configured rules trigger.

## Current rules

| Rule | Severity | What it flags |
|---|---|---|
| CS001 | Critical | `eval()` / `exec()` calls |
| CS002 | High | Common subprocess calls with `shell=True` |
| CS003 | Critical | `pickle.load()` / `pickle.loads()` |
| CS004 | High | `yaml.load()` without an explicit safe loader |
| CS005 | High | Credential-like names assigned non-placeholder string literals |
| CS006 | Medium | MD5 / SHA-1 function calls |
| CS007 | High | Interpolated/concatenated SQL expression passed directly to `execute()` |
| CS008 | High | `verify=False` argument |
| CS009 | Low | Bare `except:` handlers |
| CS010 | Medium | Mutable list/dict/set defaults on functions |
| CS011 | High | `os.system()` calls |

## Design and limitations

This is a rule-based static analyzer, not a full security scanner. AST rules detect syntax patterns and do not perform whole-program data-flow or taint analysis. For example, CS007 currently catches interpolation passed directly into `execute()` but does not trace SQL stored in a variable first. CS005 can flag test fixtures or benign constants. Some rule checks require recognizable names and syntax; alternate aliases or indirect calls can evade them. Findings need human review, and an empty report does not mean code is secure.

The API does not persist submitted code. The current web app is intended for local/demo use; before exposing it publicly, add authentication, request rate limiting, deployment hardening, and appropriate privacy controls.

## Next engineering improvements

1. Add data-flow tracking for SQL construction and user-input sources.
2. Add SARIF output for code-scanning integrations.
3. Add rule configuration and ignore comments.
4. Add CI workflows, coverage reporting, and pinned dependency lockfiles.
5. Add safe multi-file project scanning with file-count and size limits.

## License

Choose and add a license before publishing this repository publicly.
