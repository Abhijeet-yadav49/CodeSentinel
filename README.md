<p align="center">
  <img src="assets/codesentinel-banner.svg" alt="CodeSentinel — Catch risky patterns before they ship" width="100%">
</p>

<p align="center">
  <strong>A lightweight, AST-based security and code-quality checker for Python.</strong><br>
  Find suspicious patterns, inspect the exact line, and get a practical remediation hint — without executing the code you submit.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/FastAPI-0.1.0-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Analysis-AST%20%7C%20Rule--based-9FE870" alt="AST rule-based analysis">
  <img src="https://img.shields.io/badge/Rules-11-243047" alt="11 rules">
  <img src="https://img.shields.io/badge/Status-Portfolio%20project-6C7A93" alt="Portfolio project">
</p>

<p align="center">
  <a href="#-features">Features</a> ·
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-rule-catalog">Rule catalog</a> ·
  <a href="#-api">API</a> ·
  <a href="#-security--limitations">Security & limitations</a>
</p>

At a glance
	
What it is	A browser-based Python static analyzer powered by Python's built-in ast module.
How it works	Parses source text and applies explicit, deterministic heuristic rules.
What it returns	Rule ID, severity, line and column, a source snippet, an explanation, and remediation advice.
What it does not do	It does not import or execute the code being analyzed, and it does not call an AI service.


[!IMPORTANT]
CodeSentinel is a learning and developer-review aid — not a replacement for a full security audit. A finding is a signal to investigate, not proof of exploitability. No findings does not mean code is secure.

✨ Features
<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🔎 Static analysis</h3>
      <p>Uses Python's standard-library AST to inspect calls, assignments, exception handlers, and function defaults without executing submitted source.</p>
    </td>
    <td width="50%" valign="top">
      <h3>📍 Actionable findings</h3>
      <p>Shows rule IDs, severity, exact line/column, a source snippet, why the pattern matters, and a suggested remediation.</p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧪 Interactive browser UI</h3>
      <p>Paste code, load the bundled demo, or select a local <code>.py</code> file. Filter findings by severity.</p>
    </td>
    <td width="50%" valign="top">
      <h3>📦 Developer-friendly outputs</h3>
      <p>Export reports as JSON or use the FastAPI endpoints to integrate analysis into a local workflow.</p>
    </td>
  </tr>
</table>

Built with
Python · ast · FastAPI · Pydantic · HTML · CSS · JavaScript · Pytest
🚀 Quick start
Requirements
- Python 3.10 or newer
- pip
1. Get the code
git clone https://github.com/Abhijeet-yadav49/CodeSentinel.git
cd CodeSentinel
2. Create an environment and install dependencies
<details open>
<summary><strong>Windows · PowerShell</strong></summary>

py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
If PowerShell blocks activation, use Command Prompt instead:
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
</details>

<details>
<summary><strong>macOS · Linux</strong></summary>

python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
</details>

3. Start CodeSentinel
uvicorn app.main:app --reload
Open http://127.0.0.1:8000 in your browser.
Local route	Purpose
/	CodeSentinel web interface
/docs	Interactive FastAPI / OpenAPI documentation
/health	Service health response
/api/rules	List configured rules
/api/analyze	Analyze submitted Python source (POST)


The current app exposes interactive API docs at /docs. If you later disable OpenAPI documentation in FastAPI configuration, update this table to match.

🧭 Try the demo
1. Open the web interface.
2. Select Load sample to populate the intentionally risky demo snippet.
3. Click Analyze code.
4. Review findings by severity, inspect the line numbers, and expand the remediation guidance.
5. Select Export JSON to download the report.
The same demo fixture is available at [`samples/vulnerable_example.py`](samples/vulnerable_example.py). It intentionally contains suspicious patterns so you can test the configured rules. It is not production code and should not be executed as a demo script.
🛡️ Rule catalog
CodeSentinel currently implements 11 heuristic rules:
Rule	Severity	Detects	Why review it?
CS001	Critical	eval() / exec()	Dynamically executes code supplied at runtime.
CS002	High	Common subprocess calls with shell=True	Shell parsing can make untrusted input dangerous.
CS003	Critical	pickle.load() / pickle.loads()	Unpickling untrusted data can execute attacker-controlled code.
CS004	High	yaml.load() without a recognized safe loader	May construct arbitrary Python objects, depending on loader and library behavior.
CS005	High	Credential-like variable assigned a non-placeholder string literal	May indicate a hardcoded secret; false positives are possible.
CS006	Medium	hashlib.md5() / hashlib.sha1()	Weak choices for security-sensitive collision resistance.
CS007	High	Interpolated/concatenated SQL passed directly to execute()	May allow SQL injection if data is untrusted.
CS008	High	verify=False argument	Disables TLS certificate verification in supported call patterns.
CS009	Low	Bare except:	Catches exceptions too broadly, including interrupt/system-exit signals.
CS010	Medium	Mutable list/dict/set function defaults	The same mutable object can be shared across calls.
CS011	High	os.system()	Invokes a command through the system shell.


Severity is a rule-defined prioritization, not a proof that every flagged instance is exploitable.
🔌 API
POST /api/analyze
Request JSON:
{
  "code": "eval(user_input)"
}
Example using curl:
curl -X POST "http://127.0.0.1:8000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{"code":"eval(user_input)"}'
The response includes the tool/version, analysis mode, summary counts, rule findings, and a disclaimer. Each finding can include a rule ID, severity, title, message, line, column, source snippet, and recommendation. The API accepts a maximum of 200,000 characters per source submission.
Other endpoints
Method	Endpoint	Purpose
GET	/health	Health check and app version
GET	/api/rules	Configured rule definitions
GET	/docs	Interactive OpenAPI UI


✅ Run tests
From the project root:
python -m pytest -q
The test suite covers selected analyzer rules, safe-pattern cases, syntax-error reporting, result metadata, and HTTP endpoints.
🐳 Run with Docker
Build and start the container from the project root:
docker build -t codesentinel .
docker run --rm -p 8000:8000 codesentinel
Then open http://127.0.0.1:8000.
🔐 Security, privacy & limitations
- Source is not executed. CodeSentinel parses the submitted Python source as text and walks its AST; it does not import or run the code being analyzed.
- No application-level source persistence. The current app does not save submitted code to its own database or files. Submitted source is sent to the server running the app so it can be analyzed; hosting providers or infrastructure may have separate logging/retention behavior.
- Use trusted deployments only. Do not submit confidential or proprietary source to a hosted instance unless you trust its operator and have reviewed the hosting and logging configuration.
- No authentication or rate limiting is implemented. Before exposing the app to unrestricted public traffic, add authentication where appropriate, request rate limiting, deployment hardening, monitoring, and privacy controls.
- Rules are heuristic. The analyzer does not do whole-program data-flow or taint analysis. For example, CS007 catches supported interpolation/concatenation patterns passed directly to execute() but does not trace an SQL string stored in a variable. Aliases, indirect calls, and alternate syntax may evade rules.
- Expect false positives and false negatives. CS005 can flag test fixtures or benign constants. Review each finding in its code context.
- External font request. The web interface loads fonts from Google Fonts, which means the browser may contact Google to retrieve those fonts.
🗺️ Roadmap
- [ ] Add data-flow tracking for SQL construction and untrusted input sources.
- [ ] Add SARIF output for code-scanning integrations.
- [ ] Add configurable rules and inline suppression comments.
- [ ] Add CI workflows, coverage reporting, and pinned dependency lockfiles.
- [ ] Add safe multi-file project scanning with file-count and size limits.
📁 Project structure
CodeSentinel/
├── app/
│   ├── analyzer.py          # AST-based rule engine
│   ├── main.py              # FastAPI application and endpoints
│   └── static/
│       ├── index.html       # Browser interface
│       ├── styles.css       # UI styles
│       └── app.js           # Browser interactions
├── assets/
│   └── codesentinel-banner.svg
├── samples/
│   └── vulnerable_example.py
├── tests/
│   ├── test_analyzer.py
│   └── test_api.py
├── Dockerfile
├── requirements.txt
├── pyproject.toml
└── README.md
📄 License
No license file has been added yet. Before publishing this repository for reuse or accepting outside contributions, choose a license and commit the corresponding LICENSE file. Public visibility alone does not automatically grant permission to reuse the code.
<p align="center">
  <sub>Built for developers who want clearer code reviews. Review findings in context and keep security decisions evidence-based.</sub>
</p>
