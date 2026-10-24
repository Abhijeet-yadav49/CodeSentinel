"""AST-based static checks for common Python security and quality issues.

This module never imports or executes the source being analyzed. Rules are
heuristics intended to support code review, not replace it.
"""
from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    line: int
    column: int
    snippet: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


RULES = [
    {"id": "CS001", "title": "Dynamic code execution", "severity": "critical", "description": "eval() and exec() can execute dynamically constructed code."},
    {"id": "CS002", "title": "Shell command with shell=True", "severity": "high", "description": "Passing a command through a shell can enable command injection when input is untrusted."},
    {"id": "CS003", "title": "Unsafe pickle deserialization", "severity": "critical", "description": "Unpickling untrusted data can execute attacker-controlled code."},
    {"id": "CS004", "title": "Potentially unsafe YAML load", "severity": "high", "description": "yaml.load without a safe loader can construct arbitrary Python objects."},
    {"id": "CS005", "title": "Possible hardcoded secret", "severity": "high", "description": "A credential-like variable is assigned a non-empty string literal."},
    {"id": "CS006", "title": "Weak hash algorithm", "severity": "medium", "description": "MD5 and SHA-1 are unsuitable for security-sensitive hashing."},
    {"id": "CS007", "title": "Possible SQL injection", "severity": "high", "description": "SQL passed to execute() appears to be built with interpolation or concatenation."},
    {"id": "CS008", "title": "TLS certificate verification disabled", "severity": "high", "description": "verify=False disables TLS certificate verification in common HTTP clients."},
    {"id": "CS009", "title": "Bare except clause", "severity": "low", "description": "A bare except catches BaseException, including interrupts and system-exit signals."},
    {"id": "CS010", "title": "Mutable default argument", "severity": "medium", "description": "A list, dict, or set default is shared between calls to the function."},
    {"id": "CS011", "title": "OS shell command execution", "severity": "high", "description": "os.system() invokes a command through a system shell."},
]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CREDENTIAL_NAME = re.compile(r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)", re.I)
_PLACEHOLDERS = {"", "changeme", "change-me", "example", "placeholder", "your_api_key", "your-secret", "none", "null", "redacted", "xxx", "***"}


class _Analyzer(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source_lines = source.splitlines()
        self.findings: list[Finding] = []

    def _add(self, node: ast.AST, rule_id: str, severity: str, title: str, message: str, recommendation: str) -> None:
        line = max(1, getattr(node, "lineno", 1))
        col = max(1, getattr(node, "col_offset", 0) + 1)
        snippet = self.source_lines[line - 1].strip() if line <= len(self.source_lines) else ""
        self.findings.append(Finding(rule_id, severity, title, message, line, col, snippet[:500], recommendation))

    @staticmethod
    def _name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = _Analyzer._name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _is_mutable_default(node: ast.AST) -> bool:
        return isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp))

    @staticmethod
    def _looks_interpolated(node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func)
        short = name.rsplit(".", 1)[-1]
        if short in {"eval", "exec"}:
            self._add(node, "CS001", "critical", "Dynamic code execution", f"{short}() executes code supplied at runtime.", "Avoid dynamic execution. Use explicit parsing, dispatch tables, or a constrained expression parser instead.")
        if short in {"run", "Popen", "call", "check_call", "check_output"}:
            shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            if shell_true:
                self._add(node, "CS002", "high", "Shell command with shell=True", "A subprocess call enables shell parsing; untrusted values can become shell syntax.", "Prefer an argument list with shell=False. Validate inputs and avoid concatenating user-controlled values into commands.")
        if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
            self._add(node, "CS003", "critical", "Unsafe pickle deserialization", "pickle can invoke code during deserialization when the input is malicious.", "Never unpickle untrusted data. Prefer a data-only format such as JSON, with schema validation.")
        if name in {"yaml.load", "yaml.unsafe_load"}:
            safe_loader = any(k.arg in {"Loader", "loader"} and isinstance(k.value, ast.Attribute) and k.value.attr in {"SafeLoader", "CSafeLoader"} for k in node.keywords)
            if not safe_loader:
                self._add(node, "CS004", "high", "Potentially unsafe YAML load", "yaml.load() does not visibly specify a safe loader.", "Use yaml.safe_load() or pass yaml.SafeLoader explicitly, and validate the resulting data.")
        if short in {"md5", "sha1"} and (name.startswith("hashlib.") or name in {"md5", "sha1"}):
            self._add(node, "CS006", "medium", "Weak hash algorithm", f"{name} is not appropriate for collision-resistant security uses.", "For integrity/security use SHA-256 or stronger. For passwords, use a dedicated password hash such as Argon2id, scrypt, or bcrypt.")
        if short == "execute" and node.args and self._looks_interpolated(node.args[0]):
            self._add(node, "CS007", "high", "Possible SQL injection", "The SQL argument to execute() appears to use string interpolation or concatenation.", "Use parameterized queries (placeholders plus a separate parameter tuple) rather than assembling SQL strings.")
        if any(k.arg == "verify" and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
            self._add(node, "CS008", "high", "TLS certificate verification disabled", "verify=False disables certificate verification for this request.", "Keep certificate verification enabled. If a private CA is used, configure its trusted certificate bundle.")
        if name == "os.system":
            self._add(node, "CS011", "high", "OS shell command execution", "os.system() executes a command through the system shell.", "Use subprocess.run() with a list of arguments and shell=False; validate any externally supplied arguments.")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self._add(node, "CS009", "low", "Bare except clause", "This handler catches every exception, including KeyboardInterrupt and SystemExit.", "Catch the specific exception types you can handle and allow unexpected errors to propagate or be logged.")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = list(node.args.defaults)
        positional = list(node.args.args)[-len(defaults):] if defaults else []
        for arg, default in zip(positional, defaults):
            if self._is_mutable_default(default):
                self._add(default, "CS010", "medium", "Mutable default argument", f"Parameter '{arg.arg}' uses a mutable default value shared across calls.", "Use None as the default and create a new list/dict/set inside the function.")
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if default is not None and self._is_mutable_default(default):
                self._add(default, "CS010", "medium", "Mutable default argument", f"Parameter '{arg.arg}' uses a mutable default value shared across calls.", "Use None as the default and create a new list/dict/set inside the function.")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_credential_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_credential_assignment([node.target], node.value)
        self.generic_visit(node)

    def _check_credential_assignment(self, targets: list[ast.AST], value: ast.AST | None) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        literal = value.value.strip()
        if not literal or literal.lower() in _PLACEHOLDERS or "${" in literal or literal.startswith(("<", "your_", "YOUR_")):
            return
        for target in targets:
            names = [target.id] if isinstance(target, ast.Name) else []
            if isinstance(target, (ast.Tuple, ast.List)):
                names.extend(e.id for e in target.elts if isinstance(e, ast.Name))
            if any(_CREDENTIAL_NAME.search(name) for name in names):
                self._add(target, "CS005", "high", "Possible hardcoded secret", f"Credential-like variable '{names[0]}' is assigned a string literal.", "Load secrets from environment variables or a secret manager. Rotate the credential if it was real and committed to version control.")
                break


def analyze_source(source: str) -> dict[str, Any]:
    """Analyze Python source and return a JSON-serializable report."""
    if not isinstance(source, str):
        raise TypeError("source must be a string")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        line = exc.lineno or 1
        lines = source.splitlines()
        finding = Finding(
            rule_id="CS000", severity="info", title="Python syntax error",
            message=exc.msg, line=line, column=exc.offset or 1,
            snippet=lines[line - 1].strip() if line <= len(lines) else "",
            recommendation="Fix the syntax error before relying on static analysis results.",
        )
        findings = [finding]
    else:
        visitor = _Analyzer(source)
        visitor.visit(tree)
        findings = visitor.findings

    # Stable deduplication for rules that can overlap on the same node.
    unique: dict[tuple[str, int, int, str], Finding] = {}
    for finding in findings:
        unique[(finding.rule_id, finding.line, finding.column, finding.title)] = finding
    findings = sorted(unique.values(), key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.line, f.column, f.rule_id))
    counts = {level: sum(1 for f in findings if f.severity == level) for level in ("critical", "high", "medium", "low", "info")}
    return {
        "tool": "CodeSentinel",
        "version": "0.1.0",
        "analysis_mode": "static_ast_rules",
        "summary": {"total_findings": len(findings), "by_severity": counts, "lines_of_code": len(source.splitlines()), "rules_checked": len(RULES)},
        "findings": [f.to_dict() for f in findings],
        "disclaimer": "Heuristic static analysis only. Findings may be false positives or false negatives; review the code and context.",
    }
