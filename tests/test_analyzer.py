from app.analyzer import analyze_source


def ids_for(source: str) -> set[str]:
    return {finding["rule_id"] for finding in analyze_source(source)["findings"]}


def test_detects_dynamic_execution_and_bare_except():
    report = analyze_source("eval(user_input)\ntry:\n    work()\nexcept:\n    pass\n")
    assert {"CS001", "CS009"}.issubset({f["rule_id"] for f in report["findings"]})
    assert report["summary"]["total_findings"] == 2


def test_detects_subprocess_shell_true():
    assert "CS002" in ids_for("import subprocess\nsubprocess.run(cmd, shell=True)\n")


def test_detects_unsafe_pickle_and_yaml():
    found = ids_for("import pickle\nimport yaml\npickle.loads(data)\nyaml.load(data)\n")
    assert {"CS003", "CS004"}.issubset(found)


def test_credential_placeholders_are_not_flagged():
    assert "CS005" not in ids_for('API_KEY = "YOUR_API_KEY"\npassword = ""\n')
    assert "CS005" in ids_for('API_KEY = "abc123-real-looking-value"\n')


def test_detects_sql_interpolation_and_tls_verification_off():
    source = 'query = f"SELECT * FROM users WHERE id={user_id}"\ncursor.execute(query)\nrequests.get(url, verify=False)\n'
    found = ids_for(source)
    assert "CS008" in found
    # The rule detects interpolation directly in execute(), not indirect variable flow.
    assert "CS007" not in found
    assert "CS007" in ids_for('cursor.execute(f"SELECT * FROM users WHERE id={user_id}")\n')


def test_detects_mutable_default_and_weak_hash():
    found = ids_for("import hashlib\ndef f(items=[]):\n    return hashlib.md5(b'x').hexdigest()\n")
    assert {"CS006", "CS010"}.issubset(found)


def test_safe_patterns_do_not_trigger_some_rules():
    source = "import subprocess\nsubprocess.run(['echo', 'hello'], check=True)\n\ndef f(items=None):\n    if items is None:\n        items = []\n    return items\n"
    found = ids_for(source)
    assert "CS002" not in found
    assert "CS010" not in found


def test_syntax_error_is_returned_as_finding():
    report = analyze_source("def broken(:\n    pass\n")
    assert report["findings"][0]["rule_id"] == "CS000"
    assert report["summary"]["by_severity"]["info"] == 1


def test_report_metadata_is_present():
    report = analyze_source("print('hello')\n")
    assert report["tool"] == "CodeSentinel"
    assert report["analysis_mode"] == "static_ast_rules"
    assert report["summary"]["rules_checked"] == 11
