"""Intentionally risky demo code. Do not use in production."""
import hashlib
import pickle
import subprocess

API_KEY = "sk_live_replace_me"


def run_query(cursor, user_input, filters=[]):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    return eval(user_input)


def load_payload(data):
    return pickle.loads(data)


def run_command(command):
    return subprocess.run(command, shell=True, check=False)


def fingerprint(value):
    return hashlib.md5(value.encode()).hexdigest()


try:
    print("ready")
except:
    pass
