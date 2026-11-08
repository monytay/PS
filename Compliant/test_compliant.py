import subprocess
import pytest

def test_compliant_count():
    out = subprocess.run(["python", "PS.py", "./Compliant"], capture_output=True, text=True).stdout
    assert "Vulnerabilities found : 0" in out