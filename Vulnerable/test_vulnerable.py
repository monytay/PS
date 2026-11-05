import subprocess

def test_vulnerable_count():
    out = subprocess.run(["python", "PS.py", "./Vulnerable"], capture_output=True, text=True).stdout
    assert "Vulnerabilities found : 10" in out