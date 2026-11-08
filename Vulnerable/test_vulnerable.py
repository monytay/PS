import subprocess
import pytest

@pytest.fixture
def subprocess_data():
    out = subprocess.run(["python", "PS.py", "./Vulnerable"], capture_output=True, text=True).stdout
    return out

def test_vulnerable_count(subprocess_data):
    assert "Vulnerabilities found : 11" in subprocess_data

def test_password(subprocess_data):
    assert "CIS 2.8" in subprocess_data

def test_S3_bucket(subprocess_data):
    assert "CIS 3.1.4" in subprocess_data

def test_db_encrypted(subprocess_data):
    assert "CIS 3.2.1" in subprocess_data

def test_db_access(subprocess_data):
    assert "CIS 3.2.3" in subprocess_data

def test_cloudTrail(subprocess_data):
    assert "CIS 4.1" in subprocess_data

def test_administrator_ports_access(subprocess_data):
    assert "CIS 6.3" in subprocess_data