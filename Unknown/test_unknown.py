import subprocess
import pytest

@pytest.fixture
def subprocess_data():
    out = subprocess.run(["python", "PS.py", "./Unknown"], capture_output=True, text=True).stdout
    return out

def test_no_vulnerabilities(subprocess_data):
    assert "Vulnerabilities found : 0" in subprocess_data

def test_unknown_count(subprocess_data):
    assert "Variables found       : 14" in subprocess_data

def test_password_unknown(subprocess_data):
    assert "CIS 2.8" in subprocess_data

def test_S3_bucket_unknown(subprocess_data):
    assert "CIS 3.1.4" in subprocess_data

def test_db_encrypted_unknown(subprocess_data):
    assert "CIS 3.2.1" in subprocess_data

def test_db_access_unknown(subprocess_data):
    assert "CIS 3.2.3" in subprocess_data

def test_cloudTrail_unknown(subprocess_data):
    assert "CIS 4.1" in subprocess_data