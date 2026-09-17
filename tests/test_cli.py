import pytest

from omna_plugin.cli import main


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_mask_command(capsys):
    assert main(["mask", "key AKIAIOSFODNN7EXAMPLE mail a@example.com", "--counts"]) == 0
    out, err = capsys.readouterr()
    assert "[SECRET_AWS_KEY_1]" in out and "AKIAIOSFODNN7EXAMPLE" not in out and "a@example.com" not in out
    assert "AWS_KEY×1" in err and "EMAIL×1" in err


def test_mask_from_stdin(capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("ssn 123-45-6789\n"))
    assert main(["mask", "-"]) == 0
    out, _ = capsys.readouterr()
    assert "123-45-6789" not in out and out.endswith("\n")


def test_allow_then_mask(capsys):
    main(["allow", "a@example.com"])
    capsys.readouterr()
    main(["mask", "mail a@example.com"])
    out, _ = capsys.readouterr()
    assert out.strip() == "mail a@example.com"


def test_version_and_log_empty(capsys):
    assert main(["version"]) == 0
    assert "omna-plugin" in capsys.readouterr()[0]
    assert main(["log"]) == 0
    assert "no receipts" in capsys.readouterr()[0]
    assert main(["log", "--verify"]) == 0
