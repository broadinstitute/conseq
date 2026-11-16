import logging

import pytest

from conseq.errors import MissingOutputDeclaration
from conseq.hashcache import HashCache
from conseq.main import main
from conseq import config
from conseq.template import create_jinja2_env
from conseq import commands
from unittest.mock import create_autospec


def test_parsing_default_config_in_home_dir(tmpdir, monkeypatch):
    # make a fake ~/.conseq file which sets a single variable
    tmpdir.join("mock_home").mkdir()
    tmpdir.join("mock_home").join(".conseq").write("let VALUE='1'\n")
    monkeypatch.setenv("HOME", str(tmpdir.join("mock_home")))

    tmpdir.join("sample.conseq").write(
        """ 
    
    eval "assert config['VALUE'] == '1' "
    
    """
    )

    # make sure that "run" properly expands ~/.conseq
    main(["--dir", str(tmpdir.join("state")), "run", str(tmpdir.join("sample.conseq"))])

    # make a mock version of 'export' which _just_ verifies that the conseq directory expansion worked correctly
    mock_export_cmd = create_autospec(commands.export_cmd)

    def _mock_export_cmd(
        state_dir, depfile, config_file, dest_gs_path, exclude_patterns
    ):
        assert config_file == str(tmpdir.join("mock_home").join(".conseq"))

    mock_export_cmd.side_effect = _mock_export_cmd
    monkeypatch.setattr(commands, "export_cmd", mock_export_cmd)

    # make sure that "export" properly expands ~/.conseq
    main(
        [
            "--dir",
            str(tmpdir.join("state")),
            "export",
            str(tmpdir.join("sample.conseq")),
            "gs://test",
        ]
    )


def _read(tmpdir, conseq_text):
    path = str(tmpdir.join("t.conseq"))
    with open(path, "wt") as fd:
        fd.write(conseq_text)

    return config.read_deps(
        path, HashCache(str(tmpdir.join("hashcache"))), create_jinja2_env()
    )


def test_rule_with_no_outputs_or_output_types_is_an_error_with_blockers(
    tmpdir, monkeypatch
):
    monkeypatch.setenv("CONSEQ_SEQ", "blockers")
    with pytest.raises(MissingOutputDeclaration, match="rule a "):
        _read(
            tmpdir,
            """
            rule a:
                run "echo" with "hello"
            """,
        )


def test_rule_with_no_outputs_or_output_types_is_a_warning_by_default(
    tmpdir, monkeypatch, caplog
):
    monkeypatch.delenv("CONSEQ_SEQ", raising=False)
    with caplog.at_level(logging.WARNING, logger="conseq.config"):
        rules = _read(
            tmpdir,
            """
            rule a:
                run "echo" with "hello"
            """,
        )
    assert len(list(rules)) == 1
    assert "rule a has neither" in caplog.text


@pytest.mark.parametrize("seq", [None, "blockers"])
def test_rules_which_declare_their_outputs_are_accepted(tmpdir, monkeypatch, seq):
    if seq:
        monkeypatch.setenv("CONSEQ_SEQ", seq)
    rules = _read(
        tmpdir,
        """
        type thing (value)

        rule with_outputs:
            outputs: {"type": "x"}

        rule with_output_types:
            output_types: (thing)
            run "echo" with "hello"

        rule with_no_outputs:
            outputs: none
        """,
    )
    assert len(list(rules)) == 3


def test_publish_rules_dont_need_to_declare_outputs(tmpdir, monkeypatch):
    monkeypatch.setenv("CONSEQ_SEQ", "blockers")
    rules = _read(
        tmpdir,
        """
        rule publish_it:
            inputs: x={"type": "x"}
            publish: "gs://bucket/path"
        """,
    )
    assert len(list(rules)) == 1
