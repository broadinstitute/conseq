import logging

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


def _rules_warned_about(tmpdir, caplog, conseq_text):
    path = str(tmpdir.join("t.conseq"))
    with open(path, "wt") as fd:
        fd.write(conseq_text)

    with caplog.at_level(logging.WARNING, logger="conseq.config"):
        config.read_deps(
            path, HashCache(str(tmpdir.join("hashcache"))), create_jinja2_env()
        )

    return [
        r.getMessage() for r in caplog.records if "neither an outputs" in r.getMessage()
    ]


def test_warns_about_rule_with_no_outputs_or_output_types(tmpdir, caplog):
    warnings = _rules_warned_about(
        tmpdir,
        caplog,
        """
        rule a:
            run "echo" with "hello"
        """,
    )
    assert len(warnings) == 1
    assert "rule a " in warnings[0]


def test_no_warning_for_rules_which_declare_their_outputs(tmpdir, caplog):
    warnings = _rules_warned_about(
        tmpdir,
        caplog,
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
    assert warnings == []


def test_no_warning_for_publish_rules(tmpdir, caplog):
    warnings = _rules_warned_about(
        tmpdir,
        caplog,
        """
        rule publish_it:
            inputs: x={"type": "x"}
            publish: "gs://bucket/path"
        """,
    )
    assert warnings == []
