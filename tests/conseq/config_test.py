from conseq.main import main
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
