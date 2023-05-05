import re
from ...conseq.exec_client import grep_logs


def test_grep_logs(tmpdir):
    stdout = str(tmpdir.join("stdout"))
    stderr = str(tmpdir.join("stderr"))

    with open(stdout, "wt") as stdout_fd:
        with open(stderr, "wt") as stderr_fd:

            state = {}

            output_files = [stdout, stderr]
            log_grep_pattern = re.compile("output.*")

            # make sure it's fine with no output
            state, lines = grep_logs(state, output_files, log_grep_pattern)

            assert lines == []

            stdout_fd.write("a\nb\noutput: 1\nc\n")
            stdout_fd.flush()

            state, lines = grep_logs(state, output_files, log_grep_pattern)
            assert lines == ["output: 1"]

            # also try multiple lines
            stdout_fd.write("output: 2\n")
            stdout_fd.flush()
            stderr_fd.write("output: 3\n")
            stderr_fd.flush()

            state, lines = grep_logs(state, output_files, log_grep_pattern)
            assert lines == ["output: 2", "output: 3"]

        # lastly after the file is closed, no new lines
        state, lines = grep_logs(state, output_files, log_grep_pattern)
        assert lines == []
