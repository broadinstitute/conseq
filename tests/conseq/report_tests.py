from ...conseq.report import run_graph_to_dot


def test_rules_to_graph(tmpdir):
    dot = run_graph_to_dot(
        tmpdir,
        """
rule A:
    outputs: {"type": "a-out"}

rule B:
    inputs: in={"type": "a-out"}
    outputs: {"type": "b-out"}

    """,
    )

    assert dot == "x"
