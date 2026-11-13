from conseq.sequencer import BlockingSequencer, SimpleSequencer, create_sequencer


def test_default_sequencer(monkeypatch):
    monkeypatch.delenv("CONSEQ_SEQ", raising=False)
    assert type(create_sequencer([])) is SimpleSequencer


def test_blockers_sequencer_selected_by_env_var(monkeypatch, caplog):
    monkeypatch.setenv("CONSEQ_SEQ", "blockers")
    assert type(create_sequencer([])) is BlockingSequencer
    assert "BlockingSequencer" in caplog.text


def test_unrecognized_env_var_falls_back_to_default(monkeypatch, caplog):
    monkeypatch.setenv("CONSEQ_SEQ", "bogus")
    assert type(create_sequencer([])) is SimpleSequencer
    assert "bogus" in caplog.text
