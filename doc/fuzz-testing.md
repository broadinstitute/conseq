# Fuzz testing the scheduler

The scheduler decides when rule executions get created and started, based on which executions
have completed. The order in which executions complete is not deterministic, so the fuzz tests
generate random pipelines and random completion orders and check that the result is always the
same.

The tests are in `tests/conseq/fuzz_test.py` and the support code is in
`tests/conseq/fuzz_harness.py`. They use [Hypothesis](https://hypothesis.readthedocs.io/), so when
a test fails, Hypothesis shrinks the failure down to a small pipeline and a short schedule.

## Running

The fuzz tests carry the `fuzz` pytest marker and are **excluded from a plain `pytest` run**
because they can be slow when they find a failure. Run them explicitly:

```
poetry run pytest -m fuzz
```

Useful variations:

```
# run many more generated cases (the default is 50 per test)
FUZZ_EXAMPLES=500 poetry run pytest -m fuzz

# run only one of the tests
poetry run pytest -m fuzz -k test_completion_order

# show the log output (hidden by default)
poetry run pytest -m fuzz -s
```

Note: naming the file directly (`pytest tests/conseq/fuzz_test.py`) selects nothing, because the
default options deselect the `fuzz` marker. Add `-m fuzz`.

At the default size a passing run takes about 10 seconds. A failing run can take minutes, because
when Hypothesis finds a failure it then tries many simplified variants (each one a full conseq
run) to find the smallest pipeline and schedule which still fails. This is called shrinking.
Hypothesis stores failures in `.hypothesis/` and replays them first on the next run.

## What gets generated

**A pipeline** (`Pipeline` in the harness) is a set of rules arranged in levels. A rule at level
`N` produces artifacts of type `TN`, and consumes artifacts from lower levels, which guarantees
the pipeline terminates. Level 0 holds the artifacts added with `add-if-missing`. Rules can have:

- no inputs, or up to three inputs,
- "foreach" inputs (`x={"type": "T1"}`) and `all` inputs (`x=all {"type": "T1"}`),
- one or two outputs.

Every output value is a pure function of the rule's inputs. For example
`r3[{{ inputs.x0.value }},{{ inputs.x1|length }}]#0`: foreach inputs contribute their value, `all`
inputs contribute the number of artifacts they were given. This means a rule that ran against an
incomplete set of artifacts produces a visibly different artifact.

**A schedule** is the sequence of decisions about which running executions complete next, and how
many complete at once. It is drawn from Hypothesis, so it is varied and shrinkable. The number of
available slots (1-4) is also generated.

**An optional crash**: the run can be interrupted at a chosen point and restarted. Executions
which were running at that point are cancelled and rerun, as they would be after a real crash.

## How the harness controls ordering

`run_pipeline()` in the harness calls the real `depexec.main()`, with two things replaced:

1. `depexec.execute` is wrapped. The real function still runs, so outputs are rendered by the real
   template code, but the execution it returns reports "still running" until the harness
   releases it.
2. `time.sleep` is replaced. `main_loop` sleeps whenever there is nothing useful to do, so
   each sleep is treated as a "tick" at which the harness chooses which running executions to
   release. (This is why `main_loop` doesn't need any test-specific hooks.)

## What is checked

The expected final state is computed independently of conseq (`expected_state()` in the harness),
by evaluating the pipeline one level at a time so each rule sees the complete set of artifacts
from lower levels. After the run (and after the restart, if there was a crash) the test checks:

- the set of artifacts is exactly the expected set (so a stale output from a rule that ran on a
  partial set is a failure),
- each rule has the expected number of completed executions,
- nothing is left pending or started,
- `main_loop` did not log that the sequencer still considered executions in progress when
  it stopped (this means an execution was lost track of),
- running conseq again on the finished state creates no new executions.

## Known failure: chained `all` rules

An `all` input over artifacts which are produced by another rule that has an `all` input (directly
or transitively) is not handled. The `SimpleSequencer` evaluates every deferred rule at the same
moment, so the downstream rule can run before the artifacts it needs exist, and then run again
when more arrive, leaving a stale output behind.

- `test_completion_order_does_not_change_result` does not generate these pipelines.
- `test_chained_all_rules` does, and is marked `xfail` (non-strict). Because the failure is
  expected, it doesn't shrink it, and it runs deterministically with more examples so that it
  reliably finds the failure. If you fix the limitation it will start reporting XPASS; at that
  point remove the `xfail` and fold it into the main test by removing the restriction in
  `pipelines()`.

## Reproducing a failure

When a test fails, Hypothesis prints the falsifying example: the `Pipeline`, the slot count, the
crash tick, and each release decision. Hypothesis also saves it in `.hypothesis/`, so rerunning the
same test replays it first. To get the conseq text for a pipeline, call
`render_conseq(pipeline)` from `tests/conseq/fuzz_harness.py`.

## Extending it

- To generate new kinds of rules, change `pipelines()` in `fuzz_test.py`, and update
  `render_conseq()` and `expected_state()` in the harness together, so the oracle keeps matching.
- To check that the fuzzer is still effective, temporarily break the scheduler (for example make
  `_has_an_all_input` in `conseq/sequencer.py` return `False`) and confirm the test fails. A fuzzer
  that can't find a deliberately introduced bug isn't providing much assurance.

## Limitations

- Restarts only test the "cancel what was running and rerun" path. Reattaching to executions that
  are still running would need a fake client with a `reattach` method.
- Failed executions aren't injected yet, and neither is re-running after changing an artifact.
- Only artifact values and execution counts are compared, not which execution produced which
  artifact.
