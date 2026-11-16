# Open issues

## Stale outputs when an `all` input changes

This section is written to be read without access to the code. It explains the background, the
problem, what has and hasn't been verified, and the options for fixing it.

### Status

**Mostly fixed, in `CONSEQ_SEQ=blockers` mode only.** On startup, while conseq removes stale
artifacts, it now also removes the outputs (and everything derived from them) of every rule with an
`all` input, if either of these is true:

- a _new_ artifact is going to be added which is an input to that rule or to any rule upstream of it,
- a _new rule_ (one which wasn't in the file the last time conseq ran) is upstream of it, because it
  could produce artifacts the rule consumes.

This is deliberately conservative: it only asks whether a new artifact or rule _could_ feed an input, not
whether the list really changes. It goes through the same confirmation prompt as stale rules. The
reproduction below now ends with only `c(count=2)`. A randomized test checks that growing the artifacts
and the rules between runs gives the same result as a fresh run.

If the database has no record at all of the rules from the previous run, every rule would look new, so
new rules are not checked in that case. (New artifacts still are.)

Still open:

1. **Existing databases.** Orphans which were already left behind have no lineage, so nothing
   finds them. This change only prevents new ones.
2. **Default mode is unchanged.** Without `CONSEQ_SEQ=blockers` nothing is removed, and the problem
   described below still happens.
3. **Changes which don't go through startup.** Only new `add-if-missing` artifacts and new rules are
   checked. Other ways an `all` rule's input list could change between runs (for example artifacts changed
   in place, or a rule whose definition changed so that it now produces different artifacts) haven't been
   examined. A rule whose definition changed already has its own outputs removed, along with what
   derives from them.

The rest of this section describes the problem as it was before the change. The analysis of the options
is still useful for item 1.

### Background: how conseq works (the parts that matter here)

Conseq is a workflow tool. A `.conseq` file declares **artifacts** and **rules**.

- An **artifact** is a set of key/value properties, for example `{"type": "c", "count": "2"}`.
  Artifacts live in a SQLite database. An artifact's identity is its properties: adding an
  artifact whose properties match an existing one doesn't create a second copy. (Properties
  written as `{"$value": "x"}` are "non-key": changing those overwrites the existing artifact in
  place instead of creating a new one. Nothing below depends on that, but it's why identical
  outputs collapse into one artifact.)
- A **rule** has input queries and a command to run, and declares the artifacts it produces. An input
  query is either **foreach**, meaning the rule runs once per matching artifact, or **`all`**, meaning
  the rule runs once with the whole list of matching artifacts bound to the input.
- A **rule execution** is a rule applied to specific input artifacts. Conseq creates rule
  executions by matching the stored artifacts against each rule's input queries, runs them,
  and stores the artifacts they produce. Those become inputs to other rules.
- Conseq is **incremental**. It is run repeatedly against the same database. Each run
  re-matches every rule against the stored artifacts, and an execution that already exists isn't
  created again.
- Lineage is recorded: for each execution, which artifacts went in and which came out. This is
  used for cascading deletes (removing an artifact also removes everything derived from it),
  for cleaning up, and for reconciling rule changes.

**How an execution's identity is decided.** Each rule execution has a key built from the rule name and
the artifacts bound to its _foreach_ inputs. The artifacts bound to `all` inputs are deliberately
left out of that key. This lets conseq notice "the same execution, but its `all` input is now
different", as opposed to "a different execution".

When conseq finds a rule execution with the same key as an existing one, it compares the
`all` inputs too:

- If they're the same, nothing happens (the execution already exists).
- If they differ, the old rule execution is **removed** and a new one is created. The rule is
  rerun with the new, current input list. This is the behavior we want: the rule's result
  depends on the whole list, so it must be recomputed.

**Reconciling rule changes.** If a rule's definition changes between runs, conseq finds all the
artifacts which that rule produced (using the recorded lineage), deletes them and everything derived
from them, and reruns the rule. (This asks for confirmation, or is automatic with a flag.)

### The problem

When an execution is replaced because its `all` input changed, the **old execution's output
artifacts are not removed**. Removing the old rule execution deletes the execution record and its
lineage links, but not the artifacts themselves. They stay in the database as ordinary artifacts.

Reproduction. The first run has a single `b` artifact. A second `b` is added before the second run:

```
# run 1
add-if-missing {"type": "b", "n": "0"}

# run 2: one more line
add-if-missing {"type": "b", "n": "1"}

# in both runs
rule c:
    inputs: bs=all {"type": "b"}
    outputs: {"type": "c", "count": "{{ inputs.bs|length }}"}
```

In shorthand, with `R(inputs) -> outputs`:

```
run 1:  c(all b(0))       -> c(count=1)
run 2:  c(all b(0), b(1)) -> c(count=2)
```

After run 2 the database contains **both** `c(count=1)` and `c(count=2)`. Run 2 itself did the right
thing (it reran `c` on both inputs). The problem is that the output of the superseded execution was left
behind.

### What was checked

All of this was run, using the `CONSEQ_SEQ=blockers` scheduler mode (see "Relation to the scheduler
work" below):

- Both artifacts exist after run 2.
- **The leftover artifact has no producer on record.** The `count=2` artifact is recorded as the
  output of the new execution. `count=1` is recorded as the output of no execution at all.
- **Changing the rule's definition doesn't clean it up.** Reconciling finds a rule's outputs by their
  recorded lineage, so it doesn't see `count=1`. After editing rule `c` and rerunning, `count=2`
  was deleted and recreated, and `count=1` was still there.
- If the new execution produces an artifact with _identical_ properties to the old one, they
  collapse into a single artifact and nothing is stale. The problem only appears when an
  output depends on the input (a count, a list of names, a checksum, and so on).

Not run on the old v2 code. The code path for replacing an execution is unchanged from v2, so the
same behavior is expected there.

### Why it matters

- **Downstream rules run on stale data.** A rule consuming `c` sees both `c(count=1)` and `c(count=2)`
  and runs once on each. Its outputs (and those derived from them) then also include results
  from the outdated inputs.
- **Nothing marks the artifact as outdated.** It looks like any other artifact, and there's no
  producer on record, so it can't be told apart from an artifact that's current.
- **It can't be cleaned up with the usual tools.** Cascading deletion and rule-change reconciling
  both follow lineage, and the lineage is gone.
- **Existing databases may already contain these.** In an older version, a chain of `all` rules
  could run on a partial set of inputs and be rerun later. That produces exactly this situation.
  Switching to the new scheduler doesn't repair it.
- **The orphans accumulate.** Each time an `all` input changes between runs, a rule whose
  outputs depend on its inputs leaves another one behind.

### Constraints for any fix

- Artifacts aren't only produced by executions. Artifacts with no producer on record can be
  legitimate, so "no producer" alone can't be used to identify stale outputs. Two known cases:

  1. `add-if-missing` artifacts (they carry a `$manually-added` property),
  2. the rewritten versions of artifacts which conseq creates when it resolves external references
     (xref) before running a rule. (Not checked in detail.)

  Artifacts from `remember-executed` statements do get a producing execution recorded, so they aren't
  an exception.

- Deleting artifacts is destructive. The existing deletion paths (stale rules, `rm`) either ask
  first or require an explicit flag.
- Outputs can refer to files, including files in cloud storage. Deleting an artifact doesn't delete
  the file, but it does drop conseq's record of it.
- Deleting an output also invalidates everything derived from it, and those executions may be expensive.
  Whether that's what the user wants isn't obvious. In the example above, a rule consuming `c(count=1)`
  was run on outdated data, so rerunning is arguably correct, but it's still a large cost to
  incur silently.

### Options

**A. Delete the old outputs (and what was derived from them) when an execution is replaced.**
Reuses the machinery that reconciling stale rules already has. Simple to explain, and the result
matches a fresh run from scratch. Costs and open questions:

- _When?_ Deleting at the moment of replacement means downstream rules lose their inputs before the
  new outputs exist. Deleting when the new execution completes is safer but means tracking the
  link between the old and new execution.
- _Confirmation?_ Stale rules ask first. Replacing an `all` execution happens on nearly every
  run where inputs grow, so asking each time may be too noisy; deleting silently may be too
  surprising.
- Old and new outputs with identical properties are the same artifact. The deletion must not remove
  an artifact which the new execution is about to produce.

**B. Keep the lineage, and mark the execution as superseded instead of deleting it.**
Keep the old execution and its links to its outputs, but flag it as obsolete. Cascading deletes,
reconciling and cleanup could then find the outputs, and a separate step (a command, or part of
garbage collection) removes them. Downstream rules would also need to ignore artifacts whose only
producer is superseded. This needs a new column or state, so it's a schema change. The database does have a
versioned migration path (`schema_version` in the `settings` table, currently 3, with an upgrade
step per version), so a migration is possible, but it would be the first change to the schema in this
branch of the work. It preserves the most information.

**C. Detect orphans and offer a cleanup command.**
Don't change the replacement behavior. Add a way to find artifacts which are not
manually added, have no producer, and aren't one of the expected exceptions above, and let the user
remove them. Least invasive, but it's a cleanup tool after the fact, doesn't prevent the problem, and
the exceptions (especially xref rewrites) make "no producer" an unreliable signal.

**D. Document it and do nothing.** Cheapest. Users hit it whenever an `all` input changes between runs.

### Questions to decide

1. Should replacing an `all` execution delete its old outputs automatically, ask first, or only mark them?
2. Should the deletion cascade to downstream executions (rerunning them on the new data)?
3. Is a schema change (a new `schema_version`, option B) acceptable, or should this stay within the
   existing tables?
4. Should databases which already contain orphans be repaired (a one-off cleanup), or only prevented
   from getting worse?
5. How should identical old/new outputs be handled so a fix never deletes a still-needed artifact?

### Relation to the scheduler work

This was found while working on how rules with `all` inputs are scheduled. A new scheduler (enabled
with the environment variable `CONSEQ_SEQ=blockers`) makes a rule with an `all` input wait until every rule
that could feed it has finished, so it no longer runs on partial input sets within a single run.
That removes the main way this happens _within one run_, but not the case here, where inputs change
_between_ runs. The scheduler work did not cause this behavior and doesn't fix it.

### Tests

- `test_outputs_of_replaced_all_execution_are_removed` (functional tests) is the reproduction. It
  used to be an expected failure and now passes.
- `test_growing_the_inputs_between_runs_matches_a_fresh_run` (randomized tests) runs on some of the
  initial artifacts and some of the rules, adds the rest, reruns, and compares with a fresh run.
  Disabling the startup check makes it fail.
- `test_new_rule_upstream_of_an_all_rule_removes_its_old_outputs` covers the new-rule case directly.

## Not covered by tests

- Reattaching to executions which were still running when conseq last exited. The scheduler is
  told about them at startup, but no test exercises it. The randomized tests only cover cancelling
  and rerunning after a crash.
- Failed executions in the randomized tests, and changes between runs other than new artifacts. These
  cases were checked by hand and aren't committed tests:
  - rerunning unchanged,
  - fixing a rule which failed,
  - changing a rule's definition,
  - adding a downstream rule with an `all` input to a finished pipeline,
  - rerunning a database written by the default scheduler,
  - forcing a rule in the middle of a pipeline to rerun.
