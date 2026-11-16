from conseq import dep


def create_executions_for_all_rules(j):
    """Evaluate every rule against the current artifacts, returning the new rule executions"""
    new_executions = []
    for rule_name in list(j.rule_template_by_name.keys()):
        for transform, inputs in j.find_new_rule_executions(rule_name):
            new_executions.append(j.create_rule_execution(transform, inputs))
    return new_executions


def test_limit_to_rule(tmpdir):
    jobdb = str(tmpdir.join("db"))

    j = dep.open_job_db(jobdb)

    def is_template1(inputs, transform):
        return transform == "template1"

    j.limitStartToTemplates([is_template1])

    # two templates which don't require any inputs.
    template1 = dep.Template([], [], "template1")
    template2 = dep.Template([], [], "template2")
    # one template which requires an object.
    template3 = dep.Template([dep.ForEach("contexts", dict(type="a"))], [], "template3")

    j.add_template(template1)
    j.add_template(template2)
    j.add_template(template3)

    # templates don't create anything until they're evaluated
    assert len(j.get_pending()) == 0

    # After evaluating those templates, we should have only created an execution for template1
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 1

    # however if we add an object, template3 can also execute
    j.add_obj("public", 1, dict(type="a"))
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 2


def test_overwrite_obj(tmpdir):
    jobdb = str(tmpdir.join("db"))

    j = dep.open_job_db(jobdb)
    j.add_template(dep.Template([dep.ForEach("in", {"A": "a"})], [], "transform"))

    # add the object, which results in a rule execution
    id1 = j.add_obj("public", 1, {"A": "a", "mut": {"$value": "1"}})
    objs = j.find_objs("public", {"A": "a"})
    assert len(objs) == 1
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 1
    assert len(j.get_all_executions()) == 0
    rule_exec_id1 = j.get_pending()[0].id

    # add object with same "key" which should result in the old rule execution being replaced
    id2 = j.add_obj("public", 2, {"A": "a", "mut": {"$value": "2"}})
    objs = j.find_objs("public", {"A": "a"})
    assert len(objs) == 1
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 1
    # there should still only be a single rule, but it should be a new rule with the new input
    rule_exec_id2 = j.get_pending()[0].id
    assert id1 != id2
    assert rule_exec_id1 != rule_exec_id2

    # now, try with a different key to make sure it's not that all objects overwrite one another
    id1 = j.add_obj("public", 1, {"B": "b", "mut": {"$filename": "1"}})
    objs = j.find_objs("public", {"B": "b"})
    assert len(objs) == 1
    id2 = j.add_obj("public", 2, {"B": "b", "mut": {"$filename": "2"}})
    objs = j.find_objs("public", {"B": "b"})
    assert len(objs) == 1
    assert id1 != id2

    # create an execution from the rule execution
    # exec_id = j.record_started(j.get_pending()[0].id)


# foreach context where context.type = "context" and context.name exists execute MakeContext yielding (type="context", name exists)
# foreach avana_lib where avana_lib.type = "crispr_dataset" and avana_lib.library = "Avana" withall gecko_libs where gecko_libs.library = "Gecko"


def test_only_new_executions_are_returned(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    j.add_template(
        dep.Template([dep.ForEach("contexts", dict(type="contexts"))], [], "Make")
    )

    j.add_obj("public", 1, dict(type="contexts", name="a"))
    new = j.find_new_rule_executions("Make")
    assert len(new) == 1
    # finding doesn't create anything, so it keeps reporting the same thing
    assert len(j.get_pending()) == 0
    assert len(j.find_new_rule_executions("Make")) == 1

    j.create_rule_execution(*new[0])
    assert len(j.get_pending()) == 1
    # once created, it's no longer reported as new
    assert len(j.find_new_rule_executions("Make")) == 0

    j.add_obj("public", 1, dict(type="contexts", name="b"))
    assert len(j.find_new_rule_executions("Make")) == 1


def test_all_input_rules_are_pending(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    j.add_template(
        dep.Template([dep.ForAll("things", dict(type="thing"))], [], "Merge")
    )

    j.add_obj("public", 1, dict(type="thing", name="a"))
    j.add_obj("public", 1, dict(type="thing", name="b"))
    new = j.find_new_rule_executions("Merge")
    assert len(new) == 1
    rule_exec = j.create_rule_execution(*new[0])
    assert len(rule_exec.inputs) == 1
    assert len(rule_exec.inputs[0][1]) == 2
    assert rule_exec.state == dep.RE_STATUS_PENDING
    assert len(j.get_pending()) == 1


def test_foreach(tmpdir):
    jobdb = str(tmpdir.join("db"))

    templates = [
        dep.Template(
            [dep.ForEach("contexts", dict(type="contexts"))], [], "MakeContexts"
        )
    ]
    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    j.add_obj("public", 1, dict(type="contexts", name="a"))
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 1
    j.add_obj("public", 1, dict(type="contexts", name="b"))
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 2


def test_input_changed(tmpdir):
    jobdb = str(tmpdir.join("db"))

    templates = [
        dep.Template(
            [dep.ForEach("contexts", dict(type="contexts"))], [], "MakeContexts"
        )
    ]
    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    j.add_obj("public", 1, dict(type="contexts", name="a"))
    create_executions_for_all_rules(j)
    pending = j.get_pending()
    assert len(pending) == 1
    exec_id = j.record_started(pending[0].id)
    j.record_completed(
        exec_id,
        pending[0].id,
        dep.STATUS_COMPLETED,
        [dict(name="a", type="context"), dict(name="b", type="context")],
    )

    create_executions_for_all_rules(j)
    pending = j.get_pending()
    assert len(pending) == 0

    j.add_obj("public", 2, dict(type="contexts", name="a"))
    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 1


def test_completion(tmpdir):
    jobdb = str(tmpdir.join("db"))

    templates = [
        dep.Template(
            [dep.ForEach("contexts", dict(type="contexts"))], [], "MakeContexts"
        ),
        dep.Template([dep.ForEach("context", dict(type="context"))], [], "PerContext"),
    ]
    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    j.add_obj("public", 1, dict(type="contexts", name="a"))
    create_executions_for_all_rules(j)
    pending = j.get_pending()
    assert len(pending) == 1

    rule_exec_id = pending[0].id

    execution_id = j.record_started(rule_exec_id)
    j.record_completed(
        execution_id,
        pending[0].id,
        dep.STATUS_COMPLETED,
        [dict(name="a", type="context"), dict(name="b", type="context")],
    )

    create_executions_for_all_rules(j)
    assert len(j.get_pending()) == 2
    for p in j.get_pending():
        assert p.transform == "PerContext"


def test_stuff(tmpdir):
    jobdb = str(tmpdir.join("db"))
    templates = [
        dep.Template(
            [dep.ForEach("contexts", dict(type="contexts"))], [], "MakeContexts"
        ),
        dep.Template(
            [
                dep.ForEach("avana_lib", dict(type="crispr_dataset", library="Avana")),
                dep.ForAll("gecko_libs", dict(library="Gecko")),
            ],
            [],
            "AvanaGeckoMerge",
        ),
        dep.Template(
            [
                dep.ForEach("dataset", dict(type="crispr_dataset")),
                dep.ForEach("context", dict(type="context")),
            ],
            [],
            "CalculateEnrichment",
        ),
        dep.Template(
            [
                dep.ForEach("dataset", dict(type="crispr_dataset")),
                dep.ForEach("parameters", dict(type="atlantis_params")),
            ],
            [],
            "RunAtlantis",
        ),
    ]

    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    def execute(execution_id, transform, inputs):
        if transform == "MakeContexts":
            j.record_completed(
                2,
                execution_id,
                dep.STATUS_COMPLETED,
                [dict(name="a", type="context"), dict(name="b", type="context")],
            )

    j.add_obj("public", 1, dict(type="contexts"))
    j.add_obj("public", 1, dict(type="atlantis_params", parameters="p1"))
    j.add_obj("public", 1, dict(type="atlantis_params", parameters="p2"))
    j.add_obj("public", 1, dict(type="crispr_dataset", library="Avana"))
    j.add_obj("public", 1, dict(type="crispr_dataset", library="Gecko"))

    create_executions_for_all_rules(j)
    for pending in j.get_pending():
        execute(pending.id, pending.transform, pending.inputs)

    # assert False


def _add_rule_with_empty_all_input(j, transform="merge"):
    # "all" inputs are tuples. An input which matched nothing is the empty tuple
    j.add_obj("public", 1, dict(type="single", name="s"))
    single = j.find_objs("public", {"type": "single"})[0]
    with j.transaction():
        return j.rule_set.add_rule("public", (("one", single), ("many", ())), transform)


def test_empty_all_input_is_stored_and_read_back(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    _add_rule_with_empty_all_input(j)

    pending = j.get_pending()
    assert len(pending) == 1
    inputs = dict(pending[0].inputs)
    assert inputs["many"] == ()
    assert inputs["one"].props["name"] == "s"

    # and it survives reopening the database
    j2 = dep.open_job_db(str(tmpdir.join("db")))
    assert dict(j2.get_pending()[0].inputs)["many"] == ()


def test_empty_all_input_is_not_duplicated(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    first = _add_rule_with_empty_all_input(j)
    single = j.find_objs("public", {"type": "single"})[0]

    # the same inputs again should find the existing rule execution, not create another one
    with j.transaction():
        second, created = j.rule_set.add_rule_and_report_new(
            "public", (("one", single), ("many", ())), "merge"
        )
    assert second == first
    assert not created
    assert len(j.get_pending()) == 1


def test_empty_all_input_is_replaced_when_it_becomes_non_empty(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    first = _add_rule_with_empty_all_input(j)
    single = j.find_objs("public", {"type": "single"})[0]
    j.add_obj("public", 1, dict(type="thing", name="t"))
    thing = j.find_objs("public", {"type": "thing"})[0]

    with j.transaction():
        second, created = j.rule_set.add_rule_and_report_new(
            "public", (("one", single), ("many", (thing,))), "merge"
        )
    assert created
    assert second != first
    # the old one was replaced
    assert [r.id for r in j.get_pending()] == [second]


def test_execution_with_empty_all_input_is_recorded(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    rule_exec_id = _add_rule_with_empty_all_input(j)

    execution_id = j.record_started(rule_exec_id)
    started = j.get_started_executions()
    assert [e.id for e in started] == [execution_id]
    assert dict(started[0].inputs)["many"] == ()

    j.add_template(dep.Template([], [], "merge"))
    j.record_completed(
        "t", execution_id, dep.STATUS_COMPLETED, [dict(type="out", name="o")]
    )
    execution = j.get_all_executions()[0]
    assert dict(execution.inputs)["many"] == ()
    assert len(execution.outputs) == 1


def test_empty_all_input_doesnt_break_lineage_queries_or_sanity_checks(tmpdir):
    j = dep.open_job_db(str(tmpdir.join("db")))
    rule_exec_id = _add_rule_with_empty_all_input(j)
    j.add_template(dep.Template([], [], "merge"))
    execution_id = j.record_started(rule_exec_id)
    j.record_completed(
        "t", execution_id, dep.STATUS_COMPLETED, [dict(type="out", name="o")]
    )
    out = j.find_objs("public", {"type": "out"})[0]
    single = j.find_objs("public", {"type": "single"})[0]

    # upstream of the output is the "single" input only. (There's no object for the empty list)
    with j.transaction():
        upstream = j.log.find_all_reachable_objs([out.id])
    assert upstream == {out.id, single.id}
    assert None not in upstream

    downstream = j.find_all_reachable_downstream_objs([single.id])
    assert {o.id for o in downstream} == {single.id, out.id}

    j.find_rule_output_ids("merge")  # runs assert_db_sane()
    assert j.gc() == []
