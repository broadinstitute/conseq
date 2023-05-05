from conseq import dep


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

    # After adding those templates, we should have only created an execution for template1
    assert len(j.get_pending()) == 1

    # however if we add an object, template3 can also execute
    j.add_obj("public", 1, dict(type="a"))
    len(j.get_pending()) == 2


def test_overwrite_obj(tmpdir):
    jobdb = str(tmpdir.join("db"))

    j = dep.open_job_db(jobdb)
    j.add_template(dep.Template([dep.ForEach("in", {"A": "a"})], [], "transform"))

    # add the object, which results in a rule execution
    id1 = j.add_obj("public", 1, {"A": "a", "mut": {"$value": "1"}})
    objs = j.find_objs("public", {"A": "a"})
    assert len(objs) == 1
    j.refresh_rules()
    assert len(j.get_pending()) == 1
    assert len(j.get_all_executions()) == 0
    rule_exec_id1 = j.get_pending()[0].id

    # add object with same "key" which should result in the old rule execution being replaced
    id2 = j.add_obj("public", 2, {"A": "a", "mut": {"$value": "2"}})
    objs = j.find_objs("public", {"A": "a"})
    assert len(objs) == 1
    j.refresh_rules()
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
    j.refresh_rules()
    assert len(j.get_pending()) == 1
    j.add_obj("public", 1, dict(type="contexts", name="b"))
    j.refresh_rules()
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
    j.refresh_rules()
    pending = j.get_pending()
    assert len(pending) == 1
    exec_id = j.record_started(pending[0].id)
    j.record_completed(
        exec_id,
        pending[0].id,
        dep.STATUS_COMPLETED,
        [dict(name="a", type="context"), dict(name="b", type="context")],
    )

    j.refresh_rules()
    pending = j.get_pending()
    assert len(pending) == 0

    j.add_obj("public", 2, dict(type="contexts", name="a"))
    j.refresh_rules()
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
    j.refresh_rules()
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

    j.refresh_rules()
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

    j.refresh_rules()
    for pending in j.get_pending():
        execute(pending.id, pending.transform, pending.inputs)

    print(j.to_dot(True))
    # assert False
