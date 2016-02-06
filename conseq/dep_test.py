from . import dep

# foreach context where context.type = "context" and context.name exists execute MakeContext yielding (type="context", name exists)
# foreach avana_lib where avana_lib.type = "crispr_dataset" and avana_lib.library = "Avana" withall gecko_libs where gecko_libs.library = "Gecko"

def test_foreach(tmpdir):
    jobdb = str(tmpdir.join("db"))

    templates = [
        dep.Template([dep.ForEach("contexts", dict(type="contexts"))],
                     [],
                     "MakeContexts")
        ]
    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    j.add_obj(1, dict(type="contexts", name="a"))
    assert len(j.get_pending()) == 1
    j.add_obj(1, dict(type="contexts", name="b"))
    assert len(j.get_pending()) == 2

def test_input_changed(tmpdir):
    jobdb = str(tmpdir.join("db"))

    templates = [
        dep.Template([dep.ForEach("contexts", dict(type="contexts"))],
                     [],
                     "MakeContexts")
        ]
    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    j.add_obj(1, dict(type="contexts", name="a"))
    pending = j.get_pending()
    assert len(pending) == 1
    j.record_completed(2, pending[0].id, dep.STATUS_COMPLETED, [dict(name="a", type="context"), dict(name="b", type="context")])

    pending = j.get_pending()
    assert len(pending) == 0

    j.add_obj(2, dict(type="contexts", name="a"))
    assert len(j.get_pending()) == 1

def test_completion(tmpdir):
    jobdb = str(tmpdir.join("db"))

    templates = [
        dep.Template([dep.ForEach("contexts", dict(type="contexts"))],
                     [],
                     "MakeContexts"),
        dep.Template([dep.ForEach("context", dict(type="context"))],
                     [],
                     "PerContext")
        ]
    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    j.add_obj(1, dict(type="contexts", name="a"))
    pending = (j.get_pending())
    assert len(pending) == 1

    j.record_completed(2, pending[0].id, dep.STATUS_COMPLETED, [dict(name="a", type="context"), dict(name="b", type="context")])

    assert len(j.get_pending()) == 2
    for p in j.get_pending():
        assert p.transform == "PerContext"

def test_stuff(tmpdir):
    jobdb = str(tmpdir.join("db"))
    templates = [
        dep.Template([dep.ForEach("contexts", dict(type="contexts"))],
                     [],
                     "MakeContexts",
                     expected=[dep.InstanceTemplate(dict(type="context", name=dep.WILDCARD))]),

        dep.Template([dep.ForEach("avana_lib", dict(type="crispr_dataset", library="Avana")), dep.ForAll("gecko_libs", dict(library="Gecko")) ],
                     [],
                     "AvanaGeckoMerge",
                     expected=[dep.InstanceTemplate(dict(type="crispr_dataset", library="Avana+Gecko"))]),

        dep.Template([dep.ForEach("dataset", dict(type="crispr_dataset")),
                      dep.ForEach("context", dict(type="context"))],
                     [],
                     "CalculateEnrichment",
                     expected=[dep.InstanceTemplate(dict(type="enrich_result", dataset=dep.WILDCARD, context=dep.WILDCARD))]),

        dep.Template([dep.ForEach("dataset", dict(type="crispr_dataset")),
                      dep.ForEach("parameters", dict(type="atlantis_params"))],
                     [],
                     "RunAtlantis",
                     expected=[dep.InstanceTemplate(dict(type="atlantis_result", dataset=dep.WILDCARD, parameters=dep.WILDCARD))]
                     )
    ]

    j = dep.open_job_db(jobdb)
    for t in templates:
        j.add_template(t)

    def execute(execution_id, transform, inputs):
        if transform == "MakeContexts":
            j.record_completed(2, execution_id, dep.STATUS_COMPLETED, [dict(name="a", type="context"), dict(name="b", type="context")])

    j.add_obj(1, dict(type="contexts"))
    j.add_obj(1, dict(type="atlantis_params", parameters="p1"))
    j.add_obj(1, dict(type="atlantis_params", parameters="p2"))
    j.add_obj(1, dict(type="crispr_dataset", library="Avana"))
    j.add_obj(1, dict(type="crispr_dataset", library="Gecko"))

    for pending in j.get_pending():
        execute(pending.id, pending.transform, pending.inputs)

    print(j.to_dot())
    #assert False