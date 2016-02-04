import dep

# foreach context where context.type = "context" and context.name exists execute MakeContext yielding (type="context", name exists)
# foreach avana_lib where avana_lib.type = "crispr_dataset" and avana_lib.library = "Avana" withall gecko_libs where gecko_libs.library = "Gecko"

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

j = dep.Jobs()
for t in templates:
    j.add_template(t)

j.add_obj(1, dict(type="contexts"))
j.add_obj(1, dict(type="atlantis_params", parameters="p1"))
j.add_obj(1, dict(type="atlantis_params", parameters="p2"))
j.add_obj(1, dict(type="crispr_dataset", library="Avana"))
j.add_obj(1, dict(type="crispr_dataset", library="Gecko"))

def execute(execution_id, transform, inputs):
    if transform == "MakeContexts":
        j.record_completed(2, execution_id, dep.STATUS_COMPLETED, [dict(name="a", type="context"), dict(name="b", type="context")])

for pending in j.get_pending():
    execute(pending.id, pending.transform, pending.inputs)

print(j.to_dot())
