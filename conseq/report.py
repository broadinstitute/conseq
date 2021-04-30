from .dataflow.dataflow import DataFlow, construct_dataflow
from conseq.config import Rules, read_rules
import os
from conseq.dep import open_job_db, Obj, DEFAULT_SPACE
from collections import namedtuple, defaultdict

def graph_to_dot(g: DataFlow) -> str:
    from io import StringIO

    out = StringIO()
    out.write("digraph {\n")

    def _format_value(v):
        # if isinstance(v, FileRef):
        #     v = "FileRef({})".format(v.path)
        assert isinstance(v, str)
        return v.replace("\"", "")

    for artifact_index, artifact in g.get_artifacts():
        # print(artifact)
        label = "\n".join(["{}={}".format(k, _format_value(v)) for k, v in artifact])
        out.write("a_{} [ shape=box, label=\"{}\" ];\n".format(artifact_index, label))

    for rule_index, rule in g.get_rules():
        out.write("r_{} [ shape=ellipse, label=\"{}\" ];\n".format(rule_index, rule.name))
        print("rule inputs", rule.inputs)
        print("rule outputs", rule.inputs)
        for input_name, input_ids in g.rule_id_to_inputs[rule_index].items():
            for input_id in input_ids:
                #            input_id = g.artifact_model_to_id.get(input_model)
                if input_id is not None:
                    out.write("a_{} -> r_{} ;\n".format(input_id, rule_index))
                else:
                    print("missing input")

        for output_id in g.rule_id_to_outputs[rule_index]:
            # print("rule output", output)
            # output_id = g.artifact_model_to_id.get(output)
            if output_id is not None:
                out.write("r_{} -> a_{} ;\n".format(rule_index, output_id))
            else:
                print("missing output")

    out.write("}")
    return out.getvalue()

def run_graph_to_dot(tmpdir, config):
    state_dir = str(tmpdir) + "/state"
    config_file = None  # str(tmpdir.join("config"))
    depfile = str(tmpdir) + "/t.conseq"
    with open(depfile, "wt") as fd:
        fd.write(config)
    # with open(config_file, "wt") as fd:
    #     fd.write("let x='v'\n")

    rules = read_rules(state_dir, depfile, config_file)
    g = construct_dataflow(rules)
    return graph_to_dot(g)



def generate_report_cmd(state_dir, dest_dir):
    from .template import create_template_jinja2_env
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    jinja2_env = create_template_jinja2_env()

    def all_objs_props(objs, exclude=[]):
        props = set()
        for obj in objs:
            props.update(obj.props.keys())
        props = props.difference(exclude)
        return sorted(props)

    def prop_summary(obj):
        result = []
        for name, value in obj.props.items():
            if isinstance(value, dict) and "$value" in value:
                value = value["$value"]
            value = str(value)
            if len(value) > 40:
                value = value[:5]+"..."+value[-20:]
            result.append((name, value))
        return sorted(result)

    import jinja2
    def value_cell(value):
        if isinstance(value, dict):
            if "$value" in value:
                return jinja2.Markup(f"<td class='transient-value'>{jinja2.escape(value['$value'])}</td>")
            elif "$filename" in value:
                return jinja2.Markup(f"<td class='filename-value'>{jinja2.escape(value['$filename'])}</td>")
            elif "$file_url" in value:
                return jinja2.Markup(f"<td class='file-url-value'>{jinja2.escape(value['$file_url'])}</td>")
        return jinja2.Markup(f"<td>{jinja2.escape(str(value))}</td>")

    jinja2_env.filters.update({"all_objs_props": all_objs_props,
                               "prop_summary": prop_summary,
                               "value_cell": value_cell,
                        'is_tuple': lambda x: isinstance(x, tuple)})
    j = open_job_db(os.path.join(state_dir, "db.sqlite3"))

    objs = j.find_objs(DEFAULT_SPACE, {})
    executions = j.get_all_executions()
    execution_by_input = defaultdict(lambda: [])
    execution_by_output = {}
    for execution in executions:
        for name, input in execution.inputs:
            if not isinstance(input, tuple):
                inputs=[input]
            else:
                inputs = input
            for input in inputs:
                execution_by_input[input.id].append(execution)
        for output in execution.outputs:
            execution_by_output[output.id] = execution

    index_template =   jinja2_env.get_template("index.html")

    obj_template = jinja2_env.get_template("artifact.html")

    execution_template = jinja2_env.get_template("execution.html")

    def write_artifact(obj : Obj):
        fn = f"{dest_dir}/obj_{obj.id}.html"
        with open(fn , "wt") as fd:
            execution = execution_by_output.get(obj.id)
            downstream_executions = execution_by_input[obj.id]
            fd.write(obj_template.render(obj=obj, execution=execution, downstream_executions=downstream_executions))

    def get_disk_usage(job_dir):
        if job_dir is None:
            return 0

        size = 0
        for fn in os.listdir(job_dir):
            fn_path = os.path.join(job_dir, fn)
            size += os.path.getsize(fn_path)
        return size

    def write_execution(execution, disk_usage):
        fn = f"{dest_dir}/exec_{execution.id}.html"

        files = []
        if execution.job_dir:
            for output_fn in os.listdir(execution.job_dir):
                files.append((os.path.relpath(os.path.join(execution.job_dir, output_fn), dest_dir), output_fn))

        with open(fn , "wt") as fd:
            fd.write(execution_template.render(execution=execution, files=files, disk_usage=disk_usage))

    ExecSummary = namedtuple("ExecSummary", "execs disk_usage")
    execs_by_name = defaultdict(lambda: ExecSummary([], 0))
    objs_by_type = defaultdict(lambda: [])
    # write a file per object
    for obj in objs:
        write_artifact(obj)
        objs_by_type[obj.props.get("type", "")].append(obj)

    # write a file per execution
    for execution in executions:
        disk_usage = get_disk_usage(execution.job_dir)
        write_execution(execution, disk_usage)
        execs, total_disk_usage = execs_by_name[execution.transform]
        execs_by_name[execution.transform] = ExecSummary(execs + [execution], total_disk_usage+disk_usage)

    rules_with_size = [ (name, summary.disk_usage) for name, summary in execs_by_name.items() ]
    rules_with_size.sort(key=lambda x: x[1], reverse=True)

    with open(f"{dest_dir}/index.html", "wt") as fd:
        sorted_objs_by_type = sorted(objs_by_type.items())
        sorted_execs_by_name = sorted(execs_by_name.items())
        fd.write(index_template.render(objs_by_type=sorted_objs_by_type, execs_by_name=sorted_execs_by_name, rules_with_size=rules_with_size))
