from conseq.config import read_deps
from conseq.hashcache import HashCache
from conseq.template import create_jinja2_env
from conseq.static_analysis.model import (
    Rule,
    Binding,
    Constraints,
    Pair,
    Artifact,
    OutputArtifact,
)
import os
from .model import createDAG


def analyze(file: str, dir: str):
    # Create a temporary hashcache
    hashcache = HashCache(os.path.join(dir, "hashcache"))
    jinja2_env = create_jinja2_env()

    # Read the rules from the depfile
    rules = read_deps(file, hashcache, jinja2_env)

    # Convert conseq rules to static analysis model rules
    model_rules = []
    for rule in rules:
        # Convert inputs to bindings
        bindings = []
        for input_spec in rule.inputs:
            constraints_props = []
            for key, value in input_spec.json_obj.items():
                if isinstance(value, dict) or isinstance(value, list):
                    # Skip complex objects for simplicity
                    continue
                constraints_props.append(Pair(name=key, value=value))

            cardinality = "all" if input_spec.for_all else "one"
            binding = Binding(
                variable=input_spec.variable,
                cardinality=cardinality,
                constraints=Constraints(properties=constraints_props),
            )
            bindings.append(binding)

        # Convert outputs to output artifacts
        outputs = []
        if rule.outputs:
            for output in rule.outputs:
                props = []
                for key, value in output.items():
                    if isinstance(value, dict) or isinstance(value, list):
                        # Skip complex objects for simplicity
                        continue
                    props.append(Pair(name=key, value=value))

                # Assume "one" cardinality for outputs
                artifact = Artifact(properties=props)
                output_artifact = OutputArtifact(artifact=artifact, cardinality="one")
                outputs.append(output_artifact)

        model_rule = Rule(name=rule.name, inputs=bindings, outputs=outputs)
        model_rules.append(model_rule)

    # Create the DAG
    dag = createDAG(model_rules)

    # Print the DAG
    print(f"DAG Analysis for {file}:")
    print(f"Total rules: {len(dag.rules)}")
    print(f"Root rules (no inputs): {len(dag.roots)}")

    print("\nRule dependencies:")
    for rule_node in dag.rules:
        print(f"\nRule: {rule_node.rule.name}")
        if rule_node.inputs:
            print("  Inputs:")
            for input_node in rule_node.inputs:
                print(
                    f"    - From rule '{input_node.produced_by.rule.name}' via binding '{input_node.binding.variable}'"
                )
        if rule_node.outputs:
            print("  Outputs:")
            for output_node in rule_node.outputs:
                print(
                    f"    - To rule '{output_node.consumed_by.rule.name}' via binding '{output_node.binding.variable}'"
                )

    return 0
