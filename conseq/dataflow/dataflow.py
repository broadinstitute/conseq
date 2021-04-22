from .partial_key_index import PartialKeyIndex
from .models import ANY_VALUE, AbstractArtifact, AnyValueSingleton
from typing import Union, Dict, Sequence
from conseq.parser import InputSpec
from conseq.config import Rules, read_rules



class RuleModel:
    def __init__(self, rule_name: str, inputs: Dict[str, AbstractArtifact], outputs: Sequence[AbstractArtifact]):
        self.name = rule_name
        self.inputs = dict([(k, tuple(v)) for k, v in inputs.items()])
        self.outputs = [tuple(output) for output in outputs]

class DataFlow:
    def __init__(self):
        self.rules = {}
        self.next_artifact_id = 0
        self.artifact_model_to_id = {}
        self.artifact_id_to_model = {}
        self.artifact_index = PartialKeyIndex()
        self.rule_id_to_outputs = {}
        self.rule_id_to_inputs = {}
        self.is_done = False

    def add_artifact(self, artifact: AbstractArtifact):
        assert not self.is_done
        assert not isinstance(artifact, dict)
        artifact = tuple(artifact)
        if artifact not in self.artifact_model_to_id:
            artifact_model_id = self.next_artifact_id
            self.artifact_model_to_id[artifact] = artifact_model_id
            self.artifact_id_to_model[artifact_model_id] = artifact
            self.next_artifact_id += 1
            self.artifact_index.add(artifact, artifact_model_id)
        else:
            artifact_model_id = self.artifact_model_to_id[artifact]
        return artifact_model_id

    def add_rule(self, rule: RuleModel):
        assert not self.is_done
        self.rules[id(rule)] = rule
        outputs = []
        for output in rule.outputs:
            artifact_model_id = self.add_artifact(output)
            outputs.append(artifact_model_id)
        self.rule_id_to_outputs[id(rule)] = outputs

    def done(self):
        for rule in self.rules.values():
            inputs = {}
            for name, artifact_model in rule.inputs.items():
                inputs[name] = self.artifact_index.get(artifact_model)
            self.rule_id_to_inputs[id(rule)] = inputs
        self.is_done = True

    def get_artifacts(self):
        return self.artifact_id_to_model.items()

    def get_rules(self):
        return self.rules.items()

def construct_dataflow(rules: Rules):
    def to_value(v: Union[Dict[str, str], str]) -> Union[AnyValueSingleton, str]:
        if isinstance(v, dict):
            ANY_VALUE
        else:
            assert isinstance(v, str)
            return v

    def artifact_to_model(artifact) -> AbstractArtifact:
        return tuple([(k, to_value(v)) for k, v in artifact.items()])

    g = DataFlow()
    for rule in rules.rule_by_name.values():
        inputs = dict()
        for input in rule.inputs:
            assert isinstance(input, InputSpec)
            inputs[input.variable] = artifact_to_model(input.json_obj)

        outputs = []
        for output in rule.outputs:
            assert isinstance(output, dict)
            outputs.append(artifact_to_model(output))

        model = RuleModel(rule.name, inputs, outputs)
        g.add_rule(model)

    for obj in rules.objs:
        g.add_artifact(artifact_to_model(obj))

    g.done()

    return g
