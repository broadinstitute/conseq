from .xref import Resolver
from typing import Tuple, Dict, Optional, List, Any, Union, Protocol
from .types import BoundInput, PropsType
import json
import os
from dataclasses import dataclass

@dataclass
class ExecResult:
    failure_msg: Optional[str]
    outputs: Optional[List[Dict[str, Any]]]
    cache_key: Optional[str] = None


class ResolveState:
    def add_script(self, script):
        raise Exception("Cannot call on base class")


class ProcLike(Protocol):
    def poll(self) -> Optional[int]:
        ...
    def terminate(self):
        ...


class ClientExecution:
    exec_xref: str

    def __init__(
        self,
        transform: str,
        id: int,
        job_dir: str,
        proc: ProcLike,
        outputs: Optional[List[PropsType]],
        captured_stdouts: Union[List[str], Tuple[str, str]],
        desc_name: str,
        executor_parameters: dict,
        *,
        watch_regex=None,
    ) -> None:
        self.transform = transform
        self.id = id
        self.proc = proc
        self.job_dir = job_dir
        self.outputs = outputs
        self.captured_stdouts = captured_stdouts
        self.desc_name = desc_name
        self.log_grep_state = {}
        self.watch_regex = watch_regex
        self.executor_parameters = executor_parameters
        assert job_dir != None

    def _resolve_filenames(self, props):
        props_copy = {}
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                full_filename = os.path.join(self.job_dir, v["$filename"])
                if not os.path.exists(full_filename):
                    raise Exception(
                        "Attempted to publish results which referenced file that did not exist: {}".format(
                            full_filename
                        )
                    )
                v = {"$filename": full_filename}
            props_copy[k] = v
        return props_copy

    def get_state_label(self) -> str:
        return "local-run"

    def get_external_id(self) -> str:
        d = dict(
            transform=self.transform,
            id=self.id,
            job_dir=self.job_dir,
            pid=self.proc.pid,
            outputs=self.outputs,
            captured_stdouts=self.captured_stdouts,
            desc_name=self.desc_name,
            executor_parameters=self.executor_parameters,
        )
        return json.dumps(d)

    @property
    def results_path(self):
        return os.path.join(self.job_dir, "results.json")

class ExecClient:
    def reattach(self, external_ref):
        raise NotImplementedError()

    def preprocess_inputs(
        self, resolver: Resolver, inputs: Tuple[BoundInput]
    ) -> Tuple[Dict[str, Dict[str, str]], ResolveState]:
        raise NotImplementedError()

    def exec_script(
        self,
        name: str,
        id: int,
        job_dir: str,
        run_stmts: List[str],
        outputs: Optional[List[Any]],
        capture_output: bool,
        prologue: str,
        desc_name: str,
        resolve_state: ResolveState,
        resources: Dict[str, float],
        watch_regex,
    ) -> ClientExecution:
        raise NotImplementedError()

