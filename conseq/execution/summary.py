import logging
from typing import Any, Callable, Dict, List, Tuple, Union, Optional
import collections
from ..dao.execution import Execution

from conseq.exec_client import (
    DelegateExecution,
    ClientExecution,
)
from ..util import indent_str
from dataclasses  import dataclass
from ..dao.execution import  RuleExecution

log = logging.getLogger(__name__)

@dataclass
class SummaryRec:
    count: int
    dirs: List[str]


def get_long_execution_summary(
    executing: Union[List[Execution], List[DelegateExecution]],
    pending: List[RuleExecution],
) -> str:
    from tabulate import tabulate

    counts = collections.defaultdict(lambda: SummaryRec(count=0, dirs=[]))
    for e in executing:
        k = (e.get_state_label(), e.transform)
        rec = counts[k]
        rec.count += 1
        rec.dirs.append(e.job_dir)

    for p in pending:
        k = ("pending", p.transform)
        rec = counts[k]
        rec.count += 1

    rows = []
    for k, rec in counts.items():
        state, transform = k
        dirs = " ".join(rec.dirs)
        if len(dirs) > 30:
            dirs = dirs[: 30 - 4] + " ..."
        rows.append([state, transform, rec.count, dirs])
    return indent_str(
        tabulate(rows, ["state", "transform", "count", "dirs"], tablefmt="simple"), 4
    )

def get_execution_summary(
    executing: Union[List[ClientExecution], List[DelegateExecution]]
) -> str:
    counts = collections.defaultdict(lambda: 0)
    for e in executing:
        counts[e.get_state_label()] += 1
    keys = list(counts.keys())
    keys.sort()
    return ", ".join(["%s:%d" % (k, counts[k]) for k in keys])
