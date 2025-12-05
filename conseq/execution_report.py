import os
import shutil
from collections import namedtuple
from typing import List, Union, Tuple

from conseq.dep import RuleExecution
from conseq.exec_client import ClientExecution
from datetime import datetime

from dataclasses import dataclass
from conseq.types import Obj

try:
    from importlib.resources import files
except ImportError:
    from importlib_resources import files

Failure = namedtuple("Failure", "transform job_dir")


@dataclass(frozen=True)
class Link:
    text: str
    url: str


def format_table(column_names, rows):
    def format_column_header():
        return "\n".join([f"<td>{name}</td>" for name in column_names])

    def format_rows():
        return "\n".join([f"<tr>{format_row(row)}</td>" for row in rows])

    def format_row(row: List[Union[str, Link]]):
        return "\n".join([f"<td>{format_cell(cell)}</td>" for cell in row])

    def format_cell(cell: Union[str, Link]):
        if isinstance(cell, Link):
            return f"<a href='{cell.url}'>{cell.text}</a>"
        else:
            return str(cell)

    return f"""
        <table>
        <thead>
        <tr>
        { format_column_header() }
        </tr>
        </thead>
        <tbody>
        { format_rows() }
        </tbody>
        </table>
    """


def format_executing_table(executing: List[ClientExecution]):
    return format_table(
        ["job_dir", "transform", "desc_name"],
        [
            (
                Link(e.job_dir, os.path.basename(e.job_dir)),
                e.transform,
                f"<pre>{e.desc_name}</pre>",
            )
            for e in executing
        ],
    )




def reformat_inputs(inputs: List[Tuple[str, Obj]]):
    lines = []

    def append_kv(v: Obj):
        for prop, prop_value in v.props.items():
            lines.append("     {}: {}\n".format(prop, repr(prop_value)))

    for variable, obj in inputs:
        if isinstance(obj, list):
            for vi, ve in enumerate(obj):
                lines.append("  {}[{}]:\n".format(variable, vi))
                append_kv(ve)
        else:
            lines.append("  {}:\n".format(variable))
            append_kv(obj)

    return "".join(lines)


def format_pending_table(pending: List[RuleExecution]):
    return format_table(
        ["transform", "inputs"],
        [(e.transform, f"<pre>{reformat_inputs(e.inputs)}</pre>") for e in pending],
    )


def format_failure_table(failures: List[Failure]):
    return format_table(
        ["transform", "job_dir"],
        [(e.transform, Link(e.job_dir, os.path.basename(e.job_dir))) for e in failures],
    )


def write_execution_report(
    executing: List[ClientExecution],
    pending: List[RuleExecution],
    failures: List[Failure],
    dest_path: str,
):
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    
    # Copy vanilla.css to the destination directory
    dest_dir = os.path.dirname(dest_path)
    css_dest_path = os.path.join(dest_dir, "vanilla.css")
    
    # Locate vanilla.css in the package
    static_files = files("conseq").joinpath("static")
    css_source = static_files.joinpath("vanilla.css")
    
    # Copy the CSS file
    with open(css_source, 'rb') as src, open(css_dest_path, 'wb') as dst:
        shutil.copyfileobj(src, dst)
    
    with open(dest_path, "wt") as fd:
        fd.write(
            f"""
<html>
<head>
<link rel="stylesheet" href="vanilla.css">
</head>
<body>
<p>
Generated at {datetime.isoformat(datetime.now())}
</p>
<h1>Executing</h1>
{format_executing_table(executing)}

<h1>Pending</h1>
{format_pending_table(pending)}

<h1>Failures</h1>
{format_failure_table(failures)}

</body>
</html>
"""
        )
