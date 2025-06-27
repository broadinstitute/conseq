from .. import dep
from typing import Dict, List, Optional
import sys
from ..parser import TypeDefStmt
from ..types import PropsType
import datetime
from ..dep import Jobs
from conseq import ui
import logging

log = logging.getLogger(__name__)

def reconcile_add_if_missing(j, objs):
    unseen_objs = {}
    for obj in j.find_objs(dep.PUBLIC_SPACE, {"$manually-added": "true"}):
        unseen_objs[obj.id] = obj

    new_objs = []
    for obj in objs:
        existing_id = j.get_existing_id(dep.PUBLIC_SPACE, obj)
        if existing_id is None:
            new_objs.append(obj)
        else:
            if existing_id in unseen_objs:
                del unseen_objs[existing_id]

    return new_objs, unseen_objs.values()


def remove_obj_and_children(j, root_obj_ids, dry_run):
    all_objs = j.find_all_reachable_downstream_objs(root_obj_ids)
    for obj in all_objs:
        log.warning("rm %s", obj)

    if not dry_run:
        j.remove_objects([obj.id for obj in all_objs])


def reconcile_rule_specifications(j: Jobs, latest_rules: Dict[str, str]):
    "returns artifact ids of objs which were invalidated due to stale rules (and therefore should be deleted from db)"

    existing_rules = dict(j.get_rule_specifications())
    # any rules for which we no longer have a definition are stale
    stale_rules = set(existing_rules.keys()).difference(latest_rules.keys())
    # print("Identified stale rules: {}".format(stale_rules))

    # now for those rules which we existed before and we have a definition now, if their definition is different, it's stale
    for transform in latest_rules.keys():
        if transform not in existing_rules:
            continue

        if existing_rules[transform] != latest_rules[transform]:
            stale_rules.add(transform)

    stale_object_ids = set()
    for transform in stale_rules:
        obj_ids = j.find_rule_output_ids(transform)
        stale_object_ids.update(obj_ids)

    return stale_object_ids


def reconcile_db(
    j: Jobs,
    rule_specifications: Dict[str, str],
    objs: List[PropsType],
    type_defs: List[TypeDefStmt],
    force: Optional[bool] = None,
    print_missing_objs: bool = True,
) -> None:
    # rewrite the objects, expanding templates and marking this as one which was manually added from the config file
    update_rule_specs_in_db = True
    processed = []
    for obj in objs:
        obj = dict(obj)
        if "$manually-added" not in obj:
            obj["$manually-added"] = {"$value": "true"}
        processed.append(obj)

    new_objs, missing_objs = reconcile_add_if_missing(j, processed)
    invalidated_objs = reconcile_rule_specifications(j, rule_specifications)

    missing_objs = set(invalidated_objs).union(missing_objs)

    if len(missing_objs) > 0:
        if print_missing_objs:
            print(
                "The following objects were not specified in the conseq file or were the result of a rule which has changed:",
                flush=True,
            )
            for obj in missing_objs:
                print("   {}".format(obj))
            sys.stdout.flush()
            if force is None:
                force = ui.ask_y_n("do you wish to remove them?")

        assert force is not None
        if force:
            remove_obj_and_children(j, [o.id for o in missing_objs], False)
        else:
            update_rule_specs_in_db = False

    for obj in new_objs:
        add_artifact_if_missing(j, obj)

    if update_rule_specs_in_db:
        j.write_rule_specifications(rule_specifications)

    for type_def in type_defs:
        j.add_type_def(type_def)

def add_artifact_if_missing(j: Jobs, obj: PropsType) -> int:
    timestamp = datetime.datetime.now()
    d = dict(obj)
    return j.add_obj(dep.PUBLIC_SPACE, timestamp.isoformat(), d, overwrite=False)

